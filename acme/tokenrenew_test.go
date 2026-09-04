package acme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// fakeTokenAuthClient 记录调用次数，TTL 与错误按调用序号可编程（超出取最后一个）；
// callsCh 每次调用发送信号——测试用 channel 等待而非 sleep 断言调用发生。
type fakeTokenAuthClient struct {
	mu            sync.Mutex
	calls         int
	ttls          []time.Duration
	errs          []error
	callsCh       chan struct{}
	lookupCalls   int
	lookupSecret  *api.Secret
	lookupErr     error
	lookupCallsCh chan struct{}
}

func newFakeTokenAuthClient() *fakeTokenAuthClient {
	return &fakeTokenAuthClient{
		callsCh:       make(chan struct{}, 64),
		lookupCallsCh: make(chan struct{}, 64),
	}
}

func (f *fakeTokenAuthClient) lookupSelf(ctx context.Context) (*api.Secret, error) {
	f.mu.Lock()
	f.lookupCalls++
	secret := f.lookupSecret
	err := f.lookupErr
	f.mu.Unlock()

	select {
	case f.lookupCallsCh <- struct{}{}:
	default:
	}
	return secret, err
}

func (f *fakeTokenAuthClient) renewSelf(ctx context.Context) (time.Duration, error) {
	f.mu.Lock()
	idx := f.calls
	f.calls++
	var ttl time.Duration
	var err error
	if idx < len(f.ttls) {
		ttl = f.ttls[idx]
	} else if len(f.ttls) > 0 {
		ttl = f.ttls[len(f.ttls)-1]
	}
	if idx < len(f.errs) {
		err = f.errs[idx]
	} else if len(f.errs) > 0 {
		err = f.errs[len(f.errs)-1]
	}
	f.mu.Unlock()

	select {
	case f.callsCh <- struct{}{}:
	default:
	}
	return ttl, err
}

func (f *fakeTokenAuthClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeTokenAuthClient) lookupCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookupCalls
}

// testTokenRenewer 构造注入短间隔的续期器（生产默认 1min/5min/30min 太慢，
// 单测必须秒级完成），logger 用 NullLogger 避免测试输出噪音。
func testTokenRenewer(client tokenAuthClient) *tokenRenewer {
	r := newTokenRenewer(client, hclog.NewNullLogger())
	r.intervalFloor = 50 * time.Millisecond
	r.backoffInit = 20 * time.Millisecond
	r.backoffMax = 100 * time.Millisecond
	return r
}

// waitCall 等待一次 renewSelf 调用信号，超时视为循环未按预期发起调用。
func waitCall(t *testing.T, ch chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(msg)
	}
}

// 场景 1：启动即续期一次，并按 TTL/2 调度下一次。
func TestTokenRenewerRenewsOnStartThenHalfTTL(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.ttls = []time.Duration{200 * time.Millisecond}
	r := testTokenRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		r.run(ctx)
		close(done)
	}()

	waitCall(t, fake.callsCh, "启动后未立即发起首次续期")
	waitCall(t, fake.callsCh, "未按 TTL/2 调度第二次续期")
	require.GreaterOrEqual(t, fake.callCount(), 2)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel 后 run 未退出")
	}
}

// 场景 2：续期失败进入指数退避并重试成功（成功后继续按 TTL/2 正常调度）。
func TestTokenRenewerBacksOffOnFailureThenRetries(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.errs = []error{errors.New("seal is unavailable")}
	// 第一次失败（TTL 值此时无意义），之后成功返回 TTL。
	fake.ttls = []time.Duration{0, 200 * time.Millisecond}
	r := testTokenRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		r.run(ctx)
		close(done)
	}()

	// 第 1 次：失败；第 2 次：退避(20ms)后重试成功；第 3 次：TTL/2 后正常续期。
	waitCall(t, fake.callsCh, "启动后未发起首次续期")
	waitCall(t, fake.callsCh, "失败后未进入退避重试")
	waitCall(t, fake.callsCh, "重试成功后未继续按 TTL/2 调度")
	require.GreaterOrEqual(t, fake.callCount(), 3)

	cancel()
	<-done
}

// 场景 3：TTL==0（root 等不可续期 token）→ 视为无需续期，记日志后停止循环。
func TestTokenRenewerStopsOnZeroTTL(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.ttls = []time.Duration{0}
	r := testTokenRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		r.run(ctx)
		close(done)
	}()

	waitCall(t, fake.callsCh, "启动后未发起首次续期")
	// 循环应已停止：等待远大于任何可能的退避/调度间隔，调用数不得再增长。
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TTL=0 后 run 未退出")
	}
	time.Sleep(150 * time.Millisecond)
	require.Equal(t, 1, fake.callCount(), "TTL=0 时不得有后续调用")
}

// 场景 4：ctx 取消后循环退出。
func TestTokenRenewerStopsOnContextCancel(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.ttls = []time.Duration{1 * time.Hour}
	r := testTokenRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.run(ctx)
		close(done)
	}()

	waitCall(t, fake.callsCh, "启动后未发起首次续期")
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后 run 未退出")
	}
}

// 场景 5：BAO_TOKEN_RENEW_DISABLE 逃生口——完全不启动循环，不发起任何调用。
func TestTokenRenewerDisabledByEnv(t *testing.T) {
	t.Setenv("BAO_TOKEN_RENEW_DISABLE", "1")
	conf := logical.TestBackendConfig()
	b, err := Backend(conf)
	require.NoError(t, err)
	fake := newFakeTokenAuthClient()
	b.renewClient = fake

	b.startTokenRenewer()
	time.Sleep(100 * time.Millisecond)
	require.Zero(t, fake.callCount(), "逃生口开启时不得发起任何 renew-self 调用")
}

// 场景 5 补充：逃生口取值解析——非空且非 "0"/"false"（大小写不敏感）才禁用。
func TestTokenRenewDisableEnvParsing(t *testing.T) {
	cases := map[string]bool{
		"":      false, // 未设置语义（空值）→ 不禁用
		"0":     false,
		"false": false,
		"FALSE": false,
		"1":     true,
		"true":  true,
		"yes":   true,
	}
	for env, want := range cases {
		t.Setenv("BAO_TOKEN_RENEW_DISABLE", env)
		require.Equal(t, want, tokenRenewDisabled(), "BAO_TOKEN_RENEW_DISABLE=%q", env)
	}
}

// 场景 7：启动前 lookup-self 检测到不可续期（root policy、renewable=false、ttl==0）→ 跳过续期循环且不调用 renewSelf。
func TestTokenRenewerStopsOnLookupSelfNonRenewable(t *testing.T) {
	cases := []struct {
		name   string
		secret *api.Secret
	}{
		{
			name: "root policy",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"policies":  []string{"root"},
					"renewable": true,
					"ttl":       3600,
				},
			},
		},
		{
			name: "renewable false",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"policies":  []string{"default"},
					"renewable": false,
					"ttl":       3600,
				},
			},
		},
		{
			name: "zero ttl",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"policies":  []string{"default"},
					"renewable": true,
					"ttl":       0,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeTokenAuthClient()
			fake.lookupSecret = tc.secret
			r := testTokenRenewer(fake)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				r.run(ctx)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("lookup-self 检测到不可续期后 run 未及时退出")
			}
			require.Equal(t, 1, fake.lookupCallCount(), "应调用一次 lookupSelf")
			require.Equal(t, 0, fake.callCount(), "不可续期 token 不得调用 renewSelf")
		})
	}
}

// 场景 8：lookup-self 失败（例如无 lookup-self 策略权限），应降级继续调用 renewSelf。
func TestTokenRenewerLookupSelfFailsFallbackToRenewSelf(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.lookupErr = errors.New("permission denied")
	fake.ttls = []time.Duration{200 * time.Millisecond}
	r := testTokenRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		r.run(ctx)
		close(done)
	}()

	waitCall(t, fake.callsCh, "lookup-self 失败后未降级发起 renew-self")
	require.Equal(t, 1, fake.lookupCallCount())
	require.GreaterOrEqual(t, fake.callCount(), 1)

	cancel()
	<-done
}

// 场景 9：renew-self 返回 400 且包含不可续期错误（如 "invalid lease ID" 或 "not renewable"），停止循环且不再退避重试。
func TestTokenRenewerStopsOnRenewSelfNonRenewableError(t *testing.T) {
	errCases := []string{
		"Error making API request.\nURL: PUT http://127.0.0.1:8200/v1/auth/token/renew-self\nCode: 400. Errors: * invalid lease ID",
		"renew-self: Code: 400. Errors: * token is not renewable",
		"renew-self: lease not found",
	}

	for _, errMsg := range errCases {
		t.Run(errMsg, func(t *testing.T) {
			fake := newFakeTokenAuthClient()
			// 让 lookup 失败以模拟 fallback 到 renewSelf
			fake.lookupErr = errors.New("lookup disabled")
			fake.errs = []error{errors.New(errMsg)}
			r := testTokenRenewer(fake)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				r.run(ctx)
				close(done)
			}()

			waitCall(t, fake.callsCh, "未发起 renew-self")
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("遇到不可续期 400 错误后 run 未退出")
			}
			time.Sleep(100 * time.Millisecond)
			require.Equal(t, 1, fake.callCount(), "不可续期错误发生后不得再重试")
		})
	}
}

// 场景 10：apiTokenAuthClient lookupSelf 真实包装层——httptest 假服务端验证请求身份与端点。
func TestAPITokenAuthClientLookupSelf(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("lookup-self 应为 GET: got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("X-Vault-Token"); got != pluginEnvToken {
			t.Errorf("应以插件 env token 身份请求: got %q", got)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"policies":["root"],"renewable":false,"ttl":0}}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	t.Setenv("BAO_ADDR", ts.URL)
	t.Setenv("BAO_TOKEN", pluginEnvToken)

	client := &apiTokenAuthClient{}
	secret, err := client.lookupSelf(context.Background())
	require.NoError(t, err)
	require.NotNil(t, secret)
	policies, err := secret.TokenPolicies()
	require.NoError(t, err)
	require.Contains(t, policies, "root")
	renewable, err := secret.TokenIsRenewable()
	require.NoError(t, err)
	require.False(t, renewable)
}

// 场景 6：apiTokenAuthClient 真实包装层——httptest 假服务端验证请求身份、
// 方法与 TTL 解析（TTL 取 auth.lease_duration，单位秒）。
func TestAPITokenAuthClientRenewSelf(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("renew-self 应为 PUT: got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// 与 credentials_test 同口径：必须以插件 env token 身份发出。
		if got := r.Header.Get("X-Vault-Token"); got != pluginEnvToken {
			t.Errorf("应以插件 env token 身份请求: got %q", got)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"renewable":true,"lease_duration":3600,"auth":{"client_token":"plugin-env-token","lease_duration":7200}}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	t.Setenv("BAO_ADDR", ts.URL)
	t.Setenv("BAO_TOKEN", pluginEnvToken)

	client := &apiTokenAuthClient{}
	ttl, err := client.renewSelf(context.Background())
	require.NoError(t, err)
	require.Equal(t, 7200*time.Second, ttl, "TTL 应取 auth.lease_duration")
}
