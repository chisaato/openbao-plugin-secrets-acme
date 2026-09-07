package tokenrenew

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

func (f *fakeTokenAuthClient) LookupSelf(ctx context.Context) (*api.Secret, error) {
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

func (f *fakeTokenAuthClient) RenewSelf(ctx context.Context) (time.Duration, error) {
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

func (f *fakeTokenAuthClient) waitCall(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-f.callsCh:
	case <-time.After(timeout):
		t.Fatalf("等待 renewSelf 超时 (%v)", timeout)
	}
}

func (f *fakeTokenAuthClient) waitLookupCall(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-f.lookupCallsCh:
	case <-time.After(timeout):
		t.Fatalf("等待 lookupSelf 超时 (%v)", timeout)
	}
}

func testRenewer(client TokenAuthClient) (*TokenRenewer, *hclog.Logger) {
	logger := hclog.NewNullLogger()
	r := NewTokenRenewer(client, logger)
	r.IntervalFloor = 10 * time.Millisecond
	r.BackoffInit = 20 * time.Millisecond
	r.BackoffMax = 80 * time.Millisecond
	return r, &logger
}

// 场景 1：首次启动即执行一次 renew-self。
func TestTokenRenewerStartupRenew(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.ttls = []time.Duration{time.Hour}
	r, _ := testRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	fake.waitCall(t, 2*time.Second)
	require.GreaterOrEqual(t, fake.callCount(), 1, "启动后应立即尝试续期")
}

// 场景 2：成功后按 TTL/2 调度下次。
func TestTokenRenewerScheduleNext(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.ttls = []time.Duration{80 * time.Millisecond, time.Hour}
	r, _ := testRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	go r.Run(ctx)

	fake.waitCall(t, 2*time.Second) // 首次立即
	fake.waitCall(t, 2*time.Second) // 第二次在 ~40ms（80ms/2）
	elapsed := time.Since(start)

	require.GreaterOrEqual(t, fake.callCount(), 2)
	require.GreaterOrEqual(t, elapsed, 30*time.Millisecond,
		"第二次调用应在约 TTL/2 (40ms) 之后发生，过快说明无等待")
}

// 场景 3：失败退避重试（初值 -> 翻倍 -> 上限）。
func TestTokenRenewerExponentialBackoff(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.errs = []error{
		errors.New("conn refuse 1"),
		errors.New("conn refuse 2"),
		errors.New("conn refuse 3"),
		errors.New("conn refuse 4"),
	}
	r, _ := testRenewer(fake)
	r.BackoffInit = 20 * time.Millisecond
	r.BackoffMax = 40 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	go r.Run(ctx)

	// 调用序：
	// #1: t=0 (启动立即)
	// #2: t ~ +20ms (backoffInit)
	// #3: t ~ +20+40 = +60ms (min(20*2, 40) = 40ms)
	// #4: t ~ +60+40 = +100ms (封顶 40ms)
	for i := 0; i < 4; i++ {
		fake.waitCall(t, 2*time.Second)
	}
	elapsed := time.Since(start)

	require.Equal(t, 4, fake.callCount())
	require.GreaterOrEqual(t, elapsed, 70*time.Millisecond,
		"4 次重试跨度应累积退避等待，当前耗时 %v", elapsed)
}

// 场景 4：失败后成功恢复，退避重置。
func TestTokenRenewerRecoveryResetsBackoff(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.errs = []error{
		errors.New("transient 1"),
		errors.New("transient 2"),
		nil,
	}
	fake.ttls = []time.Duration{0, 0, time.Hour}
	r, _ := testRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	for i := 0; i < 3; i++ {
		fake.waitCall(t, 2*time.Second)
	}
	require.Equal(t, 3, fake.callCount())
}

// 场景 5：TTL <= 0（root 等不可续期 token）停止循环。
func TestTokenRenewerStopsOnZeroTTL(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.ttls = []time.Duration{0}
	r, _ := testRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	fake.waitCall(t, 2*time.Second)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, fake.callCount(), "TTL<=0 时应退出循环，不再重试")
}

// 场景 5.1：LookupSelf 返回 root policy 时跳过自动续期
func TestTokenRenewerSkipsOnRootPolicy(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.lookupSecret = &api.Secret{
		Data: map[string]interface{}{
			"policies":  []interface{}{"root"},
			"renewable": false,
			"ttl":       0,
		},
	}
	r, _ := testRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	fake.waitLookupCall(t, 2*time.Second)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 0, fake.callCount(), "拥有 root policy 的 token 应该跳过自动续期循环")
}

// 场景 5.2：renewSelf 返回 400 不可续期错误时退出循环不再刷屏报错
func TestTokenRenewerStopsOnNonRenewableError(t *testing.T) {
	fake := newFakeTokenAuthClient()
	fake.errs = []error{
		errors.New("Error making API request. URL: PUT http://127.0.0.1:8200/v1/auth/token/renew-self Code: 400. Errors: * lease not found or lease is not renewable"),
	}
	r, _ := testRenewer(fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	fake.waitCall(t, 2*time.Second)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, fake.callCount(), "返回不可续期 400 错误时应停止循环退出")
}

func TestTokenRenewDisabled(t *testing.T) {
	t.Setenv("BAO_TOKEN_RENEW_DISABLE", "1")
	require.True(t, TokenRenewDisabled())

	t.Setenv("BAO_TOKEN_RENEW_DISABLE", "true")
	require.True(t, TokenRenewDisabled())

	t.Setenv("BAO_TOKEN_RENEW_DISABLE", "TRUE")
	require.True(t, TokenRenewDisabled())

	t.Setenv("BAO_TOKEN_RENEW_DISABLE", "0")
	require.False(t, TokenRenewDisabled())

	t.Setenv("BAO_TOKEN_RENEW_DISABLE", "false")
	require.False(t, TokenRenewDisabled())

	t.Setenv("BAO_TOKEN_RENEW_DISABLE", "")
	require.False(t, TokenRenewDisabled())
}

func TestAPITokenAuthClientLookupSelf(t *testing.T) {
	pluginEnvToken := "plugin-env-token"
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

	client := &APITokenAuthClient{}
	secret, err := client.LookupSelf(context.Background())
	require.NoError(t, err)
	require.NotNil(t, secret)
	policies, err := secret.TokenPolicies()
	require.NoError(t, err)
	require.Contains(t, policies, "root")
	renewable, err := secret.TokenIsRenewable()
	require.NoError(t, err)
	require.False(t, renewable)
}

func TestAPITokenAuthClientRenewSelf(t *testing.T) {
	pluginEnvToken := "plugin-env-token"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("renew-self 应为 PUT: got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
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

	client := &APITokenAuthClient{}
	ttl, err := client.RenewSelf(context.Background())
	require.NoError(t, err)
	require.Equal(t, 7200*time.Second, ttl, "TTL 应取 auth.lease_duration")
}
