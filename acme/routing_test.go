package acme

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recordingProvider 记录 Present/CleanUp 的 domain，用于断言委托。
type recordingProvider struct{ domains []string }

func (p *recordingProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	p.domains = append(p.domains, "present:"+domain)
	return nil
}
func (p *recordingProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	p.domains = append(p.domains, "cleanup:"+domain)
	return nil
}
func (p *recordingProvider) Timeout() (time.Duration, time.Duration) {
	return 10 * time.Second, 1 * time.Second
}

func TestRoutingMatch(t *testing.T) {
	slow := &recordingProvider{}
	fallback := &recordingProvider{}
	rp, err := newRoutingProvider([]providerRoute{
		{Name: "cf-base", Zones: []string{"example.com"}, Provider: slow},
		{Name: "cf-sys", Zones: []string{"sys.example.com"}, Provider: fallback},
		{Name: "catch-all", Provider: fallback},
	})
	require.NoError(t, err)

	// 精度优先：sys.example.com 胜过 example.com
	r, err := rp.match("www.sys.example.com")
	require.NoError(t, err)
	require.Equal(t, "cf-sys", r.Name)

	// 后缀匹配
	r, _ = rp.match("www.example.com")
	require.Equal(t, "cf-base", r.Name)

	// 通配符剥除
	r, _ = rp.match("*.example.com")
	require.Equal(t, "cf-base", r.Name)

	// 兜底
	r, _ = rp.match("other.org")
	require.Equal(t, "catch-all", r.Name)
}

func TestRoutingNoFallbackError(t *testing.T) {
	rp, err := newRoutingProvider([]providerRoute{
		{Name: "only", Zones: []string{"example.com"}, Provider: &recordingProvider{}},
	})
	require.NoError(t, err)
	_, err = rp.match("other.org")
	require.ErrorContains(t, err, "无匹配")
}

func TestRoutingOrderTieBreak(t *testing.T) {
	first, second := &recordingProvider{}, &recordingProvider{}
	rp, _ := newRoutingProvider([]providerRoute{
		{Name: "first", Zones: []string{"a.com", "b.com"}, Provider: first},
		{Name: "second", Zones: []string{"b.com"}, Provider: second},
	})
	r, err := rp.match("x.b.com")
	require.NoError(t, err)
	require.Equal(t, "first", r.Name) // 深度平局 → 列表顺序
}

func TestRoutingDelegation(t *testing.T) {
	p := &recordingProvider{}
	rp, _ := newRoutingProvider([]providerRoute{
		{Name: "cf", Zones: []string{"example.com"}, Provider: p},
	})
	ctx := context.Background()
	require.NoError(t, rp.Present(ctx, "www.example.com", "tok", "ka"))
	require.NoError(t, rp.CleanUp(ctx, "www.example.com", "tok", "ka"))
	require.Equal(t, []string{"present:www.example.com", "cleanup:www.example.com"}, p.domains)
}

func TestRoutingTimeoutAggregate(t *testing.T) {
	rp, _ := newRoutingProvider([]providerRoute{
		{Name: "a", Provider: &recordingProvider{}},      // 10s/1s
		{Name: "b", Provider: &routingDefaultProvider{}}, // 无 Timeout 接口
	})
	timeout, interval := rp.Timeout()
	require.Equal(t, 10*time.Second, timeout)
	require.Equal(t, time.Second, interval)
}

// routingDefaultProvider 只有 Provider 接口（测试无 Timeout 的子 provider）。
type routingDefaultProvider struct{ recordingProvider }
