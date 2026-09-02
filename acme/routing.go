package acme

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge"
)

// providerRoute 把 DNS zone 列表绑定到一个已构造的 provider；Zones 空=兜底。
type providerRoute struct {
	Name     string
	Zones    []string
	Provider challenge.Provider
}

// routingProvider 按域名委托 Present/CleanUp。路由表构造后只读，并发安全。
type routingProvider struct {
	routes []providerRoute
}

// 编译期断言：具备超时聚合能力。
var _ challenge.ProviderTimeout = (*routingProvider)(nil)

func newRoutingProvider(routes []providerRoute) (*routingProvider, error) {
	for i, r := range routes {
		if r.Provider == nil {
			return nil, fmt.Errorf("route[%d] (%s) provider 为空", i, r.Name)
		}
	}
	return &routingProvider{routes: routes}, nil
}

// match：zones 后缀匹配、zone 段数多者优先、平局按列表顺序、无 zones 兜底、无匹配报错。
func (rp *routingProvider) match(domain string) (*providerRoute, error) {
	d := strings.TrimPrefix(strings.ToLower(domain), "*.")

	var best *providerRoute
	bestLabels := -1
	for i := range rp.routes {
		r := &rp.routes[i]
		for _, zone := range r.Zones {
			zone = strings.ToLower(strings.TrimSuffix(zone, "."))
			if d == zone || strings.HasSuffix(d, "."+zone) {
				if labels := strings.Count(zone, ".") + 1; labels > bestLabels {
					best, bestLabels = r, labels
				}
				break
			}
		}
	}
	if best != nil {
		return best, nil
	}
	for i := range rp.routes {
		if len(rp.routes[i].Zones) == 0 {
			return &rp.routes[i], nil
		}
	}
	return nil, fmt.Errorf("域名 %q 无匹配的 dns provider 路由（已配置 zones: %s）", domain, rp.configuredZones())
}

// configuredZones 汇总所有路由的 zone 与兜底路由名，仅用于错误信息，不含凭据。
func (rp *routingProvider) configuredZones() string {
	var parts []string
	for _, r := range rp.routes {
		if len(r.Zones) == 0 {
			parts = append(parts, r.Name+"(兜底)")
			continue
		}
		parts = append(parts, r.Name+":"+strings.Join(r.Zones, ","))
	}
	return strings.Join(parts, "; ")
}

func (rp *routingProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	r, err := rp.match(domain)
	if err != nil {
		return err
	}
	return r.Provider.Present(ctx, domain, token, keyAuth)
}

func (rp *routingProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	r, err := rp.match(domain)
	if err != nil {
		return err
	}
	return r.Provider.CleanUp(ctx, domain, token, keyAuth)
}

// Timeout 返回各子 provider 最保守（最大）的组合；全默认时 60s/2s。
func (rp *routingProvider) Timeout() (timeout, interval time.Duration) {
	for _, r := range rp.routes {
		if pt, ok := r.Provider.(challenge.ProviderTimeout); ok {
			t, i := pt.Timeout()
			if t > timeout {
				timeout = t
			}
			if i > interval {
				interval = i
			}
		}
	}
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if interval == 0 {
		interval = 2 * time.Second
	}
	return timeout, interval
}
