package scope

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Result is the outcome of a scope check against one resolved host.
type Result struct {
	Host    string
	IPs     []net.IP
	InScope bool
	Reason  string // populated when InScope is false
}

// Checker is the single gate every module calls before it sends a request.
// It is safe for concurrent use.
type Checker struct {
	scope *Scope
}

func NewChecker(s *Scope) *Checker {
	return &Checker{scope: s}
}

// Check resolves host and decides whether it is in scope. This is the
// function the spec means by "every module that's about to send a request
// checks the resolved host/IP against this file first" — it is called
// fresh for every target, not cached from a startup-time pass, so a host
// whose DNS answer changes mid-run is re-evaluated rather than trusted
// from an earlier lookup.
//
// Fail closed: a DNS resolution failure returns InScope=false with an
// error, never "treat as in scope".
func (c *Checker) Check(ctx context.Context, host string) (Result, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	// Exclude-by-hostname check happens before DNS even runs — no point
	// resolving a host we're going to reject by name anyway, and it avoids
	// leaking a resolution attempt for hosts an operator explicitly carved
	// out.
	if matchesHostEntries(host, c.scope.excludeEntries) {
		return Result{Host: host, InScope: false, Reason: "excluded"}, nil
	}

	ips, err := resolveHost(ctx, host)
	if err != nil {
		// Fail closed: a resolution failure is never treated as in scope.
		return Result{Host: host, InScope: false, Reason: "dns_resolution_failed"},
			fmt.Errorf("resolving %s: %w", host, err)
	}

	// Exclude by IP/CIDR wins over everything, including a targets-CIDR
	// match — this implements "exclude ... carved out even if they'd match
	// a targets CIDR".
	for _, ip := range ips {
		if matchesIPEntries(ip, c.scope.excludeEntries) {
			return Result{Host: host, IPs: ips, InScope: false, Reason: "excluded"}, nil
		}
	}

	if matchesHostEntries(host, c.scope.targetEntries) {
		return Result{Host: host, IPs: ips, InScope: true}, nil
	}
	for _, ip := range ips {
		if matchesIPEntries(ip, c.scope.targetEntries) {
			return Result{Host: host, IPs: ips, InScope: true}, nil
		}
	}

	return Result{Host: host, IPs: ips, InScope: false, Reason: "not_in_target_list"}, nil
}

// AllowSubdomainDiscovery reports the scope file's policy on auto-adding
// newly discovered subdomains to the live target set.
func (c *Checker) AllowSubdomainDiscovery() bool {
	return c.scope.AllowSubdomainDiscovery
}

func (c *Checker) MaxConcurrentRequests() int { return c.scope.MaxConcurrentRequests }
func (c *Checker) Ports() []int               { return c.scope.Ports }
func (c *Checker) Raw() *Scope                { return c.scope }

func matchesHostEntries(host string, entries []entry) bool {
	for _, e := range entries {
		if e.isCIDR {
			continue
		}
		if strings.HasPrefix(e.raw, "*.") {
			suffix := strings.TrimPrefix(e.raw, "*")
			if strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == e.raw || strings.HasSuffix(host, "."+e.raw) {
			return true
		}
	}
	return false
}

func matchesIPEntries(ip net.IP, entries []entry) bool {
	for _, e := range entries {
		if !e.isCIDR {
			continue
		}
		if e.cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveHost does a real DNS lookup unless host is already a literal IP.
func resolveHost(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses returned")
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}
