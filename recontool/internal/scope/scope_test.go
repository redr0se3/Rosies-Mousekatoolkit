package scope

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeScope(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_RejectsMalformedCIDR(t *testing.T) {
	path := writeScope(t, "targets:\n  - 10.0.0.0/abc\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for malformed CIDR, got nil")
	}
}

func TestLoad_RejectsEmptyTargets(t *testing.T) {
	path := writeScope(t, "targets: []\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for empty targets list, got nil")
	}
}

func TestLoad_RejectsUnknownFields(t *testing.T) {
	path := writeScope(t, "targets:\n  - example.com\nmax_concurent_requests: 5\n") // typo'd key
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown field (typo'd key), got nil")
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	path := writeScope(t, "targets:\n  - example.com\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.MaxConcurrentRequests != 5 {
		t.Errorf("expected default max_concurrent_requests=5, got %d", s.MaxConcurrentRequests)
	}
	if len(s.Ports) != 2 || s.Ports[0] != 80 || s.Ports[1] != 443 {
		t.Errorf("expected default ports [80,443], got %v", s.Ports)
	}
	if s.AllowSubdomainDiscovery {
		t.Error("expected allow_subdomain_discovery to default false")
	}
}

func TestChecker_ExcludeWinsOverTargetCIDR(t *testing.T) {
	path := writeScope(t, "targets:\n  - 127.0.0.0/8\nexclude:\n  - 127.0.0.1/32\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c := NewChecker(s)

	res, err := c.Check(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if res.InScope {
		t.Error("expected 127.0.0.1 to be excluded even though it matches the targets CIDR")
	}
	if res.Reason != "excluded" {
		t.Errorf("expected reason 'excluded', got %q", res.Reason)
	}
}

func TestChecker_HostnameInCIDRTargetScope(t *testing.T) {
	path := writeScope(t, "targets:\n  - 127.0.0.0/8\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c := NewChecker(s)

	res, err := c.Check(context.Background(), "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !res.InScope {
		t.Error("expected 127.0.0.2 to be in scope via the targets CIDR")
	}
}

func TestChecker_SubdomainOfTargetDomainInScope(t *testing.T) {
	path := writeScope(t, "targets:\n  - example.com\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = NewChecker(s) // exercising Load's side effects; the check below is pure string logic

	// matchesHostEntries is pure string logic, so this test exercises it
	// without needing a real DNS lookup — a bare "example.com" target
	// must authorize "www.example.com" by suffix, not just exact match.
	if !matchesHostEntries("www.example.com", s.targetEntries) {
		t.Error("expected www.example.com to match target entry example.com by suffix")
	}
	if matchesHostEntries("notexample.com", s.targetEntries) {
		t.Error("notexample.com must NOT match example.com (suffix check must be dot-delimited)")
	}
}

func TestChecker_UnresolvableHostFailsClosed(t *testing.T) {
	path := writeScope(t, "targets:\n  - example.com\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c := NewChecker(s)

	res, err := c.Check(context.Background(), "this-host-should-not-exist-recontool-test.invalid")
	if err == nil {
		t.Fatal("expected a DNS resolution error for an invalid TLD, got nil")
	}
	if res.InScope {
		t.Error("fail-closed violated: unresolvable host must never be reported in scope")
	}
}
