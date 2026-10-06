// Package scope implements the recon tool's authorization boundary.
//
// Design principle (see spec "Security and Safety Requirements"): scope is
// not a one-time filter applied to the initial target list. Every module,
// at the moment it is about to send a request, must call Checker.Check
// against the *resolved* host. A host discovered mid-run (crt.sh, a vhost
// hit, a JS-harvested endpoint) gets the exact same gate as a host that was
// in the original scope file.
//
// Fail-closed: any parse error, malformed CIDR/hostname, or DNS resolution
// failure returns an error rather than silently defaulting to "in scope".
package scope

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope is the on-disk YAML schema described in the feature spec.
type Scope struct {
	Targets                 []string `yaml:"targets"`
	Exclude                 []string `yaml:"exclude"`
	MaxConcurrentRequests   int      `yaml:"max_concurrent_requests"`
	AllowSubdomainDiscovery bool     `yaml:"allow_subdomain_discovery"`
	Ports                   []int    `yaml:"ports"`

	// Config-file-only fields. Not required by the spec's scope table, but
	// they live in the same file since the CLI surface says "config-file
	// fields, not required flags".
	WorkerPoolSize    int             `yaml:"worker_pool_size"`
	RecursionDepthCap int             `yaml:"recursion_depth_cap"`
	WordlistBaseDir   string          `yaml:"wordlist_base_dir"`
	Wordlists         WordlistConfig  `yaml:"wordlists"`
	Timeouts          TimeoutsConfig  `yaml:"timeouts"`
	ToolPaths         ToolPathsConfig `yaml:"tool_paths"`

	// parsed, not serialized
	targetEntries  []entry
	excludeEntries []entry
}

// WordlistConfig lists the wordlist files used by the directory brute-force
// module, plus any tech-fingerprint-triggered lists (e.g. "wordpress").
type WordlistConfig struct {
	Generic      []string            `yaml:"generic"`
	TechSpecific map[string][]string `yaml:"tech_specific"`
	Subdomains   []string            `yaml:"subdomains"`
}

// TimeoutsConfig holds per-module timeouts, all overridable, all with sane
// defaults applied in Load.
type TimeoutsConfig struct {
	HTTPSeconds    int `yaml:"http_seconds"`
	DNSSeconds     int `yaml:"dns_seconds"`
	ToolRunSeconds int `yaml:"tool_run_seconds"`
}

// ToolPathsConfig lets a user point at non-PATH binaries. Still invoked via
// exec.Command with argv slices, never through a shell.
type ToolPathsConfig struct {
	WhatWeb     string `yaml:"whatweb"`
	Feroxbuster string `yaml:"feroxbuster"`
	Gowitness   string `yaml:"gowitness"`
}

// entry is one parsed targets/exclude line: either a CIDR or a bare
// hostname/domain (subdomain matching is suffix-based for domains).
type entry struct {
	raw    string
	cidr   *net.IPNet
	isCIDR bool
}

// Load reads and validates a scope file. It never returns a partially
// validated Scope — on error the caller must stop, per the "fail closed"
// requirement.
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scope file: %w", err)
	}

	var s Scope
	// yaml.v3's default decoder is strict enough to reject duplicate keys;
	// KnownFields catches typos like `max_concurent_requests` instead of
	// silently ignoring them, which matters for a security boundary file.
	dec := yaml.NewDecoder(strings_NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parsing scope file: %w", err)
	}

	s.applyDefaults()

	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("invalid scope file: %w", err)
	}

	return &s, nil
}

func strings_NewReader(b []byte) *strings.Reader {
	return strings.NewReader(string(b))
}

func (s *Scope) applyDefaults() {
	if s.MaxConcurrentRequests <= 0 {
		s.MaxConcurrentRequests = 5
	}
	if s.WorkerPoolSize <= 0 {
		s.WorkerPoolSize = s.MaxConcurrentRequests
	}
	if s.RecursionDepthCap <= 0 {
		s.RecursionDepthCap = 3
	}
	if len(s.Ports) == 0 {
		s.Ports = []int{80, 443}
	}
	if s.Timeouts.HTTPSeconds <= 0 {
		s.Timeouts.HTTPSeconds = 10
	}
	if s.Timeouts.DNSSeconds <= 0 {
		s.Timeouts.DNSSeconds = 5
	}
	if s.Timeouts.ToolRunSeconds <= 0 {
		s.Timeouts.ToolRunSeconds = 300
	}
	if s.ToolPaths.WhatWeb == "" {
		s.ToolPaths.WhatWeb = "whatweb"
	}
	if s.ToolPaths.Feroxbuster == "" {
		s.ToolPaths.Feroxbuster = "feroxbuster"
	}
	if s.ToolPaths.Gowitness == "" {
		s.ToolPaths.Gowitness = "gowitness"
	}
}

// validate parses every targets/exclude entry up front. A malformed entry
// (bad CIDR syntax, empty string, etc.) fails the whole load — we never
// want half the scope file silently dropped.
func (s *Scope) validate() error {
	if len(s.Targets) == 0 {
		return fmt.Errorf("scope file has no targets")
	}

	parsed, err := parseEntries(s.Targets)
	if err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	s.targetEntries = parsed

	parsedExclude, err := parseEntries(s.Exclude)
	if err != nil {
		return fmt.Errorf("exclude: %w", err)
	}
	s.excludeEntries = parsedExclude

	for _, p := range s.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid port %d", p)
		}
	}

	return nil
}

func parseEntries(raw []string) ([]entry, error) {
	out := make([]entry, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			return nil, fmt.Errorf("empty entry")
		}
		if strings.Contains(r, "/") {
			_, ipnet, err := net.ParseCIDR(r)
			if err != nil {
				return nil, fmt.Errorf("malformed CIDR %q: %w", r, err)
			}
			out = append(out, entry{raw: r, cidr: ipnet, isCIDR: true})
			continue
		}
		// Bare hostname/domain. Reject obviously invalid characters so a
		// stray shell metacharacter in the scope file can't end up passed
		// to exec.Command downstream believing it is a validated hostname.
		if !isPlausibleHostname(r) {
			return nil, fmt.Errorf("malformed hostname %q", r)
		}
		out = append(out, entry{raw: strings.ToLower(r), isCIDR: false})
	}
	return out, nil
}

func isPlausibleHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '*':
			// '*' allowed only as a leading wildcard marker; we don't fully
			// support wildcard DNS entries in the scope file itself here,
			// but we don't want to reject it outright either.
		default:
			return false
		}
	}
	return true
}
