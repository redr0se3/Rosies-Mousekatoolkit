// Package state defines the shared "target state" object the whole spec
// revolves around: every module reads from and writes to the same struct
// per target, instead of returning disconnected result sets that only the
// orchestrator understands.
package state

import (
	"sync"
	"time"
)

// PathFinding is one discovered path/file from directory brute-forcing.
type PathFinding struct {
	Path          string `json:"path"`
	Status        int    `json:"status"`
	ContentLength int64  `json:"content_length"`
	ContentHash   string `json:"content_hash"`
	FoundBy       string `json:"found_by"` // which wordlist/module found it
}

// VHostFinding is one discovered vhost/subdomain.
type VHostFinding struct {
	Hostname string   `json:"hostname"`
	Source   string   `json:"source"` // "dns", "ct_log", "host_header_fuzz"
	IPs      []string `json:"ips,omitempty"`
}

// JSFinding is one regex hit inside a harvested JavaScript file.
type JSFinding struct {
	File        string `json:"file"`
	PatternType string `json:"pattern_type"` // "endpoint", "secret", "hostname"
	Snippet     string `json:"snippet"`
}

// ScreenshotFinding maps a URL to its captured screenshot file.
type ScreenshotFinding struct {
	URL      string `json:"url"`
	FilePath string `json:"file_path"`
}

// SkippedFinding records anything found but intentionally excluded, with
// the reason — this is how "discovered, out of scope" items stay visible
// in the output instead of disappearing silently.
type SkippedFinding struct {
	Item   string `json:"item"`
	Reason string `json:"reason"` // "out_of_scope", "excluded", "recursion_depth_cap"
}

// Target is the one struct passed by pointer into every module. Modules
// mutate it (via the Lock/Unlock helpers below) rather than handing back
// disconnected results for the orchestrator to reconcile.
type Target struct {
	mu sync.Mutex

	Hostname  string   `json:"hostname"`
	IPs       []string `json:"ips"`
	InScope   bool     `json:"in_scope"`
	TechStack []string `json:"tech_stack"`

	Paths       []PathFinding       `json:"paths"`
	VHosts      []VHostFinding      `json:"vhosts"`
	Endpoints   []string            `json:"endpoints"` // JS-harvested, queued back into dir brute-force
	JSFindings  []JSFinding         `json:"js_findings"`
	Screenshots []ScreenshotFinding `json:"screenshots"`
	Skipped     []SkippedFinding    `json:"skipped"`

	// WordlistSeeds are extra path segments harvested by passive recon
	// (robots.txt, sitemap.xml, Wayback/CommonCrawl history) that feed
	// Phase 2's directory brute-force as an additional wordlist, not a
	// confirmed finding in their own right — excluded from the JSON
	// output schema, which is why this isn't listed in the spec's Output
	// table.
	WordlistSeeds []string `json:"-"`

	// ModuleStatus records what happened per module: "ok", "error:<msg>",
	// "skipped_out_of_scope".
	ModuleStatus map[string]string `json:"module_status"`

	// WildcardDNS is set once wildcard-catch-all detection runs, so later
	// vhost brute-force modules know to fingerprint responses rather than
	// trust "did it resolve".
	WildcardDNS    bool   `json:"wildcard_dns"`
	BaselineHash   string `json:"baseline_hash,omitempty"`
	BaselineLength int64  `json:"baseline_length,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewTarget(hostname string) *Target {
	return &Target{
		Hostname:     hostname,
		ModuleStatus: make(map[string]string),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
}

// Mutate runs fn under the target's lock. Every module must go through
// this (or the typed helpers below) instead of touching fields directly —
// modules run concurrently inside the worker pool, and the target struct
// is shared, mutable state.
func (t *Target) Mutate(fn func(*Target)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fn(t)
	t.UpdatedAt = time.Now().UTC()
}

func (t *Target) AddPaths(paths ...PathFinding) {
	t.Mutate(func(t *Target) { t.Paths = append(t.Paths, paths...) })
}

func (t *Target) AddVHosts(vhosts ...VHostFinding) {
	t.Mutate(func(t *Target) { t.VHosts = append(t.VHosts, vhosts...) })
}

func (t *Target) AddEndpoints(endpoints ...string) {
	t.Mutate(func(t *Target) { t.Endpoints = append(t.Endpoints, endpoints...) })
}

func (t *Target) AddJSFindings(f ...JSFinding) {
	t.Mutate(func(t *Target) { t.JSFindings = append(t.JSFindings, f...) })
}

func (t *Target) AddScreenshots(s ...ScreenshotFinding) {
	t.Mutate(func(t *Target) { t.Screenshots = append(t.Screenshots, s...) })
}

func (t *Target) AddSkipped(s ...SkippedFinding) {
	t.Mutate(func(t *Target) { t.Skipped = append(t.Skipped, s...) })
}

func (t *Target) AddWordlistSeeds(seeds ...string) {
	t.Mutate(func(t *Target) {
		seen := make(map[string]bool, len(t.WordlistSeeds))
		for _, s := range t.WordlistSeeds {
			seen[s] = true
		}
		for _, s := range seeds {
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			t.WordlistSeeds = append(t.WordlistSeeds, s)
		}
	})
}

func (t *Target) MergeTechStack(tech ...string) {
	t.Mutate(func(t *Target) {
		seen := make(map[string]bool, len(t.TechStack))
		for _, existing := range t.TechStack {
			seen[existing] = true
		}
		for _, tag := range tech {
			if tag == "" || seen[tag] {
				continue
			}
			seen[tag] = true
			t.TechStack = append(t.TechStack, tag)
		}
	})
}

func (t *Target) SetModuleStatus(module, status string) {
	t.Mutate(func(t *Target) { t.ModuleStatus[module] = status })
}

func (t *Target) GetModuleStatus(module string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.ModuleStatus[module]
	return s, ok
}

// LoadFrom copies every field from src into t except the mutex itself
// (copying a locked sync.Mutex by value is a go vet "copylocks" footgun
// we avoid entirely by copying field-by-field). Used by --resume to
// rehydrate a Target from a previously saved results.json without ever
// assigning *t = *src.
func (t *Target) LoadFrom(src *Target) {
	t.Mutate(func(t *Target) {
		t.Hostname = src.Hostname
		t.IPs = append([]string{}, src.IPs...)
		t.InScope = src.InScope
		t.TechStack = append([]string{}, src.TechStack...)
		t.Paths = append([]PathFinding{}, src.Paths...)
		t.VHosts = append([]VHostFinding{}, src.VHosts...)
		t.Endpoints = append([]string{}, src.Endpoints...)
		t.JSFindings = append([]JSFinding{}, src.JSFindings...)
		t.Screenshots = append([]ScreenshotFinding{}, src.Screenshots...)
		t.Skipped = append([]SkippedFinding{}, src.Skipped...)
		t.WordlistSeeds = append([]string{}, src.WordlistSeeds...)
		status := make(map[string]string, len(src.ModuleStatus))
		for k, v := range src.ModuleStatus {
			status[k] = v
		}
		t.ModuleStatus = status
		t.WildcardDNS = src.WildcardDNS
		t.BaselineHash = src.BaselineHash
		t.BaselineLength = src.BaselineLength
		t.CreatedAt = src.CreatedAt
	})
}

// Snapshot is a plain-data (no mutex) copy of Target for safe read access
// — e.g. by the orchestrator deciding what to queue next, or by a module
// that wants a consistent read of several fields without holding the
// target's lock across its own (possibly slow) work. Deliberately a
// distinct type from Target rather than Target-by-value: copying a
// struct that embeds a sync.Mutex is a classic footgun (go vet's
// "copylocks" check exists specifically to catch it), and giving the
// snapshot its own type means that mistake can't compile.
type Snapshot struct {
	Hostname       string
	IPs            []string
	InScope        bool
	TechStack      []string
	Paths          []PathFinding
	VHosts         []VHostFinding
	Endpoints      []string
	JSFindings     []JSFinding
	Screenshots    []ScreenshotFinding
	Skipped        []SkippedFinding
	WordlistSeeds  []string
	ModuleStatus   map[string]string
	WildcardDNS    bool
	BaselineHash   string
	BaselineLength int64
}

func (t *Target) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	status := make(map[string]string, len(t.ModuleStatus))
	for k, v := range t.ModuleStatus {
		status[k] = v
	}
	return Snapshot{
		Hostname:       t.Hostname,
		IPs:            append([]string{}, t.IPs...),
		InScope:        t.InScope,
		TechStack:      append([]string{}, t.TechStack...),
		Paths:          append([]PathFinding{}, t.Paths...),
		VHosts:         append([]VHostFinding{}, t.VHosts...),
		Endpoints:      append([]string{}, t.Endpoints...),
		JSFindings:     append([]JSFinding{}, t.JSFindings...),
		Screenshots:    append([]ScreenshotFinding{}, t.Screenshots...),
		Skipped:        append([]SkippedFinding{}, t.Skipped...),
		WordlistSeeds:  append([]string{}, t.WordlistSeeds...),
		ModuleStatus:   status,
		WildcardDNS:    t.WildcardDNS,
		BaselineHash:   t.BaselineHash,
		BaselineLength: t.BaselineLength,
	}
}

// Store is the registry of all targets discovered during a run — the
// initial scope-file targets plus anything the feedback loop (passive
// recon, vhost hits, JS harvesting) adds after a fresh scope check.
type Store struct {
	mu      sync.Mutex
	targets map[string]*Target
	order   []string
}

func NewStore() *Store {
	return &Store{targets: make(map[string]*Target)}
}

// GetOrCreate returns the existing Target for hostname, or creates and
// registers a new one. Returns (target, created).
func (s *Store) GetOrCreate(hostname string) (*Target, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.targets[hostname]; ok {
		return t, false
	}
	t := NewTarget(hostname)
	s.targets[hostname] = t
	s.order = append(s.order, hostname)
	return t, true
}

func (s *Store) Get(hostname string) (*Target, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.targets[hostname]
	return t, ok
}

// All returns targets in discovery order (stable output, deterministic
// diffing between runs).
func (s *Store) All() []*Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Target, 0, len(s.order))
	for _, h := range s.order {
		out = append(out, s.targets[h])
	}
	return out
}
