package active

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/httpx"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/safety"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// DirBrute wraps feroxbuster. It:
//
//   - Captures a soft-404 baseline (a few guaranteed-nonexistent paths)
//     before each wordlist pass and filters feroxbuster's own hits
//     against it, instead of trusting status codes alone — a host that
//     answers every unknown path with "200 OK, here's our SPA shell"
//     would otherwise report thousands of false positives.
//   - Picks which wordlists to run from the target's already-fingerprinted
//     tech stack (a WordPress hit adds the wordpress-specific list on top
//     of the generic ones) plus any passive-recon wordlist seeds.
//   - Caps recursion depth so a deeply nested, highly linked site can't
//     turn one brute-force pass into an unbounded crawl.
//   - Passes feroxbuster's own -t (threads) flag from the same
//     max_concurrent_requests value the orchestrator's HostLimiter
//     enforces, so the tool's internal concurrency and our own worker
//     pool don't multiply against each other.
type DirBrute struct{}

func (DirBrute) Name() string { return "active.dirbrute" }

type feroxEvent struct {
	Type          string `json:"type"`
	URL           string `json:"url"`
	Path          string `json:"path"`
	Status        int    `json:"status"`
	ContentLength int64  `json:"content_length"`
}

func (DirBrute) Run(rc *module.RunContext, t *state.Target) (module.Findings, error) {
	res, err := rc.Scope.Check(rc.Ctx, t.Hostname)
	if err != nil || !res.InScope {
		return module.Findings{}, fmt.Errorf("scope check failed for %s: %v (in_scope=%v)", t.Hostname, err, res.InScope)
	}

	if err := rc.HostLimiter.Acquire(rc.Ctx, t.Hostname); err != nil {
		return module.Findings{}, err
	}
	defer rc.HostLimiter.Release(t.Hostname)

	snap := t.Snapshot()
	baseURL := targetURL(rc, t.Hostname)

	baseline, err := captureSoft404Baseline(rc.Ctx, baseURL)
	if err != nil {
		rc.Log.Warnf("soft-404 baseline capture failed for %s: %v (continuing without it)", t.Hostname, err)
	}

	wordlists, err := selectWordlists(rc, snap)
	if err != nil {
		return module.Findings{}, err
	}
	if len(wordlists) == 0 {
		rc.Log.Warnf("dirbrute: no wordlists configured for %s, skipping", t.Hostname)
		return module.Findings{}, nil
	}

	var findings module.Findings
	seenPaths := make(map[string]bool)

	for _, wl := range wordlists {
		events, err := runFeroxbuster(rc.Ctx, rc, baseURL, wl.path)
		if err != nil {
			rc.Log.Warnf("feroxbuster (%s) failed for %s: %v", wl.label, t.Hostname, err)
			continue
		}
		for _, ev := range events {
			if ev.Type != "response" && ev.Type != "" {
				continue
			}
			if baseline.valid && baseline.looksLike(ev.Status, ev.ContentLength) {
				continue // soft-404, not a real finding
			}
			path := strings.TrimPrefix(ev.Path, "/")
			dedupKey := path + "|" + strconv.Itoa(ev.Status)
			if seenPaths[dedupKey] {
				continue
			}
			seenPaths[dedupKey] = true

			findings.Paths = append(findings.Paths, state.PathFinding{
				Path:          path,
				Status:        ev.Status,
				ContentLength: ev.ContentLength,
				FoundBy:       wl.label,
			})
			if strings.HasSuffix(strings.ToLower(path), ".js") {
				findings.Endpoints = append(findings.Endpoints, path)
			}
		}
	}

	return findings, nil
}

type wordlistChoice struct {
	label string
	path  string
}

func selectWordlists(rc *module.RunContext, snap state.Snapshot) ([]wordlistChoice, error) {
	var choices []wordlistChoice

	for _, configured := range rc.Scoped.Wordlists.Generic {
		path, err := safety.ResolveWordlistPath(rc.Scoped.WordlistBaseDir, configured)
		if err != nil {
			return nil, fmt.Errorf("generic wordlist: %w", err)
		}
		choices = append(choices, wordlistChoice{label: "generic:" + configured, path: path})
	}

	// Tech-stack-triggered lists: a fingerprint hit for e.g. "wordpress"
	// adds the WP-specific list on top of (not instead of) the generic
	// passes, per spec: "a WordPress hit triggers a WP-specific wordlist
	// pass before the generic ones."
	for _, tech := range snap.TechStack {
		key := strings.ToLower(tech)
		for configuredKey, lists := range rc.Scoped.Wordlists.TechSpecific {
			if !strings.Contains(key, strings.ToLower(configuredKey)) {
				continue
			}
			for _, configured := range lists {
				path, err := safety.ResolveWordlistPath(rc.Scoped.WordlistBaseDir, configured)
				if err != nil {
					return nil, fmt.Errorf("tech-specific wordlist (%s): %w", configuredKey, err)
				}
				// Prepend so tech-specific passes are listed/run first.
				choices = append([]wordlistChoice{{label: configuredKey + ":" + configured, path: path}}, choices...)
			}
		}
	}

	if len(snap.WordlistSeeds) > 0 {
		seedPath, err := writeSeedWordlist(rc, snap.Hostname, snap.WordlistSeeds)
		if err == nil {
			choices = append(choices, wordlistChoice{label: "passive_seeds", path: seedPath})
		} else {
			rc.Log.Warnf("could not write passive-seed wordlist for %s: %v", snap.Hostname, err)
		}
	}

	return choices, nil
}

func writeSeedWordlist(rc *module.RunContext, hostname string, seeds []string) (string, error) {
	// Seed wordlists are generated by us at runtime, from already-fetched
	// (robots.txt/sitemap/Wayback) paths — not an operator-configured
	// path — so they're written under the wordlist base dir rather than
	// validated against it.
	return writeTempWordlist(rc.Scoped.WordlistBaseDir, hostname, seeds)
}

func captureSoft404Baseline(ctx context.Context, baseURL string) (soft404Baseline, error) {
	client := httpx.New(10 * time.Second)
	var statuses []int
	var lengths []int64

	for i := 0; i < 3; i++ {
		label, err := randomLabel(16)
		if err != nil {
			return soft404Baseline{}, err
		}
		url := strings.TrimSuffix(baseURL, "/") + "/" + label + "-does-not-exist"
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := client.Fetch(ctx, url, nil)
		cancel()
		if err != nil {
			continue
		}
		statuses = append(statuses, resp.StatusCode)
		lengths = append(lengths, resp.ContentLength)
	}

	if len(statuses) == 0 {
		return soft404Baseline{}, fmt.Errorf("all baseline probes failed")
	}

	return soft404Baseline{valid: true, status: statuses[0], length: lengths[0]}, nil
}

// soft404Baseline is a lighter-weight cousin of httpx.Baseline: we only
// get status+content-length back out of feroxbuster's JSON events, not a
// body hash, so the comparison here is necessarily coarser than the
// Baseline.Matches check used elsewhere (e.g. vhost fuzzing, which fetches
// bodies directly and can hash them).
type soft404Baseline struct {
	valid  bool
	status int
	length int64
}

func (b soft404Baseline) looksLike(status int, length int64) bool {
	if !b.valid {
		return false
	}
	return status == b.status && length == b.length
}

// runFeroxbuster shells out with argv as separate slice elements — see
// internal/safety/exec.go for why that's load-bearing, not stylistic.
func runFeroxbuster(ctx context.Context, rc *module.RunContext, baseURL, wordlistPath string) ([]feroxEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(rc.Scoped.Timeouts.ToolRunSeconds)*time.Second)
	defer cancel()

	args := []string{
		"-u", baseURL,
		"-w", wordlistPath,
		"-t", strconv.Itoa(rc.HostLimiter.MaxPerHost()),
		"--depth", strconv.Itoa(rc.Scoped.RecursionDepthCap),
		"--json",
		"--silent",
		"--no-state",
	}

	out, err, installed := safety.RunToolCapped(ctx, rc.Scoped.ToolPaths.Feroxbuster, args)
	if !installed {
		return nil, fmt.Errorf("feroxbuster not installed")
	}
	if err != nil && len(out) == 0 {
		return nil, err
	}

	var events []feroxEvent
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev feroxEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue // skip non-JSON/log noise lines
		}
		events = append(events, ev)
	}
	return events, nil
}
