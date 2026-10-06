// Package active implements Phase 2: everything here sends real requests
// to the target and therefore MUST pass rc.Scope.Check before doing
// anything, and MUST respect rc.HostLimiter so concurrency stays bounded
// to what the scope file authorizes.
package active

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/safety"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// Fingerprint runs whatweb and (if installed) the Wappalyzer CLI against
// a target and merges/dedupes the results into one tech-stack list.
//
// Why run both instead of picking one: whatweb and Wappalyzer use
// different, only partially overlapping signature databases (response
// headers, cookie names, favicon hashes, JS globals, meta generator
// tags). Each one alone under-fingerprints some stacks the other
// catches. The merge is what later lets the dirbrute module pick a
// WordPress-specific wordlist from a Wappalyzer hit even if whatweb
// missed it, or vice versa.
type Fingerprint struct{}

func (Fingerprint) Name() string { return "active.fingerprint" }

func (Fingerprint) Run(rc *module.RunContext, t *state.Target) (module.Findings, error) {
	res, err := rc.Scope.Check(rc.Ctx, t.Hostname)
	if err != nil || !res.InScope {
		return module.Findings{}, fmt.Errorf("scope check failed for %s: %v (in_scope=%v)", t.Hostname, err, res.InScope)
	}

	if err := rc.HostLimiter.Acquire(rc.Ctx, t.Hostname); err != nil {
		return module.Findings{}, err
	}
	defer rc.HostLimiter.Release(t.Hostname)

	url := targetURL(rc, t.Hostname)

	var tech []string
	if hits, err := runWhatWeb(rc.Ctx, rc.Scoped.ToolPaths.WhatWeb, url); err != nil {
		rc.Log.Warnf("whatweb failed for %s: %v", t.Hostname, err)
	} else {
		tech = append(tech, hits...)
	}

	if hits, err := runWappalyzer(rc.Ctx, url); err != nil {
		rc.Log.Warnf("wappalyzer failed for %s: %v", t.Hostname, err)
	} else {
		tech = append(tech, hits...)
	}

	return module.Findings{TechStack: normalizeTech(tech)}, nil
}

// targetURL picks the first configured port/scheme pair. Modules that
// need to probe every configured port do their own loop; fingerprinting
// just needs one representative response.
func targetURL(rc *module.RunContext, host string) string {
	scheme := "https"
	for _, p := range rc.Scoped.Ports {
		if p == 80 {
			scheme = "http"
			break
		}
		if p == 443 {
			scheme = "https"
			break
		}
	}
	return fmt.Sprintf("%s://%s/", scheme, host)
}

// whatweb -a 1 keeps the aggression level passive-ish (no brute forcing
// of its own); --log-json=- streams JSON to stdout so we can parse it
// instead of scraping human-readable text.
func runWhatWeb(ctx context.Context, bin, url string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err, installed := safety.RunToolCapped(ctx, bin, []string{"-a", "1", "--log-json=-", "--no-errors", url})
	if !installed {
		return nil, fmt.Errorf("whatweb not installed")
	}
	if err != nil && len(out) == 0 {
		return nil, err
	}

	// whatweb's --log-json=- emits one JSON object per target line; be
	// tolerant and scan for "plugins" keys across every line rather than
	// assuming a single well-formed document.
	var tech []string
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var rec struct {
			Plugins map[string]json.RawMessage `json:"plugins"`
		}
		if err := dec.Decode(&rec); err != nil {
			break
		}
		for name := range rec.Plugins {
			tech = append(tech, name)
		}
	}
	return tech, nil
}

// runWappalyzer shells out to the Wappalyzer CLI (npm package
// `wappalyzer`, binary name `wappalyzer`), which prints
// {"urls":{...},"technologies":[{"name":"..."}]} as JSON.
func runWappalyzer(ctx context.Context, url string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err, installed := safety.RunToolCapped(ctx, "wappalyzer", []string{url})
	if !installed {
		return nil, fmt.Errorf("wappalyzer not installed")
	}
	if err != nil && len(out) == 0 {
		return nil, err
	}

	var result struct {
		Technologies []struct {
			Name string `json:"name"`
		} `json:"technologies"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parsing wappalyzer output: %w", err)
	}

	tech := make([]string, 0, len(result.Technologies))
	for _, t := range result.Technologies {
		tech = append(tech, t.Name)
	}
	return tech, nil
}

func normalizeTech(in []string) []string {
	seen := make(map[string]string, len(in))
	for _, raw := range in {
		key := strings.ToLower(strings.TrimSpace(raw))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; !ok {
			seen[key] = strings.TrimSpace(raw)
		}
	}
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	return out
}
