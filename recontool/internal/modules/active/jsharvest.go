package active

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/httpx"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// JSHarvest pulls every .js file found by feroxbuster or linked from the
// target's root page, and regex-scans each one for three things: API
// endpoints, hardcoded secrets/keys, and internal hostnames. Discovered
// endpoints get fed back into Findings.Endpoints — the orchestrator
// queues those back into the directory brute-force target list, which is
// the feedback loop the spec calls out explicitly: JS harvesting isn't a
// dead-end report, it's an input to another pass of the same phase.
type JSHarvest struct{}

func (JSHarvest) Name() string { return "active.js_harvest" }

var (
	// A quoted string that looks like a server-relative API path:
	// "/api/v2/users/:id", '/internal/admin', etc. Length floor avoids
	// matching every single-character string literal in minified JS.
	endpointRe = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-./]{3,200})["']`)

	// Known secret shapes. Not exhaustive — this is a triage net, not a
	// guarantee — but it catches the overwhelmingly common
	// hardcoded-credential mistakes.
	secretPatterns = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"aws_access_key_id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"generic_api_key_assignment", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,64}['"]`)},
		{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
		{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`)},
		{"generic_secret_assignment", regexp.MustCompile(`(?i)(secret|password|passwd|token)\s*[:=]\s*['"][^'"\s]{8,64}['"]`)},
		{"private_key_header", regexp.MustCompile(`-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----`)},
	}

	// A hostname-looking token that is NOT the target's own domain or a
	// handful of common third-party/CDN names — flagged as a potential
	// internal hostname leak (e.g. a staging/internal backend referenced
	// from client-side JS by mistake).
	hostnameRe = regexp.MustCompile(`\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(internal|corp|local|intra|lan|vpn)\b`)

	scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"'>]+)["']`)
)

func (JSHarvest) Run(rc *module.RunContext, t *state.Target) (module.Findings, error) {
	res, err := rc.Scope.Check(rc.Ctx, t.Hostname)
	if err != nil || !res.InScope {
		return module.Findings{}, fmt.Errorf("scope check failed for %s: %v (in_scope=%v)", t.Hostname, err, res.InScope)
	}

	if err := rc.HostLimiter.Acquire(rc.Ctx, t.Hostname); err != nil {
		return module.Findings{}, err
	}
	defer rc.HostLimiter.Release(t.Hostname)

	client := httpx.New(time.Duration(rc.Scoped.Timeouts.HTTPSeconds) * time.Second)
	baseURL := targetURL(rc, t.Hostname)

	jsURLs := map[string]bool{}

	// .js paths feroxbuster already found.
	snap := t.Snapshot()
	for _, p := range snap.Paths {
		if strings.HasSuffix(strings.ToLower(p.Path), ".js") {
			jsURLs[resolveAgainst(baseURL, p.Path)] = true
		}
	}

	// .js linked from the root page itself.
	if body, _, err := client.FetchRaw(rc.Ctx, baseURL); err == nil {
		for _, m := range scriptSrcRe.FindAllStringSubmatch(string(body), -1) {
			jsURLs[resolveAgainst(baseURL, m[1])] = true
		}
	}

	var findings module.Findings
	seenEndpoints := map[string]bool{}
	seenFindings := map[string]bool{}

	for jsURL := range jsURLs {
		parsed, err := url.Parse(jsURL)
		if err != nil {
			continue
		}
		// A .js file can point off-host (a CDN, a third-party widget).
		// Re-check scope for that host before fetching it — this is the
		// exact "host discovered mid-run" case the spec's scope-
		// enforcement requirement calls out by name.
		if parsed.Host != "" && parsed.Hostname() != t.Hostname {
			scopeRes, err := rc.Scope.Check(rc.Ctx, parsed.Hostname())
			if err != nil || !scopeRes.InScope {
				findings.Skipped = append(findings.Skipped, state.SkippedFinding{
					Item: jsURL, Reason: "out_of_scope",
				})
				continue
			}
		}

		body, _, err := client.FetchRaw(rc.Ctx, jsURL)
		if err != nil {
			continue
		}
		text := string(body)

		for _, m := range endpointRe.FindAllStringSubmatch(text, -1) {
			ep := m[1]
			if seenEndpoints[ep] {
				continue
			}
			seenEndpoints[ep] = true
			findings.Endpoints = append(findings.Endpoints, strings.TrimPrefix(ep, "/"))
			findings.JSFindings = append(findings.JSFindings, state.JSFinding{
				File: jsURL, PatternType: "endpoint", Snippet: ep,
			})
		}

		for _, sp := range secretPatterns {
			for _, m := range sp.re.FindAllString(text, -1) {
				key := "secret|" + sp.name + "|" + m
				if seenFindings[key] {
					continue
				}
				seenFindings[key] = true
				findings.JSFindings = append(findings.JSFindings, state.JSFinding{
					File: jsURL, PatternType: "secret", Snippet: redactSecret(sp.name, m),
				})
			}
		}

		for _, m := range hostnameRe.FindAllString(text, -1) {
			key := "host|" + m
			if seenFindings[key] {
				continue
			}
			seenFindings[key] = true
			findings.JSFindings = append(findings.JSFindings, state.JSFinding{
				File: jsURL, PatternType: "hostname", Snippet: m,
			})
		}
	}

	return findings, nil
}

// redactSecret keeps a finding actionable (you know *what* leaked and
// roughly *where*) without putting a usable credential into results.json
// or a report that might get shared more widely than the raw scan output.
func redactSecret(kind, match string) string {
	if len(match) <= 8 {
		return kind + ": [redacted]"
	}
	return fmt.Sprintf("%s: %s...%s (redacted)", kind, match[:4], match[len(match)-4:])
}

func resolveAgainst(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}
