package active

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/httpx"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/safety"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// VHostDiscovery combines two techniques, run per wordlist label:
//
//  1. DNS brute-force: does label.domain resolve at all? If the target
//     has wildcard DNS (WildcardDetect already ran), a bare resolution
//     means nothing — we additionally compare the HTTP response at that
//     hostname against the wildcard baseline fingerprint.
//  2. HTTP Host-header fuzzing: send a request straight at the target's
//     already-known IP, but with Host: label.domain. This catches vhosts
//     the web server is configured to answer for even when they have no
//     DNS record of their own — a common setup for internal/staging
//     vhosts that were never meant to be publicly discoverable by name.
//
// Every hit is returned as an unverified CandidateHost. The orchestrator
// re-checks scope before anything discovered here is queued for
// directory brute-forcing — per spec, "every hit re-checked against the
// scope file before being queued."
type VHostDiscovery struct{}

func (VHostDiscovery) Name() string { return "active.vhost_discovery" }

func (VHostDiscovery) Run(rc *module.RunContext, t *state.Target) (module.Findings, error) {
	res, err := rc.Scope.Check(rc.Ctx, t.Hostname)
	if err != nil || !res.InScope {
		return module.Findings{}, fmt.Errorf("scope check failed for %s: %v (in_scope=%v)", t.Hostname, err, res.InScope)
	}

	labels, err := loadSubdomainWordlist(rc)
	if err != nil {
		return module.Findings{}, err
	}
	if len(labels) == 0 {
		rc.Log.Warnf("vhost discovery: no subdomain wordlist configured for %s, skipping", t.Hostname)
		return module.Findings{}, nil
	}

	snap := t.Snapshot()
	rootIP := ""
	if len(snap.IPs) > 0 {
		rootIP = snap.IPs[0]
	}

	// This client intentionally skips certificate verification: Host-
	// header fuzzing connects to a fixed IP while *claiming* an arbitrary
	// hostname, so the TLS SNI/CN will almost never match for a genuine
	// hit either. That trade-off is scoped to this one fuzzing client —
	// every other HTTP client in the codebase (httpx.Client) verifies
	// normally. We only use this to observe response *shape* (status,
	// length, hash), never to trust its identity.
	fuzzClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- see comment above
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				if rootIP == "" {
					return nil, fmt.Errorf("no resolved IP for %s", t.Hostname)
				}
				port := "80"
				for _, p := range rc.Scoped.Ports {
					if p == 443 {
						port = "443"
					}
				}
				return net.DialTimeout(network, net.JoinHostPort(rootIP, port), 8*time.Second)
			},
		},
	}
	defer fuzzClient.CloseIdleConnections()

	dnsClient := httpx.New(10 * time.Second)

	var (
		mu   sync.Mutex
		hits []module.CandidateHost
		wg   sync.WaitGroup
	)

	maxConc := rc.HostLimiter.MaxPerHost()
	sem := make(chan struct{}, maxConc)

	for _, label := range labels {
		label := label
		candidateHost := label + "." + snap.Hostname

		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if err := rc.HostLimiter.Acquire(rc.Ctx, snap.Hostname); err != nil {
				return
			}
			defer rc.HostLimiter.Release(snap.Hostname)

			if hit := probeDNSVHost(rc.Ctx, dnsClient, candidateHost, snap); hit {
				mu.Lock()
				hits = append(hits, module.CandidateHost{Hostname: candidateHost, Source: "dns"})
				mu.Unlock()
			}

			if rootIP != "" {
				if hit := probeHostHeaderVHost(rc.Ctx, fuzzClient, candidateHost, rootIP, snap); hit {
					mu.Lock()
					hits = append(hits, module.CandidateHost{Hostname: candidateHost, Source: "host_header_fuzz"})
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	return module.Findings{NewCandidateHosts: dedupCandidates(hits)}, nil
}

func probeDNSVHost(ctx context.Context, client *httpx.Client, candidateHost string, snap state.Snapshot) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := net.DefaultResolver.LookupHost(ctx, candidateHost)
	if err != nil {
		return false // doesn't resolve at all
	}
	if !snap.WildcardDNS {
		return true // real DNS record, no catch-all to worry about
	}

	// Wildcard present: a bare resolution is meaningless noise. Fetch and
	// compare against the baseline fingerprint captured by WildcardDetect.
	url := "http://" + candidateHost + "/"
	resp, err := client.Fetch(ctx, url, nil)
	if err != nil {
		return false
	}
	baseline := httpx.Baseline{BodyHash: snap.BaselineHash, ContentLength: snap.BaselineLength}
	return !baseline.Matches(resp)
}

func probeHostHeaderVHost(ctx context.Context, fuzzClient *http.Client, candidateHost, rootIP string, snap state.Snapshot) bool {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+candidateHost+"/", nil)
	if err != nil {
		return false
	}
	req.Host = candidateHost
	req.Header.Set("User-Agent", "recontool/1.0 (authorized-recon)")

	resp, err := fuzzClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil || len(body) >= 10<<20 {
			break
		}
	}
	fingerprint := &httpx.Response{
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(body)),
		BodyHash:      httpx.HashBody(body),
	}

	// With no root-level baseline captured (non-wildcard targets), fall
	// back to "did we get something other than a connection-level
	// error", since a webserver answering a Host header it doesn't
	// recognize with its *default* vhost response still looks identical
	// to hitting the root domain directly — not a distinct finding.
	if snap.BaselineHash == "" {
		return resp.StatusCode != http.StatusNotFound
	}
	baseline := httpx.Baseline{BodyHash: snap.BaselineHash, ContentLength: snap.BaselineLength}
	return !baseline.Matches(fingerprint)
}

func loadSubdomainWordlist(rc *module.RunContext) ([]string, error) {
	var all []string
	seen := make(map[string]bool)
	for _, configured := range rc.Scoped.Wordlists.Subdomains {
		path, err := safety.ResolveWordlistPath(rc.Scoped.WordlistBaseDir, configured)
		if err != nil {
			return nil, fmt.Errorf("subdomain wordlist: %w", err)
		}
		f, err := os.Open(path)
		if err != nil {
			rc.Log.Warnf("could not open subdomain wordlist %s: %v", path, err)
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || seen[line] {
				continue
			}
			seen[line] = true
			all = append(all, line)
		}
		f.Close()
	}
	return all, nil
}

func dedupCandidates(in []module.CandidateHost) []module.CandidateHost {
	seen := make(map[string]bool, len(in))
	out := make([]module.CandidateHost, 0, len(in))
	for _, c := range in {
		key := c.Hostname + "|" + c.Source
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}
