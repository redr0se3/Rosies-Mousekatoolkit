package active

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/httpx"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// WildcardDetect resolves several deliberately-random, non-existent
// subdomains before any real subdomain/vhost brute-force runs.
//
// The "why": a DNS catch-all (`*.example.com` pointing at one IP, common
// on CDN/shared-hosting setups) makes every single brute-forced label
// "resolve" — if vhost discovery trusted "did it resolve" as its signal,
// a 50,000-word subdomain list would report 50,000 hits, 100% of them
// noise. Resolving a handful of labels we know can't be real, up front,
// tells us whether that trap exists so the real brute-force pass can
// switch to a response-fingerprint signal (content hash/length) instead.
type WildcardDetect struct{}

func (WildcardDetect) Name() string { return "active.wildcard_dns" }

func (WildcardDetect) Run(rc *module.RunContext, t *state.Target) (module.Findings, error) {
	res, err := rc.Scope.Check(rc.Ctx, t.Hostname)
	if err != nil || !res.InScope {
		return module.Findings{}, fmt.Errorf("scope check failed for %s: %v (in_scope=%v)", t.Hostname, err, res.InScope)
	}

	const probes = 4
	ipSets := make([][]string, 0, probes)

	for i := 0; i < probes; i++ {
		label, err := randomLabel(12)
		if err != nil {
			return module.Findings{}, fmt.Errorf("generating random label: %w", err)
		}
		probeHost := label + "." + t.Hostname

		ctx, cancel := context.WithTimeout(rc.Ctx, time.Duration(5)*time.Second)
		ips, err := net.DefaultResolver.LookupHost(ctx, probeHost)
		cancel()
		if err != nil {
			// Any single probe failing to resolve means there's no
			// catch-all — a real wildcard answers everything.
			t.Mutate(func(t *state.Target) { t.WildcardDNS = false })
			return module.Findings{}, nil
		}
		sort.Strings(ips)
		ipSets = append(ipSets, ips)
	}

	allSame := true
	for i := 1; i < len(ipSets); i++ {
		if strings.Join(ipSets[i], ",") != strings.Join(ipSets[0], ",") {
			allSame = false
			break
		}
	}

	if !allSame {
		t.Mutate(func(t *state.Target) { t.WildcardDNS = false })
		return module.Findings{}, nil
	}

	// Confirmed wildcard. Capture an HTTP baseline against one of the
	// random hosts so later vhost brute-forcing can fingerprint-filter
	// rather than trust resolution alone.
	client := httpx.New(10 * time.Second)
	probeURL := targetURL(rc, t.Hostname) // reuses scheme selection from fingerprint.go
	baselineHash, baselineLen := "", int64(0)
	if resp, err := client.Fetch(rc.Ctx, probeURL, nil); err == nil {
		baselineHash = resp.BodyHash
		baselineLen = resp.ContentLength
	}

	t.Mutate(func(t *state.Target) {
		t.WildcardDNS = true
		t.BaselineHash = baselineHash
		t.BaselineLength = baselineLen
	})

	return module.Findings{}, nil
}

func randomLabel(n int) (string, error) {
	buf := make([]byte, n/2+1)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf)[:n], nil
}
