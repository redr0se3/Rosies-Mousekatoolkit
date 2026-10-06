// Package passive implements Phase 1 modules: everything here runs
// against third-party data sources (crt.sh, the Wayback Machine,
// CommonCrawl) or does a direct, read-only fetch of the target's own
// published robots.txt/sitemap.xml. None of it does any brute-forcing or
// enumeration against the target itself.
//
// Output here is explicitly a *candidate* list. The orchestrator is
// responsible for running every NewCandidateHosts entry through the
// scope checker before Phase 2 ever touches it — passive modules must
// not assume anything they discover is authorized.
package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// CTLog queries crt.sh's JSON API for certificates issued to the target
// domain and any subdomain. Every distinct name found is returned as an
// unverified CandidateHost — crt.sh is a public log scraped by anyone, so
// it routinely surfaces decommissioned or never-deployed hostnames that
// must never be auto-enumerated.
type CTLog struct{}

func (CTLog) Name() string { return "passive.crtsh" }

type crtshEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

func (CTLog) Run(rc *module.RunContext, t *state.Target) (module.Findings, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", t.Hostname)

	ctx, cancel := context.WithTimeout(rc.Ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return module.Findings{}, err
	}
	req.Header.Set("User-Agent", "recontool/1.0 (authorized-recon)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// crt.sh is a third party with no uptime guarantee; treat this as
		// a soft failure for the target, not a fatal pipeline error.
		return module.Findings{}, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return module.Findings{}, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []crtshEntry
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&entries); err != nil {
		return module.Findings{}, fmt.Errorf("decoding crt.sh response: %w", err)
	}

	seen := make(map[string]bool)
	var candidates []module.CandidateHost
	for _, e := range entries {
		for _, raw := range []string{e.NameValue, e.CommonName} {
			for _, name := range strings.Split(raw, "\n") {
				name = strings.ToLower(strings.TrimSpace(name))
				name = strings.TrimPrefix(name, "*.")
				if name == "" || seen[name] {
					continue
				}
				seen[name] = true
				candidates = append(candidates, module.CandidateHost{Hostname: name, Source: "ct_log"})
			}
		}
	}

	return module.Findings{NewCandidateHosts: candidates}, nil
}
