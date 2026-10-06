package passive

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// Historical queries the Wayback Machine's CDX API and the CommonCrawl
// index for URLs ever observed under the target domain. Both are
// third-party archives — zero requests hit the target itself. Results
// seed Phase 2's directory brute-force wordlist with endpoints that may
// no longer be linked from the live site but could still respond.
type Historical struct{}

func (Historical) Name() string { return "passive.historical_urls" }

func (Historical) Run(rc *module.RunContext, t *state.Target) (module.Findings, error) {
	var seeds []string

	if paths, err := fetchWaybackPaths(rc.Ctx, t.Hostname); err == nil {
		seeds = append(seeds, paths...)
	} else {
		rc.Log.Warnf("wayback CDX lookup failed for %s: %v", t.Hostname, err)
	}

	if paths, err := fetchCommonCrawlPaths(rc.Ctx, t.Hostname); err == nil {
		seeds = append(seeds, paths...)
	} else {
		rc.Log.Warnf("commoncrawl lookup failed for %s: %v", t.Hostname, err)
	}

	return module.Findings{WordlistSeeds: dedupStrings(seeds)}, nil
}

// fetchWaybackPaths hits the CDX server API, which returns plain-text
// (or JSON) rows of "timestamp original ..." — we only need the original
// URL's path component.
func fetchWaybackPaths(ctx context.Context, host string) ([]string, error) {
	api := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&limit=2000",
		url.QueryEscape(host),
	)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "recontool/1.0 (authorized-recon)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback CDX returned status %d", resp.StatusCode)
	}

	// Output with output=json&fl=original is a JSON array of 1-element
	// arrays (first row is the header ["original"]).
	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decoding wayback CDX response: %w", err)
	}

	var seeds []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue // header row
		}
		if p := pathFromRawURL(row[0]); p != "" {
			seeds = append(seeds, p)
		}
	}
	return seeds, nil
}

// fetchCommonCrawlPaths queries the CommonCrawl index server. CommonCrawl
// publishes a rotating set of crawl indexes; rather than hardcode one
// (which goes stale), we query the collinfo endpoint for the latest
// index id and use that.
func fetchCommonCrawlPaths(ctx context.Context, host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	indexID, err := latestCommonCrawlIndex(ctx)
	if err != nil {
		return nil, err
	}

	api := fmt.Sprintf(
		"https://index.commoncrawl.org/%s-index?url=%s/*&output=json&limit=2000",
		indexID, url.QueryEscape(host),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "recontool/1.0 (authorized-recon)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("commoncrawl index returned status %d", resp.StatusCode)
	}

	// CommonCrawl's index API returns newline-delimited JSON, one record
	// per line, not a single JSON array.
	var seeds []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if p := pathFromRawURL(rec.URL); p != "" {
			seeds = append(seeds, p)
		}
	}
	return seeds, nil
}

func latestCommonCrawlIndex(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "recontool/1.0 (authorized-recon)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("collinfo returned status %d", resp.StatusCode)
	}

	var collections []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&collections); err != nil {
		return "", err
	}
	if len(collections) == 0 {
		return "", fmt.Errorf("no commoncrawl collections returned")
	}
	return collections[0].ID, nil // most recent is first
}

func pathFromRawURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(parsed.Path, "/")
}
