package passive

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/httpx"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// RobotsAndSitemap does a direct, single, read-only GET of robots.txt and
// sitemap.xml against the root domain. Unlike the crt.sh/Wayback modules,
// this one DOES touch the target's web server — which is exactly why it
// re-checks scope itself (defense in depth) rather than relying solely on
// the orchestrator's gate, per the module interface contract.
type RobotsAndSitemap struct{}

func (RobotsAndSitemap) Name() string { return "passive.robots_sitemap" }

func (RobotsAndSitemap) Run(rc *module.RunContext, t *state.Target) (module.Findings, error) {
	res, err := rc.Scope.Check(rc.Ctx, t.Hostname)
	if err != nil || !res.InScope {
		return module.Findings{}, fmt.Errorf("scope check failed for %s: %v (in_scope=%v)", t.Hostname, err, res.InScope)
	}

	client := httpx.New(10 * time.Second)
	var seeds []string

	for _, scheme := range []string{"https", "http"} {
		robotsURL := fmt.Sprintf("%s://%s/robots.txt", scheme, t.Hostname)
		ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
		body, _, err := client.FetchRaw(ctx, robotsURL)
		cancel()
		if err != nil || body == nil {
			continue
		}
		seeds = append(seeds, parseRobots(body)...)
		break // one scheme succeeding is enough
	}

	for _, scheme := range []string{"https", "http"} {
		sitemapURL := fmt.Sprintf("%s://%s/sitemap.xml", scheme, t.Hostname)
		ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
		body, _, err := client.FetchRaw(ctx, sitemapURL)
		cancel()
		if err != nil || body == nil {
			continue
		}
		seeds = append(seeds, parseSitemap(body)...)
		break
	}

	return module.Findings{WordlistSeeds: dedupStrings(seeds)}, nil
}

func parseRobots(body []byte) []string {
	var seeds []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "disallow:") || strings.HasPrefix(lower, "allow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				p := strings.TrimSpace(parts[1])
				p = strings.TrimPrefix(p, "/")
				if p != "" && p != "*" {
					seeds = append(seeds, p)
				}
			}
		}
		if strings.HasPrefix(lower, "sitemap:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if u, err := url.Parse(strings.TrimSpace(parts[1])); err == nil {
					p := strings.TrimPrefix(u.Path, "/")
					if p != "" {
						seeds = append(seeds, p)
					}
				}
			}
		}
	}
	return seeds
}

type sitemapURLSet struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

func parseSitemap(body []byte) []string {
	var set sitemapURLSet
	if err := xml.Unmarshal(body, &set); err != nil {
		return nil
	}
	var seeds []string
	for _, u := range set.URLs {
		parsed, err := url.Parse(u.Loc)
		if err != nil {
			continue
		}
		p := strings.TrimPrefix(parsed.Path, "/")
		if p != "" {
			seeds = append(seeds, p)
		}
	}
	return seeds
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
