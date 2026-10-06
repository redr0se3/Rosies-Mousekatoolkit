// Package postprocess implements Phase 3: visual triage (screenshots)
// and the dedup pass over everything Phase 1/2 collected. Nothing here
// sends new requests to the target directly except via gowitness, which
// still goes through the same scope gate as every other module.
package postprocess

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/safety"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// Screenshot shells out to gowitness for a headless-Chrome screenshot of
// every live host/vhost/endpoint found for this target. The spec offers
// chromedp as an in-process alternative; we use gowitness here to avoid
// pulling a full CDP/Chrome-driving dependency into the binary when a
// single, well-maintained CLI does the same job — the module interface
// means swapping this for a chromedp-based implementation later touches
// nothing outside this one file.
type Screenshot struct {
	OutputDir string
}

func (Screenshot) Name() string { return "postprocess.screenshot" }

func (s Screenshot) Run(rc *module.RunContext, t *state.Target) (module.Findings, error) {
	res, err := rc.Scope.Check(rc.Ctx, t.Hostname)
	if err != nil || !res.InScope {
		return module.Findings{}, fmt.Errorf("scope check failed for %s: %v (in_scope=%v)", t.Hostname, err, res.InScope)
	}

	outDir := s.OutputDir
	if outDir == "" {
		outDir = "screenshots"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return module.Findings{}, fmt.Errorf("creating screenshot output dir: %w", err)
	}

	snap := t.Snapshot()
	urls := targetsToScreenshot(rc, snap)
	if len(urls) == 0 {
		return module.Findings{}, nil
	}

	if err := rc.HostLimiter.Acquire(rc.Ctx, t.Hostname); err != nil {
		return module.Findings{}, err
	}
	defer rc.HostLimiter.Release(t.Hostname)

	args := []string{
		"file",
		"-d", outDir,
		"--threads", strconv.Itoa(rc.HostLimiter.MaxPerHost()),
	}
	// gowitness's `file` subcommand reads URLs from a newline-delimited
	// file via -f; write one rather than passing dozens of positional
	// args, which keeps the exec.Command argv list short and avoids any
	// ambiguity about argument boundaries.
	listPath := filepath.Join(outDir, sanitizeFilename(t.Hostname)+"_urls.txt")
	if err := writeURLList(listPath, urls); err != nil {
		return module.Findings{}, err
	}
	args = append(args, "-f", listPath)

	timeoutCtx, cancel := context.WithTimeout(rc.Ctx, time.Duration(rc.Scoped.Timeouts.ToolRunSeconds)*time.Second)
	defer cancel()

	_, err, installed := safety.RunToolCapped(timeoutCtx, rc.Scoped.ToolPaths.Gowitness, args)
	if !installed {
		rc.Log.Warnf("gowitness not installed, skipping screenshots for %s", t.Hostname)
		return module.Findings{}, nil
	}
	if err != nil {
		return module.Findings{}, fmt.Errorf("gowitness failed: %w", err)
	}

	var findings module.Findings
	for _, u := range urls {
		findings.Screenshots = append(findings.Screenshots, state.ScreenshotFinding{
			URL:      u,
			FilePath: outDir, // gowitness names files internally by its own hash scheme
		})
	}
	return findings, nil
}

func targetsToScreenshot(rc *module.RunContext, snap state.Snapshot) []string {
	scheme := "https"
	for _, p := range rc.Scoped.Ports {
		if p == 80 {
			scheme = "http"
		}
	}
	var urls []string
	urls = append(urls, fmt.Sprintf("%s://%s/", scheme, snap.Hostname))
	for _, v := range snap.VHosts {
		urls = append(urls, fmt.Sprintf("%s://%s/", scheme, v.Hostname))
	}
	for _, p := range snap.Paths {
		if p.Status >= 200 && p.Status < 400 {
			urls = append(urls, fmt.Sprintf("%s://%s/%s", scheme, snap.Hostname, p.Path))
		}
	}
	return urls
}

func writeURLList(path string, urls []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, u := range urls {
		if _, err := fmt.Fprintln(f, u); err != nil {
			return err
		}
	}
	return nil
}

func sanitizeFilename(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
