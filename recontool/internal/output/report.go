package output

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// WriteMarkdownReport renders a human-readable view over Results. It is
// deliberately a pure function over already-collected data — nothing
// here sends a request or touches scope, because by the time a report is
// generated, the run is over.
func WriteMarkdownReport(path string, r *Results) error {
	var b strings.Builder

	fmt.Fprintf(&b, "# Recon Report\n\n")
	fmt.Fprintf(&b, "_Generated: %s — phase: %s_\n\n", r.GeneratedAt.Format("2006-01-02 15:04:05 MST"), r.Phase)

	inScope, skipped := 0, 0
	for _, t := range r.Targets {
		if t.InScope {
			inScope++
		} else {
			skipped++
		}
	}
	fmt.Fprintf(&b, "**%d targets processed** (%d in scope, %d skipped/out of scope)\n\n", len(r.Targets), inScope, skipped)

	for _, t := range r.Targets {
		writeTargetSection(&b, t)
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("writing report to %s: %w", path, err)
	}
	return nil
}

func writeTargetSection(b *strings.Builder, t *state.Target) {
	fmt.Fprintf(b, "## %s\n\n", t.Hostname)
	fmt.Fprintf(b, "- IPs: %s\n", joinOrNone(t.IPs))
	fmt.Fprintf(b, "- In scope: %v\n", t.InScope)
	if t.WildcardDNS {
		fmt.Fprintf(b, "- Wildcard DNS: yes (vhost findings fingerprint-filtered)\n")
	}
	if len(t.TechStack) > 0 {
		sorted := append([]string{}, t.TechStack...)
		sort.Strings(sorted)
		fmt.Fprintf(b, "- Tech stack: %s\n", strings.Join(sorted, ", "))
	}
	fmt.Fprintln(b)

	if len(t.VHosts) > 0 {
		fmt.Fprintf(b, "### VHosts / Subdomains (%d)\n\n", len(t.VHosts))
		fmt.Fprintf(b, "| Hostname | Source |\n|---|---|\n")
		for _, v := range t.VHosts {
			fmt.Fprintf(b, "| %s | %s |\n", v.Hostname, v.Source)
		}
		fmt.Fprintln(b)
	}

	if len(t.Paths) > 0 {
		fmt.Fprintf(b, "### Paths (%d)\n\n", len(t.Paths))
		fmt.Fprintf(b, "| Path | Status | Length | Found by |\n|---|---|---|---|\n")
		for _, p := range t.Paths {
			fmt.Fprintf(b, "| /%s | %d | %d | %s |\n", p.Path, p.Status, p.ContentLength, p.FoundBy)
		}
		fmt.Fprintln(b)
	}

	if len(t.JSFindings) > 0 {
		fmt.Fprintf(b, "### JS Findings (%d)\n\n", len(t.JSFindings))
		fmt.Fprintf(b, "| File | Type | Snippet |\n|---|---|---|\n")
		for _, j := range t.JSFindings {
			fmt.Fprintf(b, "| %s | %s | `%s` |\n", j.File, j.PatternType, strings.ReplaceAll(j.Snippet, "|", "\\|"))
		}
		fmt.Fprintln(b)
	}

	if len(t.Screenshots) > 0 {
		fmt.Fprintf(b, "### Screenshots (%d)\n\n", len(t.Screenshots))
		for _, s := range t.Screenshots {
			fmt.Fprintf(b, "- %s → `%s`\n", s.URL, s.FilePath)
		}
		fmt.Fprintln(b)
	}

	if len(t.Skipped) > 0 {
		fmt.Fprintf(b, "### Skipped (%d)\n\n", len(t.Skipped))
		fmt.Fprintf(b, "| Item | Reason |\n|---|---|\n")
		for _, s := range t.Skipped {
			fmt.Fprintf(b, "| %s | %s |\n", s.Item, s.Reason)
		}
		fmt.Fprintln(b)
	}

	fmt.Fprintln(b, "---")
	fmt.Fprintln(b)
}

func joinOrNone(ss []string) string {
	if len(ss) == 0 {
		return "none"
	}
	return strings.Join(ss, ", ")
}
