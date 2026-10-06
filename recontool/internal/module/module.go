// Package module defines the one interface every recon step implements.
// This is what the spec calls out as the extensibility point: "adding a
// new tool later means writing one function that satisfies the interface
// and registering it in the phase it belongs to, not touching the
// orchestration logic."
package module

import (
	"context"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/config"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/pool"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/scope"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// RunContext bundles everything a module needs besides the target itself:
// the scope gate every request-sending module must consult, the shared
// store (for queuing newly discovered hosts back in as fresh targets),
// the worker pool / host limiter, and run configuration.
type RunContext struct {
	Ctx         context.Context
	Scope       *scope.Checker
	Store       *state.Store
	Pool        *pool.Pool
	HostLimiter *pool.HostLimiter
	Config      *config.RunConfig
	Scoped      *scope.Scope
	Log         Logger
}

// Logger is a tiny seam so modules don't print directly; cmd/recontool
// wires up the real implementation.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Findings is the disconnected-result-free return value every module
// produces; the orchestrator merges it into the target's shared state and
// handles any feedback-loop consequences (new hosts needing a scope
// check, a tech-stack change that should re-trigger a targeted pass).
type Findings struct {
	TechStack   []string
	Paths       []state.PathFinding
	VHosts      []state.VHostFinding
	Endpoints   []string
	JSFindings  []state.JSFinding
	Screenshots []state.ScreenshotFinding
	Skipped     []state.SkippedFinding

	// WordlistSeeds are extra paths (from robots.txt, sitemap.xml, Wayback
	// / CommonCrawl history) that should feed Phase 2's directory
	// brute-force wordlist for this target.
	WordlistSeeds []string

	// NewCandidateHosts are hostnames this module observed (crt.sh,
	// wayback, a Host-header hit, a JS-harvested internal hostname) that
	// have NOT yet been scope-checked. The orchestrator is the only place
	// that is allowed to act on these — it runs each one through
	// scope.Checker.Check before anything is queued.
	NewCandidateHosts []CandidateHost
}

// CandidateHost carries provenance so a "skipped_out_of_scope" entry in
// the output can say where the host came from.
type CandidateHost struct {
	Hostname string
	Source   string
}

// MergeInto applies the findings to a target's shared state. Modules
// should prefer returning Findings over mutating the target directly
// where practical, but direct mutation via the Target's own locked
// helpers is also valid for long-running modules that want to make
// partial progress visible (e.g. feroxbuster streaming results).
func (f Findings) MergeInto(t *state.Target) {
	if len(f.TechStack) > 0 {
		t.MergeTechStack(f.TechStack...)
	}
	if len(f.Paths) > 0 {
		t.AddPaths(f.Paths...)
	}
	if len(f.VHosts) > 0 {
		t.AddVHosts(f.VHosts...)
	}
	if len(f.Endpoints) > 0 {
		t.AddEndpoints(f.Endpoints...)
	}
	if len(f.JSFindings) > 0 {
		t.AddJSFindings(f.JSFindings...)
	}
	if len(f.Screenshots) > 0 {
		t.AddScreenshots(f.Screenshots...)
	}
	if len(f.Skipped) > 0 {
		t.AddSkipped(f.Skipped...)
	}
	if len(f.WordlistSeeds) > 0 {
		t.AddWordlistSeeds(f.WordlistSeeds...)
	}
}

// Module is the one interface every recon step implements.
type Module interface {
	// Name identifies the module in ModuleStatus and in findings'
	// FoundBy/Source fields.
	Name() string
	// Run executes the module against one target. Implementations that
	// send any network request MUST check rc.Scope before doing so, even
	// though the orchestrator also gates target-level dispatch — defense
	// in depth for a module that discovers a *different* host mid-run
	// (e.g. a redirect target, a vhost hit).
	Run(rc *RunContext, t *state.Target) (Findings, error)
}
