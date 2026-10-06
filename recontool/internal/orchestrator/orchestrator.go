// Package orchestrator implements the pipeline described in the spec's
// Architecture section: every resolved target passes through the same
// scope gate before any module touches it, and every module's output
// lands back in the same shared state object that the next module reads.
package orchestrator

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/config"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/module"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/modules/active"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/modules/passive"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/modules/postprocess"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/output"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/pool"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/scope"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

type Orchestrator struct {
	cfg     *config.RunConfig
	scoped  *scope.Scope
	checker *scope.Checker
	store   *state.Store
	pool    *pool.Pool
	limiter *pool.HostLimiter
	log     module.Logger

	passiveModules []module.Module
	activeModules  []module.Module // sequence matters: wildcard -> fingerprint -> vhost -> dirbrute -> jsharvest
}

func New(cfg *config.RunConfig, scoped *scope.Scope, log module.Logger) *Orchestrator {
	checker := scope.NewChecker(scoped)
	return &Orchestrator{
		cfg:     cfg,
		scoped:  scoped,
		checker: checker,
		store:   state.NewStore(),
		pool:    pool.New(scoped.WorkerPoolSize),
		limiter: pool.NewHostLimiter(scoped.MaxConcurrentRequests),
		log:     log,

		// Registering a new module means adding one line here, in the
		// phase it belongs to — nothing else in this file changes. This
		// is the extensibility point the spec's module interface exists
		// to provide.
		passiveModules: []module.Module{
			passive.CTLog{},
			passive.RobotsAndSitemap{},
			passive.Historical{},
		},
		activeModules: []module.Module{
			active.WildcardDetect{},
			active.Fingerprint{},
			active.VHostDiscovery{},
			active.DirBrute{},
			active.JSHarvest{},
		},
	}
}

func (o *Orchestrator) rc(ctx context.Context) *module.RunContext {
	return &module.RunContext{
		Ctx:         ctx,
		Scope:       o.checker,
		Store:       o.store,
		Pool:        o.pool,
		HostLimiter: o.limiter,
		Config:      o.cfg,
		Scoped:      o.scoped,
		Log:         o.log,
	}
}

// Run executes the full pipeline and returns the final results document.
func (o *Orchestrator) Run(ctx context.Context) (*output.Results, error) {
	if o.cfg.ResumePath != "" {
		prior, err := output.Load(o.cfg.ResumePath)
		if err != nil {
			// Fail closed: a malformed resume file must stop the run,
			// not silently fall back to an empty store that would
			// re-hit every target from scratch.
			return nil, fmt.Errorf("loading resume file: %w", err)
		}
		prior.PopulateStore(o.store)
		o.log.Infof("resumed %d targets from %s", len(prior.Targets), o.cfg.ResumePath)
	}

	if err := o.seedInitialTargets(ctx); err != nil {
		return nil, err
	}

	if o.cfg.RunsPassive() {
		o.runPassivePhase(ctx)
	}

	if o.cfg.RunsActive() {
		o.runActivePhase(ctx)
		o.runPostProcessPhase(ctx)
	}

	results := &output.Results{Phase: string(o.cfg.Phase), Targets: o.store.All()}
	return results, nil
}

// seedInitialTargets resolves and scope-checks every hostname entry in
// the scope file's targets list. CIDR entries authorize matching IPs
// for anything discovered later, but — deliberately — are not expanded
// into individual hosts to scan here; actively probing every address in
// a /16 is a different, much noisier tool than what this spec describes,
// and the operator can always list specific hostnames.
func (o *Orchestrator) seedInitialTargets(ctx context.Context) error {
	for _, raw := range o.scoped.Targets {
		if strings.Contains(raw, "/") {
			continue // CIDR: scope-matching only, not an enumerable host
		}
		hostname := strings.ToLower(strings.TrimSpace(raw))
		hostname = strings.TrimPrefix(hostname, "*.")

		t, _ := o.store.GetOrCreate(hostname)
		res, err := o.checker.Check(ctx, hostname)
		if err != nil {
			// Fail closed per spec: a DNS resolution failure for an
			// explicitly configured target stops that target's
			// pipeline rather than silently treating it as in scope.
			o.log.Errorf("seed target %s failed DNS resolution: %v — this target's pipeline will not run", hostname, err)
			t.Mutate(func(t *state.Target) { t.InScope = false })
			t.AddSkipped(state.SkippedFinding{Item: hostname, Reason: "dns_resolution_failed"})
			continue
		}
		t.Mutate(func(t *state.Target) {
			t.InScope = res.InScope
			t.IPs = ipsToStrings(res.IPs)
		})
		if !res.InScope {
			t.AddSkipped(state.SkippedFinding{Item: hostname, Reason: res.Reason})
		}
	}
	return nil
}

func (o *Orchestrator) runPassivePhase(ctx context.Context) {
	rc := o.rc(ctx)
	targets := o.store.All()

	for _, t := range targets {
		if !t.InScope {
			continue
		}
		t := t
		for _, m := range o.passiveModules {
			m := m
			if status, ok := t.GetModuleStatus(m.Name()); ok && status == "ok" {
				continue // --resume: already completed
			}
			// Candidate admission (scope-checking anything a passive
			// module surfaces) happens inside runModuleSync, so it's
			// safe to fire-and-forget here — each submitted job mutates
			// only its own target and the shared store, both of which
			// are already safe for concurrent access.
			o.pool.Submit(func() { o.runModuleSync(rc, m, t) })
		}
	}
	o.pool.Wait()
}

func (o *Orchestrator) runActivePhase(ctx context.Context) {
	rc := o.rc(ctx)

	// A simple work-queue drains itself as new in-scope vhosts are
	// admitted mid-phase — each admitted vhost becomes its own Target and
	// runs the full active sequence (including its own Fingerprint and
	// DirBrute pass), which is what gives the "tech-stack feedback loop"
	// its effect for free: a vhost on different software than the root
	// domain gets its own targeted wordlist selection naturally, because
	// wordlist selection is computed from each target's own TechStack.
	processed := make(map[string]bool)
	queue := hostnamesOf(o.store.All())

	for len(queue) > 0 {
		hostname := queue[0]
		queue = queue[1:]
		if processed[hostname] {
			continue
		}
		processed[hostname] = true

		t, ok := o.store.Get(hostname)
		if !ok || !t.InScope {
			continue
		}

		for _, m := range o.activeModules {
			status, done := t.GetModuleStatus(m.Name())
			if done && status == "ok" {
				continue // --resume
			}
			admitted, _ := o.runModuleSync(rc, m, t)
			for _, h := range admitted {
				if !processed[h] {
					queue = append(queue, h)
				}
			}
		}
	}
}

func (o *Orchestrator) runPostProcessPhase(ctx context.Context) {
	rc := o.rc(ctx)
	shot := postprocess.Screenshot{OutputDir: "screenshots"}

	for _, t := range o.store.All() {
		if !t.InScope {
			continue
		}
		postprocess.Dedup(t)

		if status, ok := t.GetModuleStatus(shot.Name()); ok && status == "ok" {
			continue
		}
		t := t
		o.pool.Submit(func() { o.runModuleSync(rc, shot, t) })
	}
	o.pool.Wait()
}

// runModuleSync is the one place that calls m.Run. It merges findings
// into the target, records module status, and — this is the scope gate
// for anything discovered *mid-run* — scope-checks every
// NewCandidateHosts entry the module returned before any of them become
// a live target. Returns the hostnames newly admitted, so the active
// phase's work queue can pick them up.
func (o *Orchestrator) runModuleSync(rc *module.RunContext, m module.Module, t *state.Target) ([]string, module.Findings) {
	start := time.Now()
	findings, err := m.Run(rc, t)
	if err != nil {
		o.log.Warnf("%s on %s failed after %s: %v", m.Name(), t.Hostname, time.Since(start).Round(time.Millisecond), err)
		t.SetModuleStatus(m.Name(), "error:"+err.Error())
		return nil, findings
	}
	findings.MergeInto(t)
	t.SetModuleStatus(m.Name(), "ok")
	o.log.Infof("%s on %s completed in %s", m.Name(), t.Hostname, time.Since(start).Round(time.Millisecond))

	var admitted []string
	for _, c := range findings.NewCandidateHosts {
		if host, ok := o.admitCandidate(rc.Ctx, t, c); ok {
			admitted = append(admitted, host)
		}
	}
	return admitted, findings
}

// admitCandidate is the single enforcement point for "scope isn't a
// one-time filter on the initial target list" — called for every
// hostname any module discovers mid-run (a crt.sh name, a vhost hit, a
// JS-harvested endpoint's host). origin is the target that discovered
// it, used to record the outcome (a VHostFinding if admitted, a
// SkippedFinding with the reason if not) in a place a human reading the
// report will actually see it.
func (o *Orchestrator) admitCandidate(ctx context.Context, origin *state.Target, c module.CandidateHost) (string, bool) {
	if _, exists := o.store.Get(c.Hostname); exists {
		return "", false // already a known target; avoid duplicate admission/finding noise
	}

	res, err := o.checker.Check(ctx, c.Hostname)
	if err != nil || !res.InScope {
		reason := res.Reason
		if reason == "" {
			reason = "dns_resolution_failed"
		}
		origin.AddSkipped(state.SkippedFinding{Item: c.Hostname, Reason: reason})
		return "", false
	}

	if !o.checker.AllowSubdomainDiscovery() {
		origin.AddSkipped(state.SkippedFinding{Item: c.Hostname, Reason: "discovered_subdomain_discovery_disabled"})
		return "", false
	}

	t, created := o.store.GetOrCreate(c.Hostname)
	if !created {
		return "", false
	}
	t.Mutate(func(t *state.Target) {
		t.InScope = true
		t.IPs = ipsToStrings(res.IPs)
	})
	origin.AddVHosts(state.VHostFinding{Hostname: c.Hostname, Source: c.Source, IPs: t.Snapshot().IPs})
	return c.Hostname, true
}

func ipsToStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func hostnamesOf(targets []*state.Target) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.Hostname)
	}
	return out
}
