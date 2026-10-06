// Command recontool is a Go CLI that orchestrates passive and active web
// recon against in-scope targets. See the feature spec for the full
// design; this file is intentionally thin — it parses flags, loads and
// validates the scope file, and hands off to the orchestrator.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/config"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/logging"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/orchestrator"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/output"
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/scope"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "recontool:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		scopePath  = flag.String("scope", "", "path to the scope YAML file (required)")
		outPath    = flag.String("out", "results.json", "path to write the JSON results")
		reportPath = flag.String("report", "", "path to write a Markdown report (optional)")
		phaseFlag  = flag.String("phase", "all", "which phase to run: passive|active|all")
		resumePath = flag.String("resume", "", "path to a prior results.json to resume from")
	)
	flag.Parse()

	if *scopePath == "" {
		flag.Usage()
		return fmt.Errorf("--scope is required")
	}

	phase, err := config.ParsePhase(*phaseFlag)
	if err != nil {
		return err
	}

	cfg := &config.RunConfig{
		ScopePath:  *scopePath,
		OutPath:    *outPath,
		ReportPath: *reportPath,
		Phase:      phase,
		ResumePath: *resumePath,
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Fail closed: a scope file parse/validation error stops the tool
	// before anything else runs. See internal/scope for why.
	scoped, err := scope.Load(cfg.ScopePath)
	if err != nil {
		return fmt.Errorf("scope file: %w", err)
	}

	log := logging.New()
	log.Infof("loaded scope: %d target(s), %d exclusion(s), max_concurrent_requests=%d, phase=%s",
		len(scoped.Targets), len(scoped.Exclude), scoped.MaxConcurrentRequests, cfg.Phase)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	orch := orchestrator.New(cfg, scoped, log)
	results, err := orch.Run(ctx)
	if err != nil {
		return fmt.Errorf("run failed: %w", err)
	}

	if err := output.Save(cfg.OutPath, results); err != nil {
		return fmt.Errorf("saving results: %w", err)
	}
	log.Infof("results written to %s", cfg.OutPath)

	if cfg.ReportPath != "" {
		if err := output.WriteMarkdownReport(cfg.ReportPath, results); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		log.Infof("report written to %s", cfg.ReportPath)
	}

	return nil
}
