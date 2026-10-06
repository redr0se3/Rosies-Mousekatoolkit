// Package output implements the JSON results schema and the
// human-readable report generated from it. Per spec: "the JSON is the
// source of truth, the report is a view over it" — every module writes
// into state.Target, which already carries the exact field set the
// spec's Output table describes, so this package's job is persistence
// (save/load for --resume) and rendering, not reshaping the data.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// Results is the top-level JSON document written to --out and read back
// by --resume.
type Results struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Phase       string          `json:"phase"`
	Targets     []*state.Target `json:"targets"`
}

// Save writes results as indented JSON. Indentation costs some file size
// but this is a recon tool's output, read by humans and by other tooling
// (Nuclei, a report generator) alike — the spec calls that out
// explicitly as the reason results.json isn't free-text logs.
func Save(path string, r *Results) error {
	r.GeneratedAt = time.Now().UTC()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing results to %s: %w", path, err)
	}
	return nil
}

// Load reads a prior results file for --resume. Fail closed: a malformed
// results file aborts the resume rather than silently starting from an
// empty store (which would re-run — and re-hit — every target).
func Load(path string) (*Results, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading resume file: %w", err)
	}
	var r Results
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing resume file %s: %w", path, err)
	}
	return &r, nil
}

// PopulateStore rebuilds a state.Store from a loaded Results document so
// --resume can skip modules a target already completed (ModuleStatus is
// preserved per target) instead of re-running the full pipeline.
func (r *Results) PopulateStore(store *state.Store) {
	for _, t := range r.Targets {
		existing, created := store.GetOrCreate(t.Hostname)
		if !created {
			continue
		}
		existing.LoadFrom(t)
	}
}
