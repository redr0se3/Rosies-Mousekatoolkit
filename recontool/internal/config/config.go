// Package config holds the CLI-level run configuration — the small set of
// flags the spec says belong on the command line, as opposed to the
// wordlists/timeouts/pool-size fields that live in the scope YAML file
// with sane defaults.
package config

import "fmt"

type Phase string

const (
	PhasePassive Phase = "passive"
	PhaseActive  Phase = "active"
	PhaseAll     Phase = "all"
)

func ParsePhase(s string) (Phase, error) {
	switch Phase(s) {
	case PhasePassive, PhaseActive, PhaseAll:
		return Phase(s), nil
	default:
		return "", fmt.Errorf("invalid --phase %q (want passive|active|all)", s)
	}
}

// RunConfig is the parsed CLI surface described in the spec:
//
//	recontool --scope scope.yaml [--out results.json] [--report report.md]
//	          [--phase passive|active|all] [--resume results.json]
type RunConfig struct {
	ScopePath  string
	OutPath    string
	ReportPath string
	Phase      Phase
	ResumePath string
}

func (c *RunConfig) Validate() error {
	if c.ScopePath == "" {
		return fmt.Errorf("--scope is required")
	}
	if c.Phase == "" {
		c.Phase = PhaseAll
	}
	if c.OutPath == "" {
		c.OutPath = "results.json"
	}
	return nil
}

func (c *RunConfig) RunsPassive() bool { return c.Phase == PhasePassive || c.Phase == PhaseAll }
func (c *RunConfig) RunsActive() bool  { return c.Phase == PhaseActive || c.Phase == PhaseAll }
