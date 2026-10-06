package safety

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ResolveWordlistPath validates that a config-supplied wordlist path
// resolves to somewhere inside baseDir, before it is ever handed to
// exec.Command as a -w/--wordlist argument.
//
// The threat this defends against: the scope/config YAML is itself an
// input the operator controls, but in a team setting it might be
// generated, templated, or reviewed less carefully than code. A
// wordlist entry of "../../../../etc/passwd" or an absolute path outside
// the expected wordlists directory would otherwise let a malicious or
// mistaken config file make feroxbuster read (and, depending on the
// tool, potentially echo back) arbitrary files on the machine running
// the scan. filepath.Abs + filepath.Clean collapse any ".." segments
// before we compare, so the check can't be defeated by path tricks that
// merely look like they stay inside baseDir.
func ResolveWordlistPath(baseDir, configured string) (string, error) {
	if configured == "" {
		return "", fmt.Errorf("empty wordlist path")
	}

	absBase, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return "", fmt.Errorf("resolving wordlist base dir: %w", err)
	}

	candidate := configured
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(absBase, candidate)
	}
	absCandidate, err := filepath.Abs(filepath.Clean(candidate))
	if err != nil {
		return "", fmt.Errorf("resolving wordlist path %q: %w", configured, err)
	}

	rel, err := filepath.Rel(absBase, absCandidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("wordlist path %q escapes base directory %q", configured, absBase)
	}

	return absCandidate, nil
}
