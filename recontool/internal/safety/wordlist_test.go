package safety

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveWordlistPath_RejectsTraversal(t *testing.T) {
	base := t.TempDir()
	if _, err := ResolveWordlistPath(base, "../../../../etc/passwd"); err == nil {
		t.Fatal("expected traversal outside base dir to be rejected")
	}
}

func TestResolveWordlistPath_RejectsAbsoluteOutsideBase(t *testing.T) {
	base := t.TempDir()
	if _, err := ResolveWordlistPath(base, "/etc/passwd"); err == nil {
		t.Fatal("expected an absolute path outside base dir to be rejected")
	}
}

func TestResolveWordlistPath_AllowsFileInsideBase(t *testing.T) {
	base := t.TempDir()
	wordlistFile := filepath.Join(base, "common.txt")
	if err := os.WriteFile(wordlistFile, []byte("admin\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	resolved, err := ResolveWordlistPath(base, "common.txt")
	if err != nil {
		t.Fatalf("expected a legitimate in-base path to resolve, got: %v", err)
	}
	if resolved != wordlistFile {
		t.Errorf("expected %q, got %q", wordlistFile, resolved)
	}
}

func TestResolveWordlistPath_RejectsSneakyRelativeThatEscapes(t *testing.T) {
	base := t.TempDir()
	// looks like it stays inside, but ".." segments walk it back out
	if _, err := ResolveWordlistPath(base, "subdir/../../escape.txt"); err == nil {
		t.Fatal("expected a relative path with escaping '..' segments to be rejected")
	}
}
