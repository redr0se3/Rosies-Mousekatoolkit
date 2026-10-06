package active

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeTempWordlist writes runtime-generated path seeds (from passive
// recon, or from JS-harvested endpoints feeding back into dirbrute) to a
// file feroxbuster can consume. These are not operator-configured paths,
// so they don't go through safety.ResolveWordlistPath — they're written
// by us, under a dedicated subdirectory of the wordlist base dir, with a
// name derived from the hostname so repeated runs are traceable.
func writeTempWordlist(baseDir, hostname string, lines []string) (string, error) {
	dir := filepath.Join(baseDir, "_generated")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating generated-wordlist dir: %w", err)
	}
	path := filepath.Join(dir, sanitizeFilename(hostname)+".txt")
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("creating generated wordlist: %w", err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := fmt.Fprintln(f, l); err != nil {
			return "", err
		}
	}
	return path, nil
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
