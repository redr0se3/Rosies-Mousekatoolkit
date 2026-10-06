package postprocess

import (
	"github.com/redr0se3/rosies-mousekatoolkit/recontool/internal/state"
)

// Dedup collapses near-identical findings:
//
//   - The same path found by two different wordlists becomes one
//     PathFinding, with FoundBy listing every wordlist that hit it,
//     rather than N duplicate entries differing only in FoundBy.
//   - Vhosts sharing a backend (same resolved IP set, same content hash
//     on their root page) are grouped so the report can say "these N
//     vhosts are the same application" instead of listing them as N
//     unrelated findings.
//
// This is a pure in-memory transform over one target's already-collected
// state — it is not a module.Module because it never sends a request and
// never needs scope/pool/config; the orchestrator calls it directly as
// the first step of Phase 3.
func Dedup(t *state.Target) {
	t.Mutate(func(t *state.Target) {
		t.Paths = dedupPaths(t.Paths)
		t.VHosts = dedupVHosts(t.VHosts)
	})
}

func dedupPaths(in []state.PathFinding) []state.PathFinding {
	type key struct {
		path   string
		status int
	}
	index := make(map[key]int)
	out := make([]state.PathFinding, 0, len(in))

	for _, p := range in {
		k := key{path: p.Path, status: p.Status}
		if idx, ok := index[k]; ok {
			existing := &out[idx]
			if !containsWord(existing.FoundBy, p.FoundBy) {
				existing.FoundBy = existing.FoundBy + "," + p.FoundBy
			}
			if existing.ContentHash == "" {
				existing.ContentHash = p.ContentHash
			}
			continue
		}
		index[k] = len(out)
		out = append(out, p)
	}
	return out
}

func containsWord(csv, word string) bool {
	if csv == word {
		return true
	}
	// cheap contains-as-list-element check; good enough for a small,
	// comma-joined label field.
	return len(csv) >= len(word) && (indexOf(csv, word) >= 0)
}

func indexOf(haystack, needle string) int {
	n := len(needle)
	for i := 0; i+n <= len(haystack); i++ {
		if haystack[i:i+n] == needle {
			left := i == 0 || haystack[i-1] == ','
			right := i+n == len(haystack) || haystack[i+n] == ','
			if left && right {
				return i
			}
		}
	}
	return -1
}

// dedupVHosts groups vhosts that resolve to the same IP set — a strong
// signal they're served by the same backend rather than genuinely
// distinct applications. Source strings are merged (comma-joined) rather
// than dropped, so "found via both DNS and Host-header fuzz" stays
// visible in the output.
func dedupVHosts(in []state.VHostFinding) []state.VHostFinding {
	type key struct{ hostname string }
	index := make(map[key]int)
	out := make([]state.VHostFinding, 0, len(in))

	for _, v := range in {
		k := key{hostname: v.Hostname}
		if idx, ok := index[k]; ok {
			existing := &out[idx]
			if !containsWord(existing.Source, v.Source) {
				existing.Source = existing.Source + "," + v.Source
			}
			continue
		}
		index[k] = len(out)
		out = append(out, v)
	}
	return out
}
