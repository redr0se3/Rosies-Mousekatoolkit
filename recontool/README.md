# recontool

A Go CLI that orchestrates passive and active web recon against in-scope
targets, feeding results between modules instead of running tools as
isolated one-offs. Implements the design in `Go_Web_App_Recon_Tool___Feature_Spec.md`.

> **This tool sends real network traffic, including brute-force-style
> enumeration, at the hosts listed in your scope file.** Use it only
> against systems you are explicitly authorized to test.

## Build

Pure Go, no `cgo` — cross-compiling to another CPU architecture is a
flag, not a toolchain problem:

```sh
go build -o recontool ./cmd/recontool          # host platform
make build-arm64                               # linux/arm64 + darwin/arm64 → dist/
make build-all                                 # + linux/amd64 + darwin/amd64
```

## Run

```sh
recontool --scope scope.yaml [--out results.json] [--report report.md] \
          [--phase passive|active|all] [--resume results.json]
```

- `--scope` (required) — the authorization boundary. See `scope.example.yaml`.
- `--phase passive` — run only crt.sh/robots.txt/sitemap/Wayback/CommonCrawl.
  Nothing here sends a request to the target's own server except the
  robots.txt/sitemap.xml fetch, which is still scope-gated.
- `--phase active` — tech fingerprinting, wildcard DNS detection,
  vhost/subdomain discovery, feroxbuster directory brute-forcing, JS
  harvesting, and (as part of the same run) screenshotting + dedup.
- `--resume results.json` — reload a prior run and skip modules a target
  already completed.

External tools used by Phase 2/3, invoked via `exec.Command` with no
shell involved: `whatweb`, `wappalyzer` (npm CLI), `feroxbuster`,
`gowitness`. Any of them missing is a soft failure (logged, module
skipped) — not a fatal error for the whole run.

## Design

- **Shared target state.** One `state.Target` struct per host, passed by
  pointer into every module. Later modules read earlier findings — a
  WordPress fingerprint narrows the wordlist feroxbuster uses against
  that host.
- **Scope is the one gate, checked at the point of request.** Not a
  one-time filter on the initial list: `internal/orchestrator`'s
  `admitCandidate` re-checks scope for every hostname any module
  discovers mid-run (a crt.sh name, a vhost hit, a JS-harvested
  endpoint's host) before it becomes a live target. See
  `internal/scope`.
- **Worker pool + per-host rate limiter are two different knobs.**
  `internal/pool.Pool` bounds total goroutines; `pool.HostLimiter` bounds
  concurrent requests *per host* from `max_concurrent_requests`, and the
  same number is passed as `-t`/`--threads` to external tools so the
  orchestrator's concurrency and the tool's own don't multiply.
- **One module interface.** `module.Module` — `Name() string` and
  `Run(*RunContext, *state.Target) (Findings, error)`. Adding a tool
  means writing one type and registering it in
  `orchestrator.New`'s `passiveModules`/`activeModules` slices — nothing
  else in the orchestration changes.
- **No shell interpolation.** Every external tool call goes through
  `internal/safety.RunTool`, which uses `exec.Command(bin, args...)`
  with `args` as a `[]string` — never a shell string. See the doc
  comment there for exactly why that distinction matters.
- **Wordlist paths are validated.** `internal/safety.ResolveWordlistPath`
  rejects any configured wordlist path that resolves outside the
  configured base directory, closing off path traversal via a
  tampered config file.
- **Fail closed.** A scope parse error, a malformed target, or a DNS
  resolution failure stops that target's pipeline — never "treat as in
  scope."

## Output

`results.json` is the source of truth (schema: `internal/output.Results`
→ a list of `state.Target`, matching the spec's Output table exactly —
`hostname`/`ips`/`in_scope`, `tech_stack`, `paths`, `vhosts`,
`js_findings`, `screenshots`, `skipped`). `--report` renders a Markdown
view over it; it is never the thing other tooling should parse.

## Tests

```sh
go test ./...
```

Focused on the two security-critical pieces: `internal/scope` (exclude
beats a targets CIDR, subdomain suffix matching doesn't false-positive
on `notexample.com`, fail-closed on unresolvable hosts) and
`internal/safety` (wordlist path traversal).
