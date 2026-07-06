# CLAUDE.md

## Project Overview

Fence is a standalone Go CLI: **guardrails for AI coding agents**. It inspects an
agent's tool calls (through that agent's hook system) and blocks or asks before
catastrophic ones run — recursive deletes of home/root, secret exfiltration,
`curl | sh`, force-pushes. Standalone Go module, Go 1.26, no runtime services.

**Scope is deliberate.** Fence is *local self-protection*: dev-owned,
dev-editable, and it fails open. It is intentionally **not** a compliance or
central-enforcement product — keep un-bypassable policy, fleet management,
central audit, and approval workflows out of scope.

## Commands

- `make build` → `./dist/fence` · `make test` · `make vet` · `make fmt` · `make tidy`
- Raw: `go build ./...` · `go test ./...` · `go vet ./...` · `gofmt -l .`
- `go test ./...` is the gate — tests pin the false-positive discipline.
- Test a rule without an agent: `fence check 'rm -rf ~'` (prints a DENY/ASK/WARN/ALLOW card).
- Exercise the hook directly:
  `echo '{"cwd":".","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}' | ./dist/fence hook claude-code`

## Architecture — agent-neutral core + per-agent adapters

- `internal/policy/` — engine (`Evaluate`, deny-overrides resolution), the neutral
  `Action`/`Effect`/`Decision` types, `Rule`/`Match`/`Rulepack`, and the embedded
  `builtin/recommended.yaml` default pack.
- `internal/analyzer/shell/` — shell-AST analysis via `mvdan.cc/sh` producing
  semantic facts (recursive-delete + target class, force-push, history-rewrite,
  net→shell pipe). **This is the differentiator** — see Conventions.
- `internal/adapter/<agent>/` — translate one agent's tool call ⇄ neutral `Action`.
  `claudecode` (Claude Code PreToolUse + the SessionStart banner) came first;
  `codex` speaks Codex's Claude-compatible hook envelope with its own tool
  vocabulary (`Bash`, `apply_patch` — expanded to one file_write per touched
  file, most severe verdict wins). Adapters stay self-contained even where the
  wire formats coincide — the two protocols are owned by different vendors and
  may drift. Decisions and chat notices ride the same JSON envelope; an explicit
  "allow" decision is never emitted (it would bypass the user's own permission
  settings).
- `internal/store/` — the user-level state dir (`~/.fence`): packs installed via
  `fence add` (the packs dir is the source of truth) + `packs.lock.json` metadata.
- `internal/registry/` — fetch + sha256-verify packs from a static index
  (`registry/` in this repo, read raw off main). Only the explicit commands
  import it — **nothing on the eval path may ever touch the network**.
- `internal/cli/` — Cobra commands: `check`, `hook`, `init`, `add`, `search`,
  `update`, `remove`, `version`.
- `cmd/fence/` — entrypoint; `version` is injected via `-ldflags "-X main.version=..."`.

## Conventions (load-bearing)

- **Semantic, not substring.** Detect dangerous commands by adding a fact in
  `analyzer/shell` + a `Match` predicate in `policy` — never a substring/regex
  denylist. A rule's `regex` field is a fallback only (e.g. fork bombs).
- **Near-zero false positives is the product thesis.** Ambiguous → `ask`; only
  unambiguous catastrophe → `deny`. Everyday ops (`rm -rf node_modules`,
  `rm -rf *`, `git push --force-with-lease`) MUST stay ALLOW.
- **Fail open.** A hook never blocks on internal error: log to stderr, exit 0.
  Decisions travel through the JSON protocol (`permissionDecision`), never via
  exit codes.
- **Every detector needs a table-driven test** asserting both the catch AND the
  safe cases (the false-positive guard). See `internal/**/*_test.go`.
- Extension points: new agent = new adapter; new detection = new analyzer fact +
  `Match` predicate. The engine and rulepacks stay agent-agnostic.

## Rulepacks

- Layering order: the embedded `recommended` pack (always active), then packs
  installed with `fence add` (`~/.fence/packs`, a-z), then `./.fence.yaml`
  (auto-discovered), then `--rules <file>`. Any pack can pull others in below
  itself with `extends:` (installed name or relative path; resolved in
  `internal/policy/resolve.go`, never over the network).
- When several rules match, the most severe effect wins (`deny` > `ask` > `warn`
  > `allow`). Default when nothing matches is `allow`.
- Ambient sources (installed packs, `.fence.yaml`) degrade on error — warn and
  skip, the rest keep protecting; an explicit `--rules` failure stays loud.
- Seed packs live in `registry/packs/` + `registry/index.yaml`; after editing a
  pack, recompute its `sha256` in the index (the seed test enforces this).

## Gotchas

- gopls may report false `BrokenImport` / "not in a workspace module" errors if
  this repo is opened inside another module's `go.work`. Ignore IDE diagnostics
  here — trust `go build ./...` and `go test ./...`.
- Dependencies: `mvdan.cc/sh/v3` (shell parser), `spf13/cobra`,
  `gopkg.in/yaml.v3`, `bmatcuk/doublestar/v4` (`**` globs).
