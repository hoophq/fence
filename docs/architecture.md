# Architecture

Leash is an **agent-neutral core** with **per-agent adapters**. The core reasons
about a normalized action; each adapter teaches one agent how to speak to it.

```
   agent tool call                                   decision
        │                                                ▲
        ▼                                                │
  ┌───────────┐   Action    ┌──────────────┐   ┌──────────┐
  │  adapter  │ ──────────▶ │    engine    │ ─▶│ rulepack │
  │ (per-agent)│  (neutral) │ (AST facts)  │   │  (yaml)  │
  └───────────┘             └──────────────┘   └──────────┘
```

1. An **adapter** translates one agent's tool call into a neutral `Action`
   (`shell`, `file_write`, `file_read`, `net_fetch`). Claude Code's `PreToolUse`
   payload is the first adapter.
2. The **engine** analyzes the action. Shell commands go through a real parser
   ([`mvdan.cc/sh`](https://github.com/mvdan/sh)) that extracts **semantic
   facts** — recursive delete + where it points, disk writes, force-push,
   `curl | sh`, secret exfiltration, and so on.
3. **Rules** in a rulepack match those facts and apply an effect. When several
   match, the most severe wins (`deny` > `ask` > `warn` > `allow`).

The engine and rulepacks know nothing about any specific agent — which is what
makes one rulepack portable across all of them.

## Semantic, not substring

This is the whole point. A denylist that greps for `rm -rf` is dodged by
`rm -fr`, `rm -r -f`, `sudo rm -rf`, or a script written then run. Leash instead
parses the command into a shell AST and asks *what does this do?* — so flag
order, `sudo`/`env` wrappers, and `$HOME` vs `~` all collapse to the same fact.
The same discipline keeps false positives near zero: `rm -rf node_modules` and
`rm -rf ./dist` are recognized as workspace-local and pass untouched.

A rule's `regex` field exists only as a fallback for the rare pattern not yet
modelled — never as the primary mechanism.

## Fails open

A guardrail must never brick the agent it protects. If an input can't be parsed
or an internal error occurs, Leash logs to stderr and exits 0 — the command
proceeds as if Leash weren't installed. Decisions travel through the agent's JSON
protocol (e.g. Claude Code's `permissionDecision`), never through exit codes.

## Package layout

| Path | Responsibility |
|---|---|
| `internal/policy` | the engine (`Evaluate`, deny-overrides), the neutral `Action`/`Effect`/`Decision` types, `Rule`/`Match`/`Rulepack`, `extends:` resolution, and the embedded `recommended` pack |
| `internal/analyzer/shell` | shell-AST analysis → semantic facts (the differentiator) |
| `internal/analyzer/manifest` | content analysis of `package.json` / `setup.py` for install hooks |
| `internal/adapter/<agent>` | translate one agent's tool call ⇄ neutral `Action` |
| `internal/store` | the user-level state dir (`~/.leash`): installed packs + lockfile |
| `internal/registry` | fetch + checksum-verify packs from a static index (never on the eval path) |
| `internal/cli` | the `check`, `hook`, `init`, `add`, `search`, `update`, `remove`, `version` commands |
| `cmd/leash` | entrypoint |

## Extending Leash

Three clean extension points:

- **A new agent** = a new adapter under `internal/adapter/`. Map the agent's
  tool call to an `Action` and its decision format back out; the engine and
  every rulepack come along for free.
- **A new detection** = a new semantic fact in an analyzer plus a `Match`
  predicate in `policy`, then a rule that uses it. Every detector ships with a
  table-driven test that pins **both** the catch and the safe cases — the
  false-positive discipline is the product.
- **A new rulepack** = a YAML file anyone can publish to the
  [registry](registry.md) and anyone can install with `leash add` — no Go
  involved. Because packs are agent-neutral, one published pack guards every
  agent Leash supports.

See [Rules](rules.md) for the match conditions those facts expose.
