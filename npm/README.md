# @hoophq/leash

**Guardrails for AI coding agents.** Leash inspects every command your agent
tries to run and stops the catastrophic ones — recursive deletes of your home
directory, secret exfiltration, `curl | sh`, force-pushes — *before* they
execute.

```bash
npx @hoophq/leash check 'rm -rf ~'      # DENY
npx @hoophq/leash init                  # wire it into Claude Code
```

This package ships the native `leash` binary. It uses the esbuild/biome
distribution model: the correct `@hoophq/leash-<os>-<cpu>` build is pulled in as
an optional dependency via npm's `os`/`cpu` selection — **no postinstall script
and no download at runtime** (a tool that flags those shouldn't ship as one).

Supported platforms: macOS and Linux on x64/arm64. For anything else, install
from source: `go install github.com/hoophq/leash/cmd/leash@latest`.

Full docs: https://github.com/hoophq/leash
