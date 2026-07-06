# @hoophq/fence

**Guardrails for AI coding agents.** Fence inspects every command your agent
tries to run and stops the catastrophic ones — recursive deletes of your home
directory, secret exfiltration, `curl | sh`, force-pushes — *before* they
execute.

```bash
npm install -g @hoophq/fence

fence check 'rm -rf ~'      # DENY
fence init                  # wire it into Claude Code
```

This package ships the native `fence` binary. It uses the esbuild/biome
distribution model: the correct `@hoophq/fence-<os>-<cpu>` build is pulled in as
an optional dependency via npm's `os`/`cpu` selection — **no postinstall script
and no download at runtime** (a tool that flags those shouldn't ship as one).

Supported platforms: macOS and Linux on x64/arm64. For anything else, install
from source: `go install github.com/hoophq/fence/cmd/fence@latest`.

Full docs: https://github.com/hoophq/fence
