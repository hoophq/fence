# Threat model

What Fence defends against, what it deliberately does not, and the known ways
around it — written down so you don't have to read the source to find out.
The one-line version: **Fence protects you from your agent's mistakes, not
from a determined adversary, and not from yourself.**

## The threat Fence is built for

An AI coding agent runs with your full permissions. The failure mode that
actually happens is not a malicious model — it's a *confused* one: an agent
that misreads a path and deletes the wrong directory, follows a prompt
injection it didn't recognize, pastes your credentials somewhere they don't
belong, or force-pushes over a branch it shouldn't. These commands are
issued plainly, because the agent believes it's doing its job.

That is the gap Fence covers: catastrophic commands *as agents actually emit
them*, judged semantically so flag order, `sudo`/`env` wrappers, and `$HOME`
vs `~` don't matter. The recommended pack covers these classes:

| Class | Examples | Worst effect |
|---|---|---|
| Destructive deletes | `rm -rf ~`, `rm -rf /`, system paths | deny (ask outside the workspace) |
| Disk destruction | `dd of=/dev/disk0`, `mkfs`, raw-device redirects | deny |
| Secret exfiltration | a credential read piped to the network | deny (ask for `.env`-grade) |
| Secrets into context | `cat ~/.ssh/id_rsa`, reading `~/.aws/credentials` | ask |
| Network → shell | `curl … \| sh` | ask |
| Permission bombs | `chmod -R 777` on sensitive paths | deny (ask elsewhere) |
| Supply chain | installs from git specs/URLs/archives, lifecycle-hook injection into `package.json` / `setup.py` | ask |
| Persistence | crontab/launchd/systemd installs, writes to shell rc files, git hooks, agent plists | ask |
| Git history loss | `git push --force`, `git reset --hard` | ask |
| Fork bombs | `:(){ :\|:& };:` and renamed variants | deny |

Most classes **ask** rather than deny — that's the false-positive discipline,
not timidity. Only the almost-never-intentional is blocked outright; for
anything a developer might legitimately mean, Fence puts a human in the loop
and gets out of the way. A guardrail that cries wolf gets uninstalled, and an
uninstalled guardrail protects nobody.

## What Fence deliberately does not protect against

**You.** Fence is dev-owned by design: it lives in your settings, and
`fence uninstall` removes it cleanly. On a machine you control, you can
disable anything — Fence included. If you need guardrails a developer
*can't* turn off — centrally managed, fleet-wide, with approval workflows
and audit — that's a different trust model, and it's what
[hoop.dev](https://hoop.dev/start?utm_source=fence&utm_medium=github&utm_campaign=att-launch-072026)
does.

**A determined, malicious agent.** Fence analyzes commands as written; it is
not a sandbox, a syscall filter, or taint tracking. An adversary who is
*trying* to evade static analysis has unbounded encodings available and will
eventually find one (see below). Against that threat you want OS-level
isolation — containers, VMs, or an agent runtime's own sandbox — with Fence
as the semantic, cross-agent rule layer on top, not the wall.

**Compliance.** No tamper-proofing, no central policy, no audit trail.
Out of scope on purpose; pretending otherwise would be dishonest.

**Anything outside the hooked surface.** Fence sees exactly the tool calls
the agent's hook system reports — for Claude Code: shell commands, file
writes/edits, file reads, and web fetches. Tool calls outside that surface
(an MCP server's tools, say) and processes the agent didn't launch through a
hooked tool are invisible to it.

## Known evasion paths

Every verdict below is real (`fence check` reproduces them). These are
accepted limits, each for the same reason: closing them generically would
either break fail-open or flood developers with false positives — and both
of those end with Fence uninstalled.

**Interpreter one-liners.**
`python3 -c "import shutil; shutil.rmtree(...)"` is **allowed**. The payload
is a string literal in another language; shell-AST analysis ends at the
`python3` invocation. Agents legitimately run interpreter one-liners all day,
so a blanket `ask` would be false-positive rain. *Future work:* an `ask` for
the narrow case of a one-liner whose argument references a secret path.

**Write, then run.**
An agent can `Write` a script and then execute it — `bash payload.sh` is
**allowed**, and the payload's contents are not analyzed at exec time. The
*write* is still screened where it lands somewhere guarded (rc files, git
hooks, launchd agents, credential paths, package manifests — the one
content-aware detector inspects manifest writes for lifecycle-hook
injection). General content analysis of every written file is future
territory, not a promise.

**Obfuscation and indirection.**
`echo cm0gLXJmIH4= | base64 -d | sh` is **allowed** — the pipe-to-shell rule
fires on *network*-sourced pipes, and a local `base64 -d` is everyday
plumbing. `X=rm; $X -rf ~` is **allowed** — AST facts don't resolve runtime
variable values. This is the static-analysis boundary: resolving it would
mean emulating execution.

**Tools Fence doesn't model yet.**
`find / -delete` is **allowed** today. The semantic vocabulary grows one
detector at a time, each shipped with catch-*and*-safe tests. An unmodeled
destructive tool passes silently — when you find one,
[file a detector-gap issue](https://github.com/hoophq/fence/issues/new?template=detector-gap.yml);
those reports are exactly how the vocabulary grows.

**Disarming Fence itself.**
The hooks live in dev-editable settings, so an agent with file-write access
can edit `.claude/settings.json` (an **allowed** write today), and deleting
the binary or `~/.fence` is at worst an *ask*. Two backstops: the agent's own
permission system still governs those writes, and the SessionStart banner
makes absence visible — a session that starts without
`🚧 Fence is guarding this session` isn't guarded. Check for the barrier.

**Fail-open, stated plainly.**
If Fence crashes, can't parse its input, or can't load its rules, the tool
call proceeds and the banner says so. A guardrail that can brick your agent
gets removed within the hour; failing open is the survivable default for a
dev-owned tool. The cost is real: anything that makes Fence error out
disarms it. That trade is deliberate.

## So what happens if the agent tries to evade Fence?

Honestly: a deliberate, structured evasion mostly succeeds. What Fence
changes is the *shape* of the risk — the overwhelmingly common failure is an
agent issuing a catastrophic command in the open, and that is caught, asked
about, or blocked. Evasion requires the agent to already be adversarial
enough to restructure its commands around static analysis — at which point
you are outside Fence's threat and should reach for isolation (a sandbox,
a VM) and centrally enforced policy, with Fence still riding along for the
mistakes.

Found a bypass we don't list here? That's a
[detector-gap report](https://github.com/hoophq/fence/issues/new?template=detector-gap.yml) —
or a [private security report](https://github.com/hoophq/fence/security/advisories/new)
if it's a flaw in Fence itself rather than a scope limit
([SECURITY.md](../SECURITY.md) draws that line). Both are welcome; this page
only stays honest if it stays current.

---

See [Architecture](architecture.md) for how decisions are produced, and
[Rules](rules.md) for the full semantic vocabulary the detectors expose.
