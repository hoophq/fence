# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
**[Security → Report a vulnerability](https://github.com/hoophq/fence/security/advisories/new)**.
Please don't open a public issue for anything you believe is exploitable —
give us a chance to ship a fix first. We'll acknowledge within a few days
and keep you in the loop through the fix and disclosure.

Only the latest release is supported with fixes.

## What counts as a vulnerability here

Fence is deliberately **fail-open** and **dev-owned** — the
[threat model](docs/threat-model.md) spells out what it does and doesn't
defend against. That line decides what belongs in the private channel:

**Report privately (a vulnerability):**

- Anything that makes Fence *itself* a risk: code execution or memory
  unsafety triggered by parsing a malicious rulepack, registry index, or
  hook payload.
- The registry client escaping its boundaries — path traversal from an
  index entry, a checksum-verification bypass, writes outside `~/.fence`.
- The hook emitting an explicit allow decision, or otherwise *weakening*
  the agent's own permission system (Fence must only ever tighten).
- Secrets handled by Fence ending up somewhere they shouldn't.

**Open a public issue instead (not a vulnerability):**

- A dangerous command Fence didn't catch — that's a
  [detector gap](https://github.com/hoophq/fence/issues/new?template=detector-gap.yml),
  unless it's one of the evasion paths the threat model already accepts.
- Fail-open behavior itself (a crash making Fence allow a call is by
  design — though the *crash* is a bug we want fixed).
- Anything that requires the developer to disable Fence on their own
  machine. Dev-owned means that's always possible; it's not a bypass.

When you're not sure which side of the line something falls on, use the
private channel — worst case we'll ask you to file it publicly.
