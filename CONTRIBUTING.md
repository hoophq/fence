# Contributing to Fence

Thanks for helping keep AI coding agents behind the fence. Two kinds of
contributions matter most here, and neither requires writing Go:

- **A false-positive report** — Fence blocked or questioned an everyday
  command. This is the single most valuable input the project gets: the
  near-zero-false-positive discipline *is* the product.
  [File one](https://github.com/hoophq/fence/issues/new?template=false-positive.yml)
  with the exact command.
- **A detector gap** — a catastrophe slipped through.
  [File that too](https://github.com/hoophq/fence/issues/new?template=detector-gap.yml)
  (check the [threat model](docs/threat-model.md) first: some evasion paths
  are accepted limits, not gaps).

## Building and testing

Go 1.26, no runtime services. The Makefile has everything:

```bash
make build   # → ./dist/fence
make test    # the gate — CI runs gofmt, go vet, go build, go test
make vet
make fmt
```

Try a rule without an agent:

```bash
fence check 'rm -rf ~'                # prints a DENY/ASK/WARN/ALLOW card
echo '{"cwd":".","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}' \
  | ./dist/fence hook claude-code    # exercise the hook directly
```

## The two conventions every detector PR must follow

**1. Semantic, not substring.** Detection means adding a fact to the shell
analyzer (`internal/analyzer/shell`) and a `Match` predicate in
`internal/policy` — never a substring or regex denylist. A grep for `rm -rf`
is dodged by `rm -fr`; a parsed AST is not. A rule's `regex` field is a
fallback for patterns not yet modelled, never the primary mechanism.

**2. Every detector ships a table-driven test that pins the catch AND the
safe cases.** The safe cases are the point: `rm -rf node_modules`,
`rm -rf *`, `git push --force-with-lease` must stay ALLOW, and the test is
what keeps them that way. A detector PR without false-positive guards will
be sent back for them. See any `*_test.go` under `internal/analyzer/shell`
or `internal/policy` for the shape.

When picking an effect, the discipline is: **`deny` only what is almost
never intentional; `ask` for anything a developer might mean; leave the
everyday untouched.** When in doubt, ask — a wrong `deny` costs the project
more than a missed catch.

## Other ways in

- **A new agent** = a new adapter under `internal/adapter/<agent>/` that
  maps the agent's tool calls ⇄ the neutral `Action`. The engine and every
  rulepack come along for free. See
  [architecture](docs/architecture.md#extending-fence).
- **A rulepack** — no Go at all: packs are YAML, published by pull request.
  The walkthrough is in [docs/registry.md](docs/registry.md#authoring-a-pack).
  After editing a seed pack, recompute its `sha256` in `registry/index.yaml`
  (the seed test fails CI on a stale one).
- **Docs** — if something surprised you, the fix is probably a docs PR.

## Public contracts

The rulepack schema, the registry index format, and the hook envelope are
frozen contracts ([what that means](docs/rules.md#schema-version--compatibility)).
A PR that changes any of them needs a compatibility story, not just passing
tests.

## Security issues

Don't open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md)
for the private channel and for what counts as a vulnerability in a
deliberately fail-open tool.
