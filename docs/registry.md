# The rulepack registry

Rulepacks are shareable guardrails: one YAML file that layers on the built-in
`recommended` pack. The registry is how they travel — publish a pack once,
and anyone gets it with one command:

```bash
leash search terraform          # discover
leash add terraform-safety      # install — active on the next tool call
```

This registry is deliberately **not** a package manager for code: a pack is
declarative YAML rules, never executable content. (It is also unrelated to the
`install-from-non-registry-source` rule, which is about npm/pip *package*
registries.)

## Consuming packs

```bash
leash search [query]        # list published packs (name, description, tags)
leash add <pack>            # fetch, verify checksum, install
leash update [pack...]      # re-install whatever the registry has newer
leash remove <pack>         # uninstall
```

Installed packs live in `~/.leash/packs/` and are **globally active**: every
`leash check` and every agent hook evaluation layers them on the recommended
pack, in this order:

```
recommended  <  installed packs (a-z)  <  ./.leash.yaml  <  --rules <file>
```

Later packs win where they overlap (`overrides`, `default`), and when several
rules match one action the most severe effect still wins. Nothing here weakens
the recommended pack unless a pack you chose to install explicitly overrides
one of its rules — and `leash check` will name the pack that did
(`rule: … · from <pack>`).

A broken installed pack can never take your protection down: it is skipped
with a stderr warning and every other pack keeps working.

### Integrity — what the checksum does and doesn't do

`leash add` and `leash update` verify each pack's **sha256 against the index**
before anything touches disk, and validate that it parses as a rulepack. That
protects against transport corruption and a tampered pack file.

It does **not** make the registry itself trustworthy: whoever controls the
index controls the checksums in it. The default registry lives in the Leash
repo and changes only by reviewed pull request; if you point `--registry`
somewhere else, you are trusting that source the same way you trust any
`--rules` file you pass by hand. Packs are inert YAML either way — the blast
radius of a malicious pack is bad *rules* (e.g. silencing an ask), not code
execution. Once installed, packs are yours: dev-owned files you can read,
edit, or delete — in keeping with what Leash is (local self-protection, not
central enforcement).

## Composing packs with `extends:`

Any rulepack — including `./.leash.yaml` — can pull other packs in
underneath itself:

```yaml
# .leash.yaml
name: my-project
extends:
  - terraform-safety        # an installed pack, by name
  - ./team/base-rules.yaml  # or a file, relative to this file
overrides:
  terraform-destroy: ask    # this file has the last word over what it extends
```

Semantics:

- **A bare name** resolves to an installed pack (`~/.leash/packs/<name>.yaml`);
  a reference with a `/` or a `.yaml`/`.yml` suffix is a file path, resolved
  relative to the file that declares it.
- **Extended packs layer below the extending file**, so its `rules`,
  `overrides`, and `default` win.
- **Missing target?** Leash warns with the fix (`run: leash add <name>`),
  skips that reference, and keeps everything else running.
- **Cycles and diamonds** are handled: a pack reached twice loads once, and a
  circular reference is skipped with a warning.

Committing a `.leash.yaml` with `extends:` is how a team shares a baseline:
teammates run `leash add <pack>` once, and the project file pins the
composition from then on.

## Authoring a pack

A pack is a normal rulepack file — same schema as `.leash.yaml`
([full reference](rules.md)):

```yaml
name: terraform-safety        # must match its registry name
rules:
  - id: terraform-destroy    # prefix ids with your pack's theme: no collisions
    description: terraform destroy tears down live infrastructure
    severity: critical
    effect: deny
    message: Blocked by terraform-safety. Run it yourself if you mean it.
    match:
      shell:
        command_in: [terraform, tofu]
      regex: '\b(terraform|tofu)\b(\s+-\S+)*\s+destroy\b'
```

Guidelines that keep packs worth installing:

- **Hold the false-positive line.** `deny` only what is almost never
  intentional; prefer `ask` for anything a developer might mean; leave the
  everyday untouched. A pack that cries wolf gets removed.
- **Prefix rule ids** with the pack's theme (`terraform-*`, `k8s-*`) so two
  packs never collide. Colliding ids still work, but every engine build warns.
- **Write the `message` for the person interrupted by it** — say why, and
  what to do instead.

Test the pack locally before publishing — no registry involved:

```bash
leash check --rules ./my-pack.yaml 'terraform destroy'    # should catch
leash check --rules ./my-pack.yaml 'terraform plan'       # must stay ALLOW
```

## Publishing to the registry

The registry is static files in the Leash repo — publishing is a pull request:

1. Fork [`hoophq/leash`](https://github.com/hoophq/leash) and add your pack as
   `registry/packs/<name>.yaml`.
2. Compute its checksum: `shasum -a 256 registry/packs/<name>.yaml`
3. Add an entry to `registry/index.yaml`:

   ```yaml
   - name: <name>
     description: One line that earns the install
     version: "1.0.0"
     sha256: <the checksum>
     path: packs/<name>.yaml
     tags: [a, few, keywords]
     maintainer: <you>
   ```

4. Open the PR. CI re-verifies every checksum and loads every pack against the
   recommended pack (no id collisions, no warnings) — a stale sha256 fails the
   build, not someone's install.

Ship an update by editing the pack, bumping `version`, and recomputing
`sha256`. Users pick it up with `leash update`. The index is read live off
`main`, so a merged PR is published — no release needed.

## Self-hosting a registry

`--registry` points the commands at any index — an HTTPS URL or a local path:

```bash
leash add my-pack --registry https://example.com/leash/index.yaml
leash add my-pack --registry ./my-registry/index.yaml    # e.g. a checkout
```

An index is just `index.yaml` (`schema: 1`, a `packs:` list as above) with
pack `path`s resolved relative to it. A git repo, an S3 bucket, or a directory
all work. Air-gapped teams can vendor the whole registry and point at the
checkout.

---

See [Rules](rules.md) for the full match reference, and
[CLI](cli.md) for every command and flag.
