# Rules

Fence decides what to do with a command by matching it against **rules**. This
page covers how rulepacks layer, how to write your own, the full set of match
conditions, and how to retune the built-in rules.

## How rulepacks layer

- The embedded **`recommended`** pack is always active.
- Packs installed with **[`fence add`](registry.md)** layer next — active in
  every project, no setup.
- Drop a **`./.fence.yaml`** in your project (auto-discovered) or pass
  **`--rules <file>`** to layer your own rules on top.
- When several rules match one command, the **most severe effect wins**:
  `deny` > `ask` > `warn` > `allow`. When nothing matches, the default is
  `allow`.

```bash
fence check 'rm -rf ~'                 # against the recommended pack
fence check --rules ./team.yaml 'rm -rf ~'   # plus your pack
```

## Anatomy of a rule

```yaml
schema: 1           # rulepack format generation (optional; absent means 1)
name: my-rules      # optional label
default: allow      # effect when nothing matches (default: allow)

rules:
  - id: no-terraform-destroy          # required, unique
    description: terraform destroy tears down real infrastructure
    severity: critical                # info | low | medium | high | critical (display only)
    effect: deny                      # allow | warn | ask | deny
    message: Blocked. Run destroys from a reviewed pipeline.
    match:                            # all set conditions must hold (logical AND)
      shell:
        command_in: [terraform]
      regex: '\bterraform\b.*\bdestroy\b'
```

An empty `match` never fires (rules must be specific). A `match` with several
conditions requires **all** of them.

## Match conditions

### Any action

| Field | Meaning |
|---|---|
| `tool` | Restrict to action kinds: `shell`, `file_write`, `file_read`, `net_fetch`. |
| `regex` | Raw regexp against the command / path / URL. A fallback for patterns not yet modelled semantically — prefer the structured matchers below. |

### Shell (`shell:`)

Matched against semantic facts from the shell parser — not the raw text.

| Field | Fires on |
|---|---|
| `recursive_delete` | an `rm` with a recursive flag (`-r`, `-R`, `--recursive`) |
| `delete_target` | where a recursive delete points: `sensitive` \| `outside_workspace` \| `any` |
| `chmod_world_writable` | a chmod granting write to "others" (`777`, `666`, `o+w`, `a+w`) |
| `chmod_target` | where a world-writable chmod points: `sensitive` \| `outside_workspace` \| `any` |
| `block_device_write` | `dd of=/dev/sdX`, `mkfs` on a device, or a redirect to a raw disk |
| `force_push` | `git push --force` / `-f` (but **not** `--force-with-lease`) |
| `history_rewrite` | `git reset --hard`, `git clean -fd` |
| `pipe_to_shell` | a network fetch piped into a shell/interpreter (`curl … \| sh`) |
| `fork_bomb` | a function that pipes into itself in the background (`:(){ :\|:& };:`) |
| `non_registry_install` | installing a package from a git spec, URL, or local archive |
| `persistence_install` | a crontab install, `launchctl load`/`bootstrap`, or `systemctl enable` |
| `secret_exfil` | a secret is read **and** routed to the network: `high` (keys / cloud creds) \| `any` (incl. `.env`) |
| `secret_read` | a content-dumping command reads a secret into stdout: `high` \| `any` |
| `command_in` | any of the named commands is invoked |

### Files (`file_write` / `file_read`)

| Field | Fires on |
|---|---|
| `path_glob` | doublestar globs against the path — `~` is expanded, `**` matches any depth |
| `manifest_hook` | a `file_write` whose content adds an install lifecycle hook (a `preinstall`/`install`/`postinstall` script in `package.json`, or a `cmdclass` in `setup.py`) |

### Network (`net_fetch`)

| Field | Fires on |
|---|---|
| `url_regex` | a regexp against the fetched URL |

## Extending another pack

Any rulepack can pull other packs in underneath itself with `extends:` — an
installed pack by name, or a file by path (relative to the file declaring it):

```yaml
extends:
  - terraform-safety        # installed with `fence add`
  - ./team/base-rules.yaml  # a file next to this one
overrides:
  terraform-destroy: ask    # this file wins over what it extends
```

The extending file layers **on top** of what it pulls in, a pack reached twice
loads once, and a missing target degrades to a warning with the fix
(`run: fence add <name>`) — it never takes the engine down.
**→ [Composition semantics, in depth](registry.md)**

## Overriding a built-in rule's effect

Retune any rule by id — including the recommended ones — **without redefining
it**. Only the effect changes; the rule's match, severity, and message stay
as-is.

```yaml
overrides:
  destructive-delete-sensitive: ask   # soften a deny -> ask
  git-force-push: deny                # strengthen an ask -> deny
  pipe-to-shell-from-network: allow   # neutralize (effectively disable)
```

An override aimed at an unknown id is reported on stderr and ignored — it never
breaks the agent.

## Schema version & compatibility

The rulepack format is a public contract, frozen at Fence 1.0. A pack declares
the format generation it requires with `schema:`; a missing marker means `1`,
so every pack published before the marker existed stays valid.

**Frozen for all of Fence 1.x** — these keep their exact meaning:

- every field above (`schema`, `name`, `default`, `extends`, `overrides`,
  `rules` and the rule fields),
- every match condition name and what it fires on,
- effect resolution (`deny` > `ask` > `warn` > `allow`, most severe wins),
- `extends:` semantics (extender wins, dedup, missing target degrades),
- the layering order (`recommended` < installed < `./.fence.yaml` < `--rules`).

**What may evolve:** minor releases may *add* match conditions and fields.
When an addition is something a rule can depend on (a new match condition),
the schema generation bumps, and a pack using it declares the new number —
e.g. `schema: 2`.

A pack that requires a newer schema than the binary understands is **refused
whole**, never half-read: from an ambient source (an installed pack,
`./.fence.yaml`) it is skipped with an "upgrade fence" warning while every
other pack keeps protecting; named explicitly via `--rules` it is a hard
error. Half-reading is the one thing the loader will never do — a match
condition silently dropped from a rule would make the rule *broader*, the
wrong failure direction for a tool that promises near-zero false positives.

In semver terms: a **patch** never changes the contract, a **minor** may add
vocabulary (bumping the schema generation packs can opt into), and only a
**major** may change or remove the meaning of anything listed above.

## More

See [`examples/custom-rules.yaml`](../examples/custom-rules.yaml) for a worked
example, and [Architecture](architecture.md) for how these facts are produced.
