# Rules

Leash decides what to do with a command by matching it against **rules**. This
page covers how rulepacks layer, how to write your own, the full set of match
conditions, and how to retune the built-in rules.

## How rulepacks layer

- The embedded **`recommended`** pack is always active.
- Drop a **`./.leash.yaml`** in your project (auto-discovered) or pass
  **`--rules <file>`** to layer your own rules on top.
- When several rules match one command, the **most severe effect wins**:
  `deny` > `ask` > `warn` > `allow`. When nothing matches, the default is
  `allow`.

```bash
leash check 'rm -rf ~'                 # against the recommended pack
leash check --rules ./team.yaml 'rm -rf ~'   # plus your pack
```

## Anatomy of a rule

```yaml
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

## More

See [`examples/custom-rules.yaml`](../examples/custom-rules.yaml) for a worked
example, and [Architecture](architecture.md) for how these facts are produced.
