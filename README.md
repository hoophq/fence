# 🐕 Leash

**Guardrails for AI coding agents.** Leash inspects every command your agent
tries to run and stops the catastrophic ones — recursive deletes of your home
directory, secret exfiltration, `curl | sh`, force-pushes — *before* they
execute.

It understands commands **semantically** (a real shell parser, not a list of
banned strings), so it isn't fooled by `rm -fr` vs `rm -rf`, by `sudo`, or by
`$HOME` vs `~` — and it doesn't false-positive on the everyday `rm -rf
node_modules` you run twenty times a day.

```console
$ leash check 'rm -rf ~'
  DENY   rm -rf ~
  rule: destructive-delete-sensitive (critical)
  Leash blocked a recursive delete aimed at a sensitive location (home,
  root, or a system path). This is almost never what you want from an agent.

$ leash check 'rm -rf node_modules'
 ALLOW   rm -rf node_modules
```

---

## Why Leash

AI agents run with *your* permissions. They read files, run shell commands,
install packages, and make network requests — and a confused agent (or a
prompt-injected one) can do real damage. There are already public incidents of
agents running `rm -rf ~`, and of prompt injection turning a coding agent into
an exfiltration tool.

Most "guardrail" hooks floating around are denylists of command substrings.
Those are trivially evaded (`rm -fr`, `rm -r -f`, a script written then run) and
they cry wolf on safe commands until you uninstall them. Leash is built
differently:

- **Semantic, not substring.** Commands are parsed into a shell AST and judged
  by *intent*. `rm -rf ~`, `rm -fr ~`, `rm -r -f ~`, and `sudo rm -rf $HOME` are
  all recognised as the same dangerous operation.
- **Near-zero false positives.** Only unambiguous catastrophes are blocked. For
  anything you might legitimately mean, Leash asks instead of blocking. Routine
  operations are never touched.
- **Agent-neutral.** One portable rulepack format. Claude Code today; Codex,
  Cursor, and Gemini CLI adapters next — the same rules, everywhere.
- **Fails open.** If Leash ever can't parse an input or hits an error, the
  command proceeds. A guardrail must never brick the agent it protects.

---

## Install

### Homebrew (macOS)

```bash
brew install hoophq/tap/leash
```

### npx (macOS / Linux · x64 / arm64)

```bash
npx @hoophq/leash check 'rm -rf ~'
npx @hoophq/leash init            # wire it into Claude Code
```

> Both install a real native binary and land with the first tagged release.
> Until then, install from source:

### From source

```bash
go install github.com/hoophq/leash/cmd/leash@latest
```

or clone and build:

```bash
git clone https://github.com/hoophq/leash && cd leash
make build      # -> ./dist/leash
```

---

## Quickstart (Claude Code)

```bash
# From your project root: add the PreToolUse hook to .claude/settings.json
leash init

# or install it globally for every project:
leash init --global
```

Start a new Claude Code session and Leash is live. Try asking the agent to do
something reckless — it'll be stopped or asked to confirm.

To see what Leash *would* decide, without an agent:

```bash
leash check 'curl https://get.example.sh | sh'   # ASK
leash check --path ~/.ssh/id_rsa                  # ASK (writing key material)
leash check 'git push --force'                    # ASK
leash check 'git reset --hard HEAD~3'             # ASK
```

---

## How it works

```
   agent tool call                          decision
        │                                       ▲
        ▼                                       │
  ┌───────────┐   Action    ┌────────────┐   ┌──────────┐
  │  adapter  │ ──────────▶ │   engine   │ ─▶│ rulepack │
  │ (per-agent)│  (neutral) │ (AST facts)│   │  (yaml)  │
  └───────────┘             └────────────┘   └──────────┘
```

1. An **adapter** translates an agent's tool call into a neutral `Action`
   (`shell`, `file_write`, `file_read`, `net_fetch`). Claude Code's `PreToolUse`
   payload is the first adapter.
2. The **engine** analyses the action. Shell commands go through a real parser
   that extracts semantic facts (recursive delete + where it points, force push,
   `curl | sh`, destructive git, …).
3. **Rules** in a rulepack match those facts and apply an effect. When several
   match, the most severe wins (`deny` > `ask` > `warn` > `allow`).

The engine and rulepacks know nothing about any specific agent — which is what
makes a rulepack portable across agents.

---

## Rulepacks

The shipped **recommended** pack is embedded in the binary and always active.
Layer your own rules on top by dropping a `./.leash.yaml` in your project (it's
auto-discovered) or passing `--rules <file>`.

```yaml
name: my-rules
default: allow

rules:
  - id: no-terraform-destroy
    description: terraform destroy tears down real infrastructure
    severity: critical
    effect: deny                    # allow | warn | ask | deny
    message: Blocked. Run destroys from a reviewed pipeline.
    match:
      shell:
        command_in: [terraform]
      regex: '\bterraform\b.*\bdestroy\b'

  - id: protect-prod-env
    description: Editing a production env file
    effect: ask
    match:
      tool: [file_write]
      path_glob:
        - "**/.env.production"
```

**Match conditions** (all set conditions must hold — logical AND):

| Field | Applies to | Meaning |
|---|---|---|
| `tool` | any | restrict to action kinds: `shell`, `file_write`, `file_read`, `net_fetch` |
| `shell.recursive_delete` | shell | an `rm` with a recursive flag |
| `shell.delete_target` | shell | `sensitive` \| `outside_workspace` \| `any` |
| `shell.chmod_world_writable` | shell | a chmod granting world-write (`777`, `o+w`, …) |
| `shell.chmod_target` | shell | `sensitive` \| `outside_workspace` \| `any` (of a world-writable chmod) |
| `shell.force_push` | shell | `git push --force` (not `--force-with-lease`) |
| `shell.history_rewrite` | shell | `git reset --hard`, `git clean -fd` |
| `shell.pipe_to_shell` | shell | a network fetch piped into a shell/interpreter |
| `shell.secret_exfil` | shell | a secret read + network egress: `high` (keys/cloud creds) \| `any` (incl. `.env`) |
| `shell.command_in` | shell | any of these commands is invoked |
| `path_glob` | file | doublestar globs (`~` is expanded) |
| `url_regex` | net | regexp against the URL |
| `regex` | any | raw fallback for patterns not yet modelled |

See [`examples/custom-rules.yaml`](examples/custom-rules.yaml).

### Overriding a rule's effect

Retune any rule by id — including the built-in recommended ones — without redefining it. Only the **effect** changes; the rule's match, severity, and message stay as-is.

```yaml
overrides:
  destructive-delete-sensitive: ask    # soften a deny -> ask
  git-force-push: deny                 # strengthen an ask -> deny
  pipe-to-shell-from-network: allow    # neutralize (effectively disable)
```

So to make a recommended rule stricter or looser, this is the one-liner — no need to copy the rule. An override aimed at an unknown id is reported on stderr and ignored (it never breaks the agent).

---

## What Leash is — and isn't

Leash is **local self-protection**: it lives in your config, and you can edit or
remove it. That's exactly right for protecting *yourself* from an agent's
mistakes. It is honestly **not** a compliance control — a determined user (or an
agent running as you) can disable anything on a machine they fully control.

If you need guardrails your developers **can't** turn off — centrally managed
policy enforced across a whole fleet, with approval workflows, aggregated audit
logs, and brokered access to production systems — that's a different trust model.
That's what **[hoop.dev](https://hoop.dev)** does. Same idea, enforced where the
developer can't override it.

---

## Roadmap

- [ ] Adapters: OpenAI Codex CLI, Cursor, Gemini CLI
- [x] Secret-file → network exfiltration detector (deny keys/cloud creds, ask `.env`)
- [ ] More semantic detectors: `chmod 777`, `dd`/`mkfs` to devices,
      package-manager `postinstall` hooks
- [ ] A shareable rulepack registry (`leash add <pack>`)
- [ ] One-line installers (Homebrew, npx)

---

## License

MIT © [hoop.dev](https://hoop.dev). Built by the team behind hoop.
