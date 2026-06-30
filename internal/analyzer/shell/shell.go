// Package shell performs semantic analysis of shell commands.
//
// Unlike substring or regexp denylists, the analyzer parses the command into a
// real shell AST (via mvdan.cc/sh) and reasons about *intent*. That means
// `rm -rf ~`, `rm -fr ~`, `rm -f -r ~` and `sudo rm -rf $HOME` are all
// recognised as the same dangerous operation, while `rm -rf node_modules` is
// correctly treated as harmless. Keeping false positives near zero is the whole
// point: a guardrail that cries wolf gets uninstalled.
package shell

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// DeleteTarget classifies where a recursive delete is pointed.
type DeleteTarget int

const (
	// TargetNone means no delete target was found.
	TargetNone DeleteTarget = iota
	// TargetCwdRelative is a path inside the current workspace (e.g. ./dist,
	// node_modules, *). These are everyday operations and must not be blocked.
	TargetCwdRelative
	// TargetOutsideWorkspace is a path that escapes the workspace but is not a
	// well-known sensitive root (e.g. ~/.cache/foo, /tmp/x, ../sibling).
	TargetOutsideWorkspace
	// TargetSensitive is a home/root/system root (~, $HOME, /, /*). Deleting
	// these recursively is almost never intentional from an agent.
	TargetSensitive
)

func (t DeleteTarget) String() string {
	switch t {
	case TargetCwdRelative:
		return "cwd_relative"
	case TargetOutsideWorkspace:
		return "outside_workspace"
	case TargetSensitive:
		return "sensitive"
	default:
		return "none"
	}
}

// SecretConfidence rates how likely a referenced path holds secret material.
type SecretConfidence int

const (
	// SecretNone means no secret material was referenced.
	SecretNone SecretConfidence = iota
	// SecretEnv is a .env-style file: often holds secrets, but is also routinely
	// read by legitimate tooling, so it warrants a prompt rather than a block.
	SecretEnv
	// SecretHigh is private-key or cloud-credential material; exfiltrating it is
	// almost never legitimate.
	SecretHigh
)

func (c SecretConfidence) String() string {
	switch c {
	case SecretEnv:
		return "env"
	case SecretHigh:
		return "high"
	default:
		return "none"
	}
}

// Analysis is the set of semantic facts extracted from a shell command. Rules
// match against these facts rather than against raw text.
type Analysis struct {
	// Parsed is false when the command could not be parsed as shell. Callers
	// should treat an unparsed command conservatively (the engine falls back to
	// regexp rules and the default effect).
	Parsed bool

	// Commands is the de-duplicated set of effective command names invoked,
	// after unwrapping prefixes like sudo/env/command.
	Commands []string

	// RecursiveDelete is true when an `rm` invocation carries a recursive flag.
	RecursiveDelete bool
	// Forced is true when an `rm` invocation carries -f/--force.
	Forced bool
	// DeleteTarget is the most severe target classification across all rm
	// operands in the command.
	DeleteTarget DeleteTarget

	// ForcePush is true for `git push --force`/`-f` (but not --force-with-lease).
	ForcePush bool
	// HistoryRewrite is true for irreversibly destructive git operations such as
	// `git reset --hard` and `git clean -fd`.
	HistoryRewrite bool

	// PipeToShellFromNet is true when a network fetch is piped straight into a
	// shell or interpreter (curl ... | sh).
	PipeToShellFromNet bool

	// SecretRead is the highest-confidence secret reference seen in the command
	// (e.g. a private key, cloud credential, or .env file being read).
	SecretRead SecretConfidence
	// NetEgress is true when the command routes data out to the network: a
	// curl/wget upload, nc connecting out, or a bash /dev/tcp redirect.
	NetEgress bool

	// Raw is the original command text.
	Raw string
}

// Has reports whether the command invokes any of the named commands.
func (a Analysis) Has(names ...string) bool {
	for _, want := range names {
		for _, got := range a.Commands {
			if got == want {
				return true
			}
		}
	}
	return false
}

var (
	commandPrefixes = map[string]bool{
		"sudo": true, "doas": true, "env": true, "command": true,
		"nice": true, "ionice": true, "nohup": true, "stdbuf": true,
	}
	networkFetchers   = map[string]bool{"curl": true, "wget": true, "fetch": true, "http": true, "https": true, "httpie": true}
	shellInterpreters = map[string]bool{
		"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
		"python": true, "python3": true, "node": true, "nodejs": true, "ruby": true,
		"perl": true, "php": true,
	}
)

// Analyze parses command and extracts semantic facts. cwd is used to decide
// whether a delete target is inside the workspace; if empty, paths that are not
// obviously sensitive are treated as outside the workspace.
func Analyze(command, cwd string) Analysis {
	a := Analysis{Raw: command}

	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		a.Parsed = false
		return a
	}
	a.Parsed = true

	seen := map[string]bool{}

	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			// Scan every word for secret references and raw /dev/tcp egress
			// targets, independent of the command name.
			for _, w := range n.Args {
				txt, _ := wordToString(w)
				if c := classifySecret(txt); c > a.SecretRead {
					a.SecretRead = c
				}
				if isDevNet(txt) {
					a.NetEgress = true
				}
			}
			name, args := resolveCommand(n)
			if name == "" {
				return true
			}
			if !seen[name] {
				seen[name] = true
				a.Commands = append(a.Commands, name)
			}
			a.inspectCommand(name, args, cwd)
			if isNetEgressCommand(name, args) {
				a.NetEgress = true
			}
		case *syntax.Redirect:
			// `cat secret > /dev/tcp/host/port` opens a network socket.
			if n.Word != nil {
				if txt, _ := wordToString(n.Word); isDevNet(txt) {
					a.NetEgress = true
				}
			}
		case *syntax.BinaryCmd:
			if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
				if isNetToShellPipe(n) {
					a.PipeToShellFromNet = true
				}
			}
		}
		return true
	})

	return a
}

func (a *Analysis) inspectCommand(name string, args []string, cwd string) {
	switch name {
	case "rm":
		recursive, forced, operands := parseRmFlags(args)
		if recursive {
			a.RecursiveDelete = true
		}
		if forced {
			a.Forced = true
		}
		if recursive {
			for _, op := range operands {
				if t := classifyTarget(op, cwd); t > a.DeleteTarget {
					a.DeleteTarget = t
				}
			}
		}
	case "git":
		a.inspectGit(args)
	}
}

func (a *Analysis) inspectGit(args []string) {
	// Find the git subcommand (first non-flag, non-global-option token).
	sub := ""
	rest := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if sub == "" {
			if strings.HasPrefix(arg, "-") {
				continue // global option like -C <path>; ignored for v0
			}
			sub = arg
			rest = args[i+1:]
			break
		}
	}
	switch sub {
	case "push":
		for _, f := range rest {
			if f == "--force" || f == "-f" {
				a.ForcePush = true
			}
		}
	case "reset":
		for _, f := range rest {
			if f == "--hard" {
				a.HistoryRewrite = true
			}
		}
	case "clean":
		forced, removesDirs := false, false
		for _, f := range rest {
			if strings.HasPrefix(f, "--") {
				switch f {
				case "--force":
					forced = true
				}
				continue
			}
			if strings.HasPrefix(f, "-") {
				for _, c := range f[1:] {
					switch c {
					case 'f':
						forced = true
					case 'd', 'x', 'X':
						removesDirs = true
					}
				}
			}
		}
		if forced && removesDirs {
			a.HistoryRewrite = true
		}
	}
}

// resolveCommand returns the effective command name and its arguments, peeling
// off prefixes like `sudo`, `env FOO=bar`, and `command`.
func resolveCommand(call *syntax.CallExpr) (string, []string) {
	words := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		s, _ := wordToString(w)
		words = append(words, s)
	}
	for len(words) > 0 {
		head := words[0]
		// env-style leading VAR=value assignments.
		if strings.Contains(head, "=") && !strings.HasPrefix(head, "-") && isAssignment(head) {
			words = words[1:]
			continue
		}
		if commandPrefixes[head] {
			words = words[1:]
			// skip options that belong to the prefix (e.g. sudo -u user)
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				words = words[1:]
			}
			continue
		}
		break
	}
	if len(words) == 0 {
		return "", nil
	}
	return baseName(words[0]), words[1:]
}

func isAssignment(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range s[:eq] {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func baseName(cmd string) string {
	// Normalise an absolute/relative path to its base (/bin/rm -> rm).
	if i := strings.LastIndexByte(cmd, '/'); i >= 0 {
		return cmd[i+1:]
	}
	return cmd
}

// parseRmFlags splits rm arguments into flags and operands, handling combined
// short flags (-rf), separate flags (-r -f), long flags, and the -- terminator.
func parseRmFlags(args []string) (recursive, forced bool, operands []string) {
	flagsDone := false
	for _, arg := range args {
		switch {
		case flagsDone:
			operands = append(operands, arg)
		case arg == "--":
			flagsDone = true
		case strings.HasPrefix(arg, "--"):
			switch arg {
			case "--recursive":
				recursive = true
			case "--force":
				forced = true
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			for _, c := range arg[1:] {
				switch c {
				case 'r', 'R':
					recursive = true
				case 'f':
					forced = true
				}
			}
		default:
			operands = append(operands, arg)
		}
	}
	return recursive, forced, operands
}

// classifyTarget decides how dangerous a single rm operand is.
func classifyTarget(target, cwd string) DeleteTarget {
	t := strings.TrimSpace(target)
	if t == "" {
		return TargetNone
	}
	// Strip a single trailing slash for comparison, but remember it existed.
	bare := strings.TrimSuffix(t, "/")

	// Root and "everything under root".
	switch bare {
	case "/", "/*":
		return TargetSensitive
	}
	if t == "/" || t == "/*" {
		return TargetSensitive
	}

	// Home root, in tilde or $HOME form, optionally with a trailing /* .
	homeRoots := map[string]bool{
		"~": true, "~/*": true,
		"$HOME": true, "${HOME}": true, "$HOME/*": true, "${HOME}/*": true,
		"$home": true,
	}
	if homeRoots[bare] || homeRoots[t] {
		return TargetSensitive
	}

	// A path *under* home (e.g. ~/.cache, $HOME/work) — escapes the workspace.
	if strings.HasPrefix(t, "~/") || strings.HasPrefix(t, "$HOME/") || strings.HasPrefix(t, "${HOME}/") {
		return TargetOutsideWorkspace
	}

	// Absolute paths: inside cwd is workspace-relative, otherwise outside.
	if strings.HasPrefix(t, "/") {
		if cwd != "" {
			if rel, err := filepath.Rel(cwd, t); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return TargetCwdRelative
			}
		}
		return TargetOutsideWorkspace
	}

	// Unresolved variable expansion we can't reason about — be cautious but not
	// alarmist: ask rather than deny.
	if strings.Contains(t, "$") {
		return TargetOutsideWorkspace
	}

	// Escaping the workspace upward.
	if t == ".." || strings.HasPrefix(t, "../") {
		return TargetOutsideWorkspace
	}

	// Everything else (., ./build, node_modules, *, dist/) is workspace-local.
	return TargetCwdRelative
}

// isNetToShellPipe reports whether a pipeline routes a network fetcher into a
// shell interpreter, e.g. `curl https://x | sh`. The fetcher and the shell need
// not be adjacent: `curl https://x | tail -n5 | sh` is caught too, because
// inserting a passthrough filter is a common way to dodge naive curl|sh checks.
func isNetToShellPipe(pipe *syntax.BinaryCmd) bool {
	stages := pipelineStages(pipe.X)
	stages = append(stages, pipelineStages(pipe.Y)...)

	seenNet := false
	for _, name := range stages {
		if seenNet && shellInterpreters[name] {
			return true
		}
		if networkFetchers[name] {
			seenNet = true
		}
	}
	return false
}

// pipelineStages flattens a pipe chain into the ordered command names of its
// stages. Non-pipe statements contribute a single stage (their command name, or
// "" if it has none, to preserve ordering).
func pipelineStages(stmt *syntax.Stmt) []string {
	if stmt == nil {
		return nil
	}
	if bc, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && (bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll) {
		return append(pipelineStages(bc.X), pipelineStages(bc.Y)...)
	}
	return []string{commandNameOfStmt(stmt)}
}

func commandNameOfStmt(stmt *syntax.Stmt) string {
	if stmt == nil {
		return ""
	}
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
		name, _ := resolveCommand(call)
		return name
	}
	return ""
}

// classifySecret rates a single command word that may reference secret
// material. It understands curl's "@file" data syntax, ~ / $HOME prefixes, and
// flags that glue the path on with '=' (e.g. --post-file=.env).
func classifySecret(word string) SecretConfidence {
	s := strings.TrimSpace(word)
	if s == "" {
		return SecretNone
	}
	best := classifySecretPath(s)
	if i := strings.LastIndexByte(s, '='); i >= 0 {
		if c := classifySecretPath(s[i+1:]); c > best {
			best = c
		}
	}
	return best
}

func classifySecretPath(s string) SecretConfidence {
	s = strings.TrimPrefix(strings.TrimSpace(s), "@") // curl --data @file / -T @file
	if s == "" {
		return SecretNone
	}
	base := s
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if strings.HasSuffix(base, ".pub") { // public keys are not secret
		return SecretNone
	}
	switch base {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return SecretHigh
	}
	if strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") {
		return SecretHigh
	}
	if strings.Contains(s, ".aws/credentials") ||
		strings.Contains(s, ".config/gcloud") ||
		strings.Contains(s, ".kube/config") {
		return SecretHigh
	}
	if strings.Contains(s, ".ssh/") && strings.HasPrefix(base, "id_") {
		return SecretHigh
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return SecretEnv
	}
	return SecretNone
}

// isNetEgressCommand reports whether a command sends local data out to the
// network. It is deliberately tight: curl/wget only count when they carry an
// upload flag (a plain GET does not exfiltrate anything), and nc only when it is
// connecting out rather than listening.
func isNetEgressCommand(name string, args []string) bool {
	switch name {
	case "curl", "wget":
		return hasUploadFlag(args)
	case "nc", "ncat", "netcat":
		return !hasListenFlag(args)
	}
	return false
}

func hasUploadFlag(args []string) bool {
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--data"), // curl --data, --data-binary
			strings.HasPrefix(a, "--form"), // curl --form, --form-string
			strings.HasPrefix(a, "--post"), // wget --post-data, --post-file
			strings.HasPrefix(a, "--body"), // wget --body-data, --body-file
			a == "--upload-file":
			return true
		case len(a) >= 2 && a[0] == '-' && a[1] != '-':
			// Short flags, optionally glued to a value (-d@file, -Tfile). curl's
			// -d/-F/-T carry the payload, so they lead the option string.
			switch a[1] {
			case 'd', 'F', 'T':
				return true
			}
		}
	}
	return false
}

func hasListenFlag(args []string) bool {
	for _, a := range args {
		if a == "--listen" {
			return true
		}
		if len(a) >= 2 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a, 'l') {
			return true
		}
	}
	return false
}

// isDevNet reports whether a word is a bash /dev/tcp or /dev/udp pseudo-device,
// used to open a raw network connection (e.g. `cat secret > /dev/tcp/host/port`).
func isDevNet(word string) bool {
	return strings.Contains(word, "/dev/tcp/") || strings.Contains(word, "/dev/udp/")
}

// wordToString reconstructs the textual value of a word. Parameter expansions
// are rendered in $NAME form (so $HOME stays recognisable) and the second
// return value reports whether any expansion was present.
func wordToString(w *syntax.Word) (string, bool) {
	var b strings.Builder
	expanded := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.Lit:
					b.WriteString(ip.Value)
				case *syntax.ParamExp:
					expanded = true
					if ip.Param != nil {
						b.WriteString("$" + ip.Param.Value)
					}
				}
			}
		case *syntax.ParamExp:
			expanded = true
			if p.Param != nil {
				b.WriteString("$" + p.Param.Value)
			}
		default:
			expanded = true
		}
	}
	return b.String(), expanded
}
