package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hoophq/leash/internal/policy"
	"github.com/hoophq/leash/internal/store"
)

func writeTestFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func evalShell(t *testing.T, e *policy.Engine, command string) policy.Effect {
	t.Helper()
	return e.Evaluate(policy.Action{Kind: policy.ActionShell, Command: command, Cwd: "/w"}).Effect
}

// chdirEmpty moves the test into an empty directory so a real ./.leash.yaml
// can never leak into discovery.
func chdirEmpty(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

func TestBuildEngineNoStoreStillProtects(t *testing.T) {
	chdirEmpty(t)
	e, failed, err := buildEngineWithStore(nil, "", &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if failed != 0 {
		t.Errorf("failed sources = %d, want 0", failed)
	}
	if got := evalShell(t, e, "rm -rf ~"); got != policy.EffectDeny {
		t.Fatalf("rm -rf ~ = %q, want deny", got)
	}
}

func TestBuildEngineInstalledPackFires(t *testing.T) {
	chdirEmpty(t)
	st := store.Open(t.TempDir())
	if _, err := st.Install("team", []byte(`name: team
rules:
  - id: team-marker
    description: test
    effect: deny
    match:
      regex: 'zzz-team-marker'
`)); err != nil {
		t.Fatal(err)
	}

	e, _, err := buildEngineWithStore(st, "", &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got := evalShell(t, e, "echo zzz-team-marker"); got != policy.EffectDeny {
		t.Fatalf("installed pack rule = %q, want deny", got)
	}
	// Recommended still layered underneath.
	if got := evalShell(t, e, "rm -rf ~"); got != policy.EffectDeny {
		t.Fatalf("rm -rf ~ = %q, want deny", got)
	}
}

func TestBuildEngineCorruptInstalledPackDegrades(t *testing.T) {
	chdirEmpty(t)
	st := store.Open(t.TempDir())
	if _, err := st.Install("good", []byte(`name: good
rules:
  - id: good-marker
    description: test
    effect: ask
    match:
      regex: 'zzz-good-marker'
`)); err != nil {
		t.Fatal(err)
	}
	// A pack corrupted on disk after install (Install would reject it).
	writeTestFile(t, st.PackPath("broken"), "rules:\n  - id: x\n    effect: nope\n")

	var stderr bytes.Buffer
	e, failed, err := buildEngineWithStore(st, "", &stderr)
	if err != nil {
		t.Fatalf("a corrupt installed pack must not abort the engine: %v", err)
	}
	if failed != 1 {
		t.Errorf("failed sources = %d, want 1 (the corrupt pack)", failed)
	}
	if !strings.Contains(stderr.String(), "broken") {
		t.Fatalf("want a warning naming the broken pack, got %q", stderr.String())
	}
	// The rest of the protection still stands.
	if got := evalShell(t, e, "rm -rf ~"); got != policy.EffectDeny {
		t.Fatalf("rm -rf ~ = %q, want deny", got)
	}
	if got := evalShell(t, e, "echo zzz-good-marker"); got != policy.EffectAsk {
		t.Fatalf("good pack rule = %q, want ask", got)
	}
}

func TestBuildEngineCorruptProjectRulesDegrade(t *testing.T) {
	dir := chdirEmpty(t)
	writeTestFile(t, filepath.Join(dir, ".leash.yaml"), "rules:\n  - id: x\n    effect: nope\n")

	var stderr bytes.Buffer
	e, failed, err := buildEngineWithStore(nil, "", &stderr)
	if err != nil {
		t.Fatalf("a corrupt .leash.yaml must not abort the engine: %v", err)
	}
	if failed != 1 {
		t.Errorf("failed sources = %d, want 1 (the corrupt .leash.yaml)", failed)
	}
	if stderr.Len() == 0 {
		t.Fatal("want a warning about the corrupt .leash.yaml")
	}
	if got := evalShell(t, e, "rm -rf ~"); got != policy.EffectDeny {
		t.Fatalf("rm -rf ~ = %q, want deny", got)
	}
}

func TestBuildEngineCorruptRulesFlagIsLoud(t *testing.T) {
	chdirEmpty(t)
	bad := writeTestFile(t, filepath.Join(t.TempDir(), "bad.yaml"), "rules:\n  - id: x\n    effect: nope\n")
	if _, _, err := buildEngineWithStore(nil, bad, &bytes.Buffer{}); err == nil {
		t.Fatal("an explicit --rules file that fails to load must be an error")
	}
}

// Layering order: recommended < installed < .leash.yaml < --rules.
func TestBuildEngineLayeringOrder(t *testing.T) {
	dir := chdirEmpty(t)
	st := store.Open(t.TempDir())
	// Installed pack softens the recommended force-push ask to allow…
	if _, err := st.Install("soften", []byte("name: soften\noverrides:\n  git-force-push: allow\n")); err != nil {
		t.Fatal(err)
	}
	// …the project pack re-hardens it to ask…
	writeTestFile(t, filepath.Join(dir, ".leash.yaml"), "name: project\noverrides:\n  git-force-push: ask\n")
	// …and the --rules file has the last word: deny.
	rules := writeTestFile(t, filepath.Join(t.TempDir(), "rules.yaml"), "name: flag\noverrides:\n  git-force-push: deny\n")

	e, _, err := buildEngineWithStore(st, rules, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got := evalShell(t, e, "git push --force"); got != policy.EffectDeny {
		t.Fatalf("git push --force = %q, want deny (--rules layers last)", got)
	}
}

// A .leash.yaml can extend an installed pack by name.
func TestBuildEngineProjectExtendsInstalledPack(t *testing.T) {
	dir := chdirEmpty(t)
	st := store.Open(t.TempDir())
	if _, err := st.Install("base", []byte(`name: base
rules:
  - id: base-marker
    description: test
    effect: deny
    match:
      regex: 'zzz-base-marker'
`)); err != nil {
		t.Fatal(err)
	}
	// Remove it from ambient activation? No — installed packs are always
	// active; extends from the project just also pins it. Both paths must
	// dedupe to a single load.
	writeTestFile(t, filepath.Join(dir, ".leash.yaml"), "name: project\nextends: [base]\noverrides:\n  base-marker: ask\n")

	var stderr bytes.Buffer
	e, _, err := buildEngineWithStore(st, "", &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if got := evalShell(t, e, "echo zzz-base-marker"); got != policy.EffectAsk {
		t.Fatalf("effect = %q, want ask (project override wins over extended base)", got)
	}
	if strings.Contains(stderr.String(), "defined by both") {
		t.Fatalf("extends of an installed pack must dedupe, got %q", stderr.String())
	}
}

func TestBuildEngineMissingExtendsTargetWarns(t *testing.T) {
	dir := chdirEmpty(t)
	writeTestFile(t, filepath.Join(dir, ".leash.yaml"), "name: project\nextends: [ghost]\n")

	var stderr bytes.Buffer
	e, _, err := buildEngineWithStore(store.Open(t.TempDir()), "", &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "leash add ghost") {
		t.Fatalf("want a `leash add ghost` hint, got %q", stderr.String())
	}
	if got := evalShell(t, e, "rm -rf ~"); got != policy.EffectDeny {
		t.Fatalf("rm -rf ~ = %q, want deny", got)
	}
}
