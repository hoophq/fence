package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePack(t *testing.T, dir, file, content string) string {
	t.Helper()
	path := filepath.Join(dir, file)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func packNames(packs []*Rulepack) []string {
	names := make([]string, 0, len(packs))
	for _, p := range packs {
		names = append(names, p.Name)
	}
	return names
}

func wantOrder(t *testing.T, r *Resolver, want ...string) {
	t.Helper()
	got := packNames(r.Packs())
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("pack order = %v, want %v", got, want)
	}
}

func TestResolverNoExtends(t *testing.T) {
	dir := t.TempDir()
	path := writePack(t, dir, "solo.yaml", "name: solo\n")
	r := NewResolver(nil)
	if err := r.Add(path); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "solo")
	if w := r.Warnings(); len(w) != 0 {
		t.Fatalf("unexpected warnings: %v", w)
	}
}

func TestResolverFileRefLayersBaseFirst(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "base.yaml", "name: base\n")
	top := writePack(t, dir, "top.yaml", "name: top\nextends: [./base.yaml]\n")
	r := NewResolver(nil)
	if err := r.Add(top); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "base", "top")
}

func TestResolverFileRefRelativeToReferencingFile(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "shared/base.yaml", "name: base\n")
	top := writePack(t, dir, "nested/top.yaml", "name: top\nextends: [../shared/base.yaml]\n")
	r := NewResolver(nil)
	if err := r.Add(top); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "base", "top")
}

func TestResolverInstalledNameRef(t *testing.T) {
	dir := t.TempDir()
	installed := writePack(t, dir, "team.yaml", "name: team\n")
	top := writePack(t, dir, "top.yaml", "name: top\nextends: [team]\n")
	locate := func(name string) (string, bool) {
		if name == "team" {
			return installed, true
		}
		return "", false
	}
	r := NewResolver(locate)
	if err := r.Add(top); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "team", "top")
}

func TestResolverMissingInstalledNameWarnsWithHint(t *testing.T) {
	dir := t.TempDir()
	top := writePack(t, dir, "top.yaml", "name: top\nextends: [ghost]\n")
	r := NewResolver(nil)
	if err := r.Add(top); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "top") // the pack itself still loads
	if len(r.Warnings()) != 1 || !strings.Contains(r.Warnings()[0], "leash add ghost") {
		t.Fatalf("want a warning hinting `leash add ghost`, got %v", r.Warnings())
	}
}

func TestResolverMissingFileRefWarns(t *testing.T) {
	dir := t.TempDir()
	top := writePack(t, dir, "top.yaml", "name: top\nextends: [./nope.yaml]\n")
	r := NewResolver(nil)
	if err := r.Add(top); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "top")
	if len(r.Warnings()) != 1 {
		t.Fatalf("want one warning, got %v", r.Warnings())
	}
}

func TestResolverChainOrdering(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "c.yaml", "name: c\n")
	writePack(t, dir, "b.yaml", "name: b\nextends: [./c.yaml]\n")
	a := writePack(t, dir, "a.yaml", "name: a\nextends: [./b.yaml]\n")
	r := NewResolver(nil)
	if err := r.Add(a); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "c", "b", "a")
}

func TestResolverSharedBaseDedupedAcrossAdds(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "base.yaml", "name: base\n")
	r1 := writePack(t, dir, "r1.yaml", "name: r1\nextends: [./base.yaml]\n")
	r2 := writePack(t, dir, "r2.yaml", "name: r2\nextends: [./base.yaml]\n")
	r := NewResolver(nil)
	if err := r.Add(r1); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(r2); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "base", "r1", "r2")
}

func TestResolverCycleSkippedNotFollowed(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "b.yaml", "name: b\nextends: [./a.yaml]\n")
	a := writePack(t, dir, "a.yaml", "name: a\nextends: [./b.yaml]\n")
	r := NewResolver(nil)
	if err := r.Add(a); err != nil {
		t.Fatal(err)
	}
	// Both packs still load; only the back-edge is dropped.
	wantOrder(t, r, "b", "a")
	if len(r.Warnings()) != 1 || !strings.Contains(r.Warnings()[0], "cycle") {
		t.Fatalf("want one cycle warning, got %v", r.Warnings())
	}
}

func TestResolverSelfExtendSkipped(t *testing.T) {
	dir := t.TempDir()
	a := writePack(t, dir, "a.yaml", "name: a\nextends: [./a.yaml]\n")
	r := NewResolver(nil)
	if err := r.Add(a); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "a")
	if len(r.Warnings()) != 1 || !strings.Contains(r.Warnings()[0], "cycle") {
		t.Fatalf("want one cycle warning, got %v", r.Warnings())
	}
}

func TestResolverRecommendedRefSkipped(t *testing.T) {
	dir := t.TempDir()
	top := writePack(t, dir, "top.yaml", "name: top\nextends: [recommended]\n")
	r := NewResolver(nil)
	if err := r.Add(top); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "top")
	if len(r.Warnings()) != 1 || !strings.Contains(r.Warnings()[0], "always active") {
		t.Fatalf("want an always-active warning, got %v", r.Warnings())
	}
}

func TestResolverDuplicateRootAddedOnce(t *testing.T) {
	dir := t.TempDir()
	a := writePack(t, dir, "a.yaml", "name: a\n")
	r := NewResolver(nil)
	if err := r.Add(a); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(a); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, r, "a")
}

func TestResolverRootLoadFailureIsAnError(t *testing.T) {
	r := NewResolver(nil)
	if err := r.Add(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("want an error for an unloadable root pack")
	}
}

// The point of the ordering: the extending pack's overrides retune what it
// extends, because extended packs land earlier in the pool.
func TestResolverExtendingPackWins(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "base.yaml", `name: base
rules:
  - id: base-rule
    description: test
    effect: deny
    match:
      regex: 'zzz-extends-marker'
`)
	top := writePack(t, dir, "top.yaml", `name: top
extends: [./base.yaml]
overrides:
  base-rule: ask
`)
	r := NewResolver(nil)
	if err := r.Add(top); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(r.Packs()...)
	d := e.Evaluate(Action{Kind: ActionShell, Command: "echo zzz-extends-marker", Cwd: "/w"})
	if d.Effect != EffectAsk {
		t.Fatalf("Effect = %q, want ask (top pack's override must win over its base)", d.Effect)
	}
}

func TestExtendsEmptyEntryRejected(t *testing.T) {
	if _, err := Load(strings.NewReader("name: bad\nextends: ['  ']\n")); err == nil {
		t.Fatal("want a validation error for an empty extends entry")
	}
}
