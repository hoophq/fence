package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPack = `name: sample
rules:
  - id: sample-rule
    description: test
    effect: ask
    match:
      regex: 'zzz-sample'
`

func TestInstallLoadRoundTrip(t *testing.T) {
	s := Open(t.TempDir())
	pack, err := s.Install("sample", []byte(validPack))
	if err != nil {
		t.Fatal(err)
	}
	if pack.Name != "sample" || len(pack.Rules) != 1 {
		t.Fatalf("parsed pack = %q with %d rules, want sample with 1", pack.Name, len(pack.Rules))
	}
	if !s.Has("sample") {
		t.Fatal("installed pack not found by Has")
	}
	path, ok := s.Locate("sample")
	if !ok || path != s.PackPath("sample") {
		t.Fatalf("Locate = %q, %v; want %q", path, ok, s.PackPath("sample"))
	}
}

func TestInstallRejectsInvalidPackAndWritesNothing(t *testing.T) {
	s := Open(t.TempDir())
	if _, err := s.Install("bad", []byte("rules:\n  - id: x\n    effect: nope\n")); err == nil {
		t.Fatal("want an error for an invalid rulepack")
	}
	if s.Has("bad") {
		t.Fatal("invalid pack must not be written to disk")
	}
}

func TestInstallRejectsUnsafeNames(t *testing.T) {
	s := Open(t.TempDir())
	for _, name := range []string{"", ".", "..", "../evil", "a/b", `a\b`, "x.yaml", "x.yml"} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Install(name, []byte(validPack)); err == nil {
				t.Fatalf("want an error for unsafe pack name %q", name)
			}
		})
	}
}

func TestListEmptyStoreIsNotAnError(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "never-created"))
	names, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("want no packs, got %v", names)
	}
}

func TestListSortedNames(t *testing.T) {
	s := Open(t.TempDir())
	for _, name := range []string{"zeta", "alpha", "mid"} {
		if _, err := s.Install(name, []byte(validPack)); err != nil {
			t.Fatal(err)
		}
	}
	names, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "alpha,mid,zeta" {
		t.Fatalf("List = %v, want sorted [alpha mid zeta]", names)
	}
}

func TestRemove(t *testing.T) {
	s := Open(t.TempDir())
	if _, err := s.Install("sample", []byte(validPack)); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("sample"); err != nil {
		t.Fatal(err)
	}
	if s.Has("sample") {
		t.Fatal("pack still present after Remove")
	}
	if err := s.Remove("sample"); err == nil {
		t.Fatal("want an error removing a pack that is not installed")
	}
}

func TestLockfileRoundTrip(t *testing.T) {
	s := Open(t.TempDir())

	lf, err := s.Lockfile()
	if err != nil {
		t.Fatal(err)
	}
	if len(lf.Packs) != 0 {
		t.Fatalf("fresh lockfile should be empty, got %v", lf.Packs)
	}

	lf.Packs["sample"] = LockEntry{Version: "1.0.0", SHA256: "abc", Source: "https://example.com/index.yaml"}
	if err := s.SaveLockfile(lf); err != nil {
		t.Fatal(err)
	}

	got, err := s.Lockfile()
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != LockSchema {
		t.Fatalf("schema = %d, want %d", got.Schema, LockSchema)
	}
	entry, ok := got.Packs["sample"]
	if !ok || entry.Version != "1.0.0" || entry.SHA256 != "abc" {
		t.Fatalf("lock entry = %+v, %v", entry, ok)
	}
}

func TestLockfileInvalidJSONIsAnError(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)
	if err := os.WriteFile(filepath.Join(dir, "packs.lock.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lockfile(); err == nil {
		t.Fatal("want an error for a corrupt lockfile")
	}
}
