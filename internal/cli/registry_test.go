package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hoophq/leash/internal/registry"
	"github.com/hoophq/leash/internal/store"
)

const fixturePackV1 = `name: fixture
rules:
  - id: fixture-rule
    description: test
    effect: ask
    match:
      regex: 'zzz-fixture'
`

const fixturePackV2 = `name: fixture
rules:
  - id: fixture-rule
    description: test v2
    effect: deny
    match:
      regex: 'zzz-fixture'
`

func hexSum(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// fakeRegistry writes a local registry with one pack and returns its index
// path. sum lets a test publish a deliberately wrong checksum.
func fakeRegistry(t *testing.T, packYAML, version, sum string) string {
	t.Helper()
	return publishFixture(t, t.TempDir(), packYAML, version, sum)
}

// publishFixture (re)writes the fixture pack and index in dir — calling it
// twice on one dir models a new version published to the same registry.
func publishFixture(t *testing.T, dir, packYAML, version, sum string) string {
	t.Helper()
	writeTestFile(t, filepath.Join(dir, "packs", "fixture.yaml"), packYAML)
	index := fmt.Sprintf(`schema: 1
packs:
  - name: fixture
    description: A fixture pack
    version: %q
    sha256: %s
    path: packs/fixture.yaml
    tags: [testing]
`, version, sum)
	return writeTestFile(t, filepath.Join(dir, "index.yaml"), index)
}

func TestRunAdd(t *testing.T) {
	st := store.Open(t.TempDir())
	index := fakeRegistry(t, fixturePackV1, "1.0.0", hexSum(fixturePackV1))

	var out bytes.Buffer
	if err := runAdd(&out, st, registry.NewClient(index), "fixture"); err != nil {
		t.Fatal(err)
	}
	if !st.Has("fixture") {
		t.Fatal("pack not installed")
	}
	if !strings.Contains(out.String(), "Installed fixture 1.0.0") {
		t.Fatalf("output = %q, want an install confirmation", out.String())
	}

	lf, err := st.Lockfile()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := lf.Packs["fixture"]
	if !ok || entry.Version != "1.0.0" || entry.SHA256 != hexSum(fixturePackV1) || entry.Source != index {
		t.Fatalf("lock entry = %+v, %v", entry, ok)
	}
}

func TestRunAddRejectsChecksumMismatchAndWritesNothing(t *testing.T) {
	st := store.Open(t.TempDir())
	index := fakeRegistry(t, fixturePackV1, "1.0.0", hexSum("tampered"))

	err := runAdd(&bytes.Buffer{}, st, registry.NewClient(index), "fixture")
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("want a checksum error, got %v", err)
	}
	if st.Has("fixture") {
		t.Fatal("nothing may be installed on checksum mismatch")
	}
}

func TestRunAddUnknownPack(t *testing.T) {
	st := store.Open(t.TempDir())
	index := fakeRegistry(t, fixturePackV1, "1.0.0", hexSum(fixturePackV1))
	err := runAdd(&bytes.Buffer{}, st, registry.NewClient(index), "nope")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want a not-found error, got %v", err)
	}
}

func TestRunSearch(t *testing.T) {
	st := store.Open(t.TempDir())
	index := fakeRegistry(t, fixturePackV1, "1.0.0", hexSum(fixturePackV1))

	var out bytes.Buffer
	if err := runSearch(&out, st, registry.NewClient(index), ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "fixture 1.0.0") || strings.Contains(out.String(), "(installed)") {
		t.Fatalf("output = %q, want the pack listed and not marked installed", out.String())
	}

	// After an install, the marker appears.
	if err := runAdd(&bytes.Buffer{}, st, registry.NewClient(index), "fixture"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runSearch(&out, st, registry.NewClient(index), "fixture"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(installed)") {
		t.Fatalf("output = %q, want an (installed) marker", out.String())
	}

	// A query that matches nothing says so.
	out.Reset()
	if err := runSearch(&out, st, registry.NewClient(index), "zzz-nope"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No packs match") {
		t.Fatalf("output = %q, want a no-match message", out.String())
	}
}

func TestRunRemove(t *testing.T) {
	st := store.Open(t.TempDir())
	index := fakeRegistry(t, fixturePackV1, "1.0.0", hexSum(fixturePackV1))
	if err := runAdd(&bytes.Buffer{}, st, registry.NewClient(index), "fixture"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runRemove(&out, st, "fixture"); err != nil {
		t.Fatal(err)
	}
	if st.Has("fixture") {
		t.Fatal("pack still installed after remove")
	}
	lf, err := st.Lockfile()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lf.Packs["fixture"]; ok {
		t.Fatal("lock entry not cleaned up")
	}

	if err := runRemove(&out, st, "fixture"); err == nil {
		t.Fatal("want an error removing a pack that is not installed")
	}
}

func TestRunUpdate(t *testing.T) {
	st := store.Open(t.TempDir())
	dir := t.TempDir()
	index := publishFixture(t, dir, fixturePackV1, "1.0.0", hexSum(fixturePackV1))
	if err := runAdd(&bytes.Buffer{}, st, registry.NewClient(index), "fixture"); err != nil {
		t.Fatal(err)
	}

	// Same registry content: up to date.
	var out bytes.Buffer
	if err := runUpdate(&out, st, registry.NewClient(index), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "up to date") {
		t.Fatalf("output = %q, want up to date", out.String())
	}

	// v2 published to the same registry: update reinstalls, rewrites the lock.
	publishFixture(t, dir, fixturePackV2, "2.0.0", hexSum(fixturePackV2))
	out.Reset()
	if err := runUpdate(&out, st, registry.NewClient(index), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "1.0.0 -> 2.0.0") {
		t.Fatalf("output = %q, want a version bump", out.String())
	}
	lf, err := st.Lockfile()
	if err != nil {
		t.Fatal(err)
	}
	if lf.Packs["fixture"].Version != "2.0.0" {
		t.Fatalf("lock version = %q, want 2.0.0", lf.Packs["fixture"].Version)
	}
	data, err := os.ReadFile(st.PackPath("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != fixturePackV2 {
		t.Fatal("pack file not updated to v2")
	}
}

func TestRunUpdateExplicitUnknownName(t *testing.T) {
	st := store.Open(t.TempDir())
	index := fakeRegistry(t, fixturePackV1, "1.0.0", hexSum(fixturePackV1))
	err := runUpdate(&bytes.Buffer{}, st, registry.NewClient(index), []string{"ghost"})
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("want a not-installed error, got %v", err)
	}
}

func TestRunUpdateNothingInstalled(t *testing.T) {
	st := store.Open(t.TempDir())
	index := fakeRegistry(t, fixturePackV1, "1.0.0", hexSum(fixturePackV1))
	var out bytes.Buffer
	if err := runUpdate(&out, st, registry.NewClient(index), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing to update") {
		t.Fatalf("output = %q, want nothing-to-update", out.String())
	}
}

func TestRunUpdateKeepsPackDroppedFromRegistry(t *testing.T) {
	st := store.Open(t.TempDir())
	index := fakeRegistry(t, fixturePackV1, "1.0.0", hexSum(fixturePackV1))
	if err := runAdd(&bytes.Buffer{}, st, registry.NewClient(index), "fixture"); err != nil {
		t.Fatal(err)
	}

	empty := writeTestFile(t, filepath.Join(t.TempDir(), "index.yaml"), "schema: 1\npacks: []\n")
	var out bytes.Buffer
	if err := runUpdate(&out, st, registry.NewClient(empty), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "kept as-is") {
		t.Fatalf("output = %q, want kept as-is", out.String())
	}
	if !st.Has("fixture") {
		t.Fatal("a pack must never be removed by update")
	}
}

// A same-named pack in a different registry is a different pack — a bare
// `leash update` against the wrong registry must never replace it.
func TestRunUpdateRefusesCrossRegistryReplacement(t *testing.T) {
	st := store.Open(t.TempDir())
	indexA := fakeRegistry(t, fixturePackV1, "1.0.0", hexSum(fixturePackV1))
	if err := runAdd(&bytes.Buffer{}, st, registry.NewClient(indexA), "fixture"); err != nil {
		t.Fatal(err)
	}

	// Another registry publishes its own pack under the same name.
	indexB := fakeRegistry(t, fixturePackV2, "9.9.9", hexSum(fixturePackV2))
	var out bytes.Buffer
	if err := runUpdate(&out, st, registry.NewClient(indexB), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "different registry") {
		t.Fatalf("output = %q, want a different-registry notice", out.String())
	}
	data, err := os.ReadFile(st.PackPath("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != fixturePackV1 {
		t.Fatal("update replaced a pack installed from another registry")
	}
}

func TestRunUpdateSkipsUnmanagedPack(t *testing.T) {
	st := store.Open(t.TempDir())
	// Hand-dropped pack: present on disk, absent from the lockfile.
	if _, err := st.Install("fixture", []byte(fixturePackV1)); err != nil {
		t.Fatal(err)
	}
	index := fakeRegistry(t, fixturePackV2, "2.0.0", hexSum(fixturePackV2))

	var out bytes.Buffer
	if err := runUpdate(&out, st, registry.NewClient(index), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "leash add fixture to adopt") {
		t.Fatalf("output = %q, want an adopt hint", out.String())
	}
	data, err := os.ReadFile(st.PackPath("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != fixturePackV1 {
		t.Fatal("update must not overwrite a pack it does not manage")
	}
}
