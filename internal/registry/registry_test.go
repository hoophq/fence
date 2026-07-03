package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPack = `name: sample
rules:
  - id: sample-rule
    description: test
    effect: ask
    match:
      regex: 'zzz-sample'
`

func sha256hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func testIndexYAML(sum string) string {
	return fmt.Sprintf(`schema: 1
packs:
  - name: sample
    description: A sample pack for infra guardrails
    version: "1.0.0"
    sha256: %s
    path: packs/sample.yaml
    tags: [infra, sample]
`, sum)
}

// writeLocalRegistry lays out index.yaml + packs/sample.yaml in a temp dir and
// returns the index path.
func writeLocalRegistry(t *testing.T, indexYAML string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "packs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packs", "sample.yaml"), []byte(testPack), 0o644); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(dir, "index.yaml")
	if err := os.WriteFile(index, []byte(indexYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return index
}

func TestIndexAndFetchPackFromLocalDir(t *testing.T) {
	index := writeLocalRegistry(t, testIndexYAML(sha256hex(testPack)))
	c := NewClient(index)

	idx, err := c.Index()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := idx.Find("sample")
	if !ok {
		t.Fatal("sample pack not found in index")
	}
	data, err := c.FetchPack(entry)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != testPack {
		t.Fatalf("fetched pack differs from published pack")
	}
}

func TestIndexAndFetchPackOverHTTP(t *testing.T) {
	var packRequests []string
	mux := http.NewServeMux()
	mux.HandleFunc("/registry/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, testIndexYAML(sha256hex(testPack)))
	})
	mux.HandleFunc("/registry/packs/sample.yaml", func(w http.ResponseWriter, r *http.Request) {
		packRequests = append(packRequests, r.URL.Path)
		fmt.Fprint(w, testPack)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/registry/index.yaml")
	idx, err := c.Index()
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := idx.Find("sample")
	data, err := c.FetchPack(entry)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != testPack {
		t.Fatal("fetched pack differs from published pack")
	}
	// The relative path in the index must resolve against the index URL.
	if len(packRequests) != 1 || packRequests[0] != "/registry/packs/sample.yaml" {
		t.Fatalf("pack fetched from %v, want /registry/packs/sample.yaml", packRequests)
	}
}

func TestFetchPackRejectsChecksumMismatch(t *testing.T) {
	index := writeLocalRegistry(t, testIndexYAML(sha256hex("something else entirely")))
	c := NewClient(index)
	idx, err := c.Index()
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := idx.Find("sample")
	data, err := c.FetchPack(entry)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("want a checksum error, got data=%v err=%v", data != nil, err)
	}
	if data != nil {
		t.Fatal("no bytes may be returned on checksum mismatch")
	}
}

func TestIndexSchemaTooNew(t *testing.T) {
	index := writeLocalRegistry(t, "schema: 99\npacks: []\n")
	if _, err := NewClient(index).Index(); err == nil || !strings.Contains(err.Error(), "upgrade leash") {
		t.Fatalf("want an upgrade-leash error for a newer schema, got %v", err)
	}
}

func TestIndexInvalidYAML(t *testing.T) {
	index := writeLocalRegistry(t, "packs: [not: valid: yaml\n")
	if _, err := NewClient(index).Index(); err == nil {
		t.Fatal("want a parse error for invalid index YAML")
	}
}

func TestIndexNotFoundOverHTTP(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := NewClient(srv.URL + "/index.yaml").Index(); err == nil {
		t.Fatal("want an error for a 404 index")
	}
}

func TestDefaultLocation(t *testing.T) {
	if got := NewClient("").Location(); got != DefaultIndexURL {
		t.Fatalf("Location = %q, want the default index URL", got)
	}
}

func TestSearch(t *testing.T) {
	idx := &Index{Packs: []Entry{
		{Name: "terraform-safety", Description: "Guard terraform operations", Tags: []string{"iac"}},
		{Name: "prod-db-guard", Description: "Ask before production databases", Tags: []string{"database"}},
		{Name: "k8s-safety", Description: "Kubernetes guardrails", Tags: []string{"kubernetes"}},
	}}

	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{"k8s-safety", "prod-db-guard", "terraform-safety"}}, // all, sorted
		{"terraform", []string{"terraform-safety"}},                       // name match
		{"PRODUCTION", []string{"prod-db-guard"}},                         // description, case-insensitive
		{"kubernetes", []string{"k8s-safety"}},                            // tag match
		{"nothing-matches-this", nil},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			var got []string
			for _, e := range idx.Search(tc.query) {
				got = append(got, e.Name)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("Search(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

// An index entry's path may only point beside the index — never to another
// host, an absolute location, or out of the index's directory.
func TestResolveRefStaysBesideIndex(t *testing.T) {
	cases := []struct {
		ref string
		ok  bool
	}{
		{"packs/x.yaml", true},
		{"./packs/x.yaml", true},
		{"https://attacker.example/x.yaml", false},
		{"//attacker.example/x.yaml", false},
		{"/etc/x.yaml", false},
		{"packs/../../escape.yaml", false},
	}
	bases := []string{"https://example.com/registry/index.yaml", "/srv/registry/index.yaml"}
	for _, base := range bases {
		for _, tc := range cases {
			t.Run(base+" -> "+tc.ref, func(t *testing.T) {
				_, err := resolveRef(base, tc.ref)
				if ok := err == nil; ok != tc.ok {
					t.Fatalf("resolveRef(%q, %q) err = %v, want ok=%v", base, tc.ref, err, tc.ok)
				}
			})
		}
	}
}

func TestIsRemote(t *testing.T) {
	cases := []struct {
		location string
		want     bool
	}{
		{"https://example.com/index.yaml", true},
		{"http://localhost:8080/index.yaml", true},
		{"/abs/path/index.yaml", false},
		{"./relative/index.yaml", false},
		{"registry/index.yaml", false},
	}
	for _, tc := range cases {
		if got := isRemote(tc.location); got != tc.want {
			t.Errorf("isRemote(%q) = %v, want %v", tc.location, got, tc.want)
		}
	}
}
