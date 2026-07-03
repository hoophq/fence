// Package registry reads shareable rulepacks from a static index — a plain
// index.yaml plus pack files, hosted anywhere. The default registry is the
// registry/ directory of the Leash repo, read live off main. Fetching happens
// only in explicit commands (leash add / search / update); the evaluation
// path never imports this package, so no agent tool call can ever wait on the
// network.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultIndexURL is the built-in registry: the index file in the Leash repo.
const DefaultIndexURL = "https://raw.githubusercontent.com/hoophq/leash/main/registry/index.yaml"

// Schema is the index schema this build understands.
const Schema = 1

// maxFetchBytes caps a fetched index or pack. Rulepacks are small YAML files;
// anything bigger is a misbehaving server, not a pack.
const maxFetchBytes = 5 << 20

// Entry describes one pack published in a registry index.
type Entry struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Version     string   `yaml:"version"`
	SHA256      string   `yaml:"sha256"`
	Path        string   `yaml:"path"` // relative to the index's own location
	Tags        []string `yaml:"tags,omitempty"`
	Maintainer  string   `yaml:"maintainer,omitempty"`
}

// Index is a registry index: the list of published packs.
type Index struct {
	Schema int     `yaml:"schema"`
	Packs  []Entry `yaml:"packs"`
}

// Client reads one registry, identified by the location of its index file —
// an http(s) URL or a local path.
type Client struct{ location string }

// NewClient returns a client for the index at location; empty means the
// built-in registry.
func NewClient(location string) *Client {
	if location == "" {
		location = DefaultIndexURL
	}
	return &Client{location: location}
}

// Location returns the index location this client reads.
func (c *Client) Location() string { return c.location }

// Index fetches and parses the registry index.
func (c *Client) Index() (*Index, error) {
	data, err := fetch(c.location)
	if err != nil {
		return nil, err
	}
	var idx Index
	if err := yaml.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse registry index: %w", err)
	}
	if idx.Schema > Schema {
		return nil, fmt.Errorf("registry index schema %d is newer than this leash understands — upgrade leash", idx.Schema)
	}
	return &idx, nil
}

// FetchPack downloads the pack e points at and verifies its sha256 against
// the checksum the index declares before returning the bytes. Nothing is
// written to disk.
func (c *Client) FetchPack(e Entry) ([]byte, error) {
	loc, err := resolveRef(c.location, e.Path)
	if err != nil {
		return nil, err
	}
	data, err := fetch(loc)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, e.SHA256) {
		return nil, fmt.Errorf("pack %q failed checksum verification: index declares sha256 %s, got %s — refusing to install", e.Name, e.SHA256, got)
	}
	return data, nil
}

// Find returns the entry named name.
func (idx *Index) Find(name string) (Entry, bool) {
	for _, e := range idx.Packs {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// Search returns entries whose name, description, or tags contain query
// (case-insensitive), sorted by name. An empty query returns everything.
func (idx *Index) Search(query string) []Entry {
	q := strings.ToLower(strings.TrimSpace(query))
	var out []Entry
	for _, e := range idx.Packs {
		if q == "" || matchesQuery(e, q) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func matchesQuery(e Entry, q string) bool {
	if strings.Contains(strings.ToLower(e.Name), q) ||
		strings.Contains(strings.ToLower(e.Description), q) {
		return true
	}
	for _, tag := range e.Tags {
		if strings.Contains(strings.ToLower(tag), q) {
			return true
		}
	}
	return false
}

func isRemote(location string) bool {
	u, err := url.Parse(location)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

// fetch reads location — over HTTP(S) for a URL, from disk for a path.
func fetch(location string) ([]byte, error) {
	if !isRemote(location) {
		return os.ReadFile(location)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(location)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", location, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFetchBytes {
		return nil, fmt.Errorf("fetch %s: response exceeds %d bytes", location, maxFetchBytes)
	}
	return data, nil
}

// resolveRef joins a pack reference against the index location: URL-relative
// for a remote index, path-relative for a local one. A ref that could escape
// the index's location — its own scheme or host, an absolute path, or a ..
// segment — is rejected, so an index entry can only ever point beside itself.
func resolveRef(base, ref string) (string, error) {
	if err := validatePackRef(ref); err != nil {
		return "", err
	}
	if isRemote(base) {
		bu, err := url.Parse(base)
		if err != nil {
			return "", err
		}
		ru, err := url.Parse(ref)
		if err != nil {
			return "", fmt.Errorf("pack path %q: %w", ref, err)
		}
		return bu.ResolveReference(ru).String(), nil
	}
	return filepath.Join(filepath.Dir(base), ref), nil
}

func validatePackRef(ref string) error {
	u, err := url.Parse(ref)
	if err != nil {
		return fmt.Errorf("pack path %q: %w", ref, err)
	}
	if u.IsAbs() || u.Host != "" || strings.HasPrefix(ref, "/") || filepath.IsAbs(ref) {
		return fmt.Errorf("pack path %q must be relative to the index", ref)
	}
	if slices.Contains(strings.Split(path.Clean(ref), "/"), "..") {
		return fmt.Errorf("pack path %q must not escape the index directory", ref)
	}
	return nil
}
