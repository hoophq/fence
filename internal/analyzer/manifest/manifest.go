// Package manifest performs semantic analysis of package-manager manifest files
// (package.json, setup.py) to spot install lifecycle hooks — code a manifest
// causes to run automatically on `npm install` / `pip install`. Injecting such a
// hook is a classic supply-chain backdoor, so an agent adding one is worth a
// prompt. Like the shell analyzer, this reasons about structure (parsed JSON
// scripts) rather than raw substrings wherever it can.
package manifest

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// Analysis is the set of semantic facts extracted from a manifest edit.
type Analysis struct {
	// LifecycleHook is true when the written content introduces an install
	// lifecycle hook: a preinstall/install/postinstall script in package.json,
	// or a cmdclass command override in setup.py.
	LifecycleHook bool
}

// npmInstallHooks are the package.json scripts that run automatically during a
// plain `npm install`. `prepare` is deliberately excluded: husky and friends
// make it ubiquitous and legitimate, so flagging it would cry wolf.
var npmInstallHooks = map[string]bool{
	"preinstall":  true,
	"install":     true,
	"postinstall": true,
}

// Analyze inspects a manifest write. content is the text being written — a whole
// file for a Write, or the replacement fragment for an Edit; path selects how to
// interpret it. Non-manifest paths yield no facts.
func Analyze(path, content string) Analysis {
	switch filepath.Base(path) {
	case "package.json":
		return Analysis{LifecycleHook: packageJSONHasInstallHook(content)}
	case "setup.py":
		return Analysis{LifecycleHook: setupPyHasInstallHook(content)}
	}
	return Analysis{}
}

// packageJSONHasInstallHook reports whether content defines an npm install
// lifecycle script. A whole file is parsed as JSON and its scripts inspected
// precisely; an Edit fragment (not valid JSON on its own) falls back to spotting
// a lifecycle key.
func packageJSONHasInstallHook(content string) bool {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err == nil {
		for name := range pkg.Scripts {
			if npmInstallHooks[name] {
				return true
			}
		}
		return false
	}
	return fragmentDefinesHook(content)
}

// fragmentDefinesHook spots a lifecycle name used as a JSON key (`"postinstall":`)
// in a partial edit that does not parse as standalone JSON. Requiring the
// trailing colon avoids matching the word inside a script's value.
func fragmentDefinesHook(content string) bool {
	for name := range npmInstallHooks {
		key := `"` + name + `"`
		rest := content
		for {
			i := strings.Index(rest, key)
			if i < 0 {
				break
			}
			after := strings.TrimLeft(rest[i+len(key):], " \t")
			if strings.HasPrefix(after, ":") {
				return true
			}
			rest = rest[i+len(key):]
		}
	}
	return false
}

// setupPyHasInstallHook reports whether a setup.py overrides install/build
// commands via cmdclass — the standard way to run code at install time. setup.py
// is arbitrary Python, so this is a deliberately narrow textual signal.
func setupPyHasInstallHook(content string) bool {
	return strings.Contains(content, "cmdclass")
}
