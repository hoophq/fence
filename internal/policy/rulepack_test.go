package policy

import (
	"strings"
	"testing"
)

// The schema marker is the forward-compatibility gate: a pack that requires
// vocabulary this build does not have must be refused whole, never half-read
// (the YAML decoder drops unknown fields silently, and a dropped match
// condition makes a rule broader — the wrong failure direction).
func TestLoadSchemaVersion(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string // empty = must load
	}{
		{
			name: "absent schema means v1",
			yaml: `name: t
rules:
  - id: r
    description: d
    effect: deny
    match: {regex: 'x'}
`,
		},
		{
			name: "current schema loads",
			yaml: `schema: 1
name: t
rules:
  - id: r
    description: d
    effect: deny
    match: {regex: 'x'}
`,
		},
		{
			name: "newer schema is refused with an upgrade hint",
			yaml: `schema: 2
name: t
rules:
  - id: r
    description: d
    effect: deny
    match: {regex: 'x'}
`,
			wantErr: "upgrade leash",
		},
		{
			name:    "negative schema is invalid",
			yaml:    "schema: -1\nname: t\nrules: []\n",
			wantErr: "invalid schema",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tc.yaml))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load() = %v, want ok", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// severity and tool are closed vocabularies: a typo must fail at load, not
// silently change what the rule matches or how it displays.
func TestLoadFieldValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string // empty = must load
	}{
		{
			name: "documented severities load",
			yaml: `name: t
rules:
  - id: a
    description: d
    severity: info
    effect: warn
    match: {regex: 'x'}
  - id: b
    description: d
    severity: critical
    effect: deny
    match: {regex: 'x'}
`,
		},
		{
			name: "unknown severity is refused",
			yaml: `name: t
rules:
  - id: r
    description: d
    severity: catastrophic
    effect: deny
    match: {regex: 'x'}
`,
			wantErr: `invalid severity "catastrophic"`,
		},
		{
			name: "known tool kinds load",
			yaml: `name: t
rules:
  - id: r
    description: d
    effect: ask
    match:
      tool: [shell, file_write, file_read, net_fetch]
      regex: 'x'
`,
		},
		{
			name: "unknown tool kind is refused",
			yaml: `name: t
rules:
  - id: r
    description: d
    effect: ask
    match:
      tool: [Shell]
      regex: 'x'
`,
			wantErr: `invalid tool "Shell"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tc.yaml))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load() = %v, want ok", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
