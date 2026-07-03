package policy

import (
	"strings"
	"testing"
)

func TestRuleProvenanceStamped(t *testing.T) {
	user := &Rulepack{Name: "user", Rules: []Rule{{
		ID: "marker", Effect: EffectDeny, Match: Match{Regex: "zzz-provenance"},
	}}}
	if err := user.validate(); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Recommended(), user)

	d := e.Evaluate(Action{Kind: ActionShell, Command: "echo zzz-provenance", Cwd: "/w"})
	if d.Rule == nil || d.Rule.Pack() != "user" {
		t.Fatalf("deciding rule pack = %v, want %q", d.Rule, "user")
	}

	d = e.Evaluate(Action{Kind: ActionShell, Command: "rm -rf ~", Cwd: "/w"})
	if d.Rule == nil || d.Rule.Pack() != "recommended" {
		t.Fatalf("deciding rule pack = %v, want %q", d.Rule, "recommended")
	}
}

func TestCrossPackDuplicateRuleIDWarns(t *testing.T) {
	a := &Rulepack{Name: "pack-a", Rules: []Rule{{
		ID: "dup", Effect: EffectAsk, Match: Match{Regex: "zzz-dup"},
	}}}
	b := &Rulepack{Name: "pack-b", Rules: []Rule{{
		ID: "dup", Effect: EffectDeny, Match: Match{Regex: "zzz-dup"},
	}}}
	for _, p := range []*Rulepack{a, b} {
		if err := p.validate(); err != nil {
			t.Fatal(err)
		}
	}
	e := NewEngine(a, b)

	var found bool
	for _, w := range e.Warnings() {
		if strings.Contains(w, `"dup"`) && strings.Contains(w, "pack-a") && strings.Contains(w, "pack-b") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a duplicate-id warning naming both packs, got %v", e.Warnings())
	}

	// Both rules stay active: the most severe effect still wins.
	d := e.Evaluate(Action{Kind: ActionShell, Command: "echo zzz-dup", Cwd: "/w"})
	if d.Effect != EffectDeny {
		t.Fatalf("Effect = %q, want deny (both duplicate rules evaluated)", d.Effect)
	}
}
