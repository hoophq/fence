package registry

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/hoophq/fence/internal/policy"
)

// seedIndex loads the registry shipped in this repo. It is the same path
// fence add takes, so a stale sha256 in registry/index.yaml fails here first,
// not on a user's machine.
func seedIndex(t *testing.T) (*Client, *Index) {
	t.Helper()
	c := NewClient(filepath.Join("..", "..", "registry", "index.yaml"))
	idx, err := c.Index()
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Packs) == 0 {
		t.Fatal("the shipped registry has no packs")
	}
	return c, idx
}

func TestSeedRegistryIntegrity(t *testing.T) {
	c, idx := seedIndex(t)

	packs := []*policy.Rulepack{policy.Recommended()}
	for _, e := range idx.Packs {
		data, err := c.FetchPack(e)
		if err != nil {
			t.Fatalf("pack %q: %v\n(after editing a seed pack, recompute its sha256 in registry/index.yaml)", e.Name, err)
		}
		pack, err := policy.Load(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("pack %q does not load: %v", e.Name, err)
		}
		if pack.Name != e.Name {
			t.Errorf("pack file name %q != index name %q", pack.Name, e.Name)
		}
		if e.Version == "" || e.Description == "" {
			t.Errorf("pack %q: index entry needs a version and description", e.Name)
		}
		packs = append(packs, pack)
	}

	// All seed packs must coexist with recommended and each other: no
	// duplicate rule ids, no override warnings.
	engine := policy.NewEngine(packs...)
	if ws := engine.Warnings(); len(ws) != 0 {
		t.Fatalf("engine warnings with all seed packs loaded: %v", ws)
	}
}

// The seed packs follow the same discipline as the recommended pack: every
// catch pinned alongside the everyday commands that must stay silent.
func TestSeedRegistryDecisions(t *testing.T) {
	c, idx := seedIndex(t)
	packs := []*policy.Rulepack{policy.Recommended()}
	for _, e := range idx.Packs {
		data, err := c.FetchPack(e)
		if err != nil {
			t.Fatal(err)
		}
		pack, err := policy.Load(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		packs = append(packs, pack)
	}
	engine := policy.NewEngine(packs...)

	cases := []struct {
		command string
		want    policy.Effect
	}{
		// terraform-safety: catches.
		{"terraform destroy", policy.EffectDeny},
		{"tofu destroy -auto-approve", policy.EffectDeny},
		{"terraform -chdir=envs/prod destroy", policy.EffectDeny},
		{"terraform apply -destroy", policy.EffectDeny},
		{"terraform apply -auto-approve", policy.EffectAsk},
		{"terraform state rm aws_instance.web", policy.EffectAsk},
		{"terraform force-unlock 1234", policy.EffectAsk},
		// terraform-safety: everyday operations stay silent.
		{"terraform plan -destroy", policy.EffectAllow},
		{"terraform plan", policy.EffectAllow},
		{"terraform apply", policy.EffectAllow},
		{"terraform state list", policy.EffectAllow},
		{"terraform init", policy.EffectAllow},

		// prod-db-guard: catches.
		{"psql postgres://prod-db.internal/app", policy.EffectAsk},
		{"mysql -h production.example.com", policy.EffectAsk},
		{`psql -c "DROP TABLE users"`, policy.EffectAsk},
		{`mysql -e "truncate table sessions"`, policy.EffectAsk},
		{`mongosh --eval "db.dropDatabase()"`, policy.EffectAsk},
		// prod-db-guard: local development stays silent.
		{"psql -h localhost dev_db", policy.EffectAllow},
		{`psql -c "SELECT * FROM users"`, policy.EffectAllow},
		{"mysql -h 127.0.0.1 test", policy.EffectAllow},
		{`mongosh --eval "db.stats()"`, policy.EffectAllow},

		// k8s-safety: catches.
		{"kubectl delete namespace staging", policy.EffectAsk},
		{"kubectl delete ns foo", policy.EffectAsk},
		{"kubectl delete pods --all", policy.EffectAsk},
		{"kubectl delete deployments -A", policy.EffectAsk},
		{"kubectl drain node-1", policy.EffectAsk},
		{"kubectl cordon node-1", policy.EffectAsk},
		{"kubectl config use-context prod-us-east", policy.EffectWarn},
		// k8s-safety: everyday operations stay silent.
		{"kubectl get pods -A", policy.EffectAllow},
		{"kubectl delete pod crashed-pod-abc", policy.EffectAllow},
		{"kubectl apply -f deploy.yaml", policy.EffectAllow},
		{"kubectl uncordon node-1", policy.EffectAllow},
		{"kubectl config use-context dev", policy.EffectAllow},
		{"kubectl config use-context product-catalog-dev", policy.EffectAllow},
		{"kubectl logs -f api-5d9", policy.EffectAllow},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			d := engine.Evaluate(policy.Action{Kind: policy.ActionShell, Command: tc.command, Cwd: "/Users/dev/project"})
			if d.Effect != tc.want {
				rule := ""
				if d.Rule != nil {
					rule = d.Rule.ID
				}
				t.Fatalf("Effect = %q (rule %q), want %q", d.Effect, rule, tc.want)
			}
		})
	}

	// terraform-safety's file rule: state files ask, ordinary files pass.
	writeCases := []struct {
		path string
		want policy.Effect
	}{
		{"infra/terraform.tfstate", policy.EffectAsk},
		{"infra/terraform.tfstate.backup", policy.EffectAsk},
		{"main.tf", policy.EffectAllow},
		{"docs/notes.md", policy.EffectAllow},
	}
	for _, tc := range writeCases {
		t.Run("write "+tc.path, func(t *testing.T) {
			d := engine.Evaluate(policy.Action{Kind: policy.ActionFileWrite, Path: tc.path, Cwd: "/Users/dev/project"})
			if d.Effect != tc.want {
				rule := ""
				if d.Rule != nil {
					rule = d.Rule.ID
				}
				t.Fatalf("Effect = %q (rule %q), want %q", d.Effect, rule, tc.want)
			}
		})
	}
}
