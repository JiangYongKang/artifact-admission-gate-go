package policy_test

import (
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
)

func sbomWith(pkgs ...model.Package) *model.SBOM {
	return &model.SBOM{ArtifactDigest: "sha256:a", Packages: pkgs}
}

func TestEvaluateViolations(t *testing.T) {
	p := model.Policy{
		Version:                7,
		AllowedBuilders:        []string{"ci-trusted"},
		RequiredMinChainLength: 2,
		AllowedLicenses:        []string{"MIT", "Apache-2.0"},
		DeniedPackages:         []string{"github.com/evil/backdoor"},
	}
	sbom := sbomWith(
		model.Package{Name: "ok", Version: "1", License: "MIT"},
		model.Package{Name: "github.com/evil/backdoor", Version: "9", License: "GPL-3.0"},
	)

	t.Run("satisfied", func(t *testing.T) {
		good := sbomWith(model.Package{Name: "ok", Version: "1", License: "MIT"})
		if vs := policy.Evaluate(p, "sha256:a", "ci-trusted", 2, good); len(vs) != 0 {
			t.Fatalf("unexpected violations: %v", vs)
		}
	})

	t.Run("every rule distinguishable", func(t *testing.T) {
		cases := []struct {
			name        string
			builder     string
			chainLength int
			bom         *model.SBOM
			wantRules   map[string]bool
		}{
			{"untrusted builder", "ci-shady", 2, sbom, map[string]bool{"allowed-builders": true}},
			{"short chain", "ci-trusted", 1, sbom, map[string]bool{"min-chain-length": true}},
			{"bad license and denied package", "ci-trusted", 3, sbom,
				map[string]bool{"allowed-licenses": true, "denied-packages": true}},
			{"wildcard license accepts any declared license", "ci-trusted", 2,
				sbomWith(model.Package{Name: "x", Version: "1", License: "Zlib"}), nil},
		}
		star := p
		star.AllowedLicenses = []string{"*"}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pp := p
				if tc.name == "wildcard license accepts any declared license" {
					pp = star
				}
				vs := policy.Evaluate(pp, "sha256:a", tc.builder, tc.chainLength, tc.bom)
				got := map[string]bool{}
				for _, v := range vs {
					got[v.Rule] = true
					t.Logf("basis [policy v%d]: rule=%s detail=%q", pp.Version, v.Rule, v.Detail)
				}
				for r := range tc.wantRules {
					if !got[r] {
						t.Fatalf("expected rule %q in %v", r, got)
					}
				}
				if tc.wantRules == nil && len(vs) != 0 {
					t.Fatalf("expected no violations, got %v", vs)
				}
			})
		}
	})

	t.Run("pure and order independent", func(t *testing.T) {
		first := policy.Evaluate(p, "sha256:a", "ci-trusted", 2, sbom)
		second := policy.Evaluate(p, "sha256:a", "ci-trusted", 2, sbom)
		if len(first) != len(second) {
			t.Fatal("repeated evaluation differs")
		}
		for i := range first {
			if first[i] != second[i] {
				t.Fatal("violations not stable across repeated evaluation")
			}
		}
	})
}
