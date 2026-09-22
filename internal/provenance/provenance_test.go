package provenance_test

import (
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/provenance"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/testutil"
)

func TestCheckReasons(t *testing.T) {
	tests := []struct {
		name   string
		wantOK bool
		want   provenance.FailureReason
		mutate func(f *testutil.Fixture) (a *model.Artifact, c *model.ProvenanceChain, s *model.SBOM)
	}{
		{
			name:   "valid signed world",
			wantOK: true,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				return f.Artifact, f.Chain, f.SBOM
			},
		},
		{
			name: "signature missing",
			want: provenance.FailureArtifactSignatureMissing,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				a := *f.Artifact
				a.Signature = nil
				return &a, f.Chain, f.SBOM
			},
		},
		{
			name: "signature cryptographically invalid",
			want: provenance.FailureArtifactSignatureInvalid,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				a := *f.Artifact
				sig := append([]byte(nil), a.Signature...)
				sig[0] ^= 0xFF
				a.Signature = sig
				return &a, f.Chain, f.SBOM
			},
		},
		{
			name: "content tampered after signing",
			want: provenance.FailureArtifactContentTampered,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				a := *f.Artifact
				a.Content = append([]byte(nil), []byte("=== tampered payload ===")...)
				return &a, f.Chain, f.SBOM
			},
		},
		{
			name: "provenance chain missing",
			want: provenance.FailureChainMissing,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				return f.Artifact, nil, f.SBOM
			},
		},
		{
			name: "provenance chain broken: statement removed, all other sigs valid",
			want: provenance.FailureChainBroken,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				chain := *f.Chain
				stmts := append([]model.ProvenanceStatement(nil), chain.Statements...)
				// Drop the final checkout statement: compile's material
				// digest then resolves to nothing (signatures stay valid).
				chain.Statements = stmts[:2]
				return f.Artifact, &chain, f.SBOM
			},
		},
		{
			name: "provenance chain broken: statement signature invalid",
			want: provenance.FailureChainBroken,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				chain := *f.Chain
				stmts := append([]model.ProvenanceStatement(nil), chain.Statements...)
				sig := append([]byte(nil), stmts[0].Signature...)
				sig[len(sig)-1] ^= 0x01
				stmts[0].Signature = sig
				chain.Statements = stmts
				return f.Artifact, &chain, f.SBOM
			},
		},
		{
			name: "provenance chain broken: first statement does not produce artifact",
			want: provenance.FailureChainBroken,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				chain := *f.Chain
				stmts := append([]model.ProvenanceStatement(nil), chain.Statements...)
				stmts[0].SubjectDigest = "sha256:different-artifact"
				chain.Statements = stmts
				return f.Artifact, &chain, f.SBOM
			},
		},
		{
			name: "provenance chain broken: material relabeled as root (signature covers flag)",
			want: provenance.FailureChainBroken,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				chain := *f.Chain
				stmts := append([]model.ProvenanceStatement(nil), chain.Statements...)
				// Replace compile's real input with an unattested digest
				// and try to declare it a root source.
				stmts[1].Materials = []model.Material{{
					Name: "ghost", Digest: "sha256:attacker-unattested", Root: true,
				}}
				chain.Statements = stmts
				return f.Artifact, &chain, f.SBOM
			},
		},
		{
			name: "sbom missing",
			want: provenance.FailureSBOMMissing,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				return f.Artifact, f.Chain, nil
			},
		},
		{
			name: "sbom bound to different artifact",
			want: provenance.FailureChainBroken,
			mutate: func(f *testutil.Fixture) (*model.Artifact, *model.ProvenanceChain, *model.SBOM) {
				sbom := *f.SBOM
				sbom.ArtifactDigest = "sha256:someone-else"
				return f.Artifact, f.Chain, &sbom
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := testutil.NewFixture(t)
			a, c, s := tc.mutate(f)
			res := f.Verifier.Check(a, c, s)

			chainStmts := 0
			if c != nil {
				chainStmts = len(c.Statements)
			}
			t.Logf("input: artifact=%q bytes=%d signatureBytes=%d chainStatements=%d sbomPresent=%v",
				a.Name, len(a.Content), len(a.Signature), chainStmts, s != nil)
			t.Logf("basis: ok=%v reason=%s detail=%q", res.OK, res.Reason, res.Detail)

			if tc.wantOK {
				if !res.OK {
					t.Fatalf("expected OK, got %s: %s", res.Reason, res.Detail)
				}
				if res.BuilderID != "ci-trusted" || res.ChainLength != 3 {
					t.Fatalf("unexpected verified fields: builder=%q chainLength=%d",
						res.BuilderID, res.ChainLength)
				}
				return
			}
			if res.OK {
				t.Fatalf("expected failure %s, got OK", tc.want)
			}
			if res.Reason != tc.want {
				t.Fatalf("expected reason %s, got %s (%s)", tc.want, res.Reason, res.Detail)
			}
		})
	}
}
