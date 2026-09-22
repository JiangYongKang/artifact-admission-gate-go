package gate_test

import (
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/testutil"
)

func TestEvaluateReasonsAndPolicyVersion(t *testing.T) {
	tests := []struct {
		name    string
		makeReq func(f *testutil.Fixture) gate.Request
		policy  func() model.Policy
		want    model.ReasonCode
	}{
		{
			name:    "admitted under v1",
			makeReq: func(f *testutil.Fixture) gate.Request { return f.GoodRequest() },
			policy:  testutil.PolicyV1,
			want:    model.ReasonAdmitted,
		},
		{
			name:    "denied by stricter v2 license policy",
			makeReq: func(f *testutil.Fixture) gate.Request { return f.GoodRequest() },
			policy:  testutil.PolicyV2,
			want:    model.ReasonPolicyNotSatisfied,
		},
		{
			name: "signature missing",
			makeReq: func(f *testutil.Fixture) gate.Request {
				a := *f.Artifact
				a.Signature = nil
				return gate.Request{Artifact: &a, Chain: f.Chain, SBOM: f.SBOM}
			},
			policy: testutil.PolicyV1,
			want:   model.ReasonSignatureMissing,
		},
		{
			name: "content tampered",
			makeReq: func(f *testutil.Fixture) gate.Request {
				a := *f.Artifact
				a.Content = []byte("tampered")
				return gate.Request{Artifact: &a, Chain: f.Chain, SBOM: f.SBOM}
			},
			policy: testutil.PolicyV1,
			want:   model.ReasonContentTampered,
		},
		{
			name: "provenance broken",
			makeReq: func(f *testutil.Fixture) gate.Request {
				chain := *f.Chain
				stmts := append([]model.ProvenanceStatement(nil), chain.Statements...)
				chain.Statements = stmts[:2] // drop checkout -> unresolved material
				return gate.Request{Artifact: f.Artifact, Chain: &chain, SBOM: f.SBOM}
			},
			policy: testutil.PolicyV1,
			want:   model.ReasonProvenanceBroken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := testutil.NewFixture(t)
			req := tc.makeReq(f)
			p := tc.policy()
			g := gate.New(f.Verifier)

			d := g.Evaluate(req, p)

			t.Logf("input: artifact=%q chainStatements=%d sbomPackages=%d",
				req.Artifact.Name, len(req.Chain.Statements), len(req.SBOM.Packages))
			t.Logf("basis: hitPolicyVersion=%d verdict=%s reason=%s message=%q violations=%d",
				d.PolicyVersion, d.Verdict, d.Reason, d.Message, len(d.Violations))

			if d.Reason != tc.want {
				t.Fatalf("reason=%s want %s (%s)", d.Reason, tc.want, d.Message)
			}
			if d.PolicyVersion != p.Version {
				t.Fatalf("decision recorded policy v%d, want v%d", d.PolicyVersion, p.Version)
			}
			if tc.want == model.ReasonAdmitted && (!d.Allowed || d.Verdict != model.VerdictAllow) {
				t.Fatal("expected ALLOW")
			}
			if tc.want != model.ReasonAdmitted && (d.Allowed || d.Verdict != model.VerdictDeny) {
				t.Fatal("expected DENY")
			}
		})
	}
}

func TestSameInputSameDecisionRegardlessOfOrder(t *testing.T) {
	f := testutil.NewFixture(t)
	g := gate.New(f.Verifier)
	p1 := testutil.PolicyV1()
	p2 := testutil.PolicyV2()

	// Evaluate under alternating snapshots repeatedly; outcomes must never
	// depend on evaluation order.
	var seq []model.ReasonCode
	for i := 0; i < 10; i++ {
		p := p1
		if i%2 == 1 {
			p = p2
		}
		d := g.Evaluate(f.GoodRequest(), p)
		seq = append(seq, d.Reason)
	}
	for i, r := range seq {
		want := model.ReasonAdmitted
		if i%2 == 1 {
			want = model.ReasonPolicyNotSatisfied
		}
		if r != want {
			t.Fatalf("iteration %d: %s want %s", i, r, want)
		}
	}
}
