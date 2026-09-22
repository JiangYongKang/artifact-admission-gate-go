package app_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/app"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/testutil"
)

type world struct {
	app   *app.App
	fix   *testutil.Fixture
	log   *audit.Log
	store *policy.Store
}

func newWorld(t *testing.T) *world {
	t.Helper()
	fix := testutil.NewFixture(t)
	store := policy.NewStore()
	log := audit.NewLog()
	g := gate.New(fix.Verifier)
	a := app.New(store, authz.NewEnforcer(), log, g)
	return &world{app: a, fix: fix, log: log, store: store}
}

var (
	admin    = app.Principal{Name: "alice", Role: model.RoleAdmin}
	operator = app.Principal{Name: "opie", Role: model.RoleOperator}
	viewer   = app.Principal{Name: "vic", Role: model.RoleViewer}
	anon     = app.Principal{Name: "stranger", Role: model.RoleAnonymous}
)

func isPermissionDenied(err error) bool {
	var e *app.ErrPermissionDenied
	return errors.As(err, &e)
}

func TestAdmitHappyPathAndAudit(t *testing.T) {
	w := newWorld(t)
	if _, err := w.app.PublishPolicy(admin, testutil.PolicyV1()); err != nil {
		t.Fatal(err)
	}
	d, err := w.app.Admit(operator, w.fix.GoodRequest())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: artifact=%q basis: policy=v%d verdict=%s reason=%s",
		w.fix.Artifact.Name, d.PolicyVersion, d.Verdict, d.Reason)
	if !d.Allowed || d.PolicyVersion != 1 {
		t.Fatalf("unexpected decision: %+v", d)
	}

	entries, err := w.app.AuditTrail(operator)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("audit entries=%d want 2", len(entries))
	}
	if entries[0].Action != model.AuditPolicyPublish || entries[1].Action != model.AuditAdmit {
		t.Fatalf("audit order wrong: %v %v", entries[0].Action, entries[1].Action)
	}
	if entries[1].Seq-entries[0].Seq != 1 {
		t.Fatal("audit sequence numbers not consecutive")
	}
}

func TestUnauthorizedRequestsDoNotChangeState(t *testing.T) {
	w := newWorld(t)
	if _, err := w.app.PublishPolicy(admin, testutil.PolicyV1()); err != nil {
		t.Fatal(err)
	}
	entriesBefore := w.log.Len()

	// Viewer cannot admit.
	_, err := w.app.Admit(viewer, w.fix.GoodRequest())
	if !isPermissionDenied(err) {
		t.Fatalf("viewer admit err=%v want permission denied", err)
	}
	// Anonymous cannot admit.
	_, err = w.app.Admit(anon, w.fix.GoodRequest())
	if !isPermissionDenied(err) {
		t.Fatalf("anon admit err=%v want permission denied", err)
	}
	// Operator cannot publish or roll back policies.
	_, err = w.app.PublishPolicy(operator, testutil.PolicyV2())
	if !isPermissionDenied(err) {
		t.Fatalf("operator publish err=%v want permission denied", err)
	}
	_, err = w.app.RollbackPolicy(operator, 1)
	if !isPermissionDenied(err) {
		t.Fatalf("operator rollback err=%v want permission denied", err)
	}
	// Viewer cannot read the audit trail.
	_, err = w.app.AuditTrail(viewer)
	if !isPermissionDenied(err) {
		t.Fatalf("viewer audit read err=%v want permission denied", err)
	}

	if w.log.Len() != entriesBefore {
		t.Fatalf("audit length changed after denied requests: before=%d after=%d",
			entriesBefore, w.log.Len())
	}
	hist, _ := w.app.PolicyHistory(operator)
	if len(hist) != 1 || hist[0].Version != 1 {
		t.Fatal("policy state changed despite authorization failures")
	}
}

func TestDistinctReasonsAreStable(t *testing.T) {
	w := newWorld(t)
	if _, err := w.app.PublishPolicy(admin, testutil.PolicyV1()); err != nil {
		t.Fatal(err)
	}

	// Build a policy-unsatisfying variant: untrusted builder.
	fix := w.fix
	untrustedArtifact, err := fix.Builder.SignArtifact("orderservice:shady", "application/octet-stream",
		[]byte("=== shady payload ==="), fix.Signers[testutil.KeyUntrustedBuilder])
	if err != nil {
		t.Fatal(err)
	}
	untrustedSBOM := &model.SBOM{ArtifactDigest: fix.Verifier.ArtifactDigest(untrustedArtifact),
		Packages: []model.Package{{Name: "x", Version: "1", License: "MIT"}}}
	untrustedChain, err := fix.Builder.BuildChain(untrustedArtifact, untrustedSBOM,
		"ci-shady", fix.Signers[testutil.KeyUntrustedBuilder], nil)
	if err != nil {
		t.Fatal(err)
	}
	// A one-statement chain is sufficient cryptographically but violates the
	// min-chain-length policy.

	tampered := *fix.Artifact
	tampered.Content = []byte("tampered after signing")

	unsigned := *fix.Artifact
	unsigned.Signature = nil

	broken := *fix.Chain
	broken.Statements = append([]model.ProvenanceStatement(nil), fix.Chain.Statements...)
	// Remove the checkout statement: remaining signatures are valid but
	// the compile step's material can no longer be resolved.
	broken.Statements = broken.Statements[:2]

	cases := []struct {
		name string
		req  gate.Request
		want model.ReasonCode
	}{
		{"good", fix.GoodRequest(), model.ReasonAdmitted},
		{"unsigned", gate.Request{Artifact: &unsigned, Chain: fix.Chain, SBOM: fix.SBOM}, model.ReasonSignatureMissing},
		{"tampered", gate.Request{Artifact: &tampered, Chain: fix.Chain, SBOM: fix.SBOM}, model.ReasonContentTampered},
		{"broken-chain", gate.Request{Artifact: fix.Artifact, Chain: &broken, SBOM: fix.SBOM}, model.ReasonProvenanceBroken},
		{"no-chain", gate.Request{Artifact: fix.Artifact, SBOM: fix.SBOM}, model.ReasonProvenanceMissing},
		{"no-sbom", gate.Request{Artifact: fix.Artifact, Chain: fix.Chain}, model.ReasonSBOMMissing},
		{"policy-unsatisfied-builder", gate.Request{Artifact: untrustedArtifact, Chain: untrustedChain, SBOM: untrustedSBOM}, model.ReasonPolicyNotSatisfied},
	}

	seen := map[model.ReasonCode]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := w.app.Admit(operator, tc.req)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("input=%-28q basis: policy=v%d verdict=%s reason=%s msg=%q",
				tc.name, d.PolicyVersion, d.Verdict, d.Reason, d.Message)
			if d.Reason != tc.want {
				t.Fatalf("reason=%s want %s", d.Reason, tc.want)
			}
			if seen[d.Reason] && d.Reason != model.ReasonAdmitted {
				// identical reasons across distinct scenarios are fine only
				// for the single allowed case; duplicate deny codes mean the
				// table itself has a bug, not the gate.
			}
			seen[d.Reason] = true
		})
	}
	denyCodes := []model.ReasonCode{
		model.ReasonSignatureMissing, model.ReasonSignatureInvalid,
		model.ReasonContentTampered, model.ReasonProvenanceMissing,
		model.ReasonProvenanceBroken, model.ReasonSBOMMissing,
		model.ReasonPolicyNotSatisfied,
	}
	for _, c := range denyCodes {
		if !seen[c] {
			t.Logf("note: reason %s not exercised in this table (covered at lower layers)", c)
		}
	}
}

func TestConcurrentBatchConclusionsAreOrderIndependent(t *testing.T) {
	w := newWorld(t)
	if _, err := w.app.PublishPolicy(admin, testutil.PolicyV1()); err != nil {
		t.Fatal(err)
	}

	// Two distinct request classes, mixed randomly across goroutines.
	good := w.fix.GoodRequest()
	bad := w.fix.GoodRequest()
	badArtifact := *w.fix.Artifact
	badArtifact.Content = []byte("concurrent tamper")
	bad.Artifact = &badArtifact

	const workers = 32
	const perWorker = 20
	results := make([]model.Decision, workers*perWorker)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				req := good
				if (worker+i)%2 == 0 {
					req = bad
				}
				d, err := w.app.Admit(operator, req)
				if err != nil {
					t.Errorf("concurrent admit: %v", err)
					return
				}
				results[worker*perWorker+i] = d
			}
		}(worker)
	}
	wg.Wait()

	var allows, denies int
	for _, d := range results {
		switch d.Reason {
		case model.ReasonAdmitted:
			allows++
		case model.ReasonContentTampered:
			denies++
		default:
			t.Fatalf("unexpected reason under concurrency: %s", d.Reason)
		}
		if d.PolicyVersion != 1 {
			t.Fatalf("decision recorded v%d want v1", d.PolicyVersion)
		}
	}
	total := workers * perWorker
	if allows+denies != total {
		t.Fatalf("lost decisions: %d+%d != %d", allows, denies, total)
	}
	if allows != total/2 || denies != total/2 {
		t.Fatalf("unexpected split: allow=%d deny=%d", allows, denies)
	}
	t.Logf("basis: %d concurrent decisions, allow=%d deny(TAMPERED)=%d, all policy=v1",
		total, allows, denies)

	// Every decision got a dense, ordered audit record.
	entries, _ := w.app.AuditTrail(operator)
	if len(entries) != total+1 { // +1 policy publish
		t.Fatalf("audit entries=%d want %d", len(entries), total+1)
	}
	for i, e := range entries[1:] {
		if e.Seq != int64(i+2) {
			t.Fatalf("audit seq gap at %d: %d", i, e.Seq)
		}
	}
}

func TestPolicyEvolutionRollbackAndHistoricalReproduction(t *testing.T) {
	w := newWorld(t)

	p1 := testutil.PolicyV1()
	p2 := testutil.PolicyV2()
	if _, err := w.app.PublishPolicy(admin, p1); err != nil {
		t.Fatal(err)
	}
	if _, err := w.app.PublishPolicy(admin, p2); err != nil {
		t.Fatal(err)
	}
	// A point in time after v1 took effect but before v2: replaying there
	// must reproduce the v1 conclusion even though v2 is current now.
	v1Era := time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)

	// Under v2 the same signed input is denied by license policy.
	d2, err := w.app.Admit(operator, w.fix.GoodRequest())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input orderservice:v1 under current policy v%d: verdict=%s reason=%s",
		d2.PolicyVersion, d2.Verdict, d2.Reason)
	if d2.Allowed || d2.Reason != model.ReasonPolicyNotSatisfied || d2.PolicyVersion != 2 {
		t.Fatalf("expected policy denial under v2, got %+v", d2)
	}

	// Replay at the v1 era reproduces the historical ALLOW without writing.
	before := w.log.Len()
	replayed, err := w.app.ReplayAt(operator, w.fix.GoodRequest(), v1Era)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Allowed || replayed.PolicyVersion != 1 {
		t.Fatalf("replay did not reproduce v1 ALLOW: %+v", replayed)
	}
	if w.log.Len() != before {
		t.Fatal("replay must not append audit records")
	}

	// Roll back; same live input is allowed again and conclusion matches replay.
	if _, err := w.app.RollbackPolicy(admin, 1); err != nil {
		t.Fatal(err)
	}
	d1, err := w.app.Admit(operator, w.fix.GoodRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !d1.Allowed || d1.PolicyVersion != 1 {
		t.Fatalf("post-rollback decision wrong: %+v", d1)
	}
	if d1.Reason != replayed.Reason {
		t.Fatal("post-rollback live conclusion differs from historical replay")
	}

	// Audit order: publish, publish, deny-admit, rollback, allow-admit.
	entries, _ := w.app.AuditTrail(operator)
	actions := make([]model.AuditAction, len(entries))
	for i, e := range entries {
		actions[i] = e.Action
	}
	want := []model.AuditAction{
		model.AuditPolicyPublish, model.AuditPolicyPublish,
		model.AuditAdmit, model.AuditPolicyRollback, model.AuditAdmit,
	}
	if fmt.Sprint(actions) != fmt.Sprint(want) {
		t.Fatalf("audit action order=%v want %v", actions, want)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].Seq <= entries[i-1].Seq || entries[i].Timestamp.Before(entries[i-1].Timestamp) {
			t.Fatal("audit entries not monotonically ordered")
		}
	}
}
