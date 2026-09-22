// Command demo exercises the full local artifact admission gate offline:
// signed/tampered/unsigned artifacts, policy version evolution with
// rollback and historical replay, a concurrent admission batch and
// role-based access control. Run with:
//
//	go run ./cmd/demo
package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/app"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/testutil"
)

func main() {
	fmt.Println("================ local artifact admission gate demo ================")

	fix := mustFixture(testutil.NewStandaloneFixture())
	store := policy.NewStore()
	log := audit.NewLog()
	application := app.New(store, authz.NewEnforcer(), log, gate.New(fix.Verifier))

	admin := app.Principal{Name: "alice", Role: model.RoleAdmin}
	op := app.Principal{Name: "opie", Role: model.RoleOperator}
	anon := app.Principal{Name: "stranger", Role: model.RoleAnonymous}

	p1 := testutil.PolicyV1()
	p2 := testutil.PolicyV2()
	mustv(application.PublishPolicy(admin, p1))

	section("1. admission reasons under policy v1")
	good := fix.GoodRequest()

	unsigned := good
	a := *fix.Artifact
	unsigned.Artifact = &a
	unsigned.Artifact.Signature = nil

	tampered := good
	b := *fix.Artifact
	tampered.Artifact = &b
	tampered.Artifact.Content = []byte("post-sign tamper payload")

	broken := good
	// Remove the final "checkout" statement while keeping every remaining
	// signature intact: the compile step now references a subject that no
	// statement in the chain attests -> structural provenance break.
	broken.Chain = cloneChain(fix.Chain)
	broken.Chain.Statements = broken.Chain.Statements[:2]

	noSBOM := good
	noSBOM.SBOM = nil

	run(application, op, "valid signed artifact", good)
	run(application, op, "unsigned artifact", unsigned)
	run(application, op, "tampered artifact", tampered)
	run(application, op, "broken provenance chain", broken)
	run(application, op, "missing SBOM", noSBOM)

	section("2. policy version evolution: publish stricter v2")
	mustv(application.PublishPolicy(admin, p2))
	run(application, op, "same input under v2 (Apache-2.0 no longer allowed)", good)

	section("3. historical replay reproduces the v1 conclusion")
	v1Era := time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)
	replay, err := application.ReplayAt(op, good, v1Era)
	must(err)
	printDecision("replay @2026-02-15", replay)

	section("4. rollback to v1 makes the same input admissible again")
	mustv(application.RollbackPolicy(admin, 1))
	run(application, op, "same input after rollback to v1", good)

	section("5. concurrent batch (order must not matter)")
	concurrentBatch(application, op, good, tampered)

	section("6. least privilege: unauthorized call changes no state")
	before := log.Len()
	_, err = application.Admit(anon, good)
	printDenied("anonymous admits artifact", err)
	_, err = application.PublishPolicy(op, model.Policy{Version: 99, Name: "rogue"})
	printDenied("operator publishes policy", err)
	_, err = application.RollbackPolicy(op, 1)
	printDenied("operator rolls policy back", err)
	fmt.Printf("audit entries before=%d after=%d (denied calls add nothing)\n", before, log.Len())

	section("7. ordered audit trail")
	entries := mustEntries(application.AuditTrail(op))
	for _, e := range entries {
		fmt.Printf("  seq=%-3d %-16s actor=%-8s policy=v%-2d verdict=%-5s reason=%-22s %s\n",
			e.Seq, e.Action, e.Actor, e.PolicyVersion, e.Verdict, e.Reason, truncate(e.Detail, 70))
	}
	fmt.Println("====================================================================")
}

func concurrentBatch(a *app.App, who app.Principal, good, bad gate.Request) {
	const workers, per = 16, 25
	var wg sync.WaitGroup
	var mu sync.Mutex
	allow, deny := 0, 0
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				req := good
				if (w+i)%2 == 0 {
					req = bad
				}
				d, err := a.Admit(who, req)
				if err != nil {
					panic(err)
				}
				mu.Lock()
				if d.Allowed {
					allow++
				} else {
					deny++
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	fmt.Printf("  %d concurrent admits: ALLOW=%d DENY=%d (identical inputs always map to the same reason)\n",
		workers*per, allow, deny)
}

func run(a *app.App, who app.Principal, label string, req gate.Request) {
	d, err := a.Admit(who, req)
	must(err)
	printDecision(label, d)
}

func printDecision(label string, d model.Decision) {
	fmt.Printf("  input=%-58s -> %s  [policy v%d, reason=%s]\n",
		label, d.Verdict, d.PolicyVersion, d.Reason)
	fmt.Printf("      basis: %s\n", truncate(d.Message, 110))
	for _, v := range d.Violations {
		fmt.Printf("      violation(%s): %s\n", v.Rule, v.Detail)
	}
}

func printDenied(label string, err error) {
	var pderr *app.ErrPermissionDenied
	if errors.As(err, &pderr) {
		fmt.Printf("  %-45s -> DENIED (role=%s lacks %s)\n", label, pderr.Role, pderr.Perm)
		return
	}
	fmt.Printf("  %s -> unexpected err %v\n", label, err)
}

func section(title string) {
	fmt.Printf("\n--- %s ---\n", title)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func cloneChain(c *model.ProvenanceChain) *model.ProvenanceChain {
	stmts := make([]model.ProvenanceStatement, len(c.Statements))
	for i, st := range c.Statements {
		stmts[i] = st
		stmts[i].Materials = append([]model.Material(nil), st.Materials...)
	}
	return &model.ProvenanceChain{ArtifactID: c.ArtifactID, Statements: stmts}
}

func mustFixture(f *testutil.Fixture, err error) *testutil.Fixture {
	must(err)
	return f
}

func mustv(_ model.Policy, err error) { must(err) }

func mustEntries(es []model.AuditEntry, err error) []model.AuditEntry {
	must(err)
	return es
}
