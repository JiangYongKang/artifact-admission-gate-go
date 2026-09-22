// Package gate produces deterministic, explainable admission decisions by
// combining cryptographic provenance verification with policy evaluation.
package gate

import (
	"fmt"
	"strings"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/provenance"
)

// Request bundles everything submitted for one admission evaluation.
type Request struct {
	Artifact *model.Artifact
	Chain    *model.ProvenanceChain
	SBOM     *model.SBOM
}

// Gate evaluates admission requests against a supplied policy snapshot.
// Evaluation itself is stateless and deterministic: it depends only on the
// request and the snapshot, so concurrent batches cannot influence each
// other and historical conclusions can be reproduced after rollback.
type Gate struct {
	verifier *provenance.Verifier
}

// New creates a Gate using the given provenance verifier.
func New(v *provenance.Verifier) *Gate {
	return &Gate{verifier: v}
}

// Evaluate runs the full admission pipeline for one request under p:
// signature -> provenance chain -> SBOM -> policy. It returns a fully
// explained decision with a stable, mutually distinguishable reason code.
// The first failed stage wins, so a given input maps to exactly one reason.
func (g *Gate) Evaluate(req Request, p model.Policy) model.Decision {
	now := time.Now().UTC()
	name := ""
	if req.Artifact != nil {
		name = req.Artifact.Name
	}
	d := model.Decision{
		Verdict:       model.VerdictDeny,
		ArtifactName:  name,
		ArtifactID:    name,
		PolicyVersion: p.Version,
		EvaluatedAt:   now,
	}

	if req.Artifact == nil {
		d.Reason = model.ReasonSignatureMissing
		d.Message = "no artifact was submitted"
		return d
	}

	check := g.verifier.Check(req.Artifact, req.Chain, req.SBOM)
	if !check.OK {
		d.Reason = model.ReasonCode(check.Reason)
		d.Message = check.Detail
		return d
	}

	d.ArtifactID = check.ArtifactDigest

	violations := policy.Evaluate(p, check.ArtifactDigest, check.BuilderID,
		check.ChainLength, check.SBOM)
	if len(violations) > 0 {
		d.Reason = model.ReasonPolicyNotSatisfied
		d.Violations = violations
		parts := make([]string, 0, len(violations))
		for _, v := range violations {
			parts = append(parts, v.Rule+": "+v.Detail)
		}
		d.Message = fmt.Sprintf("policy v%d violated: %s", p.Version, strings.Join(parts, "; "))
		return d
	}

	d.Allowed = true
	d.Verdict = model.VerdictAllow
	d.Reason = model.ReasonAdmitted
	d.Message = fmt.Sprintf(
		"signature valid; provenance chain of %d signed statement(s) complete; "+
			"builder %q accepted; satisfies policy v%d",
		check.ChainLength, check.BuilderID, p.Version)
	return d
}
