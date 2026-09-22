// Package provenance builds and verifies signed provenance chains,
// computes artifact/SBOM digests and binds an SBOM into a chain.
package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/signer"
)

// FailureReason explains a failed check with a stable, distinguishable code.
type FailureReason string

// SBOMMaterialName marks the first provenance statement material that
// attaches the artifact's SBOM. It is an external attachment rather than a
// recursively attested subject, so chain validation exempts it from the
// "every material must resolve to a statement" rule and instead checks its
// digest against the supplied SBOM.
const SBOMMaterialName = "sbom.json"

const (
	FailureArtifactSignatureMissing FailureReason = FailureReason(model.ReasonSignatureMissing)
	FailureArtifactSignatureInvalid FailureReason = FailureReason(model.ReasonSignatureInvalid)
	FailureArtifactContentTampered  FailureReason = FailureReason(model.ReasonContentTampered)
	FailureChainMissing             FailureReason = FailureReason(model.ReasonProvenanceMissing)
	FailureChainBroken              FailureReason = FailureReason(model.ReasonProvenanceBroken)
	FailureSBOMMissing              FailureReason = FailureReason(model.ReasonSBOMMissing)
)

// CheckResult is the cryptographic/structural verification of an artifact
// against its provenance chain and SBOM.
type CheckResult struct {
	OK     bool
	Reason FailureReason
	Detail string
	// Verified fields, only trustworthy when OK is true.
	ArtifactDigest string
	BuilderID      string
	ChainLength    int
	SBOM           *model.SBOM
}

func fail(r FailureReason, format string, args ...any) CheckResult {
	return CheckResult{OK: false, Reason: r, Detail: fmt.Sprintf(format, args...)}
}

// Verifier verifies artifact signatures, provenance chains and SBOM binding.
type Verifier struct {
	ring *signer.KeyRing
}

// NewVerifier creates a Verifier trusting the given key ring.
func NewVerifier(ring *signer.KeyRing) *Verifier {
	return &Verifier{ring: ring}
}

// ArtifactDigest returns the hex sha256 digest of the artifact content.
func (v *Verifier) ArtifactDigest(a *model.Artifact) string {
	sum := sha256.Sum256(a.Content)
	return hex.EncodeToString(sum[:])
}

// Check cryptographically verifies the artifact, its provenance chain and
// the SBOM binding. On failure Reason distinguishes missing signature,
// invalid signature, tampered content, missing/broken chain or missing SBOM.
//
// Evaluation order (the first failure wins, so reason codes never overlap):
//  1. artifact signature presence
//  2. artifact signature validity against the registered signer key
//  3. signed digest matches current content (tamper detection)
//  4. provenance chain presence
//  5. chain structure and statement signatures (broken chain)
//  6. SBOM presence and binding to the chain (missing SBOM)
func (v *Verifier) Check(a *model.Artifact, chain *model.ProvenanceChain, sbom *model.SBOM) CheckResult {
	// 1. signature presence
	if len(a.Signature) == 0 || a.SignerKeyID == "" {
		return fail(FailureArtifactSignatureMissing,
			"artifact %q carries no signature", a.Name)
	}

	actualDigest := v.ArtifactDigest(a)

	// 2. signature validity over the signed digest.
	if err := v.ring.Verify(a.SignerKeyID, []byte(a.SignedDigest), a.Signature); err != nil {
		return fail(FailureArtifactSignatureInvalid,
			"artifact %q: %v", a.Name, err)
	}

	// 3. tamper detection: a valid signature over a digest that no longer
	// matches the content proves the content was altered after signing.
	if a.SignedDigest != actualDigest {
		return fail(FailureArtifactContentTampered,
			"artifact %q: signed digest %s != current content digest %s",
			a.Name, a.SignedDigest, actualDigest)
	}

	// 4. chain presence.
	if chain == nil || len(chain.Statements) == 0 {
		return fail(FailureChainMissing,
			"artifact %q has no provenance statements", a.Name)
	}

	// 5. chain structure + statement signatures.
	if err := v.checkChain(chain, actualDigest, sbom); err != nil {
		return fail(FailureChainBroken, "artifact %q: %s", a.Name, err.Error())
	}

	// 6. SBOM presence and binding.
	if sbom == nil {
		return fail(FailureSBOMMissing, "artifact %q has no SBOM", a.Name)
	}
	if sbom.ArtifactDigest != actualDigest {
		return fail(FailureChainBroken,
			"artifact %q: SBOM is bound to %s, want %s",
			a.Name, sbom.ArtifactDigest, actualDigest)
	}
	if !v.chainContainsMaterial(chain, SBOMDigest(sbom)) {
		return fail(FailureChainBroken,
			"artifact %q: signed provenance chain does not reference the SBOM",
			a.Name)
	}

	first := chain.Statements[0]
	return CheckResult{
		OK:             true,
		ArtifactDigest: actualDigest,
		BuilderID:      first.BuilderID,
		ChainLength:    len(chain.Statements),
		SBOM:           sbom,
	}
}

// checkChain validates a linear signed provenance chain ending at
// artifactDigest. It returns a human readable detail on any break.
func (v *Verifier) checkChain(chain *model.ProvenanceChain, artifactDigest string, sbom *model.SBOM) error {
	stmts := chain.Statements

	// Root sources are materials explicitly marked Root in signed
	// statements; they do not need their own attestation in this local
	// simulation. The flag is covered by each statement's signature, so an
	// attacker cannot simply relabel a missing input as a root.
	roots := map[string]bool{}
	for _, st := range stmts {
		for _, m := range st.Materials {
			if m.Root {
				roots[m.Digest] = true
			}
		}
	}

	// Expected SBOM attachment digest, when an SBOM was supplied.
	wantSBOMDigest := ""
	if sbom != nil {
		wantSBOMDigest = SBOMDigest(sbom)
	}

	// Subject -> statement index; subjects must be unique.
	bySubject := map[string]int{}
	for i, s := range stmts {
		if s.SubjectDigest == "" {
			return fmt.Errorf("statement %d has empty subject", i)
		}
		if _, dup := bySubject[s.SubjectDigest]; dup {
			return fmt.Errorf("duplicate statement subject %s", s.SubjectDigest)
		}
		bySubject[s.SubjectDigest] = i

		if err := v.ring.Verify(s.SignerKeyID, StatementBytes(&s), s.Signature); err != nil {
			return fmt.Errorf("statement %d (step %q): %v", i, s.Step, err)
		}
	}

	// First statement must produce the verified artifact.
	if stmts[0].SubjectDigest != artifactDigest {
		return fmt.Errorf(
			"first statement subject %s does not match artifact digest %s",
			stmts[0].SubjectDigest, artifactDigest)
	}

	// Walk the chain: every non-final statement must consume at least one
	// material that is the subject of a later statement; every non-root
	// material must resolve to a statement subject.
	for i, s := range stmts {
		if len(s.Materials) == 0 {
			return fmt.Errorf("statement %d (step %q) lists no materials", i, s.Step)
		}
		linksForward := i == len(stmts)-1 // final step is rooted at sources
		for _, m := range s.Materials {
			// SBOM attachment: external by design; verify digest when an
			// SBOM was supplied, otherwise leave it to the missing-SBOM check.
			if m.Name == SBOMMaterialName {
				if wantSBOMDigest != "" && m.Digest != wantSBOMDigest {
					return fmt.Errorf(
						"statement %d (step %q) references SBOM digest %s, want %s",
						i, s.Step, m.Digest, wantSBOMDigest)
				}
				continue
			}
			if roots[m.Digest] {
				continue
			}
			j, ok := bySubject[m.Digest]
			if !ok {
				return fmt.Errorf(
					"statement %d (step %q) references unattested material %s",
					i, s.Step, m.Digest)
			}
			if j <= i {
				return fmt.Errorf(
					"statement %d (step %q) does not walk forward to material %s",
					i, s.Step, m.Digest)
			}
			linksForward = true
		}
		if !linksForward {
			return fmt.Errorf(
				"statement %d (step %q) is not connected to a preceding statement",
				i, s.Step)
		}
	}
	return nil
}

func (v *Verifier) chainContainsMaterial(chain *model.ProvenanceChain, digest string) bool {
	for _, s := range chain.Statements {
		for _, m := range s.Materials {
			if m.Digest == digest {
				return true
			}
		}
	}
	return false
}
