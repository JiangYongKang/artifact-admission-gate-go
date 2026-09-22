package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/signer"
)

// Builder constructs correctly signed artifacts, provenance chains and SBOMs
// for local tests and demos.
type Builder struct {
	v *Verifier
}

// NewBuilder creates a Builder sharing the given verifier's trusted keys.
func NewBuilder(v *Verifier) *Builder {
	return &Builder{v: v}
}

// ChainStep is one signed provenance step when constructing a chain.
// The step's Materials must include the digest of the next step's subject
// (the final step lists root source materials).
type ChainStep struct {
	SubjectDigest string
	BuilderID     string
	Step          string
	Materials     []model.Material
	Signer        *signer.Signer
}

// SignArtifact creates an artifact whose signature covers its content digest.
func (b *Builder) SignArtifact(name, contentType string, content []byte, s *signer.Signer) (*model.Artifact, error) {
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	sig, err := s.Sign([]byte(digest))
	if err != nil {
		return nil, fmt.Errorf("sign artifact %q: %w", name, err)
	}
	return &model.Artifact{
		Name:         name,
		ContentType:  contentType,
		Content:      content,
		SignedDigest: digest,
		Signature:    sig,
		SignerKeyID:  s.KeyID(),
	}, nil
}

// StatementBytes returns the canonical bytes that a provenance statement
// signature is computed over. The canonical form is JSON with the signature
// and signer fields stripped, keyed in a fixed order.
func StatementBytes(stmt *model.ProvenanceStatement) []byte {
	type canonical struct {
		SubjectDigest string           `json:"subjectDigest"`
		BuilderID     string           `json:"builderId"`
		Step          string           `json:"step"`
		Materials     []model.Material `json:"materials"`
	}
	raw, _ := json.Marshal(canonical{
		SubjectDigest: stmt.SubjectDigest,
		BuilderID:     stmt.BuilderID,
		Step:          stmt.Step,
		Materials:     stmt.Materials,
	})
	return raw
}

// SignStatement signs the canonical representation of stmt in place.
func (b *Builder) SignStatement(stmt *model.ProvenanceStatement, s *signer.Signer) error {
	if stmt.SignerKeyID != "" {
		return fmt.Errorf("statement for %s is already signed", stmt.SubjectDigest)
	}
	sig, err := s.Sign(StatementBytes(stmt))
	if err != nil {
		return err
	}
	stmt.Signature = sig
	stmt.SignerKeyID = s.KeyID()
	return nil
}

// BuildChain constructs a signed linear provenance chain for an artifact.
// The first statement is produced by firstSigner/firstBuilderID and consumes
// the SBOM plus (if present) the subject of the first supplied step; each
// supplied step is signed with its own signer, walking back toward root
// sources.
func (b *Builder) BuildChain(a *model.Artifact, sbom *model.SBOM, firstBuilderID string, firstSigner *signer.Signer, steps []ChainStep) (*model.ProvenanceChain, error) {
	if sbom == nil {
		return nil, fmt.Errorf("cannot build chain for %q: SBOM is required", a.Name)
	}
	artifactDigest := b.v.ArtifactDigest(a)
	stmts := make([]model.ProvenanceStatement, 0, len(steps)+1)

	firstMaterials := []model.Material{{Name: SBOMMaterialName, Digest: SBOMDigest(sbom)}}
	if len(steps) > 0 {
		firstMaterials = append(firstMaterials, model.Material{
			Name: steps[0].Step, Digest: steps[0].SubjectDigest,
		})
	}
	stmts = append(stmts, model.ProvenanceStatement{
		SubjectDigest: artifactDigest,
		BuilderID:     firstBuilderID,
		Step:          "package",
		Materials:     firstMaterials,
	})
	if err := b.SignStatement(&stmts[0], firstSigner); err != nil {
		return nil, err
	}

	for i, step := range steps {
		stmts = append(stmts, model.ProvenanceStatement{
			SubjectDigest: step.SubjectDigest,
			BuilderID:     step.BuilderID,
			Step:          step.Step,
			Materials:     step.Materials,
		})
		if err := b.SignStatement(&stmts[len(stmts)-1], step.Signer); err != nil {
			return nil, fmt.Errorf("sign step %d (%q): %w", i, step.Step, err)
		}
	}

	return &model.ProvenanceChain{ArtifactID: a.Name, Statements: stmts}, nil
}

// SBOMDigest returns the hex sha256 of an SBOM's canonical JSON encoding.
func SBOMDigest(sbom *model.SBOM) string {
	raw, _ := json.Marshal(struct {
		ArtifactDigest string          `json:"artifactDigest"`
		Packages       []model.Package `json:"packages"`
	}{
		ArtifactDigest: sbom.ArtifactDigest,
		Packages:       sbom.Packages,
	})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
