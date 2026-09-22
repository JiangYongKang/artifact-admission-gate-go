// Package testutil builds deterministic, fully signed local fixtures
// (artifacts, provenance chains, SBOMs and versioned policies) shared by the
// unit tests. Everything is generated in memory and works offline.
package testutil

import (
	"fmt"
	"testing"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/provenance"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/signer"
)

// Well-known key IDs used by the fixtures.
const (
	KeyTrustedBuilder   = "key-builder-ci-trusted"
	KeyUntrustedBuilder = "key-builder-ci-untrusted"
)

// Fixed timestamps so EffectiveAt replay is deterministic in tests.
var (
	PolicyV1Time = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	PolicyV2Time = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
)

// Fixture holds one freshly generated signed world.
type Fixture struct {
	Ring     *signer.KeyRing
	Verifier *provenance.Verifier
	Builder  *provenance.Builder
	Signers  map[string]*signer.Signer

	Artifact *model.Artifact
	SBOM     *model.SBOM
	Chain    *model.ProvenanceChain
}

// NewFixture generates the default valid world for a test, failing it on
// construction errors: an artifact signed by the trusted builder, a signed
// three-statement provenance chain and an SBOM with MIT / Apache-2.0 packages.
func NewFixture(t *testing.T) *Fixture {
	t.Helper()
	f, err := NewStandaloneFixture()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// NewStandaloneFixture generates the default valid world outside a test
// (used by the offline demo command).
func NewStandaloneFixture() (*Fixture, error) {
	ring := signer.NewKeyRing()
	signers := map[string]*signer.Signer{}
	for _, id := range []string{KeyTrustedBuilder, KeyUntrustedBuilder} {
		s, err := signer.GenerateSigner(id)
		if err != nil {
			return nil, fmt.Errorf("generate signer %s: %w", id, err)
		}
		ring.AddKey(id, s.PublicKey())
		signers[id] = s
	}

	verifier := provenance.NewVerifier(ring)
	builder := provenance.NewBuilder(verifier)

	content := []byte("=== orderservice:v1 build payload ===")
	a, err := builder.SignArtifact("orderservice:v1", "application/octet-stream",
		content, signers[KeyTrustedBuilder])
	if err != nil {
		return nil, err
	}

	sbom := &model.SBOM{
		ArtifactDigest: verifier.ArtifactDigest(a),
		Packages: []model.Package{
			{Name: "github.com/example/libfoo", Version: "1.2.3", License: "MIT"},
			{Name: "github.com/example/libbar", Version: "0.9.1", License: "Apache-2.0"},
		},
	}

	chain, err := builder.BuildChain(a, sbom, "ci-trusted",
		signers[KeyTrustedBuilder], []provenance.ChainStep{
			{
				SubjectDigest: "sha256:build-output-orderservice-v1",
				BuilderID:     "ci-trusted",
				Step:          "compile",
				Materials:     []model.Material{{Name: "checkout", Digest: "sha256:source-checkout-orderservice-v1"}},
				Signer:        signers[KeyTrustedBuilder],
			},
			{
				SubjectDigest: "sha256:source-checkout-orderservice-v1",
				BuilderID:     "ci-trusted",
				Step:          "checkout",
				Materials: []model.Material{
					{Name: "source.tar.gz", Digest: "sha256:root-src-v1", Root: true},
					{Name: "base-image", Digest: "sha256:root-baseimage-v1", Root: true},
				},
				Signer: signers[KeyTrustedBuilder],
			},
		})
	if err != nil {
		return nil, err
	}

	return &Fixture{
		Ring:     ring,
		Verifier: verifier,
		Builder:  builder,
		Signers:  signers,
		Artifact: a,
		SBOM:     sbom,
		Chain:    chain,
	}, nil
}

// GoodRequest returns the admission request for the valid signed world.
func (f *Fixture) GoodRequest() gate.Request {
	return gate.Request{Artifact: f.Artifact, Chain: f.Chain, SBOM: f.SBOM}
}

// PolicyV1 is the permissive baseline policy.
func PolicyV1() model.Policy {
	return model.Policy{
		Version:                1,
		Name:                   "baseline",
		EffectiveFrom:          PolicyV1Time,
		AllowedBuilders:        []string{"ci-trusted"},
		RequiredMinChainLength: 2,
		AllowedLicenses:        []string{"MIT", "Apache-2.0"},
		DeniedPackages:         []string{"github.com/evil/backdoor"},
	}
}

// PolicyV2 is a stricter successor: Apache-2.0 is no longer accepted, so the
// default fixture (which ships libbar under Apache-2.0) is denied under v2
// but allowed under v1.
func PolicyV2() model.Policy {
	return model.Policy{
		Version:                2,
		Name:                   "strict-licenses",
		EffectiveFrom:          PolicyV2Time,
		AllowedBuilders:        []string{"ci-trusted"},
		RequiredMinChainLength: 2,
		AllowedLicenses:        []string{"MIT"},
		DeniedPackages:         []string{"github.com/evil/backdoor"},
	}
}
