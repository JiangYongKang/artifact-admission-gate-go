// Package model defines the core data types shared across the local
// artifact admission gate: signed artifacts, provenance chains, SBOMs,
// versioned policies, admission decisions and audit records.
package model

import "time"

// Role identifies a principal that interacts with the gate.
type Role string

const (
	RoleAdmin     Role = "admin"     // manages policies and can inspect everything
	RoleOperator  Role = "operator"  // runs admission checks and reads audit trail
	RoleViewer    Role = "viewer"    // read-only access to decisions
	RoleAnonymous Role = "anonymous" // no grants; every request must be denied
)

// Permission is an atomic capability that may be granted to a role.
type Permission string

const (
	PermArtifactAdmit  Permission = "artifact:admit"  // submit an artifact for admission
	PermPolicyRead     Permission = "policy:read"     // read the effective / historical policies
	PermPolicyWrite    Permission = "policy:write"    // publish a new policy version
	PermPolicyRollback Permission = "policy:rollback" // roll the effective policy back
	PermAuditRead      Permission = "audit:read"      // read the audit trail
)

// DigestAlgorithm is the name of the digest algorithm used locally.
const DigestAlgorithm = "sha256"

// Artifact is a locally simulated signed build artifact.
//
// Content is the raw artifact bytes. SignedDigest is the digest over the
// original content that was signed at build time. Signature is the raw
// signature bytes over SignedDigest. A tampered artifact keeps its original
// signature but mutates Content; a missing-signature artifact has nil
// Signature.
type Artifact struct {
	Name         string
	ContentType  string
	Content      []byte
	SignedDigest string
	Signature    []byte
	SignerKeyID  string
}

// Material is a reference to an input that went into a build step,
// identified by its digest. Root marks inputs that need no further
// attestation in this local simulation (e.g. a trusted base image or a
// source tarball at the end of the chain).
type Material struct {
	Name   string
	Digest string
	Root   bool
}

// ProvenanceStatement is one signed statement in a provenance chain
// (a simplified, in-toto inspired attestation).
//
// SubjectDigest is the digest of what this statement produces. Materials
// are the digests consumed by this step. BuilderID identifies the builder.
// A statement is authentic when Signature verifies against the canonical
// bytes of (SubjectDigest, BuilderID, Materials).
type ProvenanceStatement struct {
	SubjectDigest string
	BuilderID     string
	Step          string
	Materials     []Material
	Signature     []byte
	SignerKeyID   string
}

// ProvenanceChain is an ordered list of signed statements.
//
// Order is build order: the first statement produces the artifact itself
// (SubjectDigest == artifact digest); each following statement produces one
// of the previous statement's materials, walking back toward source.
type ProvenanceChain struct {
	ArtifactID string
	Statements []ProvenanceStatement
}

// Package describes one component recorded in an SBOM.
type Package struct {
	Name    string
	Version string
	License string
}

// SBOM is the software component inventory for an artifact.
type SBOM struct {
	ArtifactDigest string
	Packages       []Package
}

// Policy is an immutable, versioned admission policy.
//
// AllowedBuilders lists the builder IDs permitted to build admitted
// artifacts. RequiredMinChainLength is the minimum number of signed
// provenance statements. AllowedLicenses is the allow-list of open-source
// licenses; "*" means any non-empty license is accepted. DeniedPackages
// rejects artifacts whose SBOM contains a listed package name.
type Policy struct {
	Version                int
	Name                   string
	EffectiveFrom          time.Time
	AllowedBuilders        []string
	RequiredMinChainLength int
	AllowedLicenses        []string
	DeniedPackages         []string
}

// Verdict is the binary admission outcome.
type Verdict string

const (
	VerdictAllow Verdict = "ALLOW"
	VerdictDeny  Verdict = "DENY"
)

// ReasonCode is a stable, mutually distinguishable machine readable reason
// for a decision (allow and deny).
type ReasonCode string

const (
	ReasonAdmitted           ReasonCode = "ADMITTED"
	ReasonSignatureMissing   ReasonCode = "SIGNATURE_MISSING"
	ReasonSignatureInvalid   ReasonCode = "SIGNATURE_INVALID"
	ReasonContentTampered    ReasonCode = "CONTENT_TAMPERED"
	ReasonProvenanceMissing  ReasonCode = "PROVENANCE_MISSING"
	ReasonProvenanceBroken   ReasonCode = "PROVENANCE_BROKEN"
	ReasonSBOMMissing        ReasonCode = "SBOM_MISSING"
	ReasonPolicyNotSatisfied ReasonCode = "POLICY_NOT_SATISFIED"
	ReasonPermissionDenied   ReasonCode = "PERMISSION_DENIED"
)

// PolicyViolation describes one failed rule of the effective policy.
type PolicyViolation struct {
	Rule   string
	Detail string
}

// Decision is the fully explained result of one admission evaluation.
type Decision struct {
	Allowed       bool
	Verdict       Verdict
	Reason        ReasonCode
	Message       string
	ArtifactName  string
	ArtifactID    string
	PolicyVersion int
	EvaluatedAt   time.Time
	Violations    []PolicyViolation
}

// AuditAction enumerates the kinds of operations recorded in the audit trail.
type AuditAction string

const (
	AuditAdmit          AuditAction = "artifact.admit"
	AuditPolicyPublish  AuditAction = "policy.publish"
	AuditPolicyRollback AuditAction = "policy.rollback"
	AuditDeniedByRBAC   AuditAction = "authz.denied"
)

// AuditEntry is one append-only, sequentially ordered audit record.
type AuditEntry struct {
	Seq           int64
	Timestamp     time.Time
	Action        AuditAction
	Role          Role
	Actor         string
	PolicyVersion int
	ArtifactID    string
	Verdict       Verdict
	Reason        ReasonCode
	Detail        string
}
