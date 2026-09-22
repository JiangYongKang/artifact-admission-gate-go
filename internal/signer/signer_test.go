package signer

import (
	"bytes"
	"testing"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	s, err := GenerateSigner("builder-1")
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	ring := NewKeyRing()
	ring.AddKey(s.KeyID(), s.PublicKey())

	msg := []byte("sha256:abcdef")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := ring.Verify(s.KeyID(), msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Determinism: signing twice yields identical signatures.
	sig2, _ := s.Sign(msg)
	if !bytes.Equal(sig, sig2) {
		t.Fatal("ed25519 signatures are not deterministic")
	}

	// Tampered message must fail.
	if err := ring.Verify(s.KeyID(), []byte("sha256:other"), sig); err == nil {
		t.Fatal("verification unexpectedly succeeded for altered message")
	}
	// Unknown key must fail distinctly.
	if err := ring.Verify("unknown", msg, sig); err == nil {
		t.Fatal("verification unexpectedly succeeded for unknown key")
	}
}
