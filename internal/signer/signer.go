// Package signer provides a tiny local ed25519 signing/verification
// abstraction used to simulate signed build artifacts and signed
// provenance statements. Everything works fully offline.
package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
)

// KeyRing holds trusted public keys keyed by key ID and verifies raw
// signatures. It is safe for concurrent use.
type KeyRing struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// NewKeyRing creates an empty key ring.
func NewKeyRing() *KeyRing {
	return &KeyRing{keys: map[string]ed25519.PublicKey{}}
}

// AddKey registers a trusted public key under id.
func (r *KeyRing) AddKey(id string, pub ed25519.PublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[id] = pub
}

// Verify checks sig over message with the public key registered for keyID.
// It returns an error when the key is unknown or the signature is invalid.
func (r *KeyRing) Verify(keyID string, message, sig []byte) error {
	r.mu.RLock()
	pub, ok := r.keys[keyID]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown signer key: %q", keyID)
	}
	if !ed25519.Verify(pub, message, sig) {
		return fmt.Errorf("signature from %q failed verification", keyID)
	}
	return nil
}

// Has reports whether id is registered in the ring.
func (r *KeyRing) Has(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.keys[id]
	return ok
}

// Signer holds an ed25519 private key and simulates a build/signing identity.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

// GenerateSigner creates a fresh local ed25519 identity with the given ID.
func GenerateSigner(keyID string) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &Signer{keyID: keyID, priv: priv, pub: pub}, nil
}

// KeyID returns the signer's key ID.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey returns the signer's public key.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.pub }

// Sign signs message deterministically (ed25519 is deterministic) and
// returns the raw signature.
func (s *Signer) Sign(message []byte) ([]byte, error) {
	sig := ed25519.Sign(s.priv, message)
	return sig, nil
}
