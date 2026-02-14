package main

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"sync"
	"time"
)

// KeyEntry holds an RSA key pair with a key identifier (kid) and expiry.
// Keys with Expiry <= current time are considered expired and excluded from JWKS.
type KeyEntry struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
	Expiry     int64 // Unix timestamp
}

// KeyStore holds key entries with thread-safe access.
type KeyStore struct {
	mu   sync.RWMutex
	keys []KeyEntry
}

// NewKeyStore creates an empty KeyStore.
func NewKeyStore() *KeyStore {
	return &KeyStore{keys: make([]KeyEntry, 0)}
}

// GenerateKeyPair creates a new 2048-bit RSA key pair.
func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// AddKey adds a key entry to the store. Thread-safe.
func (ks *KeyStore) AddKey(entry KeyEntry) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys = append(ks.keys, entry)
}

// GetSnapshot returns a copy of all key entries. Thread-safe.
func (ks *KeyStore) GetSnapshot() []KeyEntry {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	out := make([]KeyEntry, len(ks.keys))
	copy(out, ks.keys)
	return out
}

// GetValidKey returns a valid (non-expired) key for signing. Thread-safe.
func (ks *KeyStore) GetValidKey() *KeyEntry {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	now := time.Now().Unix()
	for i := range ks.keys {
		if ks.keys[i].Expiry > now {
			return &ks.keys[i]
		}
	}
	return nil
}

// GetExpiredKey returns an expired key for signing. Thread-safe.
func (ks *KeyStore) GetExpiredKey() *KeyEntry {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	now := time.Now().Unix()
	for i := range ks.keys {
		if ks.keys[i].Expiry <= now {
			return &ks.keys[i]
		}
	}
	return nil
}

// BigEndianBytes returns the big-endian byte representation of an integer,
// used for encoding the RSA public exponent (e) in JWK format.
func BigEndianBytes(n int) []byte {
	return big.NewInt(int64(n)).Bytes()
}
