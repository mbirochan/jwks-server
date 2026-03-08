package main

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

// KeyEntry holds an RSA key pair with a key identifier (kid) and expiry.
// Keys with Expiry <= current time are considered expired and excluded from JWKS.
type KeyEntry struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
	Expiry     int64 // Unix timestamp
}

// GenerateKeyPair creates a new 2048-bit RSA key pair.
func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// BigEndianBytes returns the big-endian byte representation of an integer,
// used for encoding the RSA public exponent (e) in JWK format.
func BigEndianBytes(n int) []byte {
	return big.NewInt(int64(n)).Bytes()
}
