// Package main implements a RESTful JWKS server that serves JSON Web Key Sets
// and an authentication endpoint that issues signed JWTs.
package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// SetupMux initializes the key store with one valid and one expired RSA key,
// then returns an HTTP ServeMux configured with the JWKS and auth handlers.
func SetupMux() *http.ServeMux {
	store := NewKeyStore()

	validPriv, validPub, err := GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	store.AddKey(KeyEntry{
		PrivateKey: validPriv,
		PublicKey:  validPub,
		Kid:        "valid-key-1",
		Expiry:     time.Now().Add(24 * time.Hour).Unix(),
	})

	expiredPriv, expiredPub, err := GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	store.AddKey(KeyEntry{
		PrivateKey: expiredPriv,
		PublicKey:  expiredPub,
		Kid:        "expired-key-1",
		Expiry:     time.Now().Add(-24 * time.Hour).Unix(),
	})

	server := &JWKServer{KeyStore: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", server.JWKSHandler)
	mux.HandleFunc("/auth", server.AuthHandler)
	return mux
}

func main() {
	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		if _, err := strconv.Atoi(p); err == nil {
			port = p
		}
	}
	addr := ":" + port
	log.Printf("JWKS server listening on %s", addr)
	if err := http.ListenAndServe(addr, SetupMux()); err != nil {
		log.Fatal(err)
	}
}
