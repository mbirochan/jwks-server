// Package main implements a RESTful JWKS server that serves JSON Web Key Sets
// and an authentication endpoint that issues signed JWTs, backed by SQLite.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// SetupMuxWithDB initializes a SQLite database at dbPath, seeds it with one
// valid and one expired RSA key, and returns the configured ServeMux and
// Database. The caller is responsible for closing the Database.
func SetupMuxWithDB(dbPath string) (*http.ServeMux, *Database, error) {
	database, err := NewDatabase(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("init database: %w", err)
	}

	// Generate and store a valid key (expires in 1 hour).
	validPriv, _, err := GenerateKeyPair()
	if err != nil {
		database.Close()
		return nil, nil, fmt.Errorf("generate valid key: %w", err)
	}
	if _, err := database.StoreKey(validPriv, time.Now().Add(time.Hour).Unix()); err != nil {
		database.Close()
		return nil, nil, fmt.Errorf("store valid key: %w", err)
	}

	// Generate and store an expired key (expired 1 hour ago).
	expiredPriv, _, err := GenerateKeyPair()
	if err != nil {
		database.Close()
		return nil, nil, fmt.Errorf("generate expired key: %w", err)
	}
	if _, err := database.StoreKey(expiredPriv, time.Now().Add(-time.Hour).Unix()); err != nil {
		database.Close()
		return nil, nil, fmt.Errorf("store expired key: %w", err)
	}

	server := &JWKServer{DB: database}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", server.JWKSHandler)
	mux.HandleFunc("/auth", server.AuthHandler)
	return mux, database, nil
}

// getPort returns the PORT environment variable if it's a valid integer,
// otherwise returns "8080".
func getPort() string {
	if p := os.Getenv("PORT"); p != "" {
		if _, err := strconv.Atoi(p); err == nil {
			return p
		}
	}
	return "8080"
}

func main() {
	mux, db, err := SetupMuxWithDB("totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	addr := ":" + getPort()
	log.Printf("JWKS server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
