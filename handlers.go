package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWK represents a single JSON Web Key for the JWKS set.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSResponse is the response body for /.well-known/jwks.json.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWKServer holds dependencies for HTTP handlers.
type JWKServer struct {
	DB *Database
}

// JWKSHandler handles GET requests to /.well-known/jwks.json and returns
// only public keys that have not yet expired. Other methods return 405.
func (s *JWKServer) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, err := s.DB.GetAllValidKeys()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	keys := make([]JWK, 0, len(entries))
	for _, entry := range entries {
		pub := entry.PublicKey
		nBytes := pub.N.Bytes()
		eBytes := BigEndianBytes(pub.E)
		keys = append(keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: entry.Kid,
			N:   base64.RawURLEncoding.EncodeToString(nBytes),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JWKSResponse{Keys: keys})
}

// AuthHandler issues a signed JWT on POST. Use query parameter expired=true
// to receive a JWT signed with an expired key and with exp in the past.
// Accepts requests with or without credentials (Basic auth header, JSON body).
func (s *JWKServer) AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	useExpired := r.URL.Query().Get("expired") == "true"
	var entry *KeyEntry
	var err error
	if useExpired {
		entry, err = s.DB.GetExpiredKey()
	} else {
		entry, err = s.DB.GetValidKey()
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if entry == nil {
		http.Error(w, "no key available", http.StatusInternalServerError)
		return
	}

	var exp time.Time
	if useExpired {
		exp = time.Unix(entry.Expiry, 0).Add(-24 * time.Hour)
	} else {
		exp = time.Now().Add(time.Hour)
	}

	claims := jwt.MapClaims{
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = entry.Kid

	signed, err := token.SignedString(entry.PrivateKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": signed})
}
