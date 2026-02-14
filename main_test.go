package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyStore(t *testing.T) {
	ks := NewKeyStore()
	priv, pub, err := GenerateKeyPair()
	require.NoError(t, err)

	entry := KeyEntry{
		PrivateKey: priv,
		PublicKey:  pub,
		Kid:        "test-kid",
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	ks.AddKey(entry)

	snap := ks.GetSnapshot()
	assert.Len(t, snap, 1)
	assert.Equal(t, "test-kid", snap[0].Kid)

	// Thread-safety: concurrent AddKey and GetSnapshot
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			p, pubKey, _ := GenerateKeyPair()
			ks.AddKey(KeyEntry{PrivateKey: p, PublicKey: pubKey, Kid: fmt.Sprintf("concurrent-%d", n), Expiry: time.Now().Unix() + int64(n)})
		}(i)
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ks.GetSnapshot()
		}()
	}
	wg.Wait()
	snap2 := ks.GetSnapshot()
	assert.GreaterOrEqual(t, len(snap2), 1)
}

func TestJWKSHandler(t *testing.T) {
	store := NewKeyStore()
	validPriv, validPub, _ := GenerateKeyPair()
	expiredPriv, expiredPub, _ := GenerateKeyPair()
	store.AddKey(KeyEntry{
		PrivateKey: validPriv,
		PublicKey:  validPub,
		Kid:        "valid-1",
		Expiry:     time.Now().Add(24 * time.Hour).Unix(),
	})
	store.AddKey(KeyEntry{
		PrivateKey: expiredPriv,
		PublicKey:  expiredPub,
		Kid:        "expired-1",
		Expiry:     time.Now().Add(-24 * time.Hour).Unix(),
	})
	server := &JWKServer{KeyStore: store}

	t.Run("valid request GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()
		server.JWKSHandler(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

		var body JWKSResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
		assert.Len(t, body.Keys, 1, "expired key must be excluded; keys count must be exactly 1")
		jwk := body.Keys[0]
		assert.Equal(t, "RSA", jwk.Kty)
		assert.Equal(t, "sig", jwk.Use)
		assert.Equal(t, "RS256", jwk.Alg)
		assert.Equal(t, "valid-1", jwk.Kid)
		// Strict Base64URL: no padding, URL-safe charset
		assert.True(t, isBase64URL(jwk.N), "n must be Base64URL")
		assert.True(t, isBase64URL(jwk.E), "e must be Base64URL")
		nDec, err := base64.RawURLEncoding.DecodeString(jwk.N)
		require.NoError(t, err)
		assert.NotEmpty(t, nDec)
		eDec, err := base64.RawURLEncoding.DecodeString(jwk.E)
		require.NoError(t, err)
		assert.NotEmpty(t, eDec)
	})

	t.Run("invalid method POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()
		server.JWKSHandler(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("empty store returns empty keys", func(t *testing.T) {
		emptyServer := &JWKServer{KeyStore: NewKeyStore()}
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()
		emptyServer.JWKSHandler(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		var body JWKSResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
		assert.Empty(t, body.Keys)
	})
}

func TestBigEndianBytes(t *testing.T) {
	b := BigEndianBytes(65537)
	assert.NotEmpty(t, b)
	assert.Equal(t, []byte{0x01, 0x00, 0x01}, b)
}

// TestSetupMux exercises the same server setup as main, ensuring JWKS and auth work end-to-end.
func TestSetupMux(t *testing.T) {
	mux := SetupMux()

	// GET JWKS returns one valid key (expired key excluded)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var jwks JWKSResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&jwks))
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, "valid-key-1", jwks.Keys[0].Kid)

	// POST /auth returns a signed JWT
	req2 := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	var out struct{ Token string }
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&out))
	require.NotEmpty(t, out.Token)
}

func isBase64URL(s string) bool {
	if s == "" {
		return false
	}
	allowed := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, c := range s {
		if !strings.ContainsRune(allowed, c) {
			return false
		}
	}
	return true
}

func TestAuthHandler(t *testing.T) {
	store := NewKeyStore()
	validPriv, validPub, _ := GenerateKeyPair()
	expiredPriv, expiredPub, _ := GenerateKeyPair()
	validExpiry := time.Now().Add(24 * time.Hour).Unix()
	expiredExpiry := time.Now().Add(-24 * time.Hour).Unix()
	store.AddKey(KeyEntry{PrivateKey: validPriv, PublicKey: validPub, Kid: "valid-auth", Expiry: validExpiry})
	store.AddKey(KeyEntry{PrivateKey: expiredPriv, PublicKey: expiredPub, Kid: "expired-auth", Expiry: expiredExpiry})
	server := &JWKServer{KeyStore: store}

	tests := []struct {
		name        string
		method      string
		query       string
		wantStatus  int
		wantExpired bool
		wantKid     string
		store       *KeyStore // nil = use default store with valid+expired keys
	}{
		{"valid POST", http.MethodPost, "", http.StatusOK, false, "valid-auth", nil},
		{"expired POST", http.MethodPost, "expired=true", http.StatusOK, true, "expired-auth", nil},
		{"invalid GET", http.MethodGet, "", http.StatusMethodNotAllowed, false, "", nil},
		{"no valid key (only expired)", http.MethodPost, "", http.StatusInternalServerError, false, "", func() *KeyStore {
			ks := NewKeyStore()
			_, pub, _ := GenerateKeyPair()
			priv, _ := rsa.GenerateKey(rand.Reader, 2048)
			ks.AddKey(KeyEntry{PrivateKey: priv, PublicKey: pub, Kid: "exp-only", Expiry: time.Now().Add(-time.Hour).Unix()})
			return ks
		}()},
		{"no expired key (only valid)", http.MethodPost, "expired=true", http.StatusInternalServerError, false, "", func() *KeyStore {
			ks := NewKeyStore()
			priv, pub, _ := GenerateKeyPair()
			ks.AddKey(KeyEntry{PrivateKey: priv, PublicKey: pub, Kid: "valid-only", Expiry: time.Now().Add(time.Hour).Unix()})
			return ks
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := server
			if tt.store != nil {
				srv = &JWKServer{KeyStore: tt.store}
			}
			url := "/auth"
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest(tt.method, url, nil)
			rec := httptest.NewRecorder()
			srv.AuthHandler(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code, "status code")

			if tt.wantStatus != http.StatusOK {
				return
			}

			var out struct {
				Token string `json:"token"`
			}
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
			require.NotEmpty(t, out.Token)

			keyFunc := func(token *jwt.Token) (interface{}, error) {
				kid, _ := token.Header["kid"].(string)
				assert.Equal(t, tt.wantKid, kid, "kid in header must match key used")
				if kid == "valid-auth" {
					return validPub, nil
				}
				return expiredPub, nil
			}
			var token *jwt.Token
			var err error
			if tt.wantExpired {
				// Parse without validating exp so we can verify signature and check exp claim
				parser := jwt.NewParser(jwt.WithoutClaimsValidation())
				token, err = parser.Parse(out.Token, keyFunc)
			} else {
				token, err = jwt.Parse(out.Token, keyFunc)
			}
			require.NoError(t, err)
			require.True(t, token.Valid, "signature must be valid")

			claims, ok := token.Claims.(jwt.MapClaims)
			require.True(t, ok)
			exp, ok := claims["exp"].(float64)
			require.True(t, ok)
			if tt.wantExpired {
				assert.True(t, int64(exp) < time.Now().Unix(), "expired token must have exp in the past")
			} else {
				assert.True(t, int64(exp) >= time.Now().Unix(), "valid token must have exp in the future")
			}
		})
	}
}
