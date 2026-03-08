package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDB creates an in-memory SQLite database for test isolation.
func setupTestDB(t *testing.T) *Database {
	t.Helper()
	db, err := NewDatabase(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSerializeDeserializeKey(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	require.NoError(t, err)

	pemBytes := SerializePrivateKey(priv)
	require.NotEmpty(t, pemBytes)
	assert.Contains(t, string(pemBytes), "RSA PRIVATE KEY")

	restored, err := DeserializePrivateKey(pemBytes)
	require.NoError(t, err)
	assert.True(t, priv.Equal(restored), "round-tripped key must equal original")
}

func TestDeserializePrivateKeyInvalid(t *testing.T) {
	_, err := DeserializePrivateKey([]byte("not pem data"))
	assert.Error(t, err)
}

func TestDatabase(t *testing.T) {
	db := setupTestDB(t)

	t.Run("empty DB returns nil for valid key", func(t *testing.T) {
		entry, err := db.GetValidKey()
		require.NoError(t, err)
		assert.Nil(t, entry)
	})

	t.Run("empty DB returns nil for expired key", func(t *testing.T) {
		entry, err := db.GetExpiredKey()
		require.NoError(t, err)
		assert.Nil(t, entry)
	})

	t.Run("empty DB returns empty slice for all valid keys", func(t *testing.T) {
		entries, err := db.GetAllValidKeys()
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	// Store a valid key
	validPriv, _, err := GenerateKeyPair()
	require.NoError(t, err)
	validExp := time.Now().Add(time.Hour).Unix()
	kid1, err := db.StoreKey(validPriv, validExp)
	require.NoError(t, err)
	assert.Equal(t, int64(1), kid1)

	// Store an expired key
	expiredPriv, _, err := GenerateKeyPair()
	require.NoError(t, err)
	expiredExp := time.Now().Add(-time.Hour).Unix()
	kid2, err := db.StoreKey(expiredPriv, expiredExp)
	require.NoError(t, err)
	assert.Equal(t, int64(2), kid2)

	t.Run("GetValidKey returns non-expired key", func(t *testing.T) {
		entry, err := db.GetValidKey()
		require.NoError(t, err)
		require.NotNil(t, entry)
		assert.Equal(t, "1", entry.Kid)
		assert.Equal(t, validExp, entry.Expiry)
		assert.True(t, validPriv.Equal(entry.PrivateKey))
	})

	t.Run("GetExpiredKey returns expired key", func(t *testing.T) {
		entry, err := db.GetExpiredKey()
		require.NoError(t, err)
		require.NotNil(t, entry)
		assert.Equal(t, "2", entry.Kid)
		assert.Equal(t, expiredExp, entry.Expiry)
		assert.True(t, expiredPriv.Equal(entry.PrivateKey))
	})

	t.Run("GetAllValidKeys returns only valid keys", func(t *testing.T) {
		entries, err := db.GetAllValidKeys()
		require.NoError(t, err)
		assert.Len(t, entries, 1)
		assert.Equal(t, "1", entries[0].Kid)
	})

	t.Run("StoreKey returns incrementing kid", func(t *testing.T) {
		priv3, _, err := GenerateKeyPair()
		require.NoError(t, err)
		kid3, err := db.StoreKey(priv3, time.Now().Add(2*time.Hour).Unix())
		require.NoError(t, err)
		assert.Equal(t, int64(3), kid3)
	})
}

func TestJWKSHandler(t *testing.T) {
	db := setupTestDB(t)
	validPriv, _, _ := GenerateKeyPair()
	expiredPriv, _, _ := GenerateKeyPair()
	db.StoreKey(validPriv, time.Now().Add(24*time.Hour).Unix())
	db.StoreKey(expiredPriv, time.Now().Add(-24*time.Hour).Unix())
	server := &JWKServer{DB: db}

	t.Run("valid request GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()
		server.JWKSHandler(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

		var body JWKSResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
		assert.Len(t, body.Keys, 1, "expired key must be excluded")
		jwk := body.Keys[0]
		assert.Equal(t, "RSA", jwk.Kty)
		assert.Equal(t, "sig", jwk.Use)
		assert.Equal(t, "RS256", jwk.Alg)
		assert.Equal(t, "1", jwk.Kid)
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
		emptyDB := setupTestDB(t)
		emptyServer := &JWKServer{DB: emptyDB}
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

func TestSetupMux(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	mux, db, err := SetupMuxWithDB(dbPath)
	require.NoError(t, err)
	defer db.Close()

	// Verify DB file was created
	_, err = os.Stat(dbPath)
	require.NoError(t, err, "database file should exist")

	// GET JWKS returns one valid key
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var jwks JWKSResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&jwks))
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, "1", jwks.Keys[0].Kid)

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

func TestNewDatabaseCreatesTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "newdb.db")
	db, err := NewDatabase(dbPath)
	require.NoError(t, err)
	defer db.Close()

	// Verify the table exists by inserting and querying
	priv, _, err := GenerateKeyPair()
	require.NoError(t, err)
	kid, err := db.StoreKey(priv, time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)
	assert.Equal(t, int64(1), kid)
}

func TestSetupMuxWithDBErrorPaths(t *testing.T) {
	t.Run("expired key auth works end-to-end", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "test.db")
		mux, db, err := SetupMuxWithDB(dbPath)
		require.NoError(t, err)
		defer db.Close()

		// POST /auth?expired=true should work
		req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		var out struct{ Token string `json:"token"` }
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
		assert.NotEmpty(t, out.Token)
	})

	t.Run("invalid db path returns error", func(t *testing.T) {
		// A path inside a non-existent directory should fail to open.
		_, _, err := SetupMuxWithDB(filepath.Join(t.TempDir(), "no", "such", "dir", "test.db"))
		assert.Error(t, err)
	})
}

func TestNewDatabaseInvalidPath(t *testing.T) {
	_, err := NewDatabase(filepath.Join(t.TempDir(), "no", "such", "dir", "test.db"))
	assert.Error(t, err)
}

func TestJWKSHandlerDBError(t *testing.T) {
	db := setupTestDB(t)
	server := &JWKServer{DB: db}
	db.Close() // force DB error

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	server.JWKSHandler(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestAuthHandlerDBError(t *testing.T) {
	db := setupTestDB(t)
	server := &JWKServer{DB: db}
	db.Close() // force DB error

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()
	server.AuthHandler(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestGetPort(t *testing.T) {
	t.Run("default port", func(t *testing.T) {
		os.Unsetenv("PORT")
		assert.Equal(t, "8080", getPort())
	})
	t.Run("valid PORT env", func(t *testing.T) {
		t.Setenv("PORT", "9090")
		assert.Equal(t, "9090", getPort())
	})
	t.Run("invalid PORT env falls back to 8080", func(t *testing.T) {
		t.Setenv("PORT", "notanumber")
		assert.Equal(t, "8080", getPort())
	})
}

func TestAuthHandler(t *testing.T) {
	db := setupTestDB(t)
	validPriv, _, _ := GenerateKeyPair()
	expiredPriv, _, _ := GenerateKeyPair()
	validExp := time.Now().Add(24 * time.Hour).Unix()
	expiredExp := time.Now().Add(-24 * time.Hour).Unix()
	db.StoreKey(validPriv, validExp)    // kid=1
	db.StoreKey(expiredPriv, expiredExp) // kid=2
	server := &JWKServer{DB: db}

	t.Run("valid POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth", nil)
		rec := httptest.NewRecorder()
		server.AuthHandler(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

		var out struct{ Token string `json:"token"` }
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
		require.NotEmpty(t, out.Token)

		token, err := jwt.Parse(out.Token, func(token *jwt.Token) (interface{}, error) {
			kid, _ := token.Header["kid"].(string)
			assert.Equal(t, "1", kid)
			return &validPriv.PublicKey, nil
		})
		require.NoError(t, err)
		require.True(t, token.Valid)

		claims := token.Claims.(jwt.MapClaims)
		exp, _ := claims["exp"].(float64)
		assert.True(t, int64(exp) >= time.Now().Unix(), "valid token must have exp in the future")
	})

	t.Run("expired POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
		rec := httptest.NewRecorder()
		server.AuthHandler(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var out struct{ Token string `json:"token"` }
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
		require.NotEmpty(t, out.Token)

		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		token, err := parser.Parse(out.Token, func(token *jwt.Token) (interface{}, error) {
			kid, _ := token.Header["kid"].(string)
			assert.Equal(t, "2", kid)
			return &expiredPriv.PublicKey, nil
		})
		require.NoError(t, err)
		require.True(t, token.Valid)

		claims := token.Claims.(jwt.MapClaims)
		exp, _ := claims["exp"].(float64)
		assert.True(t, int64(exp) < time.Now().Unix(), "expired token must have exp in the past")
	})

	t.Run("invalid GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		rec := httptest.NewRecorder()
		server.AuthHandler(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("no valid key returns 500", func(t *testing.T) {
		emptyDB := setupTestDB(t)
		priv, _, _ := GenerateKeyPair()
		emptyDB.StoreKey(priv, time.Now().Add(-time.Hour).Unix()) // only expired
		srv := &JWKServer{DB: emptyDB}
		req := httptest.NewRequest(http.MethodPost, "/auth", nil)
		rec := httptest.NewRecorder()
		srv.AuthHandler(rec, req)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("no expired key returns 500", func(t *testing.T) {
		emptyDB := setupTestDB(t)
		priv, _, _ := GenerateKeyPair()
		emptyDB.StoreKey(priv, time.Now().Add(time.Hour).Unix()) // only valid
		srv := &JWKServer{DB: emptyDB}
		req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
		rec := httptest.NewRecorder()
		srv.AuthHandler(rec, req)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("POST with Basic auth header succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth", nil)
		req.SetBasicAuth("userABC", "password123")
		rec := httptest.NewRecorder()
		server.AuthHandler(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		var out struct{ Token string `json:"token"` }
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
		assert.NotEmpty(t, out.Token)
	})

	t.Run("POST with JSON body succeeds", func(t *testing.T) {
		body := `{"username":"userABC","password":"password123"}`
		req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.AuthHandler(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		var out struct{ Token string `json:"token"` }
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
		assert.NotEmpty(t, out.Token)
	})
}
