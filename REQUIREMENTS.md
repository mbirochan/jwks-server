# Project 2 Requirements Checklist

## SQLite Backed Storage
- **DB file:** `totally_not_my_privateKeys.db` — created on startup in `main.go`.
- **Table schema:** `CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)` — `db.go`: `NewDatabase()`.
- **Save private keys to DB:** `db.go`: `StoreKey()` serializes keys as PKCS1 PEM and inserts with parameterized query.
- **Keys generated on startup:** `main.go`: `SetupMuxWithDB()` generates one valid key (+1hr) and one expired key (-1hr).

## POST /auth
- **Reads key from DB:** `handlers.go`: `AuthHandler()` calls `s.DB.GetValidKey()` or `s.DB.GetExpiredKey()`.
- **Unexpired key by default:** `db.go`: `GetValidKey()` — `SELECT ... WHERE exp > ? LIMIT 1`.
- **Expired key with ?expired=true:** `db.go`: `GetExpiredKey()` — `SELECT ... WHERE exp <= ? LIMIT 1`.
- **Signs JWT and returns it:** `handlers.go`: RS256 signing with `kid` in header, returns `{"token": "..."}`.
- **Handles Basic auth and JSON body:** Handler ignores credentials (no validation required), does not reject either format.

## GET /.well-known/jwks.json
- **Reads all valid keys from DB:** `db.go`: `GetAllValidKeys()` — `SELECT ... WHERE exp > ?`.
- **Returns JWKS response:** `handlers.go`: `JWKSHandler()` builds JWK array with kty, use, alg, kid, n, e.

## SQL Injection Prevention
- **Parameterized queries:** All queries in `db.go` use `?` placeholders — `StoreKey`, `GetValidKey`, `GetExpiredKey`, `GetAllValidKeys`.

## Documentation / Organization / Linting
- **Code organized:** Separated into `main.go`, `db.go`, `keys.go`, `handlers.go`, `main_test.go`.
- **Comments:** Doc comments on all exported types, functions, and methods.
- **Linted:** `go vet ./...` passes cleanly.

## Tests
- **Test suite:** `main_test.go` — TestDatabase, TestSerializeDeserializeKey, TestJWKSHandler, TestAuthHandler, TestSetupMux, TestGetPort, error path tests.
- **Coverage:** `go test -cover` reports 82.0% (>80% threshold).
- **Test isolation:** All tests use in-memory SQLite (`:memory:`), no file cleanup needed.

## Blackbox / Gradebot Testing
- **Gradebot score:** 96.47% — all functional rubric items passed with full marks.
