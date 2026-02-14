# Assignment Requirements Checklist

This document maps each requirement of *Implementing a Basic JWKS Server* to this repository.

## Key Generation
- **RSA key pair generation** — `keys.go`: `GenerateKeyPair()` (2048-bit RSA).
- **kid and expiry per key** — `keys.go`: `KeyEntry` has `Kid` and `Expiry`; set in `main.go` and tests.

## Web Server
- **Serve HTTP on port 8080** — `main.go`: default `:8080`; `PORT` env overrides.
- **RESTful JWKS endpoint** — `handlers.go`: GET `/.well-known/jwks.json`, JSON with `keys` array (kty, use, alg, kid, n, e).
- **Only non-expired keys in JWKS** — `handlers.go`: keys with `Expiry <= now` are excluded.
- **POST /auth returns signed JWT** — `handlers.go`: POST only; returns `{"token": "<signed JWT>"}` with `kid` in header.
- **?expired=true → JWT with expired key and past exp** — `handlers.go`: uses `GetExpiredKey()`, sets token `exp` in the past.

## Documentation / Organization / Linting
- **Code organized** — `main.go`, `keys.go`, `handlers.go`, `main_test.go`.
- **Comments where needed** — Doc comments on types and handlers.
- **Linted** — `go vet ./...` passes.

## Tests
- **Test suite present** — `main_test.go`: TestKeyStore, TestJWKSHandler, TestAuthHandler, TestBigEndianBytes, TestSetupMux.
- **Coverage over 80%** — `go test -cover` reports >80% (e.g. 85%+).

## Blackbox / Test Client
- **Test client works** — POST `/auth` with no body returns 200 and a signed JWT.

## kid in JWT and JWKS
- **JWTs include kid** — `handlers.go`: `token.Header["kid"] = entry.Kid`.
- **JWKS serves key by kid** — Each JWK has `Kid`; verifiers match JWT header to JWKS key.
