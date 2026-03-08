# JWKS Server (Project 2 — SQLite Backed)

A RESTful JSON Web Key Set (JWKS) server implemented in Go, backed by a SQLite database for persistent key storage. It exposes public keys for JWT verification and an authentication endpoint that issues signed JWTs using RSA key pairs with key identifiers (`kid`) and expiry timestamps.

## Overview

- **SQLite storage** — Private keys are persisted in `totally_not_my_privateKeys.db` using PKCS1 PEM encoding. Keys survive server restarts.
- **JWKS endpoint** (`GET /.well-known/jwks.json`) — Returns public keys in JWKS format. Only non-expired keys are included.
- **Auth endpoint** (`POST /auth`) — Returns a signed JWT (RS256) with `kid` in the header. Optional query parameter `expired=true` returns a JWT signed with an expired key. Accepts requests with HTTP Basic auth or JSON body credentials.
- **SQL injection prevention** — All database queries use parameterized placeholders (`?`).

## Project Structure

| File | Description |
|------|-------------|
| `main.go` | Entry point, server setup, database initialization, and HTTP listener. |
| `db.go` | SQLite database operations: table creation, key storage/retrieval, PEM serialization. |
| `keys.go` | RSA key generation (`GenerateKeyPair`) and JWK encoding helpers (`BigEndianBytes`). |
| `handlers.go` | HTTP handlers for the JWKS and auth endpoints. |
| `main_test.go` | Unit and integration tests using in-memory SQLite; coverage >80%. |

## Prerequisites

- [Go](https://go.dev/dl/) 1.21 or later

## Building and Running

```bash
go build -o jwks-server.exe .
./jwks-server.exe
```

Or simply:

```bash
go run .
```

The server listens on **port 8080** by default. Override with `PORT` environment variable:

```bash
PORT=9090 go run .
```

On startup, the server creates `totally_not_my_privateKeys.db` in the current directory with one valid key (expires in 1 hour) and one expired key (expired 1 hour ago).

## Database Schema

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```

Private keys are stored as PKCS1 PEM-encoded BLOBs. The `exp` column holds a Unix timestamp.

## Testing

Run tests with coverage:

```bash
go test -v -cover ./...
```

Lint:

```bash
go vet ./...
```

## API Reference

### GET /.well-known/jwks.json

Returns a JSON object with a `keys` array containing all non-expired public keys. Each key includes `kty`, `use`, `alg`, `kid`, `n`, and `e`. Other HTTP methods return `405`.

### POST /auth

Returns `{"token": "<signed JWT>"}`. The JWT header includes `kid` for key matching.

- **POST /auth** — JWT signed with a valid key; `exp` in the future.
- **POST /auth?expired=true** — JWT signed with an expired key; `exp` in the past.

Accepts HTTP Basic auth headers and JSON body credentials without rejecting. Other HTTP methods return `405`.

## Screenshots

The `screenshots/` directory contains:

- **gradebot_test.png** — Gradebot test client output running against the server (Project 2).
- **test-coverage.png** — Test suite output showing coverage percentage above 80%.
