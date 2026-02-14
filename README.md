# JWKS Server

A RESTful JSON Web Key Set (JWKS) server implemented in Go. It exposes public keys for JWT verification and an authentication endpoint that issues signed JWTs. The server uses RSA key pairs with key identifiers (`kid`) and expiry timestamps; expired keys are excluded from the JWKS response.

## Overview

- **JWKS endpoint** (`GET /.well-known/jwks.json`): Returns public keys in JWKS format. Only keys that have not expired are included, so clients can verify JWTs using the correct key identified by `kid`.
- **Auth endpoint** (`POST /auth`): Returns a signed JWT (RS256) with `kid` in the header. Optional query parameter `expired=true` returns a JWT signed with an expired key and with `exp` set in the past.

This project is for educational purposes. In production, key management and authentication would integrate with a proper identity provider and security practices.

## Project Structure

| File | Description |
|------|-------------|
| `main.go` | Entry point, server setup, and HTTP listener. Port is configurable via `PORT` (default 8080). |
| `keys.go` | RSA key generation, key store with thread-safe access, and JWK encoding helpers. |
| `handlers.go` | HTTP handlers for the JWKS and auth endpoints. |
| `main_test.go` | Unit and handler tests; coverage meets the required threshold. |

## Prerequisites

- [Go](https://go.dev/dl/) 1.21 or later, installed and on your `PATH`.

## Building and Running

From the project root:

```bash
go run .
```

The server listens on **port 8080** by default. To use a different port (e.g. if 8080 is in use):

**Windows (PowerShell):**
```powershell
$env:PORT="8081"; go run .
```

**Unix-like (Bash):**
```bash
PORT=8081 go run .
```

## Testing

Run the test suite (verbose: shows each test name and result):

```bash
go test -v
```

Run tests with coverage (single-line summary):

```bash
go test -cover
```

Run tests and generate a **detailed coverage report** (table of statements and coverage per function, suitable for screenshots):

```bash
go test -v -coverprofile=coverage.out
go tool cover -func coverage.out
```

On Windows PowerShell, use `go test -v "-coverprofile=coverage.out"` (quotes) so the profile file is created correctly.

The coverage table shows coverage percentage per function and total coverage. The test suite covers key generation and storage, the JWKS endpoint (including exclusion of expired keys and correct JWK fields), the auth endpoint (valid and expired tokens, method restrictions), and server setup. Linting can be run with:

```bash
go vet ./...
```

## API Reference

Base URL: `http://localhost:8080` (or the port you configured).

### GET /.well-known/jwks.json

Returns a JSON object with a `keys` array. Each key includes `kty`, `use`, `alg`, `kid`, `n`, and `e`. Only non-expired keys are included. Other HTTP methods return `405 Method Not Allowed`.

### POST /auth

Returns a JSON object with a single field `token` containing a signed JWT. The JWT header includes `kid` so verifiers can select the correct key from the JWKS. No request body is required.

- **POST /auth** — JWT signed with a valid key; `exp` is in the future.
- **POST /auth?expired=true** — JWT signed with an expired key; `exp` is in the past.

Other HTTP methods return `405 Method Not Allowed`.

## Verifying the Endpoints

Replace `8080` with your port if you set `PORT`.

**Using curl (e.g. Git Bash, WSL, or `curl.exe` in PowerShell):**

```bash
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
```

**Using PowerShell (Invoke-WebRequest):**

```powershell
Invoke-WebRequest -Uri "http://localhost:8080/.well-known/jwks.json" -UseBasicParsing | Select-Object -ExpandProperty Content
Invoke-WebRequest -Uri "http://localhost:8080/auth" -Method POST -UseBasicParsing | Select-Object -ExpandProperty Content
Invoke-WebRequest -Uri "http://localhost:8080/auth?expired=true" -Method POST -UseBasicParsing | Select-Object -ExpandProperty Content
```

Expected responses: JWKS with a `keys` array; auth responses with a `token` field containing a JWT string.

## Screenshots

The `screenshots/` directory contains:

- **test-client.png** — The course test client (or equivalent POST to `/auth`) running successfully against the server.
- **test-coverage.png** — Output of `go test -cover` (or the detailed coverage commands in the Testing section) showing coverage above 80%.

**Identifying information:** Per the assignment, include identifying information on each screenshot (e.g. your name, course, or student ID as required by your instructor).

## Requirements Checklist

A mapping of the assignment requirements to this implementation is provided in **REQUIREMENTS.md**.

## Deliverables (Before You Submit)

1. **GitHub repo** — Push this code to a GitHub repository and provide the link as required.
2. **Test client screenshot** — In `screenshots/test-client.png`: test client (or POST to `/auth`) running successfully. Include identifying information on the screenshot.
3. **Test suite screenshot** — In `screenshots/test-coverage.png`: output of `go test -cover` (or the verbose + coverage table commands) showing coverage percent. Include identifying information on the screenshot.
