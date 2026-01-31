# Architecture

QTLS Bridge contains two binaries:

- `qtls-client`; a local forward proxy and a one-shot request tool.
- `qtls-server`; a reverse proxy that terminates QTLS requests and forwards to an upstream.

## Request path

Proxy mode:

1. An application sends HTTP to the local client listener (default `127.0.0.1:7777`).
2. The client seals the request; derives a per-message shared secret; signs the envelope; then sends a QTLS request to the server endpoint.
3. The server verifies and opens the envelope; reconstructs the upstream request; forwards it to the configured upstream.
4. The upstream response is returned; the server seals it; the client opens it; the client returns a normal HTTP response to the local application.

One-shot mode:

- The client constructs a single request from CLI flags; sends it to the server; prints the response body to stdout.

## Repository layout

- `cmd/client`; CLI and forward proxy implementation.
- `cmd/server`; server reverse proxy; chunk reassembly endpoints.
- `cmd/keyutil`; key generation for circl mode.
- `internal/qtls`; sealing and opening; replay ID generation; shared secret derivation.
- `internal/crypto/app`; Go crypto provider (CIRCL) for ML-KEM and ML-DSA.
- `internal/crypto/openssl`; OpenSSL external command integration.
- `internal/crypto/system`; Windows CNG integration for system mode.
- `internal/envelope` and `internal/payload`; deterministic framing.

## Modes

- `circl`; Go implementation (CIRCL) for ML-KEM and ML-DSA.
- `openssl`; external OpenSSL binary; suitable for audited OpenSSL deployments.
- `system`; Windows-only; uses CNG; intended for approved platform primitives.

Trade-offs:
- Stronger cryptography comes with overhead; expect larger requests; more CPU; more bandwidth.
- The protocol adds its own envelope; plan for observability and explicit limits.
