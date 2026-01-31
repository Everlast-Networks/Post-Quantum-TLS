# QTLS Bridge

Open source; Apache 2.0 licence. A commercial edition exists with additional operational and compliance features (for example: certificate inventory checks, serial validation, and extended policy enforcement).

## What this project is

QTLS Bridge is an application security wrapper intended for internal networks and evaluation environments. It adds post-quantum cryptography at the application protocol level while you continue to run conventional transports (HTTP, HTTPS, mTLS) through a gateway such as NGINX or Apache.

QTLS Bridge is not the TLS wire protocol; it uses standard Internet PKI concepts (X.509 certificate chains) to authenticate peers while protecting application messages in a separate envelope format. See RFC 5280 for the Internet PKI certificate profile and RFC 8446 for TLS 1.3 as a point of comparison.

## Where it sits in your stack

- **Client**: a forward-proxy style component; it can run as a background local listener on 127.0.0.1 for existing apps, or as a one-shot binary invoked by scripts/automation.
- **Server**: a reverse-proxy style component; it typically sits behind your existing HTTPS/mTLS gateway and forwards to your upstream application.

A typical deployment is:

`App -> QTLS Client -> (HTTP/HTTPS/mTLS) -> Gateway (NGINX/Apache) -> QTLS Server -> Upstream service`

## Cryptography model

QTLS Bridge uses certificates for identity and trust decisions; the certificates contain signature keys, consistent with the Internet PKI profile.

For post-quantum encryption at the application level, QTLS uses separate KEM key material (sidecar files) rather than replacing the certificate public key. This avoids breaking conventional TLS semantics where the certificate public key must match the corresponding private key used by the TLS endpoint.

### OpenSSL mode

OpenSSL mode relies on the OpenSSL CLI for:

- certificate chain verification (`openssl verify`)
- extracting peer public keys from certificates (`openssl x509 -pubkey -noout`)

This is deliberate for PQ evaluation; it keeps verification behaviour consistent with the OpenSSL stack used by many gateways.

### Application mode

Application mode remains available for generating and using application-specific key material (via `keyutil`); it is orthogonal to certificate identity and is flagged to not be supported in future versions.

## Certificate and key artefacts

The CA export is expected to produce a folder with:

- `root.crt`, `chain.pem`, `issuing-ca.crt`, `issuing.crt`
- `client.crt`, `server.crt`
- an `openssl/` subdirectory containing signing keys and KEM materials

Key changes in the minting flow:

- KEM artefacts (`<stem>.kem.key`, `<stem>.kem.pub`, `<stem>.kem.seed`) are generated and exported for both client and server regardless of the `enable_kem` flag.
- `enable_kem` only controls whether the legacy debug behaviour is used to inject the KEM public key into the certificate SPKI via `-force_pubkey`; keep this disabled for normal operation.

## Commercial support

Everlast Networks provides commercial support in consulting and services for:
- production hardening and rollout planning;
- performance tuning and operational instrumentation;
- integration with existing gateways and service meshes;
- delivery of advanced features under disciplined security review.

## PKI, OCSP, and CRL boundaries

Do not build bespoke OCSP, CRL, or PKI extensions in the open-source repository. Those areas carry high compliance and security requirements; changes should be delivered with formal design review, test evidence, and audit artefacts. Everlast Networks will be shortly adding these components in a revised build and offering compliant implementations that have been rigorously tested.

## AI-assisted development

AI-assisted development can accelerate delivery, but it can also introduce subtle security defects. For cryptographic, parsing, or protocol changes:
- require independent peer review and security review;
- add regression tests and cross-platform fixtures;
- run static analysis and fuzzing for message parsing;
- avoid changes that lack measurable evidence.

## Certificates and trust model

QTLS Bridge supports self-signed certificates and CA-issued certificates (private or public). For teams that want a managed CA with strong defaults and reduced operational burden, Everlast Networks offers a CA service appropriate for production deployments.


### Optional detached binding for auditability

If enabled, the minting logic may emit `<stem>.kem.pub.sig` as a detached signature over `<stem>.kem.pub` using `<stem>.sig.key`. This provides an explicit binding between the KEM public key and the identity certificate private key.

## Configuration model (YAML)

Client and server configuration files use stable, TLS-aligned naming for certificate paths:

- `x509.root_cert_path`
- `x509.chain_path`
- `x509.client_cert_path`
- `x509.server_cert_path`

OpenSSL invocation is controlled via:

- `openssl.dir` (Linux/macOS: standalone install under `/opt`; Windows often uses a system-installed OpenSSL on PATH)
- `openssl.command` (optional explicit path to `openssl`)
- `openssl.conf_path` (path to an OpenSSL config that loads the PQ provider when required)

Keys are configured explicitly:

- `keys.sig_private_path` (this node’s signing key)
- `keys.kem_private_path` (this node’s KEM private key)
- `keys.kem_public_path` (peer KEM public key)
- `keys.sig_public_path` is optional in OpenSSL mode; it can be derived from the peer certificate.

## Operational notes

- Ensure `OPENSSL_CONF` is set for OpenSSL mode so provider configuration is loaded consistently; the code sets this environment for child processes when `openssl.conf_path` is provided.
- For production hardening, avoid system calls and prefer library bindings; for this R&D project, OpenSSL CLI calls are accepted by design.

## Security notes and trade-offs

- This project provides application-message confidentiality and authenticity; it does not implement the TLS handshake or record layer.
- Certificate chain validation follows Internet PKI conventions; pinning the root CA is the cleanest operational model for intranets.
- The legacy `-force_pubkey` path should remain off unless testing a specific compatibility scenario; it can produce certificates that no longer match the private key expected by conventional TLS endpoints.

## Roadmap

- WolfSSL integration is under active development as part of the broader compatibility pipeline.
