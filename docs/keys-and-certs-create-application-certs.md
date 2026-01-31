# Keys and certificates

QTLS Bridge uses two PQ key pairs per endpoint:

- ML-KEM-1024; key establishment; per-message shared secret.
- ML-DSA; signing; parameter set inferred from key material.

## Circl mode key formats

Circl mode accepts:
- packed key material produced by `cmd/keyutil`;
- OpenSSL containers (PKCS#8 private keys; SPKI public keys) in PEM or DER.

Windows distribution note:
- Prefer the `.hex` key artefacts under `certs/circl/`; they are robust across packaging and copy tooling.

## Generate circl keys

From the repo root:

```sh
go run ./cmd/keyutil -out ./certs -role client -sig 87 -force
go run ./cmd/keyutil -out ./certs -role server -sig 87 -force
```

Client needs:
- its own KEM seed and signature private key;
- the server KEM public key and signature public key.

Server needs:
- its own KEM seed and signature private key;
- the client KEM public key and signature public key.

## Certificates

QTLS Bridge runs over existing HTTPS or mTLS; certificates are managed by your chosen approach:
- self-signed for development;
- private CA for internal deployments;
- public CA where appropriate.

Keep private keys out of logs and out of source control.
