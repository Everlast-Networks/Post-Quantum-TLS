# Changelog

**260124**
- Changelog created
- Began updates to documentation and codebase replacing mode=application with mode=circl.

**270126**
- Updated documentation to reflect changes in codebase.

**280126**
- Changed README to reflect project fit and use-cases.
- `qtls_application.py` - Replaced the conditional KEM generator with ensure_kem_materials() so that client.kem.{key,pub,seed} and server.kem.{key,pub,seed} are always emitted. Enable_kem will now only control whether the certificate SPKI is overwritten via openssl x509 -force_pubkey for legacy/debug use cases.
- `qtls_application.py` - Added optional detached binding sign_kem_pub_detached()) to produce <stem>.kem.pub.sig using the identity private key. Call it immediately after each ensure_kem_materials() invocation for server and client, giving an auditable link between the KEM public key and the signing identity.
- `internal/config/config.go` - Introduced x509.* paths (root_cert_path, chain_path, client_cert_path, server_cert_path) plus openssl.conf_path, this separates identity material from protocol keys, and makes path resolution stable relative to the config file directory.
- `internal/certinfo/verify_openssl.go` - Added OpenSSL-based chain verification (openssl verify) and peer public key extraction (openssl x509 -pubkey -noout) for PQ-signed chains in OpenSSL mode.

**290126**
- `internal/osslutil/osslutil.go` - Added a small helper to inject OPENSSL_CONF into child process environments. This will ensure the OQS provider config is consistently applied when invoking OpenSSL CLI.
- `cmd/client/main.go` - Updated certificate chain validation to use OpenSSL in mode: openssl (which is a prioritised direction); but retained Go crypto/x509 verification for non-OpenSSL operative modes. Keys are now loaded from cfg.Keys with peer signature public key derived from server.crt when sig_public_path is blank in OpenSSL mode.
- `cmd/server/main.go` - Mirrored the client-side changes - OpenSSL-mode chain verification is used for both server and client certs, and the peer signature public key is now derived from client.crt when sig_public_path is blank.
- `config/client.yaml` + `config/server.yaml` - Added explicit x509 and openssl sections consistent with the new structs. Default paths match your export layout (certs at certs_dir root; keys under certs_dir/openssl/).
- Added copyright disclaimer to program file headers.

**300126**
- Updated `README.md`
- Updated `Changelog.md`
- Updated `AGENTS.md`