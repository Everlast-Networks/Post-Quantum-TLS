# Build and release

The repository includes two build scripts:

- `compile_install_mac_linux.sh`
- `compile_install_windows.ps1`

Both scripts:
- validate a Go 1.22+ toolchain;
- build `cmd/client` and `cmd/server`;
- create a clean `./release/` tree for distribution.

## Cross compilation

Both scripts accept `GOOS` and `GOARCH`; they validate the target using `go tool dist list`.

## Release tree

Release artefacts are produced under:

- `release/client/`
- `release/server/`

Each side has:
- a `config/` directory containing YAML;
- a `certs/` directory containing `application/` and `openssl/`.
