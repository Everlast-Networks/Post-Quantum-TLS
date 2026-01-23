# Configuration

QTLS Bridge uses YAML config files; the build scripts place them under `release/<side>/config/`.

## Path resolution

`certs_dir` is resolved relative to the YAML file location; it does not depend on the current working directory.

Example release tree:

```
release/
  client/
    config/client.yaml
    certs/...
  server/
    config/server.yaml
    certs/...
```

In this layout, `certs_dir: ../certs` is correct because the YAML file actually lives in `config/`.

## Client configuration

See `config/client-example-application.yaml` and `config/client-example-openssl.yaml`.

Key points:
- `mode`; `application`, `openssl`, or `system` (Windows only).
- `certs_dir`; directory that holds `application/` and `openssl/`.
- `keys.*`; key material paths relative to `certs_dir` unless absolute.

## Server configuration

See `config/server-example-application.yaml` and `config/server-example-openssl.yaml`.

Key points:
- `listen`; bind address for the reverse proxy.
- `upstream`; where requests are forwarded after opening and verifying.
- `replay_*`; bounds for replay tracking.

## Windows payload quoting

When your upstream behaves as a plain text echo server, send JSON as a string; avoid `application/json`. Use PowerShell single-quoted strings or `--%` for native programs.
