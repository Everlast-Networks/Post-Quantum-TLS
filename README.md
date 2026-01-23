# QTLS Bridge

QTLS Bridge is a Post-Quantum Enabled client forward proxy, and a server reverse proxy. Together, they link to provide simplified post-quantum key establishment and signing for HTTP request and response bodies at the Application layer, without having to carry out extensive rewrites in client applications - and carried over existing HTTPS or mTLS connection (Post-Quantum or Traditional AES).

The intent is to allow a standardised method for teams and organisations to rapidly and reliably add post-quantum security to existing services, with minimal change or disruption to application code and operational topology, or into programs where the software is either hard to change, or legacy systems where post-quantum is not supported.

## Project scope

Designed for:
- Application-level protection for HTTP request and response bodies, plus selected headers;
- A local forward proxy for clients that cannot embed PQC primitives;
- A reverse proxy for servers that need PQC protection in front of an existing upstream;
- Windows, Linux, and macOS platform support.
- Evaluation on mobile (iOS and Android) or embedded platforms (ARM and RISC-V) through mobile support.

## Documentation

Start here:
- Quick Start (below)

Further reading in `/docs`:
- `docs/README.md`; index and navigation
- `docs/architecture.md`; components and data flow
- `docs/configuration.md`; config files and directory layout
- `docs/keys-and-certs.md`; key formats; generating keys and certs
- `docs/testing.md`; local test recipes; Windows quoting notes
- `docs/security.md`; disclosure; supply chain; hardening notes
- `docs/compliance.md`; standards context and procurement guidance

## Quick Start

### Prerequisites

- Go 1.23+
- OpenSSL 3.5+ for Test Certificate generation
- Python 3.12+ for example server endpoint.

### 1) Building a release tree

macOS or Linux:

```sh
chmod +x ./compile_install_mac_linux.sh
./compile_install_mac_linux.sh
```

Windows (PowerShell):

```powershell
.\compile_install_windows.ps1
```

By default, the scripts build the client and server and create `./release/`:

```
release/
  client/
    qtls-client[.exe]
    config/
      client.yaml
    certs/
      application/
      openssl/
  server/
    qtls-server[.exe]
    config/
      server.yaml
    certs/
      application/
      openssl/
```

### 2) Run a demo upstream (optional)

From the repo root:

```sh
python3 ./qtls_test_backend.py --listen 127.0.0.1 --port 5500
```

This demo backend exposes `/echo` and `/largefile` on localhost.

### 3) Run the server reverse proxy

```sh
./release/server/qtls-server -config ./release/server/config/server.yaml -debug
```

If your client is on a different host, set `listen: 0.0.0.0:5000` in the server config and use the server host address in the client URL.

### 4) Run the client forward proxy

Linux or macOS:

```sh
export QTLS_URL="http://127.0.0.1:5000/qtls"

./release/client/qtls-client \
  -config ./release/client/config/client.yaml \
  -server "$QTLS_URL" \
  -listen -listen-addr 127.0.0.1 -listen-port 7777 \
  -chunk-threshold $((8<<20)) -chunk-size $((4<<20)) \
  -timeout 15m \
  -debug
```

Windows (PowerShell):

```powershell
$QTLS_URL = "http://127.0.0.1:5000/qtls"
$chunkThreshold = 8 * 1024 * 1024
$chunkSize      = 4 * 1024 * 1024

.\release\client\qtls-client.exe `
  -config .\release\client\config\client.yaml `
  -server $QTLS_URL `
  -listen -listen-addr 127.0.0.1 -listen-port 7777 `
  -chunk-threshold $chunkThreshold -chunk-size $chunkSize `
  -timeout 15m `
  -debug
```

### 5) Send a request through the forward proxy

Plain text echo:

```sh
curl -sS -X POST "http://127.0.0.1:7777/echo" --data-binary "meow"
```

JSON as a string literal (recommended for simple echo servers):

Linux or macOS:

```sh
curl -sS -X POST "http://127.0.0.1:7777/echo" --data-binary '{ "hello": "world" }'
```

Windows (PowerShell); use single quotes or stop parsing for native programs:

```powershell
curl.exe -sS -X POST "http://127.0.0.1:7777/echo" --data-binary '{ "hello": "world" }'
```

```powershell
.\release\client\qtls-client.exe --% -config .\release\client\config\client.yaml -server http://127.0.0.1:5000/qtls -method POST -path /echo -message {"hello":"world"}
```

### 6) Download a file through the forward proxy

Linux or macOS:

```sh
curl -sS -o ./out_large.bin "http://127.0.0.1:7777/largefile"
```

Windows:

```powershell
curl.exe -sS -o .\out_large.bin "http://127.0.0.1:7777/largefile"
```

## Operational notes

- Application mode is the simplest for cross-platform use; use the `.hex` key artefacts under `certs/application/` on Windows.
- OpenSSL mode runs the `openssl` binary as an external command; it suits environments where OpenSSL is delivered and audited separately.
- Expect overhead; extra bytes on the wire; additional CPU for sealing and opening; more moving parts to test. Plan for load and observability early.

## Security

See `SECURITY.md` for reporting and disclosure expectations. Keep deployments conservative; treat this as security infrastructure that deserves testing, review, and operational discipline.

## Licence

Apache Licence 2.0; see `LICENSE`.
