# Testing and troubleshooting

## Local demo upstream

```sh
python3 ./qtls_test_backend.py --listen 127.0.0.1 --port 5500
```

## Start server

```sh
./release/server/qtls-server -config ./release/server/config/server.yaml -debug
```

## Start client proxy

Linux or macOS:

```sh
export QTLS_URL="http://127.0.0.1:5000/qtls"
./release/client/qtls-client -config ./release/client/config/client.yaml -server "$QTLS_URL" -listen -listen-addr 127.0.0.1 -listen-port 7777 -chunk-threshold $((8<<20)) -chunk-size $((4<<20)) -timeout 15m -debug
```

Windows:

```powershell
$QTLS_URL = "http://127.0.0.1:5000/qtls"
$chunkThreshold = 8 * 1024 * 1024
$chunkSize      = 4 * 1024 * 1024

.\release\client\qtls-client.exe -config .\release\client\config\client.yaml -server $QTLS_URL -listen -listen-addr 127.0.0.1 -listen-port 7777 -chunk-threshold $chunkThreshold -chunk-size $chunkSize -timeout 15m -debug
```

## Echo test

```sh
curl -sS -X POST "http://127.0.0.1:7777/echo" --data-binary "meow"
```

If your upstream is a strict JSON endpoint, set the correct `Content-Type` and ensure the upstream expects JSON. If your upstream is a plain text echo, send JSON as text.

## Common issues

- Windows quoting; prefer single quotes or `--%` for native programs.
- Cross-host test; set server `listen` to a reachable address; update the client `-server` URL.
- ML-DSA key parsing failures on Windows; use `.hex` key files under `certs/application/`.
