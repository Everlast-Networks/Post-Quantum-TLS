# QTLS certificates; manual creation (OpenSSL + keyutil)

This document will guide you through creating your own QTLS certificate set for use with QTLS Client/Server software. You will generate:

- an ML-DSA Root CA certificate (`root.crt`) and private key (`root.key`);
- server and client certificates signed by the Root CA;
- ML-KEM keypairs for the server and client (used by QTLS for key establishment);
- Circl-mode key material produced by `keyutil`.

Note: An automation script is being actively developed.

## Prerequisites

- Linux shell (Debian 12 recommended).
- OpenSSL 3.5 or above available on `PATH`; it must support **ML-DSA** and **ML-KEM** (older versions are supported with the add-in for oqs-provider, but we highly recommend using OpenSSL 3.5+ where possible). Note that your organisation *may* require a FIPS compliant precompiled version of OpenSSL.
- `keyutil` built in your repo at `./bin/keyutil`.

If OpenSSL needs the OQS provider, the commands below include a safe fallback.

## Output layout

From the project directory:

```
certs/
  openssl/
  circl/
  root.crt
  server.crt
  client.crt
  chain.pem
```

Certificate Locations:

- QTLS OpenSSL mode uses files under `certs/openssl/`.
- QTLS Circl mode uses files under `certs/circl/`.

## Step 1: Create the folders

```bash
mkdir -p certs/openssl certs/circl
```

## Step 2: Set the names and validity

```bash
ROOT_CN="QTLS Root PQ"
SERVER_CN="api.example.local"
SERVER_SANS="api.example.local,localhost"
CLIENT_CN="qtls-client"

MLDSA_LEVEL="87"     # example; use the level your deployment expects - we recommend leaving this at 87.
DAYS_ROOT="3650"
DAYS_EE="397"
```

## Step 3: Pick the OpenSSL algorithm and provider flags

Some OpenSSL builds expose `MLDSA87`; others require the OQS provider and use `mldsa87`.

```bash
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

if "$OPENSSL_BIN" list -signature-algorithms | grep -q "MLDSA${MLDSA_LEVEL}"; then
  SIGALG="MLDSA${MLDSA_LEVEL}"
  PROV=()
else
  SIGALG="mldsa${MLDSA_LEVEL}"
  PROV=(-provider oqsprovider -provider default)
fi
```

## Step 4: Create a minimal OpenSSL config

```bash
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/qtls.cnf" <<'EOF'
[ v3_ca ]
basicConstraints = critical,CA:true,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ server_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth

[ client_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
EOF
```

## Step 5: Mint the OpenSSL bundle

All OpenSSL outputs go into `certs/openssl/`.

```bash
OUT="certs/openssl"
```

### 5.1 Root CA (ML-DSA)

```bash
"$OPENSSL_BIN" genpkey -algorithm "$SIGALG" "${PROV[@]}" -out "$OUT/root.key"

"$OPENSSL_BIN" req -x509 -new   -key "$OUT/root.key"   -out "$OUT/root.crt"   -days "$DAYS_ROOT" -sha512   -subj "/CN=$ROOT_CN"   -config "$WORK/qtls.cnf" -extensions v3_ca   "${PROV[@]}"
```

### 5.2 Server keys (ML-DSA signing; ML-KEM keypair)

```bash
"$OPENSSL_BIN" genpkey -algorithm "$SIGALG" "${PROV[@]}" -out "$OUT/server.sig.key"
"$OPENSSL_BIN" pkey -in "$OUT/server.sig.key" -pubout -out "$OUT/server.sig.pub"

"$OPENSSL_BIN" genpkey -algorithm "ML-KEM-1024" "${PROV[@]}" -out "$OUT/server.kem.key"
"$OPENSSL_BIN" pkey -in "$OUT/server.kem.key" -pubout -out "$OUT/server.kem.pub"
```

### 5.3 Server certificate (public key forced to the ML-KEM public key)

QTLS expects the server certificate’s public key to be the ML-KEM public key; OpenSSL can do this using `-force_pubkey`.

```bash
SAN_EXT="subjectAltName=$(printf '%s' "$SERVER_SANS" | awk -v RS=',' '{gsub(/^[ 	]+|[ 	]+$/, "", $0); if (NR==1) printf "DNS:%s", $0; else printf ",DNS:%s", $0}')"

"$OPENSSL_BIN" genpkey -algorithm "$SIGALG" "${PROV[@]}" -out "$OUT/server.tmp.key"

"$OPENSSL_BIN" req -new   -key "$OUT/server.tmp.key"   -out "$OUT/server.tmp.csr"   -subj "/CN=$SERVER_CN"   -addext "$SAN_EXT"   "${PROV[@]}"

"$OPENSSL_BIN" x509 -req   -in "$OUT/server.tmp.csr"   -CA "$OUT/root.crt" -CAkey "$OUT/root.key" -CAcreateserial   -out "$OUT/server.crt"   -days "$DAYS_EE" -sha512   -extfile "$WORK/qtls.cnf" -extensions server_cert   -force_pubkey "$OUT/server.kem.pub"   "${PROV[@]}"
```

### 5.4 Client keys and certificate (ML-DSA signing; ML-KEM keypair)

```bash
"$OPENSSL_BIN" genpkey -algorithm "$SIGALG" "${PROV[@]}" -out "$OUT/client.sig.key"
"$OPENSSL_BIN" pkey -in "$OUT/client.sig.key" -pubout -out "$OUT/client.sig.pub"

# Compatibility alias; some integrations expect client.key
cp -f "$OUT/client.sig.key" "$OUT/client.key"

"$OPENSSL_BIN" req -new   -key "$OUT/client.sig.key"   -out "$OUT/client.csr"   -subj "/CN=$CLIENT_CN"   "${PROV[@]}"

"$OPENSSL_BIN" x509 -req   -in "$OUT/client.csr"   -CA "$OUT/root.crt" -CAkey "$OUT/root.key" -CAserial "$OUT/root.srl"   -out "$OUT/client.crt"   -days "$DAYS_EE" -sha512   -extfile "$WORK/qtls.cnf" -extensions client_cert   "${PROV[@]}"

"$OPENSSL_BIN" genpkey -algorithm "ML-KEM-1024" "${PROV[@]}" -out "$OUT/client.kem.key"
"$OPENSSL_BIN" pkey -in "$OUT/client.kem.key" -pubout -out "$OUT/client.kem.pub"
```

### 5.5 Chain and basic verification

```bash
cp -f "$OUT/root.crt" "$OUT/chain.pem"
"$OPENSSL_BIN" verify -CAfile "$OUT/root.crt" "$OUT/server.crt" "$OUT/client.crt"
```

## Step 6: Produce Circl-mode artefacts with keyutil

This step is optional, and only required if you intend on using QTLS Bridge in Circl Mode - that is, using internal crypto implementations rather than OpenSSL on your target systems - ie, where deployment is constrained, OpenSSL is not supported, etc.

Circl-mode outputs go into `certs/circl/`.

Run the first command that works for your `keyutil` build:

```bash
APP_OUT="certs/circl"

./bin/keyutil -out "$APP_OUT" -mldsa "$MLDSA_LEVEL" -force   || ./bin/keyutil --out "$APP_OUT" --mldsa "$MLDSA_LEVEL" --force   || ( ./bin/keyutil -out "$APP_OUT" -role client -sig "$MLDSA_LEVEL" -force        && ./bin/keyutil -out "$APP_OUT" -role server -sig "$MLDSA_LEVEL" -force )
```

Note: `certs/circl/` is owned by `keyutil`; do not attempt to “convert” OpenSSL keys into this format as this will break QTLS.

## Step 7: Convenience copies at `certs/` root

These make it easier for external software to find the certificates without caring about subfolders.

```bash
cp -f "$OUT/root.crt"   "certs/root.crt"
cp -f "$OUT/server.crt" "certs/server.crt"
cp -f "$OUT/client.crt" "certs/client.crt"
cp -f "$OUT/chain.pem"  "certs/chain.pem"
```

## Step 8: File permissions

Keep private keys restricted.

```bash
chmod 600   "$OUT/root.key"   "$OUT/server.sig.key" "$OUT/server.kem.key"   "$OUT/client.sig.key" "$OUT/client.kem.key" "$OUT/client.key"   2>/dev/null || true

chmod 644   "$OUT/root.crt" "$OUT/server.crt" "$OUT/client.crt" "$OUT/chain.pem"   "$OUT/server.sig.pub" "$OUT/server.kem.pub"   "$OUT/client.sig.pub" "$OUT/client.kem.pub"   2>/dev/null || true

chmod 600 certs/circl/*.seed 2>/dev/null || true
chmod 644 certs/circl/*.pub  2>/dev/null || true
```

## Quick check

```bash
"$OPENSSL_BIN" x509 -in "certs/server.crt" -noout -subject -serial
"$OPENSSL_BIN" verify -CAfile "certs/root.crt" "certs/server.crt"
ls -la certs/circl
```
