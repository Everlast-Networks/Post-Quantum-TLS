#!/usr/bin/env bash
set -euo pipefail

# ---- repo-specific defaults (match this repository) ----
CLIENT_PKG="./cmd/client"
SERVER_PKG="./cmd/server"

CLIENT_BIN="qtls-client"
SERVER_BIN="qtls-server"

CLIENT_CFG_SRC="./config/client-example-application.yaml"
SERVER_CFG_SRC="./config/server-example-application.yaml"

RELEASE_DIR="./release"
# -------------------------------------------------------

usage() {
  cat <<'EOF'
Usage:
  ./compile_install_mac_linux.sh [--os <goos>] [--arch <goarch>] [--cgo <0|1>] [--build <string>] [--with-keyutil]

Examples:
  ./compile_install_mac_linux.sh
  ./compile_install_mac_linux.sh --os linux --arch amd64
  ./compile_install_mac_linux.sh --os windows --arch amd64 --build "V2601 OSS"
EOF
}

die() { echo "fatal: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

parse_go_version_ok() {
  # Returns 0 when Go version is >= 1.22; else 1.
  local v maj min
  v="$(go env GOVERSION 2>/dev/null || true)"
  v="${v#go}"
  maj="$(echo "$v" | awk -F. '{print $1}')"
  min="$(echo "$v" | awk -F. '{print $2}')"
  [[ "${maj:-0}" -gt 1 ]] && return 0
  [[ "${maj:-0}" -lt 1 ]] && return 1
  [[ "${min:-0}" -ge 22 ]]
}

GOOS_ARG=""
GOARCH_ARG=""
CGO_VAL="0"
BUILD_STR=""
WITH_KEYUTIL="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --os) GOOS_ARG="${2:-}"; shift 2 ;;
    --arch) GOARCH_ARG="${2:-}"; shift 2 ;;
    --cgo) CGO_VAL="${2:-}"; shift 2 ;;
    --build) BUILD_STR="${2:-}"; shift 2 ;;
    --with-keyutil) WITH_KEYUTIL="1"; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

need_cmd go

[[ -f "./go.mod" ]] || die "run this from the repo root (go.mod not found)"

echo "Go toolchain: $(go env GOVERSION)"
parse_go_version_ok || die "Go 1.22+ required"

HOST_GOOS="$(go env GOOS)"
HOST_GOARCH="$(go env GOARCH)"

if [[ -z "$GOOS_ARG" ]]; then
  echo "Select target OS (default: ${HOST_GOOS})"
  select choice in "linux" "darwin" "windows" "freebsd" "openbsd" "netbsd" "other"; do
    if [[ "$choice" == "other" ]]; then
      read -r -p "Enter GOOS: " GOOS_ARG
    elif [[ -n "${choice:-}" ]]; then
      GOOS_ARG="$choice"
    else
      GOOS_ARG="$HOST_GOOS"
    fi
    break
  done
fi

if [[ -z "$GOARCH_ARG" ]]; then
  echo "Select target architecture (default: ${HOST_GOARCH})"
  select choice in "amd64" "arm64" "386" "arm" "other"; do
    if [[ "$choice" == "other" ]]; then
      read -r -p "Enter GOARCH: " GOARCH_ARG
    elif [[ -n "${choice:-}" ]]; then
      GOARCH_ARG="$choice"
    else
      GOARCH_ARG="$HOST_GOARCH"
    fi
    break
  done
fi

TARGET="${GOOS_ARG}/${GOARCH_ARG}"

echo "Validating target: ${TARGET}"
if ! go tool dist list | grep -Fqx "${TARGET}"; then
  die "unsupported target for this Go toolchain: ${TARGET} (check: go tool dist list)"
fi

if [[ -z "$BUILD_STR" ]]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    BUILD_STR="$(git describe --tags --always --dirty 2>/dev/null || git rev-parse --short HEAD)"
  else
    BUILD_STR="$(date -u +%Y%m%dT%H%M%SZ)"
  fi
fi

[[ "$CGO_VAL" == "0" || "$CGO_VAL" == "1" ]] || die "--cgo must be 0 or 1"

EXT=""
if [[ "$GOOS_ARG" == "windows" ]]; then
  EXT=".exe"
fi

echo "Preparing release tree: ${RELEASE_DIR}"
rm -rf "${RELEASE_DIR}"
mkdir -p \
  "${RELEASE_DIR}/client" \
  "${RELEASE_DIR}/client/config" \
  "${RELEASE_DIR}/server" \
  "${RELEASE_DIR}/server/config" \
  "${RELEASE_DIR}/client/certs/openssl" \
  "${RELEASE_DIR}/client/certs/application" \
  "${RELEASE_DIR}/server/certs/openssl" \
  "${RELEASE_DIR}/server/certs/application"

echo "Copying default configs (application examples)"
[[ -f "${CLIENT_CFG_SRC}" ]] || die "missing config: ${CLIENT_CFG_SRC}"
[[ -f "${SERVER_CFG_SRC}" ]] || die "missing config: ${SERVER_CFG_SRC}"
cp -f "${CLIENT_CFG_SRC}" "${RELEASE_DIR}/client/config/client.yaml"
cp -f "${SERVER_CFG_SRC}" "${RELEASE_DIR}/server/config/server.yaml"

CLIENT_OUT="${RELEASE_DIR}/client/${CLIENT_BIN}${EXT}"
SERVER_OUT="${RELEASE_DIR}/server/${SERVER_BIN}${EXT}"

echo "Building:"
echo "  ${CLIENT_OUT}"
echo "  ${SERVER_OUT}"

ENVV=( "CGO_ENABLED=${CGO_VAL}" "GOOS=${GOOS_ARG}" "GOARCH=${GOARCH_ARG}" )

env "${ENVV[@]}" \
  go build -trimpath -buildvcs=false -ldflags "-X main.Build=${BUILD_STR}" \
  -o "${CLIENT_OUT}" "${CLIENT_PKG}"

env "${ENVV[@]}" \
  go build -trimpath -buildvcs=false -ldflags "-X main.Build=${BUILD_STR}" \
  -o "${SERVER_OUT}" "${SERVER_PKG}"

if [[ "$GOOS_ARG" != "windows" ]]; then
  chmod 0755 "${CLIENT_OUT}" "${SERVER_OUT}"
fi

if [[ "$WITH_KEYUTIL" == "1" ]]; then
  KEYUTIL_PKG="./cmd/keyutil"
  KEYUTIL_BIN="qtls-keyutil"
  mkdir -p "${RELEASE_DIR}/tools"
  env "${ENVV[@]}" \
    go build -trimpath -buildvcs=false \
    -o "${RELEASE_DIR}/tools/${KEYUTIL_BIN}${EXT}" "${KEYUTIL_PKG}"
  [[ "$GOOS_ARG" != "windows" ]] && chmod 0755 "${RELEASE_DIR}/tools/${KEYUTIL_BIN}${EXT}"
fi

cat <<EOF

Done.

Target:      ${TARGET}
Build tag:   ${BUILD_STR}
Release dir: ${RELEASE_DIR}

Tree:
  ${RELEASE_DIR}/client/{${CLIENT_BIN}${EXT},config/client.yaml,certs/...}
  ${RELEASE_DIR}/server/{${SERVER_BIN}${EXT},config/server.yaml,certs/...}

EOF
