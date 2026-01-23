#!/usr/bin/env python3

# -----
# Copyright (c) 2026 Everlast Networks Pty. Ltd. All rights reserved.
#
# No licence is granted by this notice; all rights are reserved.
# This software is provided "AS IS", without warranties or conditions of any kind,
# whether express or implied, to the maximum extent permitted by law.
# -----

import argparse
import hashlib
import os
import re
import secrets
from typing import Generator, Optional, Tuple

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

_RANGE_RE = re.compile(r"^bytes=(.+)$")
_SINGLE_RANGE_RE = re.compile(r"^\s*(\d*)\s*-\s*(\d*)\s*$")

# Populated at startup.
LARGE_FILE_PATH: str = ""
LARGE_FILE_SIZE: int = 0
LARGE_FILE_SHA256: str = ""


@app.route("/echo", methods=["GET", "POST", "PUT", "PATCH"])
def echo():
    if request.method == "GET":
        return jsonify({
            "method": "GET",
            "args": request.args,
            "headers": dict(request.headers),
        })

    data = request.get_data()
    content_type = request.headers.get("Content-Type", "")

    if content_type.startswith("application/json"):
        return jsonify({
            "method": request.method,
            "json": request.get_json(force=True),
        })

    resp = Response(data, status=200, mimetype="application/octet-stream")
    resp.headers["X-Byte-Length"] = str(len(data))
    resp.headers["X-SHA256"] = hashlib.sha256(data).hexdigest()
    return resp


@app.route("/sink", methods=["POST"])
def sink():
    data = request.get_data()
    return jsonify({
        "status": "ok",
        "bytes_received": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    })


def _parse_single_range(range_header: str, size: int) -> Optional[Tuple[int, int]]:
    """
    Parse a single HTTP Range header for bytes.

    Supports:
      - bytes=start-end
      - bytes=start-
      - bytes=-suffix

    Returns (start, end) inclusive, or None if unsatisfiable/invalid.
    """
    m = _RANGE_RE.match(range_header.strip())
    if not m:
        return None

    spec = m.group(1).strip()
    # Single range only; multipart/byteranges is out of scope for this test endpoint.
    if "," in spec:
        return None

    m2 = _SINGLE_RANGE_RE.match(spec)
    if not m2:
        return None

    start_s, end_s = m2.group(1), m2.group(2)
    if start_s == "" and end_s == "":
        return None

    if size <= 0:
        return None

    if start_s == "":
        # Suffix range: last N bytes.
        try:
            suffix_len = int(end_s)
        except ValueError:
            return None
        if suffix_len <= 0:
            return None
        if suffix_len >= size:
            return (0, size - 1)
        return (size - suffix_len, size - 1)

    try:
        start = int(start_s)
    except ValueError:
        return None

    if start < 0 or start >= size:
        return None

    if end_s == "":
        return (start, size - 1)

    try:
        end = int(end_s)
    except ValueError:
        return None

    if end < start:
        return None

    if end >= size:
        end = size - 1

    return (start, end)


def _file_iter(path: str, start: int, length: int, chunk_size: int = 1024 * 1024) -> Generator[bytes, None, None]:
    with open(path, "rb") as f:
        f.seek(start)
        remaining = length
        while remaining > 0:
            to_read = chunk_size if remaining > chunk_size else remaining
            b = f.read(to_read)
            if not b:
                break
            yield b
            remaining -= len(b)


def _make_416(size: int, etag: str) -> Response:
    # RFC 9110: for 416, include Content-Range: bytes */<complete-length>.
    resp = Response(b"", status=416, mimetype="application/octet-stream")
    resp.headers["Accept-Ranges"] = "bytes"
    resp.headers["Content-Range"] = f"bytes */{size}"
    resp.headers["ETag"] = etag
    resp.content_length = 0
    return resp


@app.route("/largefile", methods=["GET", "HEAD"])
def largefile():
    size = LARGE_FILE_SIZE
    etag = f"\"{LARGE_FILE_SHA256}\""

    range_header = request.headers.get("Range", "")
    if range_header:
        rng = _parse_single_range(range_header, size)
        if rng is None:
            return _make_416(size, etag)

        start, end = rng
        length = end - start + 1

        if request.method == "HEAD":
            # Werkzeug will otherwise compute Content-Length from an empty body; set explicitly.
            resp = Response(b"", status=206, mimetype="application/octet-stream")
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Content-Range"] = f"bytes {start}-{end}/{size}"
            resp.headers["ETag"] = etag
            resp.content_length = length
            return resp

        resp = Response(_file_iter(LARGE_FILE_PATH, start, length), status=206, mimetype="application/octet-stream", direct_passthrough=True)
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Range"] = f"bytes {start}-{end}/{size}"
        resp.headers["ETag"] = etag
        resp.content_length = length
        return resp

    # No Range: full representation.
    if request.method == "HEAD":
        resp = Response(b"", status=200, mimetype="application/octet-stream")
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["ETag"] = etag
        # Critical: HEAD must report the length that would have been sent for GET.
        resp.content_length = size
        return resp

    resp = Response(_file_iter(LARGE_FILE_PATH, 0, size), status=200, mimetype="application/octet-stream", direct_passthrough=True)
    resp.headers["Accept-Ranges"] = "bytes"
    resp.headers["ETag"] = etag
    resp.content_length = size
    return resp


def _ensure_large_file(path: str, min_mib: int, max_mib: int) -> Tuple[int, str]:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    if os.path.exists(path):
        size = os.path.getsize(path)
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return size, h.hexdigest()

    if min_mib < 1:
        min_mib = 1
    if max_mib < min_mib:
        max_mib = min_mib

    size_mib = min_mib + secrets.randbelow((max_mib - min_mib) + 1)
    target = size_mib * 1024 * 1024

    h = hashlib.sha256()
    with open(path, "wb") as f:
        remaining = target
        while remaining > 0:
            n = 1024 * 1024 if remaining > 1024 * 1024 else remaining
            b = os.urandom(n)
            f.write(b)
            h.update(b)
            remaining -= n

    return target, h.hexdigest()


def main():
    global LARGE_FILE_PATH, LARGE_FILE_SIZE, LARGE_FILE_SHA256

    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5500)
    parser.add_argument("--largefile-path", default="./large_test.bin")
    parser.add_argument("--large-min-mib", type=int, default=32)
    parser.add_argument("--large-max-mib", type=int, default=128)
    args = parser.parse_args()

    LARGE_FILE_PATH = os.path.abspath(args.largefile_path)
    LARGE_FILE_SIZE, LARGE_FILE_SHA256 = _ensure_large_file(LARGE_FILE_PATH, args.large_min_mib, args.large_max_mib)

    print(f"[backend] largefile={LARGE_FILE_PATH} size={LARGE_FILE_SIZE} sha256={LARGE_FILE_SHA256}")
    app.run(host=args.listen, port=args.port, debug=False)


if __name__ == "__main__":
    main()
