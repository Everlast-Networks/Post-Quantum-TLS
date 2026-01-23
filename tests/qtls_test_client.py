#!/usr/bin/env python3
"""
QTLS Test Client (Cassette Futurism CLI)

Purpose
- Drives QTLS through one-shot and forward-proxy modes.
- Exercises JSON, binary upload, and large file downloads (including Range slicing).
- Produces a concise report with timings, sizes, and hashes.

Assumptions
- Run from repository ./tests or provide explicit paths.
- QTLS server reachable at --qtls-url (default http://127.0.0.1:5000/qtls).
- Forward proxy tests require an already-running forward proxy at --proxy-url.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import secrets
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


ASCII = r"""
   ____ _______ _       _____ 
  / __ \__   __| |     / ____|
 | |  | | | |  | |    | (___  
 | |  | | | |  | |     \___ \ 
 | |__| | | |  | |____ ____) |
  \___\_\ |_|  |______|_____/ 
                              
"""


def _hr() -> str:
    return "=" * 78


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S %z")


def _fmt_bytes(n: int) -> str:
    if n <= 0:
        return "-"
    if n < 1024:
        return f"{n} B"
    f = float(n)
    for unit in ["KiB", "MiB", "GiB", "TiB"]:
        f /= 1024.0
        if f < 1024.0:
            return f"{f:.2f} {unit}"
    return f"{n} B"


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _require_file(p: Path, desc: str) -> None:
    if not p.is_file():
        raise RuntimeError(f"missing {desc}: {p}")


def _run(cmd: List[str], *, stdin_bytes: Optional[bytes] = None, timeout_s: Optional[int] = None) -> Tuple[int, bytes, bytes, float]:
    t0 = time.perf_counter()
    p = subprocess.run(
        cmd,
        input=stdin_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_s,
        check=False,
    )
    dt = time.perf_counter() - t0
    return p.returncode, p.stdout, p.stderr, dt


@dataclasses.dataclass
class TestResult:
    name: str
    ok: bool
    seconds: float
    detail: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    sha256_in: str = ""
    sha256_out: str = ""


def _banner_line(k: str, v: str) -> str:
    return f">> {k.strip().upper():<18} {v}"


def _print_header(args: argparse.Namespace) -> None:
    print(ASCII.rstrip())
    print(_hr())
    print(_banner_line("START", _now()))
    print(_banner_line("REPO", str(args.repo_root)))
    print(_banner_line("CLIENT BIN", str(args.client_bin)))
    print(_banner_line("CLIENT CFG", str(args.client_config)))
    print(_banner_line("QTLS URL", args.qtls_url))
    print(_banner_line("PROXY", f"{args.proxy_url} (enabled={str(args.proxy).lower()})"))
    print(_banner_line("DEBUG", str(args.debug).lower()))
    print(_hr())
    print("")


def _print_footer(results: List[TestResult]) -> None:
    passed = sum(1 for r in results if r.ok)
    total = len(results)
    print("")
    print(_hr())
    print(_banner_line("RESULT", f"{passed}/{total} passed"))
    print(_banner_line("END", _now()))
    print(_hr())


def _table(results: List[TestResult]) -> None:
    cols = ["TEST", "OK", "TIME", "IN", "OUT", "SHA256(OUT)", "DETAIL"]
    widths = [26, 4, 8, 10, 10, 16, 0]

    def cell(s: str, w: int) -> str:
        if w == 0:
            return s
        if len(s) <= w:
            return s.ljust(w)
        return s[: max(0, w - 1)] + "…"

    print("".join(cell(c, w) + " " for c, w in zip(cols, widths)).rstrip())
    print("-" * 78)
    for r in results:
        row = [
            r.name,
            "yes" if r.ok else "no",
            f"{r.seconds:.3f}s",
            _fmt_bytes(r.bytes_in),
            _fmt_bytes(r.bytes_out),
            (r.sha256_out[:16] if r.sha256_out else "-"),
            r.detail,
        ]
        print("".join(cell(c, w) + " " for c, w in zip(row, widths)).rstrip())


def _ensure_payload(path: Path, size_mb: int) -> None:
    if path.is_file() and path.stat().st_size > 0:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    target = max(1, size_mb) * 1024 * 1024
    with path.open("wb") as f:
        remaining = target
        while remaining > 0:
            chunk = secrets.token_bytes(min(1024 * 1024, remaining))
            f.write(chunk)
            remaining -= len(chunk)


def _qtls_oneshot(
    client_bin: Path,
    cfg: Path,
    qtls_url: str,
    method: str,
    path: str,
    *,
    debug: bool,
    stdin_bytes: Optional[bytes] = None,
    message: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    timeout_s: int = 900,
) -> Tuple[int, bytes, bytes, float]:
    cmd = [str(client_bin), "-config", str(cfg), "-server", qtls_url, "-method", method, "-path", path]
    if debug:
        cmd.append("-debug")
    if stdin_bytes is not None:
        cmd.append("-stdin")
    if message is not None:
        cmd.extend(["-message", message])
    if extra_args:
        cmd.extend(extra_args)
    return _run(cmd, stdin_bytes=stdin_bytes, timeout_s=timeout_s)


def _curl(url: str, *, method: str = "GET", data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None, timeout_s: int = 900) -> Tuple[int, bytes, bytes, float]:
    cmd = ["curl", "-sS", "-X", method]
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    if data is not None:
        cmd.extend(["--data-binary", "@-"])
    cmd.append(url)
    return _run(cmd, stdin_bytes=data, timeout_s=timeout_s)


def test_json_echo(args: argparse.Namespace) -> TestResult:
    name = "oneshot_json_echo"
    payload = b'{"hello":"world","ts":"' + _now().encode("utf-8") + b'"}'
    rc, out, err, dt = _qtls_oneshot(
        args.client_bin,
        args.client_config,
        args.qtls_url,
        "POST",
        "/echo",
        debug=args.debug,
        stdin_bytes=payload,
        timeout_s=args.timeout_s,
    )
    if rc != 0:
        return TestResult(name, False, dt, detail=err.decode("utf-8", "replace").strip()[:240])

    ok = out.strip() == payload.strip()
    return TestResult(
        name,
        ok,
        dt,
        detail="echo matched" if ok else "echo mismatch",
        bytes_in=len(payload),
        bytes_out=len(out),
        sha256_in=_sha256_bytes(payload),
        sha256_out=_sha256_bytes(out),
    )


def test_methods_smoke(args: argparse.Namespace) -> TestResult:
    name = "oneshot_http_methods"
    methods = ["GET", "PUT", "PATCH"]
    t0 = time.perf_counter()
    for m in methods:
        rc, _, err, _ = _qtls_oneshot(
            args.client_bin,
            args.client_config,
            args.qtls_url,
            m,
            "/echo",
            debug=args.debug,
            stdin_bytes=(b'{"m":"' + m.encode("utf-8") + b'"}') if m != "GET" else None,
            timeout_s=args.timeout_s,
        )
        if rc != 0:
            dt = time.perf_counter() - t0
            return TestResult(name, False, dt, detail=f"{m} failed: {err.decode('utf-8','replace').strip()[:200]}")
    dt = time.perf_counter() - t0
    return TestResult(name, True, dt, detail="GET/PUT/PATCH ok")


def test_binary_upload_sink_oneshot(args: argparse.Namespace) -> TestResult:
    name = "oneshot_binary_upload_sink"
    _ensure_payload(args.upload_file, args.upload_mb)
    data = args.upload_file.read_bytes()

    rc, out, err, dt = _qtls_oneshot(
        args.client_bin,
        args.client_config,
        args.qtls_url,
        "POST",
        "/sink",
        debug=args.debug,
        stdin_bytes=data,
        timeout_s=args.timeout_s,
    )
    if rc != 0:
        return TestResult(name, False, dt, detail=err.decode("utf-8", "replace").strip()[:240])

    try:
        j = json.loads(out.decode("utf-8"))
        ok = int(j.get("bytes_received", -1)) == len(data) and str(j.get("sha256", "")).lower() == _sha256_bytes(data)
        detail = f"bytes_received={j.get('bytes_received')} sha256_ok={str(j.get('sha256','')).lower()==_sha256_bytes(data)}"
    except Exception as e:
        ok = False
        detail = f"bad json: {e!r}"

    return TestResult(
        name,
        ok,
        dt,
        detail=detail,
        bytes_in=len(data),
        bytes_out=len(out),
        sha256_in=_sha256_bytes(data),
        sha256_out=_sha256_bytes(out),
    )


def test_large_download_oneshot(args: argparse.Namespace) -> TestResult:
    name = "oneshot_large_download"
    rc, out, err, dt = _qtls_oneshot(
        args.client_bin,
        args.client_config,
        args.qtls_url,
        "GET",
        "/largefile",
        debug=args.debug,
        extra_args=["-chunk-threshold", str(args.chunk_threshold), "-chunk-size", str(args.chunk_size)],
        timeout_s=args.timeout_s,
    )
    if rc != 0:
        return TestResult(name, False, dt, detail=err.decode("utf-8", "replace").strip()[:240])

    out_path = args.work_dir / "out_large.oneshot.bin"
    out_path.write_bytes(out)

    got = _sha256_file(out_path)
    want = _sha256_file(args.largefile_ref)
    ok = got == want and out_path.stat().st_size == args.largefile_ref.stat().st_size

    return TestResult(
        name,
        ok,
        dt,
        detail=f"sha256={'ok' if ok else 'mismatch'}",
        bytes_out=len(out),
        sha256_out=got,
    )


def test_proxy_upload_sink(args: argparse.Namespace) -> TestResult:
    name = "proxy_binary_upload_sink"
    if not args.proxy:
        return TestResult(name, True, 0.0, detail="skipped (proxy disabled)")

    _ensure_payload(args.upload_file, args.upload_mb)
    data = args.upload_file.read_bytes()

    rc, out, err, dt = _curl(
        args.proxy_url.rstrip("/") + "/sink",
        method="POST",
        data=data,
        headers={"Content-Type": "application/octet-stream", "Expect": "100-continue"},
        timeout_s=args.timeout_s,
    )
    if rc != 0:
        return TestResult(name, False, dt, detail=err.decode("utf-8", "replace").strip()[:240])

    try:
        j = json.loads(out.decode("utf-8"))
        ok = int(j.get("bytes_received", -1)) == len(data) and str(j.get("sha256", "")).lower() == _sha256_bytes(data)
        detail = f"bytes_received={j.get('bytes_received')} sha256_ok={str(j.get('sha256','')).lower()==_sha256_bytes(data)}"
    except Exception as e:
        ok = False
        detail = f"bad json: {e!r}"

    return TestResult(
        name,
        ok,
        dt,
        detail=detail,
        bytes_in=len(data),
        bytes_out=len(out),
        sha256_in=_sha256_bytes(data),
        sha256_out=_sha256_bytes(out),
    )


def test_proxy_large_download(args: argparse.Namespace) -> TestResult:
    name = "proxy_large_download"
    if not args.proxy:
        return TestResult(name, True, 0.0, detail="skipped (proxy disabled)")

    rc, out, err, dt = _curl(
        args.proxy_url.rstrip("/") + "/largefile",
        method="GET",
        timeout_s=args.timeout_s,
    )
    if rc != 0:
        return TestResult(name, False, dt, detail=err.decode("utf-8", "replace").strip()[:240])

    out_path = args.work_dir / "out_large.proxy.bin"
    out_path.write_bytes(out)

    got = _sha256_file(out_path)
    want = _sha256_file(args.largefile_ref)
    ok = got == want and out_path.stat().st_size == args.largefile_ref.stat().st_size

    return TestResult(
        name,
        ok,
        dt,
        detail=f"sha256={'ok' if ok else 'mismatch'}",
        bytes_out=len(out),
        sha256_out=got,
    )


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="QTLS test client with human-friendly reporting.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1], help="Repository root")
    p.add_argument("--client-bin", type=Path, default=None, help="Path to qtls-client binary")
    p.add_argument("--client-config", type=Path, default=None, help="Path to client.yaml")
    p.add_argument("--qtls-url", default="http://127.0.0.1:5000/qtls", help="QTLS server URL")
    p.add_argument("--proxy", action="store_true", help="Run proxy-mode tests (requires forward proxy already running)")
    p.add_argument("--proxy-url", default="http://127.0.0.1:7777", help="Forward proxy base URL")
    p.add_argument("--debug", action="store_true", help="Enable -debug for qtls-client in one-shot tests")
    p.add_argument("--timeout-s", type=int, default=900, help="Timeout for each test case, seconds")

    p.add_argument("--work-dir", type=Path, default=Path("/tmp/qtls-tests"), help="Scratch dir for outputs")
    p.add_argument("--upload-file", type=Path, default=None, help="Binary file for upload tests; created if absent")
    p.add_argument("--upload-mb", type=int, default=32, help="Size for generated upload payload (MiB)")
    p.add_argument("--largefile-ref", type=Path, default=None, help="Reference large_test.bin to compare downloads against")
    p.add_argument("--chunk-threshold", type=int, default=(8 << 20), help="One-shot chunk threshold (bytes)")
    p.add_argument("--chunk-size", type=int, default=(4 << 20), help="One-shot chunk size (bytes)")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=True)

    if args.client_bin is None:
        for c in [
            args.repo_root / "bin" / "qtls-client",
            Path(__file__).resolve().parents[1] / "bin" / "qtls-client",
            Path(__file__).resolve().parents[2] / "bin" / "qtls-client",
        ]:
            if c.is_file():
                args.client_bin = c
                break
        if args.client_bin is None:
            raise RuntimeError("could not locate qtls-client; provide --client-bin")

    if args.client_config is None:
        for c in [
            args.repo_root / "config" / "client.yaml",
            Path(__file__).resolve().parents[1] / "config" / "client.yaml",
        ]:
            if c.is_file():
                args.client_config = c
                break
        if args.client_config is None:
            raise RuntimeError("could not locate client.yaml; provide --client-config")

    if args.upload_file is None:
        args.upload_file = args.work_dir / "upload_payload.bin"

    if args.largefile_ref is None:
        for c in [
            args.repo_root / "tests" / "large_test.bin",
            Path(__file__).resolve().parent / "large_test.bin",
        ]:
            if c.is_file():
                args.largefile_ref = c
                break
        if args.largefile_ref is None:
            raise RuntimeError("could not locate large_test.bin; provide --largefile-ref")

    _require_file(args.client_bin, "qtls-client binary")
    _require_file(args.client_config, "client config")
    _require_file(args.largefile_ref, "reference large file")

    _print_header(args)

    tests = [
        test_json_echo,
        test_methods_smoke,
        test_binary_upload_sink_oneshot,
        test_large_download_oneshot,
        test_proxy_upload_sink,
        test_proxy_large_download,
    ]

    results: List[TestResult] = []
    for fn in tests:
        try:
            r = fn(args)
        except subprocess.TimeoutExpired:
            r = TestResult(fn.__name__, False, float(args.timeout_s), detail="timeout")
        except Exception as e:
            r = TestResult(fn.__name__, False, 0.0, detail=f"{e.__class__.__name__}: {e}")
        results.append(r)

        sig = "OK" if r.ok else "FAIL"
        print(f"[{sig:4}] {r.name:26} {r.seconds:7.3f}s  {r.detail}")

    print("")
    _table(results)
    _print_footer(results)

    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
