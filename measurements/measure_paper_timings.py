#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial>=3.5"]
# ///
"""Measure the paper's Section 6 timings LOCALLY on a real ESP32 board.

Reuses the project's tested helpers (RawRepl, upload, loader run, tamper) so we
do not reinvent the serial/upload logic. Times each operation host-side with
time.monotonic across the full serial round-trip, the same methodology the paper
declares. Each device operation is repeated N times; we report min/median/mean.

Numbers produced: the device must already be enrolled. The paper measurements
use board A in the complete configuration, 256 selected bits, off-time 50 ms:
  - puf_identity_reconstruction_s : p.identity(attempts=5) round-trip
  - secure_execution_s           : loader verify-before-decrypt + AES + exec (.py path)
  - tamper_rejection_s           : loader rejects a 1-byte-flipped envelope (HMAC fails)
  - envelope_build_total_s       : device round-trip for k_root + local AES/HMAC
  - envelope_build_pure_s        : local AES/HMAC only, key already in host RAM
  - plaintext_bytes / envelope_bytes / overhead_bytes / overhead_pct

Enrollment time is NOT re-measured here (destructive); it is taken from the
existing enroll log (board A complete configuration: 445.9 s device / 463.8 s
host).

Usage:
  cd <this dir> && uv run measure_paper_timings.py \
      --port /dev/cu.usbserial-0001 \
      --source ../firmware/micropython_puf/device/protected_app.py \
      --reps 5 --out timings/boardA-paper-timings.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

# Resolved relative to this repository layout (measurements/ -> firmware/).
TOOLS_DIR = (
    Path(__file__).resolve().parent.parent / "firmware" / "micropython_puf" / "tools"
).resolve()
DEVICE_DIR = TOOLS_DIR.parent / "device"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# Tested helpers from the project (do not reinvent serial/upload logic).
from run_micropython_rtc_slow_auto import RawRepl  # noqa: E402
from run_encrypted_mpy_demo_check import (  # noqa: E402
    PY_MAIN,
    TEXT_SOURCES,
    cleanup_known_files,
    make_tampered_payload,
    sha256_hex,
    upload_bytes,
    upload_literal,
)
from build_encrypted_firmware_from_device import derive_device_key  # noqa: E402
from build_encrypted_firmware import build_envelope  # noqa: E402

NONCE = "firmware-v1"
SIZE = 4096

RECON_CODE = (
    "import rtc_slow_puf_native as p\n"
    f"d = p.identity(size={SIZE}, nonce={NONCE!r}, attempts=5)\n"
    'print("RECON_ACCEPTED {}".format("true" if d.get("accepted") else "false"))\n'
    'print("RECON_ERR_PCT {}".format(d.get("corrected_bit_errors_pct", -1)))\n'
)

# Secure execution of the .py path: the loader reconstructs the PUF, derives the
# subkeys, verifies the HMAC, decrypts, and exec()s the module in RAM.
EXEC_CODE = (
    "import gc, sys\n"
    "for _n in ('main', 'secure_firmware_loader', '_puf_protected_app'):\n"
    "    sys.modules.pop(_n, None)\n"
    "gc.collect()\n"
    "import secure_firmware_loader as _l\n"
    "_r = _l.run_encrypted_module(path='protected_app.enc')\n"
    'print("EXEC_OK plaintext_sha256={}".format(_r["plaintext_sha256"]))\n'
)

# Tamper rejection: same loader entry, but the envelope was 1-byte-flipped, so
# the HMAC check fails and the loader raises BEFORE any decryption.
TAMPER_CODE = (
    "import gc, sys\n"
    "for _n in ('main', 'secure_firmware_loader', '_puf_protected_app'):\n"
    "    sys.modules.pop(_n, None)\n"
    "gc.collect()\n"
    "import secure_firmware_loader as _l\n"
    "try:\n"
    "    _l.run_encrypted_module(path='protected_app.enc')\n"
    '    print("TAMPER_UNEXPECTED_OK")\n'
    "except Exception as _e:\n"
    '    print("TAMPER_REJECTED {}".format(_e))\n'
)


def _time_exec(repl, code, timeout, marker):
    """Run code on the device, return (elapsed_s, decoded_stdout). Assert marker present."""
    start = time.monotonic()
    out = repl.exec(code, timeout=timeout)
    elapsed = time.monotonic() - start
    text = out.decode("utf-8", errors="replace")
    if marker not in text:
        raise RuntimeError(f"expected marker {marker!r} missing; output={text!r}")
    return elapsed, text


def _stats(samples):
    return {
        "n": len(samples),
        "min": round(min(samples), 4),
        "median": round(statistics.median(samples), 4),
        "mean": round(statistics.mean(samples), 4),
        "max": round(max(samples), 4),
        "raw": [round(s, 4) for s in samples],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="/dev/cu.usbserial-0001")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument(
        "--source",
        type=Path,
        default=DEVICE_DIR / "protected_app.py",
        help="plaintext module to encrypt (587 B protected_app.py)",
    )
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--chunk-size", type=int, default=384)
    ap.add_argument("--out", type=Path, default=Path("timings/boardA-paper-timings.json"))
    args = ap.parse_args()

    try:
        import serial  # noqa: F401
    except ImportError:
        print("error: pyserial required (uv run ...)", file=sys.stderr)
        return 2

    source = args.source.expanduser().resolve()
    plaintext = source.read_bytes()
    print(f"SOURCE {source} bytes={len(plaintext)} sha256={sha256_hex(plaintext)}")

    # --- Envelope build (total = device round-trip for k_root + local crypto) ---
    t0 = time.monotonic()
    root_key, identity, key_sha = derive_device_key(
        serial, port=args.port, baud=args.baud, nonce=NONCE, size=SIZE
    )
    t_keyfetch = time.monotonic() - t0
    # build_pure: local AES-256-CBC + HMAC only, key already in host RAM
    t1 = time.monotonic()
    envelope = build_envelope(plaintext, root_key)
    t_build_pure = time.monotonic() - t1
    t_build_total = t_keyfetch + t_build_pure
    overhead = len(envelope) - len(plaintext)
    print(
        f"BUILD key_sha256={key_sha} plaintext_bytes={len(plaintext)} "
        f"envelope_bytes={len(envelope)} overhead_bytes={overhead} "
        f"keyfetch_s={t_keyfetch:.3f} build_pure_s={t_build_pure:.4f}"
    )

    # Write the real envelope and a tampered copy to disk for upload
    workdir = args.out.expanduser().resolve().parent
    workdir.mkdir(parents=True, exist_ok=True)
    enc_path = workdir / "protected_app.enc"
    enc_path.write_bytes(envelope)
    tampered_path = workdir / "protected_app.tampered.enc"
    make_tampered_payload(enc_path, tampered_path)

    # --- Device round-trip timings (recon / exec / tamper) ---
    recon, execu, tamper = [], [], []
    repl = RawRepl(serial, args.port, args.baud)
    try:
        repl.enter()
        # upload device modules + py main + the real envelope
        cleanup_known_files(repl)
        for dest, src in TEXT_SOURCES.items():
            upload_bytes(repl, src, dest, args.chunk_size)
        upload_literal(repl, PY_MAIN, "main.py", args.chunk_size)
        upload_bytes(repl, enc_path, "protected_app.enc", args.chunk_size)

        for i in range(args.reps):
            e, _ = _time_exec(repl, RECON_CODE, 180, "RECON_ACCEPTED true")
            recon.append(e)
            print(f"  recon[{i}] = {e:.4f}s")
        for i in range(args.reps):
            e, _ = _time_exec(repl, EXEC_CODE, 180, "EXEC_OK")
            execu.append(e)
            print(f"  exec[{i}]  = {e:.4f}s")

        # swap in the tampered envelope, then time the rejection path
        upload_bytes(repl, tampered_path, "protected_app.enc", args.chunk_size)
        for i in range(args.reps):
            e, _ = _time_exec(repl, TAMPER_CODE, 180, "TAMPER_REJECTED")
            tamper.append(e)
            print(f"  tamper[{i}]= {e:.4f}s")

        cleanup_known_files(repl)
        repl.exit()
    finally:
        repl.close()

    result = {
        "port": args.port,
        "source": str(source),
        "config": "complete (1000 samples, 256 selected bits, 64x128 windows, off 50 ms)",
        "enrollment_s_note": "445.9 device / 463.8 host (from boardA-c2-sleep50/enroll.log; not re-measured here)",
        "plaintext_bytes": len(plaintext),
        "envelope_bytes": len(envelope),
        "overhead_bytes": overhead,
        "overhead_pct": round(100.0 * overhead / len(plaintext), 2),
        "envelope_build_pure_s": round(t_build_pure, 4),
        "envelope_build_total_s": round(t_build_total, 4),
        "key_fetch_roundtrip_s": round(t_keyfetch, 4),
        "puf_identity_reconstruction_s": _stats(recon),
        "secure_execution_s": _stats(execu),
        "tamper_rejection_s": _stats(tamper),
    }
    args.out.expanduser().write_text(json.dumps(result, indent=2))
    print("\n=== SUMMARY (medians) ===")
    print(f"recon  = {result['puf_identity_reconstruction_s']['median']} s")
    print(f"exec   = {result['secure_execution_s']['median']} s")
    print(f"tamper = {result['tamper_rejection_s']['median']} s")
    print(f"build  = pure {result['envelope_build_pure_s']} s / total {result['envelope_build_total_s']} s")
    print(f"bytes  = {result['plaintext_bytes']} -> {result['envelope_bytes']} (+{overhead} B, {result['overhead_pct']}%)")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
