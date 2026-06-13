#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial>=3.5"]
# ///
"""Build a PUF-bound encrypted payload using the real ESP32-derived key.

The script asks the board for the key over raw REPL, keeps it in host RAM, and
then calls the local envelope builder. It reports fingerprints and sizes, but
never prints the raw PUF-derived key.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

from build_encrypted_firmware import (
    FirmwareBuildError,
    TMP_ROOT,
    compile_to_mpy,
    is_inside,
    mpy_cross_path,
    sha256_hex,
    validate_mpy_cross_version,
    write_envelope_bytes,
)
from run_micropython_rtc_slow_auto import RawRepl, parse_identity_dict


TOOL_DIR = Path(__file__).resolve().parent
MICROPYTHON_PUF_DIR = TOOL_DIR.parent
DEVICE_DIR = MICROPYTHON_PUF_DIR / "device"
REPO_ROOT = TOOL_DIR.parents[2]
KEY_LEN = 32


def _find_prefixed_line(text: str, prefix: str) -> str:
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    raise FirmwareBuildError(f"device output did not include {prefix.strip()}")


def _parse_device_identity(text: str) -> dict[str, object]:
    try:
        return parse_identity_dict(text.encode("utf-8"))
    except (SyntaxError, ValueError):
        payload = _find_prefixed_line(text, "PUF_IDENTITY ")
        value = ast.literal_eval(payload)
        if not isinstance(value, dict):
            raise FirmwareBuildError("PUF_IDENTITY was not a dictionary")
        return value


def _parse_key(text: str) -> bytes:
    key_hex = _find_prefixed_line(text, "PUF_KEY_HEX ")
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise FirmwareBuildError("device returned non-hex key material") from exc
    if len(key) != KEY_LEN:
        raise FirmwareBuildError("device returned key material with unexpected length")
    return key


def derive_device_key(serial_module, *, port: str, baud: int, nonce: str, size: int) -> tuple[bytes, dict[str, object], str]:
    repl = RawRepl(serial_module, port, baud)
    try:
        repl.enter()
        stdout = repl.exec(
            "import ubinascii\n"
            "import uhashlib\n"
            "import rtc_slow_puf_native as p\n"
            "import time\n"
            f"identity = p.identity(size={size}, nonce={nonce!r}, attempts=5)\n"
            "time.sleep_ms(20)\n"
            'print("MPUF_IDENTITY_BEGIN")\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_ACCEPTED {}".format("true" if identity.get("accepted") else "false"))\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_META storage={} sample_size={} selected_bits={} attempts={}".format(identity.get("storage", "-"), identity.get("sample_size", 0), identity.get("selected_bits", 0), identity.get("attempts", 0)))\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_ERRORS corrected_bit_errors_total={} corrected_bit_errors_pct={} max_errors_per_codeword={} uncertain_codewords={} material_tie_bits={}".format(identity.get("corrected_bit_errors_total", 0), identity.get("corrected_bit_errors_pct", 0), identity.get("max_errors_per_codeword", 0), identity.get("uncertain_codewords", 0), identity.get("material_tie_bits", 0)))\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_KEY key_sha256={}".format(identity.get("key_sha256", "-")))\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_END")\n'
            f"key = p.derive_key(nonce={nonce!r}, size={size})\n"
            "print('PUF_KEY_HEX ' + ubinascii.hexlify(key).decode())\n"
            "print('PUF_KEY_SHA256 ' + ubinascii.hexlify(uhashlib.sha256(key).digest()).decode())\n",
            timeout=180,
        )
        repl.exit()
    finally:
        repl.close()

    text = stdout.decode("utf-8", errors="replace")
    identity = _parse_device_identity(text)
    if identity.get("accepted") is not True:
        raise FirmwareBuildError(f"device PUF identity did not pass acceptance policy: {identity}")
    key = _parse_key(text)
    device_key_sha256 = _find_prefixed_line(text, "PUF_KEY_SHA256 ")
    if sha256_hex(key) != device_key_sha256:
        raise FirmwareBuildError("host key fingerprint did not match device fingerprint")
    return key, identity, device_key_sha256


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbserial-0001")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--nonce", default="firmware-v1")
    parser.add_argument("--size", type=int, default=4096)
    parser.add_argument("--input", type=Path, default=DEVICE_DIR / "protected_app.py")
    parser.add_argument("--output", type=Path, default=TMP_ROOT / "protected_app.mpy.enc")
    parser.add_argument("--compile-mpy", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--mpy-cross", type=Path)
    parser.add_argument("--allow-mpy-version-mismatch", action="store_true")
    parser.add_argument("--allow-repo-output", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        import serial
    except ImportError:
        print("error: pyserial is required. Use uv run build_encrypted_firmware_from_device.py ...", file=sys.stderr)
        return 2

    try:
        output = args.output.expanduser()
        if is_inside(output, REPO_ROOT) and not args.allow_repo_output:
            raise FirmwareBuildError("--output must stay outside the repo unless --allow-repo-output is explicit")

        root_key, identity, key_sha256 = derive_device_key(
            serial,
            port=args.port,
            baud=args.baud,
            nonce=args.nonce,
            size=args.size,
        )

        payload_kind = "python"
        mpy_version = None
        if args.compile_mpy:
            cross = mpy_cross_path(args.mpy_cross)
            mpy_version = validate_mpy_cross_version(cross, allow_mismatch=args.allow_mpy_version_mismatch)
            plaintext, _mpy_path = compile_to_mpy(args.input.expanduser(), cross)
            payload_kind = "mpy"
        else:
            plaintext = args.input.expanduser().read_bytes()

        envelope = write_envelope_bytes(plaintext, output, root_key)
        print(f"output: {output}")
        print(f"payload_kind: {payload_kind}")
        if mpy_version is not None:
            print(f"mpy_cross_version: {mpy_version}")
        print(f"device_selected_bits: {identity.get('selected_bits')}")
        print(f"device_corrected_bit_errors_pct: {identity.get('corrected_bit_errors_pct')}")
        print(f"device_key_sha256: {key_sha256}")
        print(f"payload_bytes: {len(plaintext)}")
        print(f"encrypted_bytes: {len(envelope)}")
        print(f"payload_sha256: {sha256_hex(plaintext)}")
        print(f"encrypted_sha256: {sha256_hex(envelope)}")
        return 0
    except (OSError, FirmwareBuildError, RuntimeError, TimeoutError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
