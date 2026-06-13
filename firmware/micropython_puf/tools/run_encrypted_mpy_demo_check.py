#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial>=3.5"]
# ///
"""Run the final ESP32 demo check for the PUF-bound encrypted .mpy payload."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from run_micropython_rtc_slow_auto import RawRepl, parse_identity_dict, parse_status_dict, status_exec_code


TOOL_DIR = Path(__file__).resolve().parent
DEVICE_DIR = TOOL_DIR.parent / "device"
HEADER_LEN = 32
TEXT_SOURCES = {
    "rtc_fast_puf_probe.py": DEVICE_DIR / "rtc_fast_puf_probe.py",
    "rtc_slow_puf_native.py": DEVICE_DIR / "rtc_slow_puf_native.py",
    "secure_firmware_loader.py": DEVICE_DIR / "secure_firmware_loader.py",
}
PY_MAIN = (
    b"import secure_firmware_loader\n\n"
    b'RESULT = secure_firmware_loader.run_encrypted_module(path="protected_app.enc")\n'
    b'print("PUF_PY_FIRMWARE_LOADER_OK plaintext_sha256={}".format(RESULT["plaintext_sha256"]))\n'
)
DISALLOWED_FILES = (
    "protected_app.py",
    "protected_app.mpy",
    "protected_app.enc",
    "_puf_protected_app.py",
    "_puf_protected_app.mpy",
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def upload_bytes(repl: RawRepl, source: Path, dest: str, chunk_size: int) -> None:
    data = source.read_bytes()
    repl.exec(f'open({dest!r}, "wb").close()', timeout=20)
    for index in range(0, len(data), chunk_size):
        chunk = data[index : index + chunk_size]
        repl.exec(
            f'with open({dest!r}, "ab") as f:\n'
            f"    f.write({chunk!r})\n",
            timeout=20,
        )
    stdout = repl.exec(
        "import os\n"
        f"print('UPLOAD_OK {dest} bytes={{}}'.format(os.stat({dest!r})[6]))\n",
        timeout=20,
    )
    print(stdout.decode("utf-8", errors="replace").strip())


def upload_literal(repl: RawRepl, data: bytes, dest: str, chunk_size: int) -> None:
    repl.exec(f'open({dest!r}, "wb").close()', timeout=20)
    for index in range(0, len(data), chunk_size):
        chunk = data[index : index + chunk_size]
        repl.exec(
            f'with open({dest!r}, "ab") as f:\n'
            f"    f.write({chunk!r})\n",
            timeout=20,
        )
    stdout = repl.exec(
        "import os\n"
        f"print('UPLOAD_OK {dest} bytes={{}}'.format(os.stat({dest!r})[6]))\n",
        timeout=20,
    )
    print(stdout.decode("utf-8", errors="replace").strip())


def cleanup_known_files(repl: RawRepl) -> None:
    names = DISALLOWED_FILES
    repl.exec(
        "import os\n"
        f"names = {names!r}\n"
        "for name in names:\n"
        "    try:\n"
        "        os.remove(name)\n"
        "        print('REMOVED ' + name)\n"
        "    except OSError:\n"
        "        pass\n",
        timeout=20,
    )


def upload_demo_files(repl: RawRepl, payload: Path, chunk_size: int, payload_kind: str) -> None:
    cleanup_known_files(repl)
    for dest, source in TEXT_SOURCES.items():
        upload_bytes(repl, source, dest, chunk_size)
    if payload_kind == "mpy":
        upload_bytes(repl, DEVICE_DIR / "main.py", "main.py", chunk_size)
        upload_bytes(repl, payload, "protected_app.mpy.enc", chunk_size)
    elif payload_kind == "py":
        upload_literal(repl, PY_MAIN, "main.py", chunk_size)
        upload_bytes(repl, payload, "protected_app.enc", chunk_size)
    else:
        raise ValueError("unsupported payload kind")


def run_main(repl: RawRepl) -> str:
    stdout = repl.exec(
        "import gc\n"
        "import sys\n"
        "for name in ('main', 'secure_firmware_loader', '_puf_protected_app'):\n"
        "    sys.modules.pop(name, None)\n"
        "gc.collect()\n"
        "import main\n",
        timeout=180,
    )
    return stdout.decode("utf-8", errors="replace")


def assert_temp_deleted(repl: RawRepl) -> str:
    stdout = repl.exec(
        "import os\n"
        "try:\n"
        "    os.stat('/_puf_protected_app.mpy')\n"
        "    print('TEMP_MPY_PRESENT')\n"
        "except OSError:\n"
        "    print('TEMP_MPY_DELETED')\n",
        timeout=20,
    )
    text = stdout.decode("utf-8", errors="replace")
    if "TEMP_MPY_DELETED" not in text:
        raise RuntimeError("temporary .mpy file was not deleted")
    return text


def require_positive_output(text: str, payload_kind: str) -> None:
    required = (
        "PROTECTED_APP_MPY_OK",
        "protected_marker_len=33",
        "PUF_MPY_FIRMWARE_LOADER_OK" if payload_kind == "mpy" else "PUF_PY_FIRMWARE_LOADER_OK",
    )
    missing = [marker for marker in required if marker not in text]
    if missing:
        raise RuntimeError(f"positive demo output missing markers: {missing}; output={text!r}")


def make_tampered_payload(source: Path, output: Path) -> None:
    data = bytearray(source.read_bytes())
    if len(data) <= HEADER_LEN:
        raise RuntimeError("encrypted payload is too short to tamper")
    data[HEADER_LEN] ^= 0x01
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)


def run_negative_case(repl: RawRepl) -> str:
    try:
        text = run_main(repl)
    except RuntimeError as exc:
        message = str(exc)
        if "HMAC verification failed; encrypted firmware was not executed" not in message:
            raise
        if "PROTECTED_APP_MPY_OK" in message:
            raise RuntimeError("negative case unexpectedly executed protected app")
        print("NEGATIVE_REJECTED HMAC verification failed; encrypted firmware was not executed")
        return message
    raise RuntimeError(f"tampered payload was accepted; output={text!r}")


def read_status(repl: RawRepl) -> str:
    stdout = repl.exec(status_exec_code(), timeout=60)
    text = stdout.decode("utf-8", errors="replace")
    status = parse_status_dict(stdout)
    if status.get("enrolled") is not True:
        raise RuntimeError(f"PUF helper is not enrolled: {text!r}")
    return text


def read_identity(repl: RawRepl) -> str:
    stdout = repl.exec(
        "import rtc_slow_puf_native as p\n"
        "import time\n"
        "d = p.identity(size=4096, nonce='firmware-v1', attempts=5)\n"
        "time.sleep_ms(20)\n"
        'print("MPUF_IDENTITY_BEGIN")\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_IDENTITY_ACCEPTED {}".format("true" if d.get("accepted") else "false"))\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_IDENTITY_META storage={} sample_size={} selected_bits={} attempts={}".format(d.get("storage", "-"), d.get("sample_size", 0), d.get("selected_bits", 0), d.get("attempts", 0)))\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_IDENTITY_ERRORS corrected_bit_errors_total={} corrected_bit_errors_pct={} max_errors_per_codeword={} uncertain_codewords={} material_tie_bits={}".format(d.get("corrected_bit_errors_total", 0), d.get("corrected_bit_errors_pct", 0), d.get("max_errors_per_codeword", 0), d.get("uncertain_codewords", 0), d.get("material_tie_bits", 0)))\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_IDENTITY_KEY key_sha256={}".format(d.get("key_sha256", "-")))\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_IDENTITY_END")\n',
        timeout=180,
    )
    text = stdout.decode("utf-8", errors="replace")
    identity = parse_identity_dict(stdout)
    if identity.get("accepted") is not True:
        raise RuntimeError(f"PUF identity was not accepted: {text!r}")
    return text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbserial-0001")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--payload", type=Path, default=Path("/private/tmp/protected_app.mpy.enc"))
    parser.add_argument("--payload-kind", choices=("mpy", "py"), default="mpy")
    parser.add_argument(
        "--tampered-output",
        type=Path,
        default=Path("/private/tmp/protected_app.mpy.tampered.enc"),
    )
    parser.add_argument("--chunk-size", type=int, default=384)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        import serial
    except ImportError:
        print("error: pyserial is required. Use uv run run_encrypted_mpy_demo_check.py ...", file=sys.stderr)
        return 2

    payload = args.payload.expanduser()
    if not payload.exists():
        print(f"error: payload does not exist: {payload}", file=sys.stderr)
        return 1

    make_tampered_payload(payload, args.tampered_output.expanduser())
    print(f"PAYLOAD_SHA256 {sha256_hex(payload.read_bytes())}")
    print(f"TAMPERED_SHA256 {sha256_hex(args.tampered_output.expanduser().read_bytes())}")

    repl = RawRepl(serial, args.port, args.baud)
    try:
        repl.enter()

        upload_demo_files(repl, payload, args.chunk_size, args.payload_kind)
        print("PUF_STATUS " + read_status(repl).strip())
        print("PUF_IDENTITY " + read_identity(repl).strip())

        positive = run_main(repl)
        require_positive_output(positive, args.payload_kind)
        print(positive.strip())
        print(assert_temp_deleted(repl).strip())

        tampered_dest = "protected_app.mpy.enc" if args.payload_kind == "mpy" else "protected_app.enc"
        upload_bytes(repl, args.tampered_output.expanduser(), tampered_dest, args.chunk_size)
        run_negative_case(repl)
        print(assert_temp_deleted(repl).strip())

        upload_bytes(repl, payload, tampered_dest, args.chunk_size)
        final_positive = run_main(repl)
        require_positive_output(final_positive, args.payload_kind)
        print(final_positive.strip())
        print(assert_temp_deleted(repl).strip())

        cleanup_known_files(repl)
        repl.exit()
    finally:
        repl.close()

    print("DEMO_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
