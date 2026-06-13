#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial>=3.5"]
# ///
"""Run a minimal PUF-bound HTTP OTA demo on stock MicroPython."""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from build_encrypted_firmware import (
    FirmwareBuildError,
    hmac_sha256,
    hkdf_sha256,
    is_inside,
    sha256_hex,
    write_envelope_bytes,
)
from build_encrypted_firmware_from_device import derive_device_key
from run_encrypted_mpy_demo_check import upload_bytes
from run_micropython_rtc_slow_auto import RawRepl, parse_status_dict, status_exec_code


TOOL_DIR = Path(__file__).resolve().parent
DEVICE_DIR = TOOL_DIR.parent / "device"
REPO_ROOT = TOOL_DIR.parents[2]
MANIFEST_SALT = b"DID-PUF-MICROPYTHON-HTTP-OTA-v1"
MANIFEST_INFO = b"manifest-hmac-sha256"
CANON_FIELDS = (
    "schema",
    "target",
    "secure_version",
    "nonce",
    "payload_kind",
    "payload_path",
    "payload_size",
    "payload_sha256",
)
CORE_DEVICE_FILES = {
    "rtc_fast_puf_probe.py": DEVICE_DIR / "rtc_fast_puf_probe.py",
    "rtc_slow_puf_native.py": DEVICE_DIR / "rtc_slow_puf_native.py",
    "secure_firmware_loader.py": DEVICE_DIR / "secure_firmware_loader.py",
    "puf_http_ota.py": DEVICE_DIR / "puf_http_ota.py",
}
DISALLOWED_DEVICE_FILES = (
    "protected_app.enc",
    "protected_app.mpy.enc",
    "puf_http_ota_state.json",
    "_puf_protected_app.py",
    "_puf_protected_app.mpy",
)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


def default_out_dir(target: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("/private/tmp") / "puf-demo-20260527" / f"micropython-http-ota-{target}-{stamp}"


def infer_host_ip(route_host: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((route_host, 80))
        return sock.getsockname()[0]
    finally:
        sock.close()


def manifest_key(root_key: bytes) -> bytes:
    return hkdf_sha256(root_key, MANIFEST_SALT, MANIFEST_INFO, 32)


def canonical_manifest(manifest: dict[str, object]) -> bytes:
    parts = []
    for key in CANON_FIELDS:
        if key not in manifest:
            raise FirmwareBuildError(f"manifest missing {key}")
        parts.append(f"{key}={manifest[key]}")
    return "\n".join(parts).encode("utf-8")


def sign_manifest(manifest: dict[str, object], root_key: bytes) -> dict[str, object]:
    signed = dict(manifest)
    signed["manifest_hmac"] = hmac_sha256(manifest_key(root_key), canonical_manifest(signed)).hex()
    return signed


def write_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def make_tampered_payload(payload: bytes) -> bytes:
    if len(payload) <= 32:
        raise FirmwareBuildError("encrypted payload is too short to tamper")
    tampered = bytearray(payload)
    tampered[32] ^= 0x01
    return bytes(tampered)


def upload_core_files(repl: RawRepl, chunk_size: int) -> None:
    repl.exec(
        "import os\n"
        f"names = {DISALLOWED_DEVICE_FILES!r}\n"
        "for name in names:\n"
        "    try:\n"
        "        os.remove(name)\n"
        "        print('REMOVED ' + name)\n"
        "    except OSError:\n"
        "        pass\n",
        timeout=20,
    )
    for dest, source in CORE_DEVICE_FILES.items():
        upload_bytes(repl, source, dest, chunk_size)


def read_status(repl: RawRepl) -> str:
    stdout = repl.exec(status_exec_code(), timeout=60)
    text = stdout.decode("utf-8", errors="replace")
    status = parse_status_dict(stdout)
    if status.get("enrolled") is not True:
        raise RuntimeError(f"PUF helper is not enrolled: {text!r}")
    return text


def run_device_code(repl: RawRepl, code: str, timeout: float) -> str:
    stdout = repl.exec(code, timeout=timeout)
    text = stdout.decode("utf-8", errors="replace")
    print(text.strip())
    return text


def start_http_server(root: Path, listen_host: str, listen_port: int) -> tuple[ThreadingHTTPServer, threading.Thread]:
    handler = functools.partial(QuietHandler, directory=str(root))
    server = ThreadingHTTPServer((listen_host, listen_port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def require_markers(text: str, markers: tuple[str, ...], label: str) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise RuntimeError(f"{label} missing markers: {missing}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("esp32", "esp32s3"), required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--wifi-ssid", default=os.environ.get("PUF_DEMO_WIFI_SSID"))
    parser.add_argument("--wifi-pass", default=os.environ.get("PUF_DEMO_WIFI_PASS", ""))
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=0)
    parser.add_argument("--device-base-url")
    parser.add_argument("--route-probe-host", default="8.8.8.8")
    parser.add_argument("--nonce", default="firmware-v1")
    parser.add_argument("--secure-version", type=int, default=1)
    parser.add_argument("--size", type=int, default=4096)
    parser.add_argument("--payload-kind", choices=("py",), default="py")
    parser.add_argument("--input", type=Path, default=DEVICE_DIR / "protected_app.py")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--chunk-size", type=int, default=384)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.wifi_ssid:
        print("error: --wifi-ssid or PUF_DEMO_WIFI_SSID is required", file=sys.stderr)
        return 2
    try:
        import serial
    except ImportError:
        print("error: pyserial is required", file=sys.stderr)
        return 2

    out_dir = (args.out_dir or default_out_dir(args.target)).expanduser().resolve()
    if is_inside(out_dir, REPO_ROOT):
        print("error: --out-dir must stay outside the repo", file=sys.stderr)
        return 2
    http_root = out_dir / "http"
    http_root.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "summary.json"

    repl = RawRepl(serial, args.port, args.baud)
    try:
        repl.enter()
        upload_core_files(repl, args.chunk_size)
        print("PUF_STATUS " + read_status(repl).strip())
        repl.exit()
    finally:
        repl.close()

    root_key, identity, _key_sha256 = derive_device_key(
        serial,
        port=args.port,
        baud=args.baud,
        nonce=args.nonce,
        size=args.size,
    )

    plaintext = args.input.expanduser().read_bytes()
    payload_name = "protected_app.py.enc"
    payload_path = http_root / payload_name
    payload = write_envelope_bytes(plaintext, payload_path, root_key)
    tampered_payload = make_tampered_payload(payload)
    (http_root / "protected_app.py.tampered.enc").write_bytes(tampered_payload)

    manifest_base: dict[str, object] = {
        "schema": "puf-mpy-http-ota-v1",
        "target": args.target,
        "secure_version": args.secure_version,
        "nonce": args.nonce,
        "payload_kind": args.payload_kind,
        "payload_path": payload_name,
        "payload_size": len(payload),
        "payload_sha256": sha256_hex(payload),
    }
    nominal_manifest = sign_manifest(manifest_base, root_key)
    write_json(http_root / "manifest.json", nominal_manifest)

    bad_manifest = dict(nominal_manifest)
    bad_manifest["manifest_hmac"] = ("0" if nominal_manifest["manifest_hmac"][0] != "0" else "1") + nominal_manifest["manifest_hmac"][1:]
    write_json(http_root / "manifest-bad-hmac.json", bad_manifest)

    server, thread = start_http_server(http_root, args.listen_host, args.listen_port)
    try:
        actual_port = server.server_address[1]
        if args.device_base_url:
            base_url = args.device_base_url.rstrip("/")
        else:
            base_url = f"http://{infer_host_ip(args.route_probe_host)}:{actual_port}"
        manifest_url = base_url + "/manifest.json"
        bad_manifest_url = base_url + "/manifest-bad-hmac.json"

        repl = RawRepl(serial, args.port, args.baud)
        try:
            repl.enter()
            nominal_code = (
                "import puf_http_ota as ota\n"
                f"ota.install_from_manifest({manifest_url!r}, wifi_ssid={args.wifi_ssid!r}, "
                f"wifi_password={args.wifi_pass!r}, run_payload=True)\n"
            )
            nominal_text = run_device_code(repl, nominal_code, timeout=240)
            require_markers(
                nominal_text,
                (
                    "MPY_OTA_WIFI ok=true",
                    "MPY_OTA_MANIFEST ok=true",
                    "MPY_OTA_DOWNLOAD ok=true",
                    "MPY_OTA_INSTALL ok=true",
                    "PROTECTED_APP_MPY_OK",
                    "MPY_OTA_RUN ok=true",
                ),
                "nominal OTA",
            )

            payload_path.write_bytes(tampered_payload)
            tamper_code = (
                "import puf_http_ota as ota\n"
                "try:\n"
                f"    ota.install_from_manifest({manifest_url!r}, wifi_ssid={args.wifi_ssid!r}, "
                f"wifi_password={args.wifi_pass!r}, run_payload=True)\n"
                "    print('MPY_OTA_TAMPER ok=true unexpected_accept')\n"
                "except Exception as e:\n"
                "    print('MPY_OTA_TAMPER ok=false error={}'.format(str(e).replace(' ', '_')))\n"
            )
            tamper_text = run_device_code(repl, tamper_code, timeout=240)
            require_markers(tamper_text, ("MPY_OTA_TAMPER ok=false", "payload_sha256_mismatch"), "payload tamper")
            payload_path.write_bytes(payload)

            manifest_tamper_code = (
                "import puf_http_ota as ota\n"
                "try:\n"
                f"    ota.install_from_manifest({bad_manifest_url!r}, wifi_ssid={args.wifi_ssid!r}, "
                f"wifi_password={args.wifi_pass!r}, run_payload=True)\n"
                "    print('MPY_OTA_MANIFEST_TAMPER ok=true unexpected_accept')\n"
                "except Exception as e:\n"
                "    print('MPY_OTA_MANIFEST_TAMPER ok=false error={}'.format(str(e).replace(' ', '_')))\n"
            )
            manifest_tamper_text = run_device_code(repl, manifest_tamper_code, timeout=240)
            require_markers(
                manifest_tamper_text,
                ("MPY_OTA_MANIFEST_TAMPER ok=false", "manifest_hmac_mismatch"),
                "manifest tamper",
            )
            repl.exit()
        finally:
            repl.close()

        summary = {
            "ok": True,
            "target": args.target,
            "port": args.port,
            "secure_version": args.secure_version,
            "payload_kind": args.payload_kind,
            "payload_sha256": sha256_hex(plaintext),
            "encrypted_sha256": sha256_hex(payload),
            "tampered_encrypted_sha256": sha256_hex(tampered_payload),
            "device_selected_bits": identity.get("selected_bits"),
            "device_corrected_bit_errors_pct": identity.get("corrected_bit_errors_pct"),
            "manifest_url": manifest_url,
            "http_root": str(http_root),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2, sort_keys=True))
        print("MPY_HTTP_OTA_DEMO ok=true")
        return 0
    except (OSError, RuntimeError, TimeoutError, FirmwareBuildError) as exc:
        summary_path.write_text(
            json.dumps(
                {
                    "ok": False,
                    "target": args.target,
                    "port": args.port,
                    "error": str(exc),
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        server.shutdown()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
