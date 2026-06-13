#!/usr/bin/env python3
"""Build a PUF-bound encrypted MicroPython firmware payload.

The builder expects the raw 32-byte key returned by the trusted device-side
`rtc_slow_puf_native.derive_key(nonce="firmware-v1")` flow. It never prints the
key. AES-CBC is delegated to the local OpenSSL binary to avoid introducing a new
Python crypto dependency into this lab tree.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final


MAGIC: Final[bytes] = b"PUFENC1\0"
VERSION: Final[int] = 1
HEADER_LEN: Final[int] = 32
AES_BLOCK: Final[int] = 16
KEY_LEN: Final[int] = 32
TAG_LEN: Final[int] = 32
ENVELOPE_KEY_LEN: Final[int] = 64
RESERVED: Final[bytes] = b"\0\0\0"
KEY_ENV_VAR: Final[str] = "PUF_FIRMWARE_KEY_HEX"
KDF_SALT: Final[bytes] = b"DID-PUF-FIRMWARE-ENVELOPE-v1"
KDF_INFO: Final[bytes] = b"aes-256-cbc+hmac-sha256"
REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
TMP_ROOT: Final[Path] = Path("/private/tmp")
MPY_VERSION_TOKEN: Final[str] = "v1.28"


class FirmwareBuildError(RuntimeError):
    """Raised when the encrypted firmware envelope cannot be built or checked."""


def is_inside(child: Path, parent: Path) -> bool:
    """Return true when `child` resolves below `parent`."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def parse_hex_bytes(value: str, *, expected_len: int, label: str) -> bytes:
    """Parse a fixed-size hex string without accepting odd lengths or prefixes."""
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != expected_len * 2:
        raise FirmwareBuildError(f"{label} must be exactly {expected_len} bytes as hex")
    try:
        parsed = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise FirmwareBuildError(f"{label} must be valid hexadecimal") from exc
    if len(parsed) != expected_len:
        raise FirmwareBuildError(f"{label} must be exactly {expected_len} bytes")
    return parsed


def read_key_file(path: Path, *, allow_repo_key_file: bool) -> bytes:
    """Read the root key from a hex file, refusing repo-local key custody by default."""
    if is_inside(path, REPO_ROOT) and not allow_repo_key_file:
        raise FirmwareBuildError("key files must stay outside the repo unless --allow-repo-key-file is explicit")
    return parse_hex_bytes(path.read_text(encoding="utf-8"), expected_len=KEY_LEN, label="key file")


def load_root_key(args: argparse.Namespace) -> bytes:
    """Load exactly one root key source: --key-hex, --key-file, or the env var."""
    env_key = os.environ.get(KEY_ENV_VAR)
    sources = [args.key_hex is not None, args.key_file is not None, env_key is not None]
    if sum(sources) != 1:
        raise FirmwareBuildError(
            f"provide exactly one key source: --key-hex, --key-file, or {KEY_ENV_VAR}"
        )
    if args.key_hex is not None:
        return parse_hex_bytes(args.key_hex, expected_len=KEY_LEN, label="--key-hex")
    if args.key_file is not None:
        return read_key_file(args.key_file, allow_repo_key_file=args.allow_repo_key_file)
    if env_key is None:
        raise FirmwareBuildError(f"{KEY_ENV_VAR} is not set")
    return parse_hex_bytes(env_key, expected_len=KEY_LEN, label=KEY_ENV_VAR)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256 using Python's standard library implementation."""
    return hmac.new(key, message, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Derive `length` bytes with HKDF-SHA256."""
    if length <= 0:
        raise FirmwareBuildError("HKDF length must be positive")
    prk = hmac_sha256(salt, ikm)
    okm = bytearray()
    previous = b""
    counter = 1
    while len(okm) < length:
        if counter > 255:
            raise FirmwareBuildError("HKDF output is too long")
        previous = hmac_sha256(prk, previous + info + bytes((counter,)))
        okm.extend(previous)
        counter += 1
    return bytes(okm[:length])


def derive_envelope_keys(root_key: bytes) -> tuple[bytes, bytes]:
    """Split the PUF-derived root key into independent AES and HMAC keys."""
    if len(root_key) != KEY_LEN:
        raise FirmwareBuildError(f"root key must be {KEY_LEN} bytes")
    material = hkdf_sha256(root_key, KDF_SALT, KDF_INFO, ENVELOPE_KEY_LEN)
    return material[:KEY_LEN], material[KEY_LEN:]


def pkcs7_pad(data: bytes) -> bytes:
    """Pad plaintext to an AES block boundary with PKCS#7."""
    pad_len = AES_BLOCK - (len(data) % AES_BLOCK)
    return data + bytes((pad_len,)) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding after OpenSSL decryption in self-tests."""
    if not data:
        raise FirmwareBuildError("decrypted payload is empty")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES_BLOCK:
        raise FirmwareBuildError("invalid PKCS#7 padding length")
    if data[-pad_len:] != bytes((pad_len,)) * pad_len:
        raise FirmwareBuildError("invalid PKCS#7 padding bytes")
    return data[:-pad_len]


def openssl_path() -> str:
    """Resolve the OpenSSL executable used for AES-CBC operations."""
    path = shutil.which("openssl")
    if path is None:
        raise FirmwareBuildError("openssl was not found on PATH")
    return path


def mpy_cross_path(path: Path | None) -> Path:
    """Resolve the mpy-cross executable used for portable MicroPython bytecode."""
    if path is not None:
        resolved = path.expanduser()
        if not resolved.exists():
            raise FirmwareBuildError(f"mpy-cross was not found at {resolved}")
        return resolved
    discovered = shutil.which("mpy-cross")
    if discovered is None:
        raise FirmwareBuildError(
            "mpy-cross was not found on PATH; build MicroPython v1.28.0 mpy-cross "
            "or pass --mpy-cross"
        )
    return Path(discovered)


def mpy_cross_version(path: Path) -> str:
    """Return mpy-cross version text for compatibility evidence."""
    result = subprocess.run([str(path), "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace").strip()
    if result.returncode != 0:
        raise FirmwareBuildError(f"mpy-cross --version failed: {output}")
    return output


def validate_mpy_cross_version(path: Path, *, allow_mismatch: bool) -> str:
    """Fail closed unless mpy-cross reports a MicroPython v1.28-compatible build."""
    version = mpy_cross_version(path)
    if MPY_VERSION_TOKEN not in version and not allow_mismatch:
        raise FirmwareBuildError(
            f"mpy-cross version must contain {MPY_VERSION_TOKEN!r}; got {version!r}. "
            "Use a v1.28.0 mpy-cross build or pass --allow-mpy-version-mismatch for an explicit lab override."
        )
    return version


def assert_plausible_mpy(data: bytes) -> None:
    """Check the minimum stable .mpy header signal before encrypting bytecode."""
    if len(data) < 4 or data[0] != ord("M"):
        raise FirmwareBuildError("compiled payload is not a plausible .mpy file")


def compile_to_mpy(input_path: Path, mpy_cross: Path, *, keep_mpy: Path | None = None) -> tuple[bytes, Path]:
    """Compile a Python source module to portable .mpy outside the repository."""
    if input_path.suffix != ".py":
        raise FirmwareBuildError("--compile-mpy expects a .py input file")
    with tempfile.TemporaryDirectory(prefix="puf-mpy-build-", dir=str(TMP_ROOT)) as temp:
        temp_dir = Path(temp)
        temp_mpy = temp_dir / f"{input_path.stem}.mpy"
        result = subprocess.run(
            [str(mpy_cross), "-o", str(temp_mpy), str(input_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise FirmwareBuildError(f"mpy-cross compilation failed: {stderr}")
        compiled = temp_mpy.read_bytes()
        assert_plausible_mpy(compiled)
        if keep_mpy is not None:
            if is_inside(keep_mpy, REPO_ROOT):
                raise FirmwareBuildError("--keep-mpy output must stay outside the repo")
            keep_mpy.parent.mkdir(parents=True, exist_ok=True)
            keep_mpy.write_bytes(compiled)
            return compiled, keep_mpy
        return compiled, temp_mpy


def openssl_aes_cbc(data: bytes, key: bytes, iv: bytes, *, decrypt: bool = False) -> bytes:
    """Run AES-256-CBC through OpenSSL with caller-managed PKCS#7 padding."""
    if len(key) != KEY_LEN:
        raise FirmwareBuildError("AES key must be 32 bytes")
    if len(iv) != AES_BLOCK:
        raise FirmwareBuildError("AES-CBC IV must be 16 bytes")
    command = [
        openssl_path(),
        "enc",
        "-aes-256-cbc",
        "-K",
        key.hex(),
        "-iv",
        iv.hex(),
        "-nosalt",
        "-nopad",
    ]
    if decrypt:
        command.insert(2, "-d")
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise FirmwareBuildError(f"OpenSSL AES-CBC failed: {stderr}")
    return result.stdout


def build_header(iv: bytes, ciphertext_len: int) -> bytes:
    """Build the fixed 32-byte envelope header."""
    if ciphertext_len <= 0:
        raise FirmwareBuildError("ciphertext must not be empty")
    if ciphertext_len > 0xFFFFFFFF:
        raise FirmwareBuildError("ciphertext is too large for envelope v1")
    return MAGIC + bytes((VERSION,)) + RESERVED + iv + ciphertext_len.to_bytes(4, "big")


def build_envelope(plaintext: bytes, root_key: bytes, *, iv: bytes | None = None) -> bytes:
    """Encrypt plaintext and return `header || ciphertext || hmac`."""
    if not plaintext:
        raise FirmwareBuildError("input firmware module is empty")
    enc_key, mac_key = derive_envelope_keys(root_key)
    actual_iv = iv if iv is not None else secrets.token_bytes(AES_BLOCK)
    if len(actual_iv) != AES_BLOCK:
        raise FirmwareBuildError("IV must be 16 bytes")
    ciphertext = openssl_aes_cbc(pkcs7_pad(plaintext), enc_key, actual_iv)
    header = build_header(actual_iv, len(ciphertext))
    tag = hmac_sha256(mac_key, header + ciphertext)
    return header + ciphertext + tag


def parse_envelope(payload: bytes) -> tuple[bytes, bytes, bytes]:
    """Return `(header, ciphertext, tag)` from an envelope v1 payload."""
    if len(payload) < HEADER_LEN + TAG_LEN:
        raise FirmwareBuildError("encrypted payload is too short")
    header = payload[:HEADER_LEN]
    if header[: len(MAGIC)] != MAGIC:
        raise FirmwareBuildError("invalid encrypted payload magic")
    if header[len(MAGIC)] != VERSION:
        raise FirmwareBuildError("unsupported encrypted payload version")
    ciphertext_len = int.from_bytes(header[28:32], "big")
    expected_len = HEADER_LEN + ciphertext_len + TAG_LEN
    if len(payload) != expected_len:
        raise FirmwareBuildError(
            f"encrypted payload length mismatch: expected {expected_len}, got {len(payload)}"
        )
    ciphertext = payload[HEADER_LEN : HEADER_LEN + ciphertext_len]
    tag = payload[-TAG_LEN:]
    return header, ciphertext, tag


def decrypt_envelope(payload: bytes, root_key: bytes) -> bytes:
    """Verify and decrypt an envelope, used by host self-tests only."""
    enc_key, mac_key = derive_envelope_keys(root_key)
    header, ciphertext, tag = parse_envelope(payload)
    expected = hmac_sha256(mac_key, header + ciphertext)
    if not hmac.compare_digest(expected, tag):
        raise FirmwareBuildError("HMAC verification failed")
    iv = header[12:28]
    return pkcs7_unpad(openssl_aes_cbc(ciphertext, enc_key, iv, decrypt=True))


def sha256_hex(data: bytes) -> str:
    """Return a printable SHA-256 fingerprint without exposing raw material."""
    return hashlib.sha256(data).hexdigest()


def write_envelope(input_path: Path, output_path: Path, root_key: bytes, *, iv: bytes | None = None) -> bytes:
    """Read, encrypt, and write the firmware envelope."""
    if input_path.resolve() == output_path.resolve():
        raise FirmwareBuildError("--input and --output must be different files")
    plaintext = input_path.read_bytes()
    return write_envelope_bytes(plaintext, output_path, root_key, iv=iv)


def write_envelope_bytes(plaintext: bytes, output_path: Path, root_key: bytes, *, iv: bytes | None = None) -> bytes:
    """Encrypt caller-provided firmware bytes and write the envelope."""
    envelope = build_envelope(plaintext, root_key, iv=iv)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(envelope)
    return envelope


def self_test() -> None:
    """Exercise encryption, decryption, tamper rejection, and string hiding."""
    root_key = bytes(range(KEY_LEN))
    iv = bytes(range(16, 32))
    secret_marker = b"PUF_BOUND_FIRMWARE_DEMO_SECRET_V1"
    plaintext = b'print("PROTECTED_APP_OK")\nSECRET_MARKER = "' + secret_marker + b'"\n'
    with tempfile.TemporaryDirectory(prefix="puf-firmware-self-test-") as temp:
        temp_dir = Path(temp)
        source = temp_dir / "protected_app.py"
        output = temp_dir / "protected_app.enc"
        source.write_bytes(plaintext)
        envelope = write_envelope(source, output, root_key, iv=iv)
        if secret_marker in envelope:
            raise FirmwareBuildError("encrypted envelope still contains the plaintext marker")
        roundtrip = decrypt_envelope(envelope, root_key)
        if roundtrip != plaintext:
            raise FirmwareBuildError("decrypted payload did not match the source module")
        tampered = bytearray(envelope)
        tampered[HEADER_LEN] ^= 0x01
        try:
            decrypt_envelope(bytes(tampered), root_key)
        except FirmwareBuildError as exc:
            if "HMAC verification failed" not in str(exc):
                raise
        else:
            raise FirmwareBuildError("tampered ciphertext was accepted")
    print("self_test: ok")


def self_test_mpy(mpy_cross: Path, *, allow_mismatch: bool) -> None:
    """Exercise the source -> .mpy -> encrypted envelope flow."""
    version = validate_mpy_cross_version(mpy_cross, allow_mismatch=allow_mismatch)
    root_key = bytes(range(KEY_LEN))
    iv = bytes(range(16, 32))
    secret_marker = b"PUF_BOUND_FIRMWARE_DEMO_SECRET_V1"
    source_text = (
        b'DEMO_SECRET_MARKER = "' + secret_marker + b'"\n\n'
        b"def main():\n"
        b'    print("PROTECTED_APP_MPY_OK")\n'
        b"    return len(DEMO_SECRET_MARKER)\n"
    )
    with tempfile.TemporaryDirectory(prefix="puf-firmware-mpy-self-test-", dir=str(TMP_ROOT)) as temp:
        temp_dir = Path(temp)
        source = temp_dir / "protected_app.py"
        output = temp_dir / "protected_app.mpy.enc"
        source.write_bytes(source_text)
        mpy_payload, _ = compile_to_mpy(source, mpy_cross)
        envelope = write_envelope_bytes(mpy_payload, output, root_key, iv=iv)
        if secret_marker in envelope:
            raise FirmwareBuildError("encrypted .mpy envelope still contains the plaintext marker")
        roundtrip = decrypt_envelope(envelope, root_key)
        if roundtrip != mpy_payload:
            raise FirmwareBuildError("decrypted .mpy payload did not match the compiled bytecode")
        assert_plausible_mpy(roundtrip)
        tampered = bytearray(envelope)
        tampered[HEADER_LEN] ^= 0x01
        try:
            decrypt_envelope(bytes(tampered), root_key)
        except FirmwareBuildError as exc:
            if "HMAC verification failed" not in str(exc):
                raise
        else:
            raise FirmwareBuildError("tampered .mpy ciphertext was accepted")
    print(f"self_test_mpy: ok ({version})")


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line interface for the firmware builder."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="plaintext MicroPython module to encrypt")
    parser.add_argument("--output", type=Path, help="encrypted firmware envelope to write")
    parser.add_argument("--key-hex", help="32-byte PUF-derived root key as hex, not printed")
    parser.add_argument("--key-file", type=Path, help="file containing 32-byte PUF-derived root key hex")
    parser.add_argument("--allow-repo-key-file", action="store_true", help="allow --key-file inside the repo")
    parser.add_argument("--iv-hex", help="16-byte IV hex for deterministic tests only")
    parser.add_argument("--compile-mpy", action="store_true", help="compile --input to .mpy before encryption")
    parser.add_argument("--mpy-cross", type=Path, help="path to MicroPython v1.28-compatible mpy-cross")
    parser.add_argument("--keep-mpy", type=Path, help="optional outside-repo path to keep the intermediate .mpy")
    parser.add_argument(
        "--allow-mpy-version-mismatch",
        action="store_true",
        help="explicit lab override when mpy-cross --version does not report v1.28",
    )
    parser.add_argument("--self-test", action="store_true", help="run local builder self-test")
    parser.add_argument("--self-test-mpy", action="store_true", help="run local builder self-test with mpy-cross")
    return parser


def main() -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        if args.self_test_mpy:
            self_test_mpy(
                mpy_cross_path(args.mpy_cross),
                allow_mismatch=args.allow_mpy_version_mismatch,
            )
            return 0
        if args.input is None or args.output is None:
            raise FirmwareBuildError("--input and --output are required unless a self-test is used")
        root_key = load_root_key(args)
        iv = parse_hex_bytes(args.iv_hex, expected_len=AES_BLOCK, label="--iv-hex") if args.iv_hex else None
        payload_kind = "python"
        mpy_version = None
        if args.compile_mpy:
            cross = mpy_cross_path(args.mpy_cross)
            mpy_version = validate_mpy_cross_version(cross, allow_mismatch=args.allow_mpy_version_mismatch)
            plaintext, mpy_path = compile_to_mpy(args.input, cross, keep_mpy=args.keep_mpy)
            payload_kind = "mpy"
        else:
            plaintext = args.input.read_bytes()
            mpy_path = None
        envelope = write_envelope_bytes(plaintext, args.output, root_key, iv=iv)
        print(f"output: {args.output}")
        print(f"payload_kind: {payload_kind}")
        if mpy_version is not None:
            print(f"mpy_cross_version: {mpy_version}")
        if mpy_path is not None and args.keep_mpy is not None:
            print(f"mpy_output: {mpy_path}")
        print(f"payload_bytes: {len(plaintext)}")
        print(f"encrypted_bytes: {len(envelope)}")
        print(f"payload_sha256: {sha256_hex(plaintext)}")
        print(f"encrypted_sha256: {sha256_hex(envelope)}")
        return 0
    except (OSError, FirmwareBuildError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
