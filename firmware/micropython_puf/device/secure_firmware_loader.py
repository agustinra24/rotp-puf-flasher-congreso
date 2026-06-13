"""PUF-bound encrypted firmware loader for ESP32 MicroPython.

This is a laboratory proof of concept aligned with the ROTP-PUF-FLASHER paper: keep a
small loader in clear text, verify an HMAC over the encrypted module, decrypt in
RAM, and execute only if integrity passes. The root key comes from
`rtc_slow_puf_native.derive_key()`, so the encrypted module is bound to the
enrolled RTC SLOW PUF helper on the device.
"""

try:
    import uhashlib as hashlib
except ImportError:
    import hashlib

try:
    import ubinascii as binascii
except ImportError:
    import binascii

try:
    from ucryptolib import aes as AES
except ImportError:
    from cryptolib import aes as AES

import os
import sys

import rtc_slow_puf_native as puf


MAGIC = b"PUFENC1\0"
VERSION = 1
HEADER_LEN = 32
AES_BLOCK = 16
KEY_LEN = 32
TAG_LEN = 32
MODE_CBC = 2
KDF_SALT = b"DID-PUF-FIRMWARE-ENVELOPE-v1"
KDF_INFO = b"aes-256-cbc+hmac-sha256"


def _sha256(data):
    digest = hashlib.sha256()
    digest.update(data)
    return digest.digest()


def _hex(data):
    return binascii.hexlify(data).decode()


def _hmac_sha256(key, message):
    if len(key) > 64:
        key = _sha256(key)
    if len(key) < 64:
        key = key + b"\0" * (64 - len(key))
    inner = bytes((byte ^ 0x36) for byte in key)
    outer = bytes((byte ^ 0x5C) for byte in key)
    return _sha256(outer + _sha256(inner + message))


def _hkdf_sha256(ikm, salt, info, length):
    if length <= 0:
        raise ValueError("HKDF length must be positive")
    prk = _hmac_sha256(salt, ikm)
    okm = bytearray()
    previous = b""
    counter = 1
    while len(okm) < length:
        if counter > 255:
            raise ValueError("HKDF output is too long")
        previous = _hmac_sha256(prk, previous + info + bytes((counter,)))
        okm.extend(previous)
        counter += 1
    return bytes(okm[:length])


def _constant_time_equal(left, right):
    if len(left) != len(right):
        return False
    diff = 0
    for index in range(len(left)):
        diff |= left[index] ^ right[index]
    return diff == 0


def _derive_envelope_keys(root_key):
    if len(root_key) != KEY_LEN:
        raise ValueError("PUF root key must be 32 bytes")
    material = _hkdf_sha256(root_key, KDF_SALT, KDF_INFO, KEY_LEN * 2)
    return material[:KEY_LEN], material[KEY_LEN:]


def _read_u32_be(data, offset):
    return (
        (data[offset] << 24)
        | (data[offset + 1] << 16)
        | (data[offset + 2] << 8)
        | data[offset + 3]
    )


def _parse_envelope(payload):
    if len(payload) < HEADER_LEN + TAG_LEN:
        raise ValueError("encrypted firmware payload is too short")
    header = payload[:HEADER_LEN]
    if header[: len(MAGIC)] != MAGIC:
        raise ValueError("invalid encrypted firmware magic")
    if header[len(MAGIC)] != VERSION:
        raise ValueError("unsupported encrypted firmware version")
    ciphertext_len = _read_u32_be(header, 28)
    expected_len = HEADER_LEN + ciphertext_len + TAG_LEN
    if len(payload) != expected_len:
        raise ValueError("encrypted firmware length mismatch")
    iv = header[12:28]
    ciphertext = payload[HEADER_LEN : HEADER_LEN + ciphertext_len]
    tag = payload[HEADER_LEN + ciphertext_len :]
    return header, iv, ciphertext, tag


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("decrypted firmware payload is empty")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES_BLOCK:
        raise ValueError("invalid firmware padding")
    if data[-pad_len:] != bytes((pad_len,)) * pad_len:
        raise ValueError("corrupted firmware padding")
    return data[:-pad_len]


def _decrypt_aes_cbc(ciphertext, key, iv):
    if len(key) != KEY_LEN:
        raise ValueError("AES key must be 32 bytes")
    if len(iv) != AES_BLOCK:
        raise ValueError("AES-CBC IV must be 16 bytes")
    cipher = AES(key, MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


def _read_file(path):
    with open(path, "rb") as handle:
        return handle.read()


def _write_file(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def _remove_if_exists(path):
    try:
        os.stat(path)
    except OSError:
        return
    os.remove(path)


def _validate_module_name(module_name):
    if not module_name:
        raise ValueError("temporary module name must not be empty")
    if "/" in module_name or "." in module_name:
        raise ValueError("temporary module name must not contain path separators or dots")
    if module_name[0] >= "0" and module_name[0] <= "9":
        raise ValueError("temporary module name must not start with a digit")
    for char in module_name:
        is_lower = char >= "a" and char <= "z"
        is_upper = char >= "A" and char <= "Z"
        is_digit = char >= "0" and char <= "9"
        if not (is_lower or is_upper or is_digit or char == "_"):
            raise ValueError("temporary module name contains an unsupported character")


def _cleanup_temp_module(module_name):
    sys.modules.pop(module_name, None)
    _remove_if_exists("/{}.py".format(module_name))
    _remove_if_exists("/{}.mpy".format(module_name))


def _assert_plausible_mpy(data):
    if len(data) < 4 or data[0] != ord("M"):
        raise ValueError("decrypted firmware is not a plausible .mpy module")


def _call_main_if_present(namespace):
    main = namespace.get("main")
    if main is not None:
        if not callable(main):
            raise ValueError("encrypted firmware main is not callable")
        main()


def run_encrypted_module(path="protected_app.enc", nonce="firmware-v1"):
    """Verify, decrypt, and execute a PUF-bound encrypted MicroPython module.

    Args:
        path: Encrypted envelope generated by `build_encrypted_firmware.py`.
        nonce: PUF key derivation nonce. Must match the key used by the builder.

    Returns:
        A dict with non-secret execution fingerprints.

    Raises:
        ValueError: if PUF reconstruction, HMAC verification, padding, or
        envelope parsing fails. The encrypted module is not executed on failure.
    """
    root_key = puf.derive_key(nonce=nonce)
    enc_key, mac_key = _derive_envelope_keys(root_key)
    payload = _read_file(path)
    header, iv, ciphertext, tag = _parse_envelope(payload)
    expected_tag = _hmac_sha256(mac_key, header + ciphertext)
    if not _constant_time_equal(expected_tag, tag):
        raise ValueError("HMAC verification failed; encrypted firmware was not executed")
    plaintext = _pkcs7_unpad(_decrypt_aes_cbc(ciphertext, enc_key, iv))
    namespace = {
        "__name__": "__encrypted_firmware__",
        "__file__": path,
    }
    exec(plaintext.decode("utf-8"), namespace)
    _call_main_if_present(namespace)
    return {
        "executed": True,
        "plaintext_sha256": _hex(_sha256(plaintext)),
        "ciphertext_sha256": _hex(_sha256(ciphertext)),
    }


def run_encrypted_mpy_module(path="protected_app.mpy.enc", module_name="_puf_protected_app", nonce="firmware-v1"):
    """Verify, decrypt, import, run, and clean up a PUF-bound .mpy payload.

    The V1.1 lab loader intentionally keeps the clear runtime small. The
    decrypted bytecode is written to a temporary root-level module path only
    after HMAC verification succeeds, imported once, then removed in `finally`.
    """
    _validate_module_name(module_name)
    temp_path = "/{}.mpy".format(module_name)
    root_key = puf.derive_key(nonce=nonce)
    enc_key, mac_key = _derive_envelope_keys(root_key)
    payload = _read_file(path)
    header, iv, ciphertext, tag = _parse_envelope(payload)
    expected_tag = _hmac_sha256(mac_key, header + ciphertext)
    if not _constant_time_equal(expected_tag, tag):
        _cleanup_temp_module(module_name)
        raise ValueError("HMAC verification failed; encrypted firmware was not executed")
    mpy_payload = _pkcs7_unpad(_decrypt_aes_cbc(ciphertext, enc_key, iv))
    _assert_plausible_mpy(mpy_payload)
    _cleanup_temp_module(module_name)
    try:
        _write_file(temp_path, mpy_payload)
        sys.modules.pop(module_name, None)
        module = __import__(module_name)
        main = getattr(module, "main", None)
        if main is None:
            raise ValueError("encrypted .mpy module does not expose main()")
        if not callable(main):
            raise ValueError("encrypted .mpy module main is not callable")
        main()
        return {
            "executed": True,
            "mpy_sha256": _hex(_sha256(mpy_payload)),
            "ciphertext_sha256": _hex(_sha256(ciphertext)),
            "module_name": module_name,
        }
    finally:
        _cleanup_temp_module(module_name)
