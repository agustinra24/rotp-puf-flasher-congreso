"""
PUF-bound at-rest encryption for /config.json.

The Web Flasher stores the operational configuration as a JSON envelope rather
than plaintext. This module derives the same envelope keys from the local
SRAM-PUF at boot, verifies the HMAC before decrypting, and returns the plaintext
configuration dictionary to config_manager.
"""

try:
    import ujson as json
except ImportError:
    import json

try:
    import os
    import ubinascii
    import uhashlib as hashlib
except ImportError as exc:
    raise ImportError("config_crypto must run on ESP32 MicroPython") from exc

import aes256
import hmac_sha256
import rtc_slow_puf_native


CONFIG_FORMAT = "ROTP-PUF-CONFIG"
CONFIG_VERSION = 1
CONFIG_ALG = "AES-256-CBC+HMAC-SHA256"
CONFIG_KDF = "HKDF-SHA256"
CONFIG_PUF_NONCE = "config-json-v1"
CONFIG_HKDF_INFO = b"ROTP-PUF-CONFIG|keys|v1"
CONFIG_SALT_BYTES = 16


def _b64(data):
    return ubinascii.b2a_base64(data).strip().decode("utf-8")


def _unb64(text):
    return ubinascii.a2b_base64(text)


def _hex(data):
    return ubinascii.hexlify(data).decode("utf-8")


def _unhex(text):
    return ubinascii.unhexlify(text)


def _sha256(data):
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


def _hkdf_sha256(ikm, salt, info, length):
    prk = hmac_sha256.hmac_sha256(salt, ikm)
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac_sha256.hmac_sha256(prk, previous + info + bytes((counter,)))
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def _constant_time_equal(left, right):
    if len(left) != len(right):
        return False
    diff = 0
    for i in range(len(left)):
        diff |= left[i] ^ right[i]
    return diff == 0


def _auth_string(envelope):
    return "{}|{}|{}|{}|{}|{}".format(
        CONFIG_FORMAT,
        CONFIG_VERSION,
        envelope["puf_nonce"],
        envelope["salt_b64"],
        envelope["iv_b64"],
        envelope["ciphertext_b64"],
    )


def _validate_envelope(envelope):
    if envelope.get("format") != CONFIG_FORMAT:
        raise ValueError("unsupported config envelope format")
    if envelope.get("version") != CONFIG_VERSION:
        raise ValueError("unsupported config envelope version")
    if envelope.get("alg") != CONFIG_ALG:
        raise ValueError("unsupported config envelope algorithm")
    if envelope.get("kdf") != CONFIG_KDF:
        raise ValueError("unsupported config envelope KDF")
    for field in ("puf_nonce", "salt_b64", "iv_b64", "ciphertext_b64", "tag_hex"):
        if field not in envelope:
            raise ValueError("missing config envelope field: {}".format(field))


def _derive_envelope_keys(puf_nonce, salt):
    puf_key = rtc_slow_puf_native.derive_key(nonce=puf_nonce)
    okm = _hkdf_sha256(puf_key, salt, CONFIG_HKDF_INFO, 64)
    return okm[:32], okm[32:]


def is_envelope(config):
    return isinstance(config, dict) and config.get("format") == CONFIG_FORMAT


def decrypt_config(envelope):
    """
    Verify and decrypt a PUF-bound configuration envelope.

    Raises ValueError when parsing, authentication, PUF reconstruction, or
    decryption fails. The plaintext is never written back to flash.
    """
    _validate_envelope(envelope)
    salt = _unb64(envelope["salt_b64"])
    enc_key, mac_key = _derive_envelope_keys(envelope["puf_nonce"], salt)
    expected = hmac_sha256.hmac_sha256(mac_key, _auth_string(envelope).encode("utf-8"))
    received = _unhex(envelope["tag_hex"])
    if not _constant_time_equal(expected, received):
        raise ValueError("config envelope HMAC verification failed")
    plaintext = aes256.decrypt(
        {
            "ciphertext": envelope["ciphertext_b64"],
            "iv": envelope["iv_b64"],
        },
        enc_key,
    )
    try:
        return json.loads(plaintext.decode("utf-8"))
    except ValueError as exc:
        raise ValueError("decrypted config is not valid JSON: {}".format(exc))


def ensure_puf_enrolled():
    """Enroll the RTC SLOW PUF helper when missing."""
    status = rtc_slow_puf_native.status()
    if not status.get("enrolled"):
        rtc_slow_puf_native.enroll()


def encrypt_config(config):
    """
    Encrypt a plaintext config dictionary as a PUF-bound envelope.

    This is used by UART provisioning. The browser normally performs the same
    operation with Web Crypto and uploads only the resulting envelope.
    """
    ensure_puf_enrolled()
    plaintext = json.dumps(config).encode("utf-8")
    salt = os.urandom(CONFIG_SALT_BYTES)
    enc_key, mac_key = _derive_envelope_keys(CONFIG_PUF_NONCE, salt)
    encrypted = aes256.encrypt(plaintext, enc_key)
    envelope = {
        "format": CONFIG_FORMAT,
        "version": CONFIG_VERSION,
        "alg": CONFIG_ALG,
        "kdf": CONFIG_KDF,
        "puf_nonce": CONFIG_PUF_NONCE,
        "salt_b64": _b64(salt),
        "iv_b64": encrypted["iv"],
        "ciphertext_b64": encrypted["ciphertext"],
    }
    envelope["tag_hex"] = _hex(hmac_sha256.hmac_sha256(mac_key, _auth_string(envelope).encode("utf-8")))
    return envelope
