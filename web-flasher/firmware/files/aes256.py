"""
AES-256-CBC encryption/decryption for MicroPython.

Compatible with the backend AES-256-CBC JSON envelope.
Output format: {"ciphertext": "<base64>", "iv": "<base64>"}
"""

import os

try:
    from ucryptolib import aes as AES
except ImportError:
    from cryptolib import aes as AES

try:
    from ubinascii import b2a_base64, a2b_base64
except ImportError:
    from binascii import b2a_base64, a2b_base64

# AES block size in bytes
_BLOCK = 16
# CBC mode identifier in MicroPython's ucryptolib
_MODE_CBC = 2


def _pkcs7_pad(data: bytes) -> bytes:
    """Apply PKCS7 padding to align data to 16-byte AES blocks."""
    pad_len = _BLOCK - (len(data) % _BLOCK)
    # PKCS7: if already aligned, add full block of padding (pad_len = 16)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding. Raises ValueError on invalid padding."""
    if len(data) == 0:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > _BLOCK:
        raise ValueError("Invalid padding value: {}".format(pad_len))
    # Verify all padding bytes match
    for i in range(pad_len):
        if data[-(i + 1)] != pad_len:
            raise ValueError("Corrupted padding at byte {}".format(i))
    return data[:-pad_len]


def _b64(data: bytes) -> str:
    """Base64-encode bytes, stripping MicroPython's trailing newline."""
    return b2a_base64(data).strip().decode("utf-8")


def encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt with AES-256-CBC + PKCS7 padding.

    Parameters:
        plaintext: Data to encrypt (any length).
        key:       32-byte AES-256 key.

    Returns:
        Dict with 'ciphertext' and 'iv', both base64-encoded strings.
        Compatible with the backend AES-256-CBC output format.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256, got {}".format(len(key)))

    iv = os.urandom(_BLOCK)
    padded = _pkcs7_pad(plaintext)
    # MicroPython ucryptolib: AES(key, mode, iv) - new object per operation
    cipher = AES(key, _MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    return {
        "ciphertext": _b64(ciphertext),
        "iv": _b64(iv)
    }


def decrypt(encrypted_data: dict, key: bytes) -> bytes:
    """
    Decrypt AES-256-CBC + PKCS7 padding.

    Parameters:
        encrypted_data: Dict with 'ciphertext' and 'iv' (base64 strings).
        key:            32-byte AES-256 key.

    Returns:
        Decrypted plaintext bytes.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256, got {}".format(len(key)))

    ciphertext = a2b_base64(encrypted_data["ciphertext"])
    iv = a2b_base64(encrypted_data["iv"])
    # New cipher object for decryption (MicroPython requires separate instances)
    cipher = AES(key, _MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)

    return _pkcs7_unpad(padded)
