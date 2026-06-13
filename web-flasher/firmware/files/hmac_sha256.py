"""
HMAC-SHA256 implementation for MicroPython (RFC 2104).

MicroPython on ESP32 does not include a built-in hmac module,
so this provides a manual implementation using uhashlib.sha256.

Used by the puzzle authentication protocol to compute:
    P2 = HMAC-SHA256(device_key || server_key, R2)
"""

try:
    from uhashlib import sha256
except ImportError:
    from hashlib import sha256

# SHA-256 block size in bytes
_BLOCK_SIZE = 64


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """
    Compute HMAC-SHA256(key, msg) per RFC 2104.

    Parameters:
        key: Secret key (any length; hashed if > 64 bytes).
        msg: Message to authenticate.

    Returns:
        32-byte HMAC digest.
    """
    # Step 1: If key is longer than block size, hash it down to 32 bytes
    if len(key) > _BLOCK_SIZE:
        h = sha256(key)
        key = h.digest()

    # Step 2: Pad key to block size with zeroes
    if len(key) < _BLOCK_SIZE:
        key = key + b'\x00' * (_BLOCK_SIZE - len(key))

    # Step 3: Create inner and outer padded keys
    # ipad = key XOR 0x36 repeated, opad = key XOR 0x5c repeated
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5c for b in key)

    # Step 4: inner hash = SHA256(ipad || msg)
    inner = sha256(ipad + msg)
    inner_digest = inner.digest()

    # Step 5: outer hash = SHA256(opad || inner_hash)
    outer = sha256(opad + inner_digest)
    return outer.digest()
