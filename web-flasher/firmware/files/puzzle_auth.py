"""
Cryptographic puzzle authentication for the IoT device.

Implements the HMAC-SHA256 + AES-256-CBC puzzle protocol expected by the
backend device-login endpoint.

Protocol:
    1. Device generates R2 (32 random bytes)
    2. P2 = HMAC-SHA256(device_key || server_key, R2)
    3. P2c = AES-256-CBC-encrypt(P2, device_key)
    4. POST {device_id, api_key, puzzle_response} to /api/v1/auth/device/login
    5. Server reconstructs P2, decrypts P2c, compares => issues JWT

Replaces Authentication3.py (password + cookie based auth).
"""

import os
import time
from hmac_sha256 import hmac_sha256
import aes256

try:
    from ubinascii import b2a_base64
except ImportError:
    from binascii import b2a_base64

# API paths
_LOGIN_PATH = "/api/v1/auth/device/login"
_LOGOUT_PATH = "/api/v1/auth/logout"

# Max retry attempts for 409 (stale session) without cached token
_STALE_SESSION_RETRIES = 5
_STALE_SESSION_DELAY = 60  # seconds between retries


def _b64(data: bytes) -> str:
    """Base64-encode bytes, stripping MicroPython's trailing newline."""
    return b2a_base64(data).strip().decode("utf-8")


class PuzzleAuth:
    """Handles puzzle-based device authentication and JWT token management."""

    def __init__(self, config: dict, http_client):
        """
        Parameters:
            config:      Loaded config dict with 'device_key' and 'server_key' as bytes.
            http_client: HttpClient instance for API requests.
        """
        self.device_id = config["device_id"]
        self.api_key = config["api_key"]
        self.device_key = config["device_key"]   # 32 bytes
        self.server_key = config["server_key"]    # 32 bytes
        self.http = http_client
        self._cached_token = None

    def _build_puzzle(self) -> dict:
        """
        Construct the puzzle_response dict matching the server's expected format.

        Field names follow the backend compatibility contract:
        - "id_origen"
        - "Random dispositivo"
        - "Parametro de identidad cifrado" (dict with "ciphertext" and "iv")
        """
        # Step 1: Generate 32-byte random R2
        r2 = os.urandom(32)

        # Step 2: HMAC key = device_key (32 bytes) + server_key (32 bytes) = 64 bytes
        hmac_key = self.device_key + self.server_key

        # Step 3: P2 = HMAC-SHA256(hmac_key, R2) => 32 bytes
        p2 = hmac_sha256(hmac_key, r2)

        # Step 4: Encrypt P2 with AES-256-CBC using device_key
        # aes256.encrypt handles PKCS7 padding (32 bytes => 48 bytes)
        p2c = aes256.encrypt(p2, self.device_key)

        return {
            "id_origen": self.device_id,
            "Random dispositivo": _b64(r2),
            "Parametro de identidad cifrado": p2c  # dict with "ciphertext" and "iv"
        }

    def authenticate(self) -> str:
        """
        Execute puzzle authentication and return a JWT access token.

        Handles:
            - 200: Success, caches and returns the token.
            - 409: Stale session. Attempts logout if cached token exists,
                   otherwise retries with backoff.
            - 401: Bad credentials, raises RuntimeError.
            - Network failure: Returns None.

        Returns:
            JWT access_token string, or None if authentication failed
            after all recovery attempts.
        """
        # Build login payload
        puzzle = self._build_puzzle()
        payload = {
            "device_id": self.device_id,
            "api_key": self.api_key,
            "puzzle_response": puzzle
        }

        status, body = self.http.post_json(_LOGIN_PATH, payload)

        # Success
        if status == 200 and body:
            token = body.get("access_token")
            if token:
                self._cached_token = token
                print("[auth] Authenticated. Token acquired.")
                return token
            print("[auth] 200 but no access_token in response")
            return None

        # Stale session: try to clear it
        if status == 409:
            return self._recover_stale_session(payload)

        # Bad credentials
        if status == 401:
            detail = body.get("detail", "unknown") if body else "no response"
            print("[auth] FATAL: 401 Unauthorized: {}".format(detail))
            print("[auth] Check device_id, api_key, and crypto keys in config.json")
            return None

        # Unexpected status or network failure
        print("[auth] Authentication failed: HTTP {}".format(status))
        return None

    def _recover_stale_session(self, login_payload: dict) -> str:
        """
        Handle HTTP 409 (active session exists).

        Strategy:
            1. If we have a cached token from a previous session, try logout + re-auth.
            2. If no cached token (device rebooted), retry with backoff waiting
               for the Redis session to expire (24h TTL, limitation of the API).
        """
        if self._cached_token:
            print("[auth] 409: Stale session detected. Attempting logout...")
            logout_status = self.http.post_no_content(_LOGOUT_PATH, self._cached_token)
            self._cached_token = None

            if logout_status == 204 or logout_status == 401:
                # 204 = logout OK, 401 = token already expired (session gone)
                print("[auth] Previous session cleared. Re-authenticating...")
                time.sleep(1)
                status, body = self.http.post_json(_LOGIN_PATH, login_payload)
                if status == 200 and body:
                    token = body.get("access_token")
                    if token:
                        self._cached_token = token
                        print("[auth] Re-authenticated after logout.")
                        return token
            print("[auth] Logout + re-auth failed (HTTP {})".format(logout_status))

        # No cached token: retry with backoff
        print("[auth] 409: No cached token. Retrying with backoff...")
        print("[auth] (Session expires in Redis after 24h; this is an API limitation)")
        for attempt in range(1, _STALE_SESSION_RETRIES + 1):
            print("[auth] Retry {}/{} in {}s...".format(
                attempt, _STALE_SESSION_RETRIES, _STALE_SESSION_DELAY))
            time.sleep(_STALE_SESSION_DELAY)

            # Rebuild puzzle (fresh R2 each attempt)
            login_payload["puzzle_response"] = self._build_puzzle()
            status, body = self.http.post_json(_LOGIN_PATH, login_payload)

            if status == 200 and body:
                token = body.get("access_token")
                if token:
                    self._cached_token = token
                    print("[auth] Authenticated on retry {}.".format(attempt))
                    return token

            if status != 409:
                print("[auth] Unexpected status {} on retry".format(status))
                break

        print("[auth] All stale session retries exhausted.")
        return None

    def logout(self) -> bool:
        """
        Explicitly close the current session.

        Returns:
            True if logout succeeded (204) or session was already gone.
        """
        if not self._cached_token:
            print("[auth] No active token to logout")
            return True

        status = self.http.post_no_content(_LOGOUT_PATH, self._cached_token)
        self._cached_token = None

        if status == 204:
            print("[auth] Logged out.")
            return True
        print("[auth] Logout returned HTTP {}".format(status))
        return status == 401  # Token expired = session already gone
