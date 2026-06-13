"""
HTTP client for IoT device communication with the FastAPI server.

Sends JSON payloads via POST with JWT Bearer authentication.
Includes retry logic with exponential backoff for network errors
and automatic response cleanup to prevent socket leaks.

Replaces the old http_communication.py which sent AES-encrypted
binary data with cookie-based sessions.
"""

import time

try:
    import ujson as json
except ImportError:
    import json

try:
    import urequests
except ImportError:
    import requests as urequests

# Backoff delays in seconds for retries on network errors
_BACKOFF = (1, 3, 9)
# NOTE: MicroPython urequests has no timeout parameter and usocket lacks
# setdefaulttimeout(). If the server becomes unreachable, POST calls may
# block until the OS-level TCP timeout (~120s on ESP32). This is acceptable
# for thesis demo scope but should be addressed for production deployments.


class HttpClient:
    """HTTP client for JSON API communication with retry and Bearer auth."""

    def __init__(self, base_url: str, port: int):
        """
        Parameters:
            base_url: Server URL without trailing slash (e.g. "http://192.168.1.100").
            port:     Server port (e.g. 5000).
        """
        self.base = "{}:{}".format(base_url.rstrip("/"), port)

    def post_json(self, path: str, data: dict, token: str = None) -> tuple:
        """
        Send a JSON POST request with optional Bearer token.

        Parameters:
            path:  API endpoint path (e.g. "/api/v1/device/reading").
            data:  Dict payload to serialize as JSON.
            token: JWT access token. Omit for unauthenticated requests (login).

        Returns:
            Tuple of (status_code: int, body: dict or None).
            On network failure after all retries: (-1, None).
        """
        url = self.base + path
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer {}".format(token)

        body = json.dumps(data)
        last_error = None

        for attempt, delay in enumerate(_BACKOFF):
            resp = None
            try:
                resp = urequests.post(url, data=body, headers=headers)
                status = resp.status_code

                # Parse JSON body if present, otherwise None
                resp_body = None
                try:
                    resp_body = resp.json()
                except Exception:
                    pass

                return (status, resp_body)

            except OSError as e:
                last_error = e
                print("[http] Attempt {}/{} failed: {}".format(
                    attempt + 1, len(_BACKOFF), e))
                if attempt < len(_BACKOFF) - 1:
                    time.sleep(delay)

            finally:
                # Always close response to free the socket
                if resp is not None:
                    try:
                        resp.close()
                    except Exception:
                        pass

        print("[http] All {} retries exhausted. Last error: {}".format(
            len(_BACKOFF), last_error))
        return (-1, None)

    def post_no_content(self, path: str, token: str) -> int:
        """
        Send a POST expecting 204 No Content (used for logout).

        Parameters:
            path:  API endpoint (e.g. "/api/v1/auth/logout").
            token: JWT access token.

        Returns:
            HTTP status code, or -1 on network failure.
        """
        url = self.base + path
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(token)
        }

        resp = None
        try:
            resp = urequests.post(url, data="", headers=headers)
            return resp.status_code
        except OSError as e:
            print("[http] Logout request failed: {}".format(e))
            return -1
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
