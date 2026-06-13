"""Minimal PUF-bound HTTP OTA helper for the MicroPython FWENC demo.

The downloaded manifest is authenticated with an HMAC key derived from the
device PUF. The encrypted payload is then checked by SHA-256 and executed
through secure_firmware_loader, which verifies the payload HMAC before decrypting.
"""

try:
    import ujson as json
except ImportError:
    import json

try:
    import uhashlib as hashlib
except ImportError:
    import hashlib

try:
    import ubinascii as binascii
except ImportError:
    import binascii

import os
import sys
import time

import network
import rtc_slow_puf_native as puf
import secure_firmware_loader as fwloader

try:
    import urequests as requests
except ImportError:
    try:
        import requests
    except ImportError:
        requests = None

try:
    import usocket as socket
except ImportError:
    import socket


SCHEMA = "puf-mpy-http-ota-v1"
STATE_FILE = "puf_http_ota_state.json"
MANIFEST_SALT = b"DID-PUF-MICROPYTHON-HTTP-OTA-v1"
MANIFEST_INFO = b"manifest-hmac-sha256"
KEY_LEN = 32
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


def _sha256(data):
    digest = hashlib.sha256()
    digest.update(data)
    return digest.digest()


def _hex(data):
    return binascii.hexlify(data).decode()


def _parse_http_url(url):
    if not url.startswith("http://"):
        raise ValueError("http_url_required")
    rest = url[len("http://") :]
    slash_index = rest.find("/")
    if slash_index < 0:
        host_port = rest
        path = "/"
    else:
        host_port = rest[:slash_index]
        path = rest[slash_index:] or "/"
    if not host_port:
        raise ValueError("http_host_required")
    if ":" in host_port:
        host, port_text = host_port.rsplit(":", 1)
        try:
            port = int(port_text)
        except Exception:
            raise ValueError("http_port_invalid")
    else:
        host = host_port
        port = 80
    if not host or port <= 0 or port > 65535:
        raise ValueError("http_endpoint_invalid")
    return host, port, path


def _socket_send(sock, data):
    if hasattr(sock, "write"):
        sock.write(data)
        return
    sock.sendall(data)


def _is_ipv4_literal(host):
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        value = int(part)
        if value < 0 or value > 255:
            return False
    return True


def _download_via_socket(url):
    host, port, path = _parse_http_url(url)
    sock = None
    try:
        address = (host, port) if _is_ipv4_literal(host) else socket.getaddrinfo(host, port)[0][-1]
        sock = socket.socket()
        sock.connect(address)
        request = (
            "GET {} HTTP/1.0\r\n"
            "Host: {}\r\n"
            "User-Agent: did-puf-mpy-ota/1\r\n"
            "Connection: close\r\n\r\n"
        ).format(path, host)
        _socket_send(sock, request.encode())
        chunks = []
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    separator = raw.find(b"\r\n\r\n")
    separator_len = 4
    if separator < 0:
        separator = raw.find(b"\n\n")
        separator_len = 2
    if separator < 0:
        raise ValueError("http_response_header")
    header = raw[:separator]
    body = raw[separator + separator_len :]
    status_line = header.splitlines()[0]
    parts = status_line.split()
    if len(parts) < 2:
        raise ValueError("http_status_missing")
    try:
        status = int(parts[1])
    except Exception:
        raise ValueError("http_status_invalid")
    if status < 200 or status >= 300:
        raise ValueError("http_status_{}".format(status))
    return body


def _download(url):
    if url.startswith("http://"):
        return _download_via_socket(url)
    if requests is None:
        raise ValueError("requests_required_for_non_http_url")
    response = None
    try:
        response = requests.get(url)
        status = getattr(response, "status_code", 200)
        if status < 200 or status >= 300:
            raise ValueError("http_status_{}".format(status))
        return response.content
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass


def _join_url(base_url, path):
    if path.startswith("http://") or path.startswith("https://"):
        return path
    prefix = base_url.rsplit("/", 1)[0]
    return prefix.rstrip("/") + "/" + path.lstrip("/")


def _load_state():
    try:
        with open(STATE_FILE, "r") as handle:
            data = json.loads(handle.read())
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def _save_state(state):
    with open(STATE_FILE, "w") as handle:
        handle.write(json.dumps(state))


def _target_matches(target):
    if target in ("", "any", None):
        return True
    machine = ""
    try:
        machine = os.uname().machine.lower()
    except Exception:
        machine = sys.platform.lower()
    target = str(target).lower()
    if target == "esp32s3":
        return "s3" in machine
    if target == "esp32":
        return "esp32" in machine and "s3" not in machine
    return target in machine


def _canonical_manifest(manifest):
    parts = []
    for key in CANON_FIELDS:
        if key not in manifest:
            raise ValueError("manifest_missing_{}".format(key))
        parts.append("{}={}".format(key, manifest[key]))
    return "\n".join(parts).encode()


def _manifest_key(root_key):
    return fwloader._hkdf_sha256(root_key, MANIFEST_SALT, MANIFEST_INFO, KEY_LEN)


def _verify_manifest(manifest):
    if manifest.get("schema") != SCHEMA:
        raise ValueError("manifest_schema")
    if not _target_matches(manifest.get("target")):
        raise ValueError("manifest_target")
    payload_kind = manifest.get("payload_kind")
    if payload_kind not in ("py", "mpy"):
        raise ValueError("manifest_payload_kind")
    try:
        secure_version = int(manifest.get("secure_version"))
        payload_size = int(manifest.get("payload_size"))
    except Exception:
        raise ValueError("manifest_numeric_field")
    if secure_version < 0 or payload_size <= 0:
        raise ValueError("manifest_invalid_value")
    payload_sha256 = str(manifest.get("payload_sha256", ""))
    if len(payload_sha256) != 64:
        raise ValueError("manifest_payload_sha256")
    tag_hex = str(manifest.get("manifest_hmac", ""))
    if len(tag_hex) != 64:
        raise ValueError("manifest_hmac")

    nonce = str(manifest.get("nonce"))
    root_key = puf.derive_key(nonce=nonce)
    mac_key = _manifest_key(root_key)
    expected = fwloader._hmac_sha256(mac_key, _canonical_manifest(manifest))
    try:
        actual = binascii.unhexlify(tag_hex)
    except Exception:
        raise ValueError("manifest_hmac")
    if not fwloader._constant_time_equal(expected, actual):
        raise ValueError("manifest_hmac_mismatch")
    return root_key


def connect_wifi(ssid, password="", timeout_s=25):
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if wlan.isconnected():
        print("MPY_OTA_WIFI ok=true ip={} mode=already_connected".format(wlan.ifconfig()[0]))
        return wlan.ifconfig()[0]
    if not ssid:
        raise ValueError("wifi_ssid_required")
    print("MPY_OTA_WIFI_CONNECT")
    wlan.connect(ssid, password or "")
    start = time.time()
    while not wlan.isconnected():
        if time.time() - start > timeout_s:
            raise ValueError("wifi_timeout")
        time.sleep(1)
    ip = wlan.ifconfig()[0]
    print("MPY_OTA_WIFI ok=true ip={}".format(ip))
    return ip


def run_installed_payload(path, payload_kind, nonce):
    if payload_kind == "py":
        result = fwloader.run_encrypted_module(path=path, nonce=nonce)
        print("MPY_OTA_RUN ok=true payload_kind=py plaintext_sha256={}".format(result["plaintext_sha256"]))
        return result
    if payload_kind == "mpy":
        result = fwloader.run_encrypted_mpy_module(path=path, nonce=nonce)
        print("MPY_OTA_RUN ok=true payload_kind=mpy mpy_sha256={}".format(result["mpy_sha256"]))
        return result
    raise ValueError("unsupported_payload_kind")


def install_from_manifest(manifest_url, wifi_ssid=None, wifi_password="", dest=None, run_payload=True):
    if wifi_ssid is not None:
        connect_wifi(wifi_ssid, wifi_password)

    manifest_bytes = _download(manifest_url)
    manifest = json.loads(manifest_bytes.decode())
    _verify_manifest(manifest)
    print(
        "MPY_OTA_MANIFEST ok=true target={} secure_version={} payload_kind={}".format(
            manifest.get("target"),
            manifest.get("secure_version"),
            manifest.get("payload_kind"),
        )
    )

    state = _load_state()
    current_version = int(state.get("secure_version", 0))
    secure_version = int(manifest["secure_version"])
    if secure_version < current_version:
        raise ValueError("secure_version_downgrade")
    if secure_version == current_version:
        raise ValueError("secure_version_replay")

    payload_url = _join_url(manifest_url, manifest["payload_path"])
    payload = _download(payload_url)
    expected_size = int(manifest["payload_size"])
    if len(payload) != expected_size:
        raise ValueError("payload_size_mismatch")
    payload_sha256 = _hex(_sha256(payload))
    if payload_sha256 != manifest["payload_sha256"]:
        raise ValueError("payload_sha256_mismatch")
    print("MPY_OTA_DOWNLOAD ok=true bytes={} sha256={}".format(len(payload), payload_sha256))

    payload_kind = manifest["payload_kind"]
    if dest is None:
        dest = "protected_app.mpy.enc" if payload_kind == "mpy" else "protected_app.enc"
    with open(dest, "wb") as handle:
        handle.write(payload)
    print("MPY_OTA_INSTALL ok=true dest={} bytes={} secure_version={}".format(dest, len(payload), secure_version))

    if run_payload:
        run_installed_payload(dest, payload_kind, manifest["nonce"])

    _save_state(
        {
            "secure_version": secure_version,
            "payload_sha256": payload_sha256,
            "payload_kind": payload_kind,
            "target": manifest.get("target"),
        }
    )
    return {
        "installed": True,
        "secure_version": secure_version,
        "payload_sha256": payload_sha256,
        "payload_kind": payload_kind,
    }
