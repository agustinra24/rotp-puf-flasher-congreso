"""
Configuration manager for the IoT device firmware.

Loads credentials and settings from /config.json on the ESP32 flash filesystem.
The Web Flasher stores /config.json as a PUF-bound encrypted envelope. Plaintext
JSON is rejected fail-closed; if the file is missing, UART provisioning collects
values interactively and saves the encrypted envelope format.

Hardware pin assignments are constants (not configurable at runtime).
"""

import sys

try:
    import ujson as json
except ImportError:
    import json

try:
    from ubinascii import unhexlify
except ImportError:
    from binascii import unhexlify

import config_crypto

# --- Hardware Pin Constants (ESP32 GPIO) ---
# These are fixed by the PCB wiring; not runtime-configurable.
PIN_SENSOR_MIC = 34
PIN_SENSOR_TEMP = 32
PIN_IR_EMITTER = 13
PIN_LED_GREEN = 21
PIN_LED_YELLOW = 22
PIN_LED_RED = 23
BUTTON_PIN = 0   # GPIO 0 = BOOT button on most ESP32 dev boards

# IR raw data timing (microseconds) for fan control signal
IR_RAW_DATA = [
    1230, 420, 1230, 420, 430, 1220, 1280, 420, 1230, 420, 430, 1220,
    430, 1220, 430, 1270, 380, 1270, 430, 1220, 430, 1270, 1230, 7020,
    1230, 420, 1280, 420, 430, 1220, 1230, 420, 1280, 370, 430, 1270,
    430, 1220, 430, 1220, 430, 1220, 430, 1270, 380, 1270, 1230, 7870,
    1280, 420, 1230, 420, 430, 1220, 1280, 420, 1230, 420, 380, 1270,
    430, 1220, 430, 1220, 430, 1270, 380, 1270, 430, 1220, 1230, 7070
]

# Path to the configuration file on flash
_CONFIG_PATH = "/config.json"

# Fields required in config.json
_REQUIRED_FIELDS = [
    "device_id", "api_key", "device_key_hex", "server_key_hex",
    "server_url", "server_port", "wifi_ssid", "wifi_pass",
    "read_interval_s", "location"
]


def _validate(config: dict) -> list:
    """Check for missing required fields. Returns list of missing field names."""
    missing = []
    for field in _REQUIRED_FIELDS:
        if field not in config:
            missing.append(field)
    # Check thresholds sub-object
    thresholds = config.get("thresholds", {})
    for t_field in ["temp_high", "temp_low", "humidity_high", "noise_high_v", "noise_medium_v"]:
        if t_field not in thresholds:
            missing.append("thresholds.{}".format(t_field))
    return missing


def _decode_keys(config: dict) -> dict:
    """Convert hex-encoded keys to raw bytes in-place."""
    try:
        config["device_key"] = unhexlify(config["device_key_hex"])
        config["server_key"] = unhexlify(config["server_key_hex"])
    except (ValueError, KeyError) as e:
        raise ValueError("Invalid hex key: {}".format(e))

    if len(config["device_key"]) != 32:
        raise ValueError("device_key must be 32 bytes (64 hex chars), got {}".format(
            len(config["device_key"])))
    if len(config["server_key"]) != 32:
        raise ValueError("server_key must be 32 bytes (64 hex chars), got {}".format(
            len(config["server_key"])))
    return config


def _check_placeholder(config: dict) -> bool:
    """Return True if config still contains placeholder values."""
    has_placeholder = "REPLACE" in config.get("api_key", "") or \
                      "REPLACE" in config.get("device_key_hex", "")
    # Warn about WiFi placeholders (won't trigger UART config, but WiFi will fail)
    if "REPLACE" in config.get("wifi_ssid", ""):
        print("[config] WARNING: WiFi credentials are placeholders. "
              "Configure again via web flasher or UART provisioning.")
    return has_placeholder


def _prompt(label: str, validate_fn=None, default=None) -> str:
    """Prompt for a value via UART. Retry on invalid input, up to 3 times."""
    suffix = " [{}]".format(default) if default is not None else ""
    for attempt in range(3):
        print("  {}{}: ".format(label, suffix), end="")
        line = sys.stdin.readline().strip()
        if not line and default is not None:
            return str(default)
        if not line:
            print("    (required, cannot be empty)")
            continue
        if validate_fn is not None:
            err = validate_fn(line)
            if err:
                print("    Invalid: {}".format(err))
                continue
        return line
    return None


def _validate_int(s: str):
    try:
        int(s)
    except ValueError:
        return "must be an integer"
    return None


def _validate_hex_key(s: str):
    if len(s) != 64:
        return "must be exactly 64 hex characters (32 bytes), got {}".format(len(s))
    try:
        unhexlify(s)
    except ValueError:
        return "invalid hex characters"
    return None


def _enter_uart_config():
    """
    Interactive UART provisioning for first-boot configuration.

    Prompts the user via serial for each required field, validates inputs,
    writes config.json to flash, and returns the config dict.
    Returns None if the user cancels or critical fields fail validation.
    """
    print()
    print("=" * 50)
    print("  IoT DEVICE PROVISIONING")
    print("  No configuration found. Enter device credentials.")
    print("  Type values and press Enter. Ctrl+C to abort.")
    print("=" * 50)
    print()

    try:
        # Network settings
        print("[1/5] Network")
        wifi_ssid = _prompt("WiFi SSID")
        if wifi_ssid is None:
            return None
        wifi_pass = _prompt("WiFi Password")
        if wifi_pass is None:
            return None

        # Server settings
        print("\n[2/5] Server")
        server_url = _prompt("Server URL (e.g. http://192.168.1.100)", default="http://192.168.1.100")
        server_port = _prompt("Server Port", _validate_int, default="5000")
        if server_port is None:
            return None
        server_port = int(server_port)

        # Device identity
        print("\n[3/5] Device Identity")
        device_id = _prompt("Device ID (integer from server)", _validate_int)
        if device_id is None:
            return None
        device_id = int(device_id)
        api_key = _prompt("API Key (32+ char string from server)")
        if api_key is None:
            return None

        # Cryptographic keys
        print("\n[4/5] Cryptographic Keys")
        print("  (Get these from the server administrator or backend provisioning records)")
        device_key_hex = _prompt("Device Key (64 hex chars)", _validate_hex_key)
        if device_key_hex is None:
            return None
        server_key_hex = _prompt("Server Key (64 hex chars)", _validate_hex_key)
        if server_key_hex is None:
            return None

        # Optional settings with defaults
        print("\n[5/5] Optional Settings")
        read_interval = _prompt("Read interval (seconds)", _validate_int, default="30")
        read_interval = int(read_interval) if read_interval else 30
        location = _prompt("Location label", default="Lab-01")
        if location is None:
            location = "Lab-01"

        config = {
            "device_id": device_id,
            "api_key": api_key,
            "device_key_hex": device_key_hex,
            "server_key_hex": server_key_hex,
            "server_url": server_url,
            "server_port": server_port,
            "wifi_ssid": wifi_ssid,
            "wifi_pass": wifi_pass,
            "read_interval_s": read_interval,
            "location": location,
            "thresholds": {
                "temp_high": 35.0,
                "temp_low": 18.0,
                "humidity_high": 80,
                "noise_high_v": 2.5,
                "noise_medium_v": 2.0
            }
        }

        envelope = config_crypto.encrypt_config(config)
        with open(_CONFIG_PATH, "w") as f:
            json.dump(envelope, f)
        print("\n[config] Saved encrypted {}".format(_CONFIG_PATH))
        return config

    except KeyboardInterrupt:
        print("\n[config] Provisioning cancelled")
        return None


def load() -> dict:
    """
    Load and validate device configuration from flash.

    Returns:
        Validated config dict with 'device_key' and 'server_key' as raw bytes.

    Raises:
        SystemExit: If config is invalid and UART provisioning is not available.
    """
    config = None

    # Attempt to read config.json from flash
    try:
        with open(_CONFIG_PATH, "r") as f:
            config = json.load(f)
        if config_crypto.is_envelope(config):
            config = config_crypto.decrypt_config(config)
            print("[config] Loaded encrypted {}".format(_CONFIG_PATH))
        else:
            raise ValueError(
                "plaintext config is not accepted; provision again to write a "
                "ROTP-PUF-CONFIG envelope"
            )
    except OSError:
        print("[config] {} not found".format(_CONFIG_PATH))
    except ValueError as e:
        print("[config] FATAL: cannot decrypt {}: {}".format(_CONFIG_PATH, e))
        sys.exit(1)

    # If no file or placeholder values, enter UART config
    if config is None or _check_placeholder(config):
        print("[config] Device needs provisioning")
        config = _enter_uart_config()
        if config is None:
            print("[config] FATAL: No configuration available")
            sys.exit(1)

    # Validate required fields
    missing = _validate(config)
    if missing:
        print("[config] FATAL: Missing fields: {}".format(", ".join(missing)))
        sys.exit(1)

    # Decode hex keys to bytes
    config = _decode_keys(config)

    print("[config] device_id={}, server={}:{}".format(
        config["device_id"], config["server_url"], config["server_port"]))
    return config
