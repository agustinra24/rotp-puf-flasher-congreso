"""
Main entry point for the IoT device firmware.

Boot sequence:
    1. Load configuration from /config.json (or enter UART provisioning)
    2. Initialize Wi-Fi, NTP, sensors, actuators, and puzzle authentication
    3. Enter telemetry loop: read sensors -> evaluate actuators -> send data
"""

import gc
import sys

import config_manager


def main():
    # Step 1: Load and validate configuration
    config = config_manager.load()
    for module_name in (
        "config_manager",
        "config_crypto",
        "rtc_slow_puf_native",
        "rtc_fast_puf_probe",
        "aes256",
        "hmac_sha256",
    ):
        try:
            del sys.modules[module_name]
        except KeyError:
            pass
    try:
        del globals()["config_manager"]
    except KeyError:
        pass
    gc.collect()

    # Import after config decryption so PUF/crypto temporaries can be collected
    # before the Wi-Fi driver allocates its RX buffers.
    from Device import DeviceIoT

    # Step 2: Initialize the device (Wi-Fi, NTP, sensors, auth)
    device = DeviceIoT(config)
    gc.collect()
    if not device.initialize():
        print("[main] Initialization failed. Halting.")
        return

    # Step 3: Enter the telemetry loop (runs indefinitely)
    device.run()


if __name__ == "__main__":
    print("=" * 50)
    print("  ROTP-PUF-FLASHER Device Firmware")
    print("  Puzzle Auth + Telemetry")
    print("=" * 50)
    main()
