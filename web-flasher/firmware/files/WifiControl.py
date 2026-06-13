"""
Wi-Fi connectivity manager for ESP32 MicroPython.

Connects the device in STA mode (Station Mode) to an existing network.
Provides automatic reconnection, connection health checks, and retry
with exponential backoff on initial connection.
"""

import gc
import time


class Wifi:
    """Manages Wi-Fi connectivity with reconnection support."""

    def __init__(self, wifi_ssid: str, wifi_password: str):
        """
        Parameters:
            wifi_ssid:     Network SSID to connect to.
            wifi_password: Network password.
        """
        self.ssid = wifi_ssid
        self.password = wifi_password
        gc.collect()
        import network
        self.wlan = network.WLAN(network.STA_IF)
        try:
            self.wlan.active(True)
        except Exception as e:
            gc.collect()
            free_heap = gc.mem_free() if hasattr(gc, "mem_free") else "n/a"
            raise RuntimeError(
                "Wi-Fi activation failed before connect: {}; free_heap={}".format(
                    e, free_heap
                )
            )

    def is_connected(self) -> bool:
        """Check if Wi-Fi is currently connected."""
        return self.wlan.isconnected()

    def get_ip(self) -> str:
        """Return the assigned IP address, or empty string if not connected."""
        if self.wlan.isconnected():
            return self.wlan.ifconfig()[0]
        return ""

    def connect(self, timeout: int = 15) -> bool:
        """
        Connect to the configured Wi-Fi network.

        Parameters:
            timeout: Maximum seconds to wait for connection.

        Returns:
            True if connected, False on timeout.
        """
        if self.wlan.isconnected():
            print("[wifi] Already connected: {}".format(self.wlan.ifconfig()[0]))
            return True

        print("[wifi] Connecting to '{}'...".format(self.ssid))

        try:
            self.wlan.connect(self.ssid, self.password)

            start = time.time()
            while not self.wlan.isconnected():
                if time.time() - start > timeout:
                    print("[wifi] Timeout after {}s".format(timeout))
                    return False
                time.sleep(1)

            print("[wifi] Connected: {}".format(self.wlan.ifconfig()[0]))
            return True

        except OSError as e:
            print("[wifi] Connection error: {}".format(e))
            return False

    def connect_with_retry(self, max_attempts: int = 3) -> bool:
        """
        Connect with exponential backoff retries.

        Timeouts per attempt: 15s, 20s, 30s.

        Parameters:
            max_attempts: Maximum connection attempts (default 3).

        Returns:
            True if connected on any attempt, False if all failed.
        """
        backoff_timeouts = [15, 20, 30]

        for attempt in range(max_attempts):
            timeout = backoff_timeouts[min(attempt, len(backoff_timeouts) - 1)]
            print("[wifi] Attempt {}/{}".format(attempt + 1, max_attempts))

            if self.connect(timeout=timeout):
                return True

            if attempt < max_attempts - 1:
                wait = (attempt + 1) * 10  # 10s, 20s, 30s between attempts
                print("[wifi] Retrying in {}s...".format(wait))
                time.sleep(wait)

        print("[wifi] All {} connection attempts failed".format(max_attempts))
        return False

    def reconnect(self) -> bool:
        """
        Reconnect after a connection drop.

        Deactivates and reactivates the interface before retrying,
        which clears stale connection state in the ESP32 Wi-Fi driver.

        Returns:
            True if reconnected, False if all retries failed.
        """
        print("[wifi] Reconnecting...")

        # Reset the interface to clear stale state
        try:
            self.wlan.disconnect()
        except OSError:
            pass
        self.wlan.active(False)
        time.sleep(1)
        self.wlan.active(True)
        time.sleep(1)

        return self.connect_with_retry()

    # Legacy alias for backward compatibility with Device.py
    def connect_wifi(self):
        """Legacy method. Use connect_with_retry() instead."""
        return self.connect_with_retry()
