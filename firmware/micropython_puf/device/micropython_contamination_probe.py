"""
RTC SLOW contamination probe for stock MicroPython on ESP32.

This script measures how much the visible RTC SLOW pattern changes after common
runtime actions. It is not a replacement for physical power-cycle testing.
"""

import gc
import uhashlib
import machine
import ubinascii


RTC_SLOW_BASE = 0x50000000
DEFAULT_SIZE = 4096
WORD_SIZE = 4
_POPCOUNT = bytes(bin(index).count("1") for index in range(256))


def read_slow(size=DEFAULT_SIZE):
    if size <= 0 or size % WORD_SIZE:
        raise ValueError("size must be a positive multiple of 4")

    out = bytearray(size)
    offset = 0
    for index in range(size // WORD_SIZE):
        value = machine.mem32[RTC_SLOW_BASE + index * WORD_SIZE]
        out[offset] = value & 0xFF
        out[offset + 1] = (value >> 8) & 0xFF
        out[offset + 2] = (value >> 16) & 0xFF
        out[offset + 3] = (value >> 24) & 0xFF
        offset += WORD_SIZE
    return out


def _hamming_weight(data):
    total = 0
    for byte in data:
        total += _POPCOUNT[byte]
    return total


def _emit(index, phase, size):
    sample = read_slow(size)
    digest = ubinascii.hexlify(uhashlib.sha256(sample).digest()).decode()
    hw = _hamming_weight(sample)
    bit_count = size * 8
    hw_percent = (hw * 1000000) // bit_count
    print(
        "MPUF_SAMPLE_METRIC index={} phase={} sha256={} hw={} bits={} hw_percent_ppm={}".format(
            index, phase, digest, hw, bit_count, hw_percent
        )
    )


def run(size=DEFAULT_SIZE):
    print("MPUF_META source=micropython_contamination region=RTC_SLOW address=0x50000000 size={}".format(size))
    _emit(0, "after_module_import", size)

    gc.collect()
    _emit(1, "after_gc", size)

    import os
    try:
        os.listdir("/")
    except Exception as exc:
        print("MPUF_NOTE filesystem_list_failed={}".format(type(exc).__name__))
    _emit(2, "after_filesystem_list", size)

    import network
    wlan = network.WLAN(network.STA_IF)
    wlan.active(False)
    _emit(3, "after_network_import_sta_off", size)

    wlan.active(True)
    _emit(4, "after_wlan_active_true_no_connect", size)

    wlan.active(False)
    _emit(5, "after_wlan_active_false", size)
    print("MPUF_DONE samples=6")
