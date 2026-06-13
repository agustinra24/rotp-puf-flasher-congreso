"""
Early RTC SLOW reader for stock MicroPython on ESP32.

Install this file as boot.py only for physical power-cycle lab captures. It
prints one line-oriented sample and then leaves the board idle. Keep the serial
output logs outside the repository because they are device identity material.
"""

import machine
import ubinascii


RTC_SLOW_BASE = 0x50000000
DEFAULT_SIZE = 4096
WORD_SIZE = 4


def _read_words(base, size):
    if size <= 0 or size % WORD_SIZE:
        raise ValueError("size must be a positive multiple of 4")

    out = bytearray(size)
    offset = 0
    for index in range(size // WORD_SIZE):
        value = machine.mem32[base + index * WORD_SIZE]
        out[offset] = value & 0xFF
        out[offset + 1] = (value >> 8) & 0xFF
        out[offset + 2] = (value >> 16) & 0xFF
        out[offset + 3] = (value >> 24) & 0xFF
        offset += WORD_SIZE
    return out


def emit_sample(size=DEFAULT_SIZE):
    sample = _read_words(RTC_SLOW_BASE, size)
    print("MPUF_META source=micropython_boot region=RTC_SLOW address=0x50000000 size={}".format(size))
    print("MPUF_SAMPLE 0000 {}".format(ubinascii.hexlify(sample).decode()))
    print("MPUF_DONE samples=1")


emit_sample()
