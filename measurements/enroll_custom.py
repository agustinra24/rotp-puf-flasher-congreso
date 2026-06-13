#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyserial"]
# ///
"""Enroll the RTC SLOW PUF with explicit sleep_us and settle_us parameters.

This complements run_micropython_rtc_slow_auto.py, whose 'enroll' action does
not forward sleep_us or settle_us to p.enroll(); the probe defaults remain at
10 ms. This driver calls p.enroll(...) through Raw REPL with explicit
parameters. Helper dumps and validation are handled by the main harness; this
script only enrolls the helper. It does not modify repository modules and
assumes the modules have already been uploaded.

Usage:
  uv run enroll_custom.py --port /dev/cu.usbserial-0001 --sleep-us 100000
  uv run enroll_custom.py --samples 2000 --threshold 0.999 --sleep-us 100000
"""
import argparse
import sys
import time

import serial as serial_module

CTRL_A = b"\x01"
CTRL_B = b"\x02"
CTRL_C = b"\x03"
CTRL_D = b"\x04"


class RawRepl:
    """Minimal Raw REPL client matching run_micropython_rtc_slow_auto.py."""

    def __init__(self, port: str, baud: int) -> None:
        self.serial = serial_module.Serial(port, baudrate=baud, timeout=0.2, write_timeout=2)
        self.serial.dtr = False
        self.serial.rts = False

    def close(self) -> None:
        self.serial.close()

    def _drain(self) -> None:
        while self.serial.read(4096):
            pass

    def _read_until(self, marker: bytes, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        data = bytearray()
        while time.monotonic() < deadline:
            chunk = self.serial.read(4096)
            if chunk:
                data.extend(chunk)
                if marker in data:
                    return bytes(data)
            else:
                time.sleep(0.02)
        raise TimeoutError(f"timeout waiting for {marker!r}; tail={bytes(data[-160:])!r}")

    def enter(self) -> None:
        time.sleep(0.2)
        self._drain()
        self.serial.write(CTRL_C + CTRL_C)
        time.sleep(0.4)
        self._drain()
        self.serial.write(CTRL_A)
        data = self._read_until(b">", timeout=30)
        if b"raw REPL" not in data:
            raise RuntimeError(f"raw REPL banner not seen: {data!r}")

    def exec(self, code: str, timeout: float) -> bytes:
        self.serial.write(code.encode("utf-8"))
        self.serial.write(CTRL_D)
        prelude = self._read_until(b"OK", timeout=10)
        _prefix, pending = prelude.split(b"OK", 1)
        deadline = time.monotonic() + timeout
        stdout = bytearray()
        stderr = bytearray()
        while time.monotonic() < deadline:
            chunk = pending if pending else self.serial.read(4096)
            pending = b""
            if not chunk:
                time.sleep(0.02)
                continue
            if CTRL_D in chunk:
                before, after = chunk.split(CTRL_D, 1)
                stdout.extend(before)
                stderr = bytearray(after)
                break
            stdout.extend(chunk)
        else:
            raise TimeoutError("timeout while reading enroll stdout")
        while CTRL_D not in stderr:
            if time.monotonic() > deadline:
                raise TimeoutError("timeout while reading enroll stderr")
            chunk = self.serial.read(4096)
            if chunk:
                stderr.extend(chunk)
            else:
                time.sleep(0.02)
        err = bytes(stderr).split(CTRL_D, 1)[0]
        if err.strip():
            raise RuntimeError(err.decode("utf-8", errors="replace"))
        return bytes(stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbserial-0001")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--size", type=int, default=4096)
    parser.add_argument("--selected-bits", type=int, default=256)
    parser.add_argument("--threshold", type=float, default=0.98)
    parser.add_argument("--sleep-us", type=int, default=10000, help="off-time del power-cycle en us")
    parser.add_argument("--settle-us", type=int, default=10000)
    parser.add_argument("--gc-interval", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=1800.0)
    args = parser.parse_args()

    threshold_ppm = int(round(args.threshold * 1_000_000))
    code = (
        "import rtc_slow_puf_native as p\r"
        "print(p.enroll("
        f"samples={args.samples}, size={args.size}, selected_bits={args.selected_bits}, "
        f"threshold_ppm={threshold_ppm}, sleep_us={args.sleep_us}, settle_us={args.settle_us}, "
        f"gc_interval={args.gc_interval}))\r"
    )
    print(f"enroll_custom: port={args.port} samples={args.samples} size={args.size} "
          f"selected_bits={args.selected_bits} threshold_ppm={threshold_ppm} "
          f"sleep_us={args.sleep_us} settle_us={args.settle_us}", flush=True)
    repl = RawRepl(args.port, args.baud)
    try:
        repl.enter()
        t0 = time.monotonic()
        out = repl.exec(code, timeout=args.timeout)
        elapsed = time.monotonic() - t0
        sys.stdout.write(out.decode("utf-8", errors="replace"))
        print(f"\nenroll_custom: host_elapsed_s={elapsed:.1f}", flush=True)
    finally:
        repl.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
