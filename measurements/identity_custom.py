#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyserial"]
# ///
"""Reconstruct the PUF identity N times with configurable timing parameters.

The 'identity' action in run_micropython_rtc_slow_auto.py does not forward
sleep_us to p.identity(); the probe default remains 10 ms. To evaluate a helper
enrolled with a longer off-time fairly, reconstruction must use the same
off-time. This driver calls p.identity(sleep_us=..., settle_us=...) several
times in one boot for same-boot reliability at a matched off-time.

The Raw REPL pattern matches the main harness: pyserial with dtr/rts=False. It
assumes the modules and helper are already on the device and does not write any
device files.
"""
import argparse
import ast
import statistics
import sys
import time

import serial as serial_module

CTRL_A = b"\x01"
CTRL_C = b"\x03"
CTRL_D = b"\x04"


class RawRepl:
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
        out = bytearray()
        pending = prelude.split(b"OK", 1)[1]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            chunk = pending if pending else self.serial.read(4096)
            pending = b""
            if not chunk:
                time.sleep(0.02)
                continue
            if CTRL_D in chunk:
                before, after = chunk.split(CTRL_D, 1)
                out.extend(before)
                stderr = bytearray(after)
                break
            out.extend(chunk)
        else:
            raise TimeoutError("timeout reading identity stdout")
        while CTRL_D not in stderr:
            if time.monotonic() > deadline:
                raise TimeoutError("timeout reading identity stderr")
            c = self.serial.read(4096)
            if c:
                stderr.extend(c)
            else:
                time.sleep(0.02)
        err = bytes(stderr).split(CTRL_D, 1)[0]
        if err.strip():
            raise RuntimeError(err.decode("utf-8", "replace"))
        return bytes(out)


def parse_dict(text: str):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return ast.literal_eval(line)
    raise ValueError(f"dict not found in: {text!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbserial-0001")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--size", type=int, default=4096)
    parser.add_argument("--sleep-us", type=int, default=10000)
    parser.add_argument("--settle-us", type=int, default=10000)
    parser.add_argument("--attempts", type=int, default=5)
    parser.add_argument("--runs", type=int, default=8)
    parser.add_argument("--nonce", default="-")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--reset-between", action="store_true",
                        help="pulso RTS (150 ms) + reboot antes de cada identity (post-reset)")
    parser.add_argument("--boot-wait", type=float, default=3.5)
    args = parser.parse_args()

    repl = RawRepl(args.port, args.baud)
    errs = []
    keys = set()
    accepted = 0
    try:
        if not args.reset_between:
            repl.enter()
            repl.exec("import rtc_slow_puf_native as p", timeout=15)
        for run in range(args.runs):
            if args.reset_between:
                repl.serial.rts = True
                time.sleep(0.15)
                repl.serial.rts = False
                time.sleep(args.boot_wait)
                repl.enter()
                repl.exec("import rtc_slow_puf_native as p", timeout=15)
            code = (
                "print(p.identity("
                f"size={args.size}, nonce={args.nonce!r}, sleep_us={args.sleep_us}, "
                f"settle_us={args.settle_us}, attempts={args.attempts}))"
            )
            out = repl.exec(code, timeout=args.timeout).decode("utf-8", "replace")
            d = parse_dict(out)
            pct = d.get("corrected_bit_errors_pct", -1)
            errs.append(pct)
            ok = d.get("accepted", False)
            accepted += 1 if ok else 0
            if d.get("key_sha256"):
                keys.add(d["key_sha256"])
            print(f"run {run}: accepted={ok} err_pct={pct} "
                  f"max_cw={d.get('max_errors_per_codeword')} key={d.get('key_sha256','-')[:16]}",
                  flush=True)
    finally:
        repl.close()
    print(f"\nSUMMARY runs={args.runs} accepted={accepted}/{args.runs} "
          f"sleep_us={args.sleep_us} unique_keys={len(keys)} "
          f"err_pct_min={min(errs):.5f} err_pct_max={max(errs):.5f} "
          f"err_pct_mean={statistics.fmean(errs):.5f}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
