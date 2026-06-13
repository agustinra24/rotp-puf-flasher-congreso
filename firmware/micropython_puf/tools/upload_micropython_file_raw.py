#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial>=3.5"]
# ///
"""Upload one file to MicroPython over raw REPL."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


CTRL_A = b"\x01"
CTRL_B = b"\x02"
CTRL_C = b"\x03"
CTRL_D = b"\x04"


class RawRepl:
    def __init__(self, serial_module, port: str, baud: int) -> None:
        self.serial_module = serial_module
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
        data = self._read_until(b">", timeout=5)
        if b"raw REPL" not in data:
            raise RuntimeError(f"raw REPL banner not seen: {data!r}")

    def exit(self) -> None:
        self.serial.write(CTRL_B)
        time.sleep(0.2)

    def exec(self, code: str, timeout: float = 20) -> bytes:
        self.serial.write(code.encode("utf-8"))
        self.serial.write(CTRL_D)
        prelude = self._read_until(b"OK", timeout=5)
        _prefix, pending = prelude.split(b"OK", 1)

        deadline = time.monotonic() + timeout
        stdout = bytearray()

        while time.monotonic() < deadline:
            if pending:
                chunk = pending
                pending = b""
            else:
                chunk = self.serial.read(4096)
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
            raise TimeoutError("timeout while reading raw REPL stdout")

        while CTRL_D not in stderr:
            if time.monotonic() > deadline:
                raise TimeoutError("timeout while reading raw REPL stderr")
            chunk = self.serial.read(4096)
            if chunk:
                stderr.extend(chunk)
            else:
                time.sleep(0.02)

        err, rest = bytes(stderr).split(CTRL_D, 1)
        if b">" not in rest:
            self._read_until(b">", timeout=5)
        if err.strip():
            raise RuntimeError(err.decode("utf-8", errors="replace"))
        return bytes(stdout)


def upload(repl: RawRepl, source: Path, dest: str, chunk_size: int) -> None:
    text = source.read_text(encoding="utf-8")
    repl.exec(f'open({dest!r}, "w").close()', timeout=10)
    for index in range(0, len(text), chunk_size):
        chunk = text[index : index + chunk_size]
        repl.exec(
            f'with open({dest!r}, "a") as f:\n'
            f"    f.write({chunk!r})\n",
            timeout=10,
        )
    out = repl.exec(f'import os; print(os.stat({dest!r}))', timeout=10)
    print(out.decode("utf-8", errors="replace").strip())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbserial-0001")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--chunk-size", type=int, default=512)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        import serial
    except ImportError:
        print("pyserial is required. Use: uv run upload_micropython_file_raw.py ...", file=sys.stderr)
        return 2

    repl = RawRepl(serial, args.port, args.baud)
    try:
        repl.enter()
        upload(repl, args.source, args.dest, args.chunk_size)
        repl.exit()
    finally:
        repl.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
