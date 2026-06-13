#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial>=3.5"]
# ///
"""Capture RTC SLOW PUF samples across manual physical power cycles."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


SAMPLE_RE = re.compile(r"^(?:MPUF|APUF|PUF)_SAMPLE\s+\d+\s+([0-9a-fA-F]+)\s*$")
META_RE = re.compile(r"^(?:MPUF|APUF|PUF)_META\b")
REPO_ROOT = Path(__file__).resolve().parents[3]


def is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def default_output(prefix: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = Path("/private/tmp") / f"rtc-slow-puf-{stamp}"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{prefix}.log"


def open_serial(serial_module, port: str, baud: int, timeout: float):
    while True:
        try:
            return serial_module.Serial(port, baudrate=baud, timeout=timeout)
        except serial_module.SerialException:
            time.sleep(0.25)


def hard_reset_with_rts(ser) -> None:
    # Same reset line behavior used by many ESP32 serial tools. This is a smoke
    # aid only; it is not a physical SRAM power-cycle.
    ser.dtr = False
    ser.rts = True
    time.sleep(0.1)
    ser.rts = False
    time.sleep(0.6)


def run_cycle_command(command_template: str, index: int, port: str, timeout: float) -> None:
    command = command_template.format(index=index, sample=index + 1, port=port)
    argv = shlex.split(command)
    if not argv:
        raise ValueError("--cycle-command expanded to an empty command")

    result = subprocess.run(argv, check=False, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"cycle command failed with exit code {result.returncode}: {command}")


def capture_one(serial_module, port: str, baud: int, timeout_s: float) -> tuple[str | None, str]:
    deadline = time.monotonic() + timeout_s
    last_meta: str | None = None

    while time.monotonic() < deadline:
        with open_serial(serial_module, port, baud, timeout=0.25) as ser:
            while time.monotonic() < deadline:
                try:
                    raw = ser.readline()
                except serial_module.SerialException:
                    break
                if not raw:
                    continue
                line = raw.decode("utf-8", errors="replace").strip()
                if META_RE.match(line):
                    last_meta = line
                match = SAMPLE_RE.match(line)
                if match:
                    return last_meta, match.group(1).lower()

    raise TimeoutError(f"no sample received from {port} within {timeout_s:.1f}s")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbserial-0001", help="serial port")
    parser.add_argument("--baud", type=int, default=115200, help="serial baud rate")
    parser.add_argument("--samples", type=int, default=30, help="number of physical power-cycle samples")
    parser.add_argument("--timeout", type=float, default=45.0, help="seconds to wait for each sample")
    parser.add_argument("--output", type=Path, help="output log path, default is under /private/tmp")
    parser.add_argument("--label", default="rtc-slow-physical", help="metadata label")
    parser.add_argument("--no-prompt", action="store_true", help="do not prompt before each cycle")
    parser.add_argument("--rts-reset", action="store_true", help="smoke only: trigger RTS reset before each read")
    parser.add_argument("--cycle-command", help="external command that performs a real power cycle before each sample")
    parser.add_argument("--cycle-timeout", type=float, default=15.0, help="seconds allowed for --cycle-command")
    parser.add_argument("--cycle-delay", type=float, default=1.5, help="seconds to wait after --cycle-command before reading serial")
    parser.add_argument("--allow-repo-output", action="store_true", help="allow writing raw PUF samples inside the repo")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.samples <= 0:
        parser.error("--samples must be positive")
    if args.rts_reset and args.cycle_command:
        parser.error("--rts-reset and --cycle-command are mutually exclusive")

    output = args.output or default_output(args.label)
    if is_inside(output, REPO_ROOT) and not args.allow_repo_output:
        parser.error("raw PUF captures must stay outside the repo unless --allow-repo-output is explicit")
    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        import serial
    except ImportError:
        print("pyserial is required. Use: uv run capture_serial_power_cycles.py ...", file=sys.stderr)
        return 2

    print(f"Writing normalized samples to: {output}")
    if args.cycle_command:
        print("Automation mode: using external power-cycle command before each sample.")
    else:
        print("Use complete physical power removal. Reset button and soft reset are not equivalent.")

    with output.open("w", encoding="utf-8") as handle:
        handle.write(
            "MPUF_META source=serial_physical_capture label={} port={} baud={} samples={} automation={}\n".format(
                args.label, args.port, args.baud, args.samples, bool(args.cycle_command)
            )
        )
        handle.flush()

        for index in range(args.samples):
            if args.cycle_command:
                run_cycle_command(args.cycle_command, index, args.port, args.cycle_timeout)
                time.sleep(args.cycle_delay)
            elif not args.no_prompt:
                input(f"[{index + 1}/{args.samples}] Disconnect power, wait 2s, reconnect, then press Enter...")

            if args.rts_reset:
                with open_serial(serial, args.port, args.baud, timeout=0.25) as ser:
                    hard_reset_with_rts(ser)
            meta, sample_hex = capture_one(serial, args.port, args.baud, args.timeout)
            if meta:
                handle.write(f"# source_meta {meta}\n")
            handle.write(f"MPUF_SAMPLE {index:04d} {sample_hex}\n")
            handle.flush()
            print(f"captured {index + 1}/{args.samples}: {len(sample_hex) // 2} bytes")

        handle.write(f"MPUF_DONE samples={args.samples}\n")

    print(f"done: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
