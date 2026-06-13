#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial>=3.5"]
# ///
"""Run an automatic RTC SLOW PUF capture on stock MicroPython."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
MICROPYTHON_PUF_DIR = TOOL_DIR.parent
DEVICE_DIR = MICROPYTHON_PUF_DIR / "device"
FIRMWARE_ROOT = TOOL_DIR.parents[1]
REPO_ROOT = TOOL_DIR.parents[2]
HOST_TOOLS_DIR = FIRMWARE_ROOT / "puf_shared" / "host_tools"
sys.path.insert(0, str(HOST_TOOLS_DIR))

from derive_puf_identity import (
    DEFAULT_CANDIDATE_POOL_PER_WINDOW,
    DEFAULT_SELECTION_POLICY,
    DEFAULT_SELECTION_SEED,
    DEFAULT_SELECTION_WINDOWS,
    DISTRIBUTED_WINDOW_POLICY,
    FIRST_STABLE_POLICY,
    helper_from_binary,
    helper_to_binary,
    load_helper,
    write_helper,
)


CTRL_A = b"\x01"
CTRL_B = b"\x02"
CTRL_C = b"\x03"
CTRL_D = b"\x04"

PROBE_SOURCE = DEVICE_DIR / "rtc_fast_puf_probe.py"
NATIVE_SOURCE = DEVICE_DIR / "rtc_slow_puf_native.py"
CONTAMINATION_SOURCE = DEVICE_DIR / "micropython_contamination_probe.py"
ANALYZER = HOST_TOOLS_DIR / "analyze_puf_samples.py"
DERIVER = HOST_TOOLS_DIR / "derive_puf_identity.py"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RawRepl:
    """Small raw REPL client tailored for large line-oriented capture output."""

    def __init__(self, serial_module, port: str, baud: int) -> None:
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

    def exit(self) -> None:
        self.serial.write(CTRL_B)
        time.sleep(0.2)

    def exec(self, code: str, stdout_path: Path | None = None, timeout: float = 30) -> bytes:
        self.serial.write(code.encode("utf-8"))
        self.serial.write(CTRL_D)
        prelude = self._read_until(b"OK", timeout=5)
        _prefix, pending = prelude.split(b"OK", 1)

        deadline = time.monotonic() + timeout
        stdout = bytearray()
        sample_count = 0

        with (stdout_path.open("wb") if stdout_path else _NullWriter()) as handle:
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
                    handle.write(before)
                    stdout.extend(before)
                    sample_count = _report_sample_progress(before, sample_count)
                    stderr = bytearray(after)
                    break

                handle.write(chunk)
                stdout.extend(chunk)
                sample_count = _report_sample_progress(chunk, sample_count)
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


class _NullWriter:
    def __enter__(self) -> "_NullWriter":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def write(self, _data: bytes) -> int:
        return 0


def _report_sample_progress(chunk: bytes, previous_count: int) -> int:
    current_count = previous_count + chunk.count(b"MPUF_SAMPLE")
    if current_count != previous_count and current_count % 25 == 0:
        print(f"samples captured: {current_count}", flush=True)
    if b"MPUF_AGG_PROGRESS" in chunk:
        for line in chunk.decode("utf-8", errors="ignore").splitlines():
            if line.startswith("MPUF_AGG_PROGRESS"):
                print(line.replace("MPUF_AGG_PROGRESS", "aggregate"), flush=True)
    return current_count


def is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def default_run_dir(label: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("/private/tmp") / f"micropython-rtc-slow-auto-{label}-{stamp}"


def upload_probe(repl: RawRepl, source: Path, dest: str, chunk_size: int) -> None:
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
    print(out.decode("utf-8", errors="replace").strip(), flush=True)


def run_host_tool(args: list[str], stdout_path: Path) -> None:
    with stdout_path.open("w", encoding="utf-8") as handle:
        result = subprocess.run(args, stdout=handle, stderr=subprocess.STDOUT, check=False, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"host tool failed with exit code {result.returncode}: {' '.join(args)}")


def parse_helper_hex(stdout: bytes) -> bytes:
    text = stdout.decode("utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith("MPUF_HELPER_HEX "):
            return bytes.fromhex(line.split(" ", 1)[1])
    chunks: list[tuple[int, str]] = []
    expected_chunks: int | None = None
    for line in text.splitlines():
        if line.startswith("MPUF_HELPER_HEX_BEGIN "):
            fields = dict(field.split("=", 1) for field in line.split()[1:] if "=" in field)
            try:
                expected_chunks = int(fields.get("chunks", "0"))
            except ValueError:
                expected_chunks = None
        elif line.startswith("MPUF_HELPER_HEX_CHUNK "):
            _prefix, index_text, payload = line.split(" ", 2)
            chunks.append((int(index_text), payload.strip()))
    if chunks:
        chunks.sort()
        if expected_chunks is not None and len(chunks) != expected_chunks:
            raise ValueError(
                f"MicroPython helper export printed {len(chunks)} chunks, expected {expected_chunks}"
            )
        return bytes.fromhex("".join(payload for _index, payload in chunks))
    raise ValueError("MicroPython helper export did not print MPUF_HELPER_HEX")


def upload_helper_hex(repl: RawRepl, helper_path: Path, chunk_size: int) -> bytes:
    helper = load_helper(helper_path)
    output = bytearray()
    hex_payload = helper_to_binary(helper).hex()
    repl.exec('open("_puf_helper_import.hex", "w").close()', timeout=10)
    for index in range(0, len(hex_payload), chunk_size):
        chunk = hex_payload[index : index + chunk_size]
        repl.exec(
            'with open("_puf_helper_import.hex", "a") as f:\n'
            f"    f.write({chunk!r})\n",
            timeout=10,
        )
    output.extend(repl.exec(
        "import rtc_slow_puf_native as p\n"
        'with open("_puf_helper_import.hex") as f:\n'
        "    print(p.import_helper_hex(f.read()))\n",
        timeout=30,
    ))
    return bytes(output)


def export_helper_json(repl: RawRepl, helper_out: Path, allow_repo_output: bool) -> bytes:
    stdout = repl.exec(
        "import rtc_slow_puf_native as p\n"
        "import time\n"
        "h = p.export_helper_hex()\n"
        "chunk = 128\n"
        'print("MPUF_HELPER_HEX_BEGIN len={} chunks={}".format(len(h), (len(h) + chunk - 1) // chunk))\n'
        "time.sleep_ms(20)\n"
        "for i in range(0, len(h), chunk):\n"
        '    print("MPUF_HELPER_HEX_CHUNK {} {}".format(i // chunk, h[i:i + chunk]))\n'
        "    time.sleep_ms(5)\n"
        'print("MPUF_HELPER_HEX_END")\n',
        timeout=30,
    )
    helper = helper_from_binary(parse_helper_hex(stdout))
    write_helper(helper_out, helper, allow_repo_output)
    payload = helper_to_binary(helper)
    return (
        b"MPUF_HELPER_HEX <redacted>\n"
        + f"host_helper_out: {helper_out}\nhost_helper_sha256: {sha256_hex(payload)}\n".encode("utf-8")
    )


def verify_device_helper_matches(repl: RawRepl, helper_path: Path, allow_repo_output: bool, output_dir: Path) -> bytes:
    expected = helper_to_binary(load_helper(helper_path))
    scratch = output_dir / "_helper-roundtrip.json"
    stdout = export_helper_json(repl, scratch, allow_repo_output)
    actual = helper_to_binary(load_helper(scratch))
    if actual != expected:
        raise RuntimeError(
            f"MicroPython helper does not match {helper_path}; "
            f"expected_sha256={sha256_hex(expected)} actual_sha256={sha256_hex(actual)}"
        )
    return stdout + b"host_helper_roundtrip_ok: true\n"


def parse_dict_line(text: str) -> dict[str, object]:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            value = ast.literal_eval(line)
            if isinstance(value, dict):
                return value
    raise ValueError(f"MicroPython dict output not found: {text!r}")


def parse_status_dict(stdout: bytes) -> dict[str, object]:
    text = stdout.decode("utf-8", errors="replace")
    data: dict[str, object] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("MPUF_STATUS_ENROLLED "):
            value = line.split(" ", 1)[1]
            if value in {"true", "false"}:
                data["enrolled"] = value == "true"
        elif line.startswith("MPUF_STATUS_META "):
            for field in line.split()[1:]:
                if "=" not in field:
                    continue
                key, value = field.split("=", 1)
                if key in {"sample_size", "selection_windows", "candidate_pool_per_window", "selected_bits", "repetition"}:
                    data[key] = int(value)
                elif value != "-":
                    data[key] = value
        elif line.startswith("MPUF_STATUS_HASH "):
            fields = dict(field.split("=", 1) for field in line.split()[1:] if "=" in field)
            helper_sha256 = fields.get("helper_sha256", "-")
            if helper_sha256 != "-":
                data["helper_sha256"] = helper_sha256
        elif line.startswith("MPUF_STATUS_ERROR "):
            error = line.split(" ", 1)[1]
            if error != "-":
                data["error"] = error
    if data:
        return data
    return parse_dict_line(text)


def status_exec_code() -> str:
    return (
        "import rtc_slow_puf_native as p\n"
        "import time\n"
        "d = p.status()\n"
        "time.sleep_ms(20)\n"
        'print("MPUF_STATUS_BEGIN")\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_STATUS_ENROLLED {}".format("true" if d.get("enrolled") else "false"))\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_STATUS_META storage={} mode={} sample_size={} selection_windows={} candidate_pool_per_window={} selected_bits={} repetition={}".format(d.get("storage", "-"), d.get("mode", "-"), d.get("sample_size", 0), d.get("selection_windows", 0), d.get("candidate_pool_per_window", 0), d.get("selected_bits", 0), d.get("repetition", 0)))\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_STATUS_HASH helper_sha256={}".format(d.get("helper_sha256", "-")))\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_STATUS_ERROR {}".format(str(d.get("error", "-")).replace(" ", "_")))\n'
        "time.sleep_ms(5)\n"
        'print("MPUF_STATUS_END")\n'
    )


def parse_identity_dict(stdout: bytes) -> dict[str, object]:
    text = stdout.decode("utf-8", errors="replace")
    data: dict[str, object] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("MPUF_IDENTITY_ACCEPTED "):
            value = line.split(" ", 1)[1]
            if value in {"true", "false"}:
                data["accepted"] = value == "true"
        elif line.startswith("MPUF_IDENTITY_META "):
            for field in line.split()[1:]:
                if "=" not in field:
                    continue
                key, value = field.split("=", 1)
                if key in {"sample_size", "selected_bits", "attempts"}:
                    data[key] = int(value)
                elif value != "-":
                    data[key] = value
        elif line.startswith("MPUF_IDENTITY_ERRORS "):
            for field in line.split()[1:]:
                if "=" not in field:
                    continue
                key, value = field.split("=", 1)
                if key == "corrected_bit_errors_pct":
                    data[key] = float(value)
                else:
                    data[key] = int(value)
        elif line.startswith("MPUF_IDENTITY_KEY "):
            fields = dict(field.split("=", 1) for field in line.split()[1:] if "=" in field)
            key_sha256 = fields.get("key_sha256", "-")
            if key_sha256 != "-":
                data["key_sha256"] = key_sha256
        if line.startswith("MPUF_IDENTITY_RESULT "):
            for field in line.split()[1:]:
                if "=" not in field:
                    continue
                key, value = field.split("=", 1)
                if value == "true":
                    data[key] = True
                elif value == "false":
                    data[key] = False
                elif key in {"selected_bits", "attempts", "corrected_bit_errors_total", "max_errors_per_codeword", "uncertain_codewords", "material_tie_bits"}:
                    data[key] = int(value)
                elif key == "corrected_bit_errors_pct":
                    data[key] = float(value)
                elif value != "-":
                    data[key] = value
            return data
    if data:
        return data
    return parse_dict_line(text)


def hamming_distance(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError(f"material length mismatch: {len(left)} != {len(right)}")
    return sum((left_byte ^ right_byte).bit_count() for left_byte, right_byte in zip(left, right))


def require_identity_verdict(stdout: bytes, should_accept: bool, args: argparse.Namespace, label: str) -> None:
    data = parse_identity_dict(stdout)
    accepted = bool(data.get("accepted"))
    if accepted != should_accept:
        expected = "ACCEPT" if should_accept else "REJECT"
        raise RuntimeError(f"{label}: expected {expected}, got {data}")
    if not should_accept:
        if "key_sha256" in data:
            raise RuntimeError(f"{label}: rejected identity emitted key_sha256: {data}")
        return
    if "key_sha256" not in data:
        raise RuntimeError(f"{label}: accepted identity did not emit key_sha256: {data}")
    uncertain = int(data.get("uncertain_codewords", -1))
    material_tie_bits = int(data.get("material_tie_bits", -1))
    max_codeword_errors = int(data.get("max_errors_per_codeword", 999))
    corrected_pct = float(data.get("corrected_bit_errors_pct", 999))
    if uncertain != 0 or material_tie_bits != 0:
        raise RuntimeError(f"{label}: identity had uncertain material: {data}")
    if max_codeword_errors > args.max_codeword_errors or corrected_pct > args.max_corrected_error_pct:
        raise RuntimeError(f"{label}: identity exceeded error policy: {data}")


def open_repl(serial_module, args: argparse.Namespace) -> RawRepl:
    repl = RawRepl(serial_module, args.port, args.baud)
    repl.enter()
    if not args.skip_upload:
        print("uploading probe...")
        upload_probe(repl, PROBE_SOURCE, "rtc_fast_puf_probe.py", args.chunk_size)
        print("uploading puf helper...")
        upload_probe(repl, NATIVE_SOURCE, "rtc_slow_puf_native.py", args.chunk_size)
    return repl


def run_identity_once(serial_module, args: argparse.Namespace, nonce: str, label: str, should_accept: bool) -> bytes:
    repl = open_repl(serial_module, args)
    try:
        stdout = repl.exec(
            "import rtc_slow_puf_native as p\n"
            "import time\n"
            f"d = p.identity(size={args.size}, nonce={nonce!r}, attempts={args.identity_attempts})\n"
            "time.sleep_ms(20)\n"
            'print("MPUF_IDENTITY_BEGIN")\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_ACCEPTED {}".format("true" if d.get("accepted") else "false"))\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_META storage={} sample_size={} selected_bits={} attempts={}".format(d.get("storage", "-"), d.get("sample_size", 0), d.get("selected_bits", 0), d.get("attempts", 0)))\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_ERRORS corrected_bit_errors_total={} corrected_bit_errors_pct={} max_errors_per_codeword={} uncertain_codewords={} material_tie_bits={}".format(d.get("corrected_bit_errors_total", 0), d.get("corrected_bit_errors_pct", 0), d.get("max_errors_per_codeword", 0), d.get("uncertain_codewords", 0), d.get("material_tie_bits", 0)))\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_KEY key_sha256={}".format(d.get("key_sha256", "-")))\n'
            "time.sleep_ms(5)\n"
            'print("MPUF_IDENTITY_END")\n',
            timeout=120,
        )
        repl.exit()
    finally:
        repl.close()
    require_identity_verdict(stdout, should_accept, args, label)
    return stdout


def run_status_once(serial_module, args: argparse.Namespace) -> tuple[bytes, dict[str, object]]:
    repl = open_repl(serial_module, args)
    try:
        stdout = repl.exec(status_exec_code(), timeout=30)
        repl.exit()
    finally:
        repl.close()
    return stdout, parse_status_dict(stdout)


def run_identity_material_once(
    serial_module,
    args: argparse.Namespace,
    nonce: str,
    label: str,
) -> tuple[bytes, dict[str, object], bytes]:
    repl = open_repl(serial_module, args)
    try:
        code = (
            "import rtc_slow_puf_native as p\n"
            "import ubinascii\n"
            "helper, material, summary = p._identity_material("
            f"{args.size}, p.probe.DEFAULT_POWER_OFF_US, p.probe.DEFAULT_SETTLE_US, {args.identity_attempts})\n"
            "accepted = (summary['uncertain_codewords'] == 0 and "
            "summary['material_tie_bits'] == 0 and "
            f"summary['max_errors_per_codeword'] <= {args.max_codeword_errors} and "
            f"summary['corrected_bit_errors_pct'] <= {args.max_corrected_error_pct})\n"
            "summary.update({'accepted': accepted, 'storage': helper['storage'], "
            "'sample_size': helper['sample_size'], 'selected_bits': helper['selected_bits'], "
            "'helper_sha256': p._sha256_hex(p._pack_helper(helper['sample_size'], "
            "helper['threshold_ppm'], helper['selected_bits'], helper['positions'], helper['ecc_data'], "
            "helper['salt'], helper['context'], helper['mode'])), "
            "'material_sha256': p._sha256_hex(material)})\n"
            "if accepted:\n"
            f"    key = p._hkdf_sha256(material, helper['salt'].encode(), p._info_bytes(helper['context'], {nonce!r}), p.KEY_BYTES)\n"
            "    summary['key_sha256'] = p._sha256_hex(key)\n"
            "summary['material_hex'] = ubinascii.hexlify(material).decode()\n"
            "print(summary)\n"
        )
        stdout = repl.exec(code, timeout=120)
        repl.exit()
    finally:
        repl.close()

    data = parse_identity_dict(stdout)
    material_hex = data.pop("material_hex", None)
    if not isinstance(material_hex, str):
        raise RuntimeError(f"{label}: identity material output missing material_hex")
    material = bytes.fromhex(material_hex)
    material_sha = data.get("material_sha256")
    if material_sha != sha256_hex(material):
        raise RuntimeError(f"{label}: material_sha256 mismatch")
    sanitized = (repr(data) + "\n").encode("utf-8")
    require_identity_verdict(sanitized, True, args, label)
    return sanitized, data, material


def run_inter_device_hd(serial_module, args: argparse.Namespace, output_dir: Path) -> bytes:
    if not args.peer_port:
        raise ValueError("--puf-action inter-device-hd requires --peer-port")
    primary_args = copy.copy(args)
    peer_args = copy.copy(args)
    peer_args.port = args.peer_port
    peer_args.label = args.peer_label or f"{args.label}-peer"

    output = bytearray()
    output.extend(
        "host_inter_device_hd_start "
        f"label={args.label} peer_label={peer_args.label} "
        f"nonce={args.identity_nonce} attempts={args.identity_attempts}\n".encode("utf-8")
    )

    primary_status_stdout, primary_status = run_status_once(serial_module, primary_args)
    peer_status_stdout, peer_status = run_status_once(serial_module, peer_args)
    output.extend(b"primary_status ")
    output.extend(primary_status_stdout)
    output.extend(b"peer_status ")
    output.extend(peer_status_stdout)
    if primary_status.get("enrolled") is not True:
        raise RuntimeError(f"primary board is not enrolled: {primary_status}")
    if peer_status.get("enrolled") is not True:
        raise RuntimeError(f"peer board is not enrolled: {peer_status}")

    primary_stdout, primary_identity, primary_material = run_identity_material_once(
        serial_module,
        primary_args,
        args.identity_nonce,
        "primary inter-device identity",
    )
    peer_stdout, peer_identity, peer_material = run_identity_material_once(
        serial_module,
        peer_args,
        args.identity_nonce,
        "peer inter-device identity",
    )
    output.extend(b"primary_identity ")
    output.extend(primary_stdout)
    output.extend(b"peer_identity ")
    output.extend(peer_stdout)

    hd_bits = hamming_distance(primary_material, peer_material)
    total_bits = len(primary_material) * 8
    hd_percent = hd_bits * 100 / total_bits if total_bits else 0.0
    primary_key = primary_identity.get("key_sha256")
    peer_key = peer_identity.get("key_sha256")
    if primary_key == peer_key:
        raise RuntimeError("inter-device identity separation failed: key_sha256 values match")
    if primary_identity.get("material_sha256") == peer_identity.get("material_sha256"):
        raise RuntimeError("inter-device identity separation failed: material_sha256 values match")

    output.extend(
        "MPUF_INTER_DEVICE_HD "
        f"ok=true bits={total_bits} hd_bits={hd_bits} hd_percent={hd_percent:.6f} "
        f"primary_material_sha256={primary_identity.get('material_sha256')} "
        f"peer_material_sha256={peer_identity.get('material_sha256')} "
        f"primary_key_sha256={primary_key} peer_key_sha256={peer_key} "
        f"primary_helper_sha256={primary_status.get('helper_sha256')} "
        f"peer_helper_sha256={peer_status.get('helper_sha256')} "
        f"primary_corrected_pct={primary_identity.get('corrected_bit_errors_pct')} "
        f"peer_corrected_pct={peer_identity.get('corrected_bit_errors_pct')}\n".encode("utf-8")
    )
    return bytes(output)


def trigger_serial_hard_reset(serial_module, args: argparse.Namespace) -> bytes:
    with serial_module.Serial(args.port, baudrate=args.baud, timeout=0.2, write_timeout=2) as serial_port:
        serial_port.dtr = False
        serial_port.rts = False
        time.sleep(0.05)
        serial_port.rts = True
        time.sleep(0.15)
        serial_port.rts = False
    time.sleep(2.0)
    return b"host_cycle_action: serial_hard_reset_rts\n"


def exec_cycle_code(serial_module, args: argparse.Namespace, code: str, action: str, wait_seconds: float) -> bytes:
    repl = open_repl(serial_module, args)
    try:
        try:
            stdout = repl.exec(code, timeout=3)
        except (RuntimeError, TimeoutError, OSError, serial_module.SerialException) as exc:
            stdout = f"host_cycle_exec_reset_expected: {type(exc).__name__}\n".encode("utf-8")
    finally:
        repl.close()
    time.sleep(wait_seconds)
    return stdout + f"host_cycle_action: {action}\n".encode("utf-8")


def trigger_deepsleep(serial_module, args: argparse.Namespace) -> bytes:
    code = (
        "import machine\n"
        f"print('MPY_DEEPSLEEP_START ms={args.sleep_ms}')\n"
        f"machine.deepsleep({args.sleep_ms})\n"
    )
    return exec_cycle_code(serial_module, args, code, "timer_deepsleep", args.sleep_ms / 1000.0 + 2.0)


def trigger_software_cycle(serial_module, args: argparse.Namespace) -> bytes:
    code = (
        "import machine\n"
        "print('MPY_RESET_START')\n"
        "machine.reset()\n"
    )
    return exec_cycle_code(serial_module, args, code, "machine_reset", 2.0)


def trigger_adversarial_cycle(serial_module, args: argparse.Namespace) -> bytes:
    if args.adversarial == "reset":
        return trigger_serial_hard_reset(serial_module, args)
    if args.adversarial == "deepsleep":
        return trigger_deepsleep(serial_module, args)
    if args.adversarial == "software-cycle":
        return trigger_software_cycle(serial_module, args)
    raise ValueError(f"unsupported adversarial mode: {args.adversarial}")


def require_same_value(observed: object, expected: object, field: str, label: str) -> None:
    if observed != expected:
        raise RuntimeError(f"{label}: {field} changed, expected={expected} observed={observed}")


def run_adversarial_sequence(serial_module, args: argparse.Namespace, output_dir: Path) -> bytes:
    output = bytearray()
    output.extend(f"host_adversarial_mode: {args.adversarial}\n".encode("utf-8"))
    output.extend(f"host_adversarial_runs: {args.adversarial_runs}\n".encode("utf-8"))

    if args.helper:
        repl = open_repl(serial_module, args)
        try:
            output.extend(upload_helper_hex(repl, args.helper, args.chunk_size))
            if args.verify_helper_import:
                output.extend(verify_device_helper_matches(repl, args.helper, args.allow_repo_output, output_dir))
            repl.exit()
        finally:
            repl.close()

    status_stdout, status = run_status_once(serial_module, args)
    output.extend(status_stdout)
    if status.get("enrolled") is not True:
        raise RuntimeError("adversarial run requires an enrolled helper")
    expected_helper_sha = status.get("helper_sha256")
    if not isinstance(expected_helper_sha, str) or not expected_helper_sha:
        raise RuntimeError("status did not include helper_sha256")

    baseline_identity = run_identity_once(serial_module, args, "", "adversarial baseline identity", True)
    output.extend(baseline_identity)
    baseline_key = parse_identity_dict(baseline_identity).get("key_sha256")
    if not isinstance(baseline_key, str) or not baseline_key:
        raise RuntimeError("baseline identity did not include key_sha256")

    baseline_nonce_key: str | None = None
    if args.identity_nonce not in {"", "-"}:
        baseline_nonce_identity = run_identity_once(
            serial_module,
            args,
            args.identity_nonce,
            "adversarial baseline nonce identity",
            True,
        )
        output.extend(baseline_nonce_identity)
        parsed_nonce = parse_identity_dict(baseline_nonce_identity).get("key_sha256")
        if not isinstance(parsed_nonce, str) or not parsed_nonce:
            raise RuntimeError("baseline nonce identity did not include key_sha256")
        baseline_nonce_key = parsed_nonce

    for index in range(1, args.adversarial_runs + 1):
        label = f"adversarial run {index}"
        output.extend(f"host_adversarial_run_start: {index}\n".encode("utf-8"))
        output.extend(trigger_adversarial_cycle(serial_module, args))
        after_status_stdout, after_status = run_status_once(serial_module, args)
        output.extend(after_status_stdout)
        require_same_value(after_status.get("helper_sha256"), expected_helper_sha, "helper_sha256", label)

        identity_stdout = run_identity_once(serial_module, args, "", f"{label} identity", True)
        output.extend(identity_stdout)
        require_same_value(parse_identity_dict(identity_stdout).get("key_sha256"), baseline_key, "key_sha256", label)

        if baseline_nonce_key is not None:
            nonce_identity_stdout = run_identity_once(
                serial_module,
                args,
                args.identity_nonce,
                f"{label} nonce identity",
                True,
            )
            output.extend(nonce_identity_stdout)
            require_same_value(
                parse_identity_dict(nonce_identity_stdout).get("key_sha256"),
                baseline_nonce_key,
                "nonce_key_sha256",
                label,
            )
        output.extend(f"host_adversarial_run_ok: {index}\n".encode("utf-8"))

    output.extend(f"host_helper_sha256_stable: {expected_helper_sha}\n".encode("utf-8"))
    output.extend(f"host_key_sha256_stable: {baseline_key}\n".encode("utf-8"))
    if baseline_nonce_key is not None:
        output.extend(f"host_nonce_key_sha256_stable: {baseline_nonce_key}\n".encode("utf-8"))
    output.extend(b"adversarial_done: true\n")
    return bytes(output)


def run_native_lifecycle(serial_module, args: argparse.Namespace, output_dir: Path) -> bytes:
    output = bytearray()
    lifecycle_helper = args.helper_out or (output_dir / f"{args.label}-helper.json")

    repl = open_repl(serial_module, args)
    try:
        output.extend(repl.exec(status_exec_code(), timeout=30))
        output.extend(export_helper_json(repl, lifecycle_helper, args.allow_repo_output))
        if args.verify_helper_import:
            output.extend(upload_helper_hex(repl, lifecycle_helper, args.chunk_size))
            output.extend(verify_device_helper_matches(repl, lifecycle_helper, args.allow_repo_output, output_dir))
        repl.exit()
    finally:
        repl.close()

    for run_index in range(1, args.identity_runs + 1):
        output.extend(run_identity_once(serial_module, args, "", f"lifecycle identity {run_index}", True))
        if args.identity_nonce not in {"", "-"}:
            output.extend(run_identity_once(serial_module, args, args.identity_nonce, f"lifecycle nonce identity {run_index}", True))

    if args.negative_helper:
        repl = open_repl(serial_module, args)
        try:
            output.extend(upload_helper_hex(repl, args.negative_helper, args.chunk_size))
            if args.verify_helper_import:
                output.extend(verify_device_helper_matches(repl, args.negative_helper, args.allow_repo_output, output_dir))
            repl.exit()
        finally:
            repl.close()
        output.extend(run_identity_once(serial_module, args, "", "negative-helper identity", False))

        repl = open_repl(serial_module, args)
        try:
            output.extend(upload_helper_hex(repl, lifecycle_helper, args.chunk_size))
            if args.verify_helper_import:
                output.extend(verify_device_helper_matches(repl, lifecycle_helper, args.allow_repo_output, output_dir))
            repl.exit()
        finally:
            repl.close()
        output.extend(run_identity_once(serial_module, args, "", "restored-helper identity", True))

    output.extend(f"lifecycle_helper: {lifecycle_helper}\n".encode("utf-8"))
    output.extend(b"lifecycle_done: true\n")
    return bytes(output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbserial-0001", help="serial port")
    parser.add_argument("--baud", type=int, default=115200, help="serial baud rate")
    parser.add_argument("--samples", type=int, default=1000, help="automatic register-cycled samples")
    parser.add_argument("--size", type=int, default=4096, help="bytes per sample")
    parser.add_argument("--timeout", type=float, default=1200.0, help="seconds allowed for MicroPython capture")
    parser.add_argument("--label", default="device-a-mpy-rtc-slow", help="run label")
    parser.add_argument("--output-dir", type=Path, help="output directory, default is under /private/tmp")
    parser.add_argument("--skip-upload", action="store_true", help="do not upload rtc_fast_puf_probe.py before capture")
    parser.add_argument("--chunk-size", type=int, default=512, help="upload chunk size")
    parser.add_argument("--threshold", type=float, default=0.98, help="stable-bit threshold")
    parser.add_argument("--derive-bits", type=int, default=256, help="stable bits used by derivation smoke")
    parser.add_argument("--allow-repo-output", action="store_true", help="allow raw capture output inside the repo")
    parser.add_argument("--repeat-runs", type=int, default=1, help="number of consecutive RTC SLOW captures")
    parser.add_argument("--compare-against", type=Path, help="existing log to compare against every captured run")
    parser.add_argument("--run-contamination", action="store_true", help="run the MicroPython runtime contamination probe")
    parser.add_argument("--verify-selected-bits", action="store_true", help="verify selected stable bits between repeated runs")
    parser.add_argument("--capture-mode", choices=("raw", "aggregate"), default="raw", help="raw samples or compact per-bit counts")
    parser.add_argument("--helper-out", type=Path, help="write enrollment helper data from the first run")
    parser.add_argument("--helper", type=Path, help="verify captured runs against existing helper data")
    parser.add_argument("--negative-helper", type=Path, help="helper from another board that must reject in lifecycle mode")
    parser.add_argument(
        "--extractor",
        choices=("fixed-reference", "repetition8"),
        default="repetition8",
        help="helper extractor for --helper-out, default: repetition8",
    )
    parser.add_argument(
        "--selection-policy",
        choices=(FIRST_STABLE_POLICY, DISTRIBUTED_WINDOW_POLICY),
        default=DEFAULT_SELECTION_POLICY,
        help="stable-position selector for host-created helpers",
    )
    parser.add_argument("--selection-windows", type=int, default=DEFAULT_SELECTION_WINDOWS)
    parser.add_argument("--candidate-pool-per-window", type=int, default=DEFAULT_CANDIDATE_POOL_PER_WINDOW)
    parser.add_argument("--selection-seed", default=DEFAULT_SELECTION_SEED)
    parser.add_argument("--max-selected-errors", type=int, default=8, help="maximum helper selected-bit reference errors")
    parser.add_argument("--max-corrected-error-pct", type=float, default=5.0, help="maximum repetition8 corrected error percent")
    parser.add_argument("--max-codeword-errors", type=int, default=3, help="maximum repetition8 errors per codeword")
    parser.add_argument(
        "--puf-action",
        choices=("capture", "status", "erase", "enroll", "identity", "dump-helper", "load-helper", "lifecycle", "inter-device-hd"),
        default="capture",
        help="run puflib-like RTC SLOW helper actions instead of capture mode",
    )
    parser.add_argument("--identity-nonce", default="", help="nonce label for identity")
    parser.add_argument("--identity-attempts", type=int, default=5, help="samples voted inside identity")
    parser.add_argument("--enroll-gc-interval", type=int, default=50, help="MicroPython enrollment gc.collect interval, 0 disables")
    parser.add_argument("--identity-runs", type=int, default=2, help="lifecycle identity repetitions")
    parser.add_argument("--reset-between-identity", action="store_true", help="reopen raw REPL between lifecycle identity checks")
    parser.add_argument("--verify-helper-import", action=argparse.BooleanOptionalAction, default=True, help="export and compare helper after import")
    parser.add_argument(
        "--adversarial",
        choices=("reset", "deepsleep", "software-cycle"),
        help="run identity across a reset, timer deep sleep, or software reset cycle",
    )
    parser.add_argument("--adversarial-runs", type=int, default=3, help="adversarial cycles to execute")
    parser.add_argument("--sleep-ms", type=int, default=3000, help="timer deep sleep duration in milliseconds")
    parser.add_argument("--peer-port", help="second board serial port for inter-device-hd")
    parser.add_argument("--peer-label", help="second board label for inter-device-hd")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.samples <= 0:
        raise ValueError("--samples must be positive")
    if args.size <= 0 or args.size % 4:
        raise ValueError("--size must be a positive multiple of 4")
    if args.repeat_runs <= 0:
        raise ValueError("--repeat-runs must be positive")
    if args.puf_action == "capture" and args.verify_selected_bits and args.repeat_runs < 2:
        raise ValueError("--verify-selected-bits requires --repeat-runs 2 or higher")
    if args.helper and args.helper_out:
        raise ValueError("--helper and --helper-out are mutually exclusive")
    if args.helper and not args.helper.exists():
        raise FileNotFoundError(f"--helper does not exist: {args.helper}")
    if args.negative_helper and not args.negative_helper.exists():
        raise FileNotFoundError(f"--negative-helper does not exist: {args.negative_helper}")
    if args.max_selected_errors < 0:
        raise ValueError("--max-selected-errors must be non-negative")
    if args.max_corrected_error_pct < 0:
        raise ValueError("--max-corrected-error-pct must be non-negative")
    if args.max_codeword_errors < 0:
        raise ValueError("--max-codeword-errors must be non-negative")
    if args.selection_windows <= 0:
        raise ValueError("--selection-windows must be positive")
    if args.candidate_pool_per_window <= 0:
        raise ValueError("--candidate-pool-per-window must be positive")
    if not args.selection_seed:
        raise ValueError("--selection-seed must be non-empty")
    if args.identity_attempts <= 0:
        raise ValueError("--identity-attempts must be positive")
    if args.enroll_gc_interval < 0:
        raise ValueError("--enroll-gc-interval must be non-negative")
    if args.identity_runs <= 0:
        raise ValueError("--identity-runs must be positive")
    if args.adversarial_runs <= 0:
        raise ValueError("--adversarial-runs must be positive")
    if args.sleep_ms <= 0:
        raise ValueError("--sleep-ms must be positive")
    if args.compare_against and not args.compare_against.exists():
        raise FileNotFoundError(f"--compare-against does not exist: {args.compare_against}")

    output_dir = args.output_dir or default_run_dir(args.label)
    if is_inside(output_dir, REPO_ROOT) and not args.allow_repo_output:
        raise ValueError("raw PUF captures must stay outside the repo unless --allow-repo-output is explicit")
    output_dir.mkdir(parents=True, exist_ok=True)
    args.allow_repo_helper = args.allow_repo_output

    try:
        import serial
    except ImportError:
        print("pyserial is required. Use the mpremote tool Python or uv run this script.", file=sys.stderr)
        return 2

    if args.adversarial:
        adversarial_log = output_dir / f"{args.label}-adversarial-{args.adversarial}.txt"
        native_output = run_adversarial_sequence(serial, args, output_dir)
        adversarial_log.write_bytes(native_output)
        print(native_output.decode("utf-8", errors="replace"))
        print(f"done: {output_dir}")
        return 0

    if args.puf_action == "inter-device-hd":
        inter_device_log = output_dir / f"{args.label}-inter-device-hd.txt"
        native_output = run_inter_device_hd(serial, args, output_dir)
        inter_device_log.write_bytes(native_output)
        print(native_output.decode("utf-8", errors="replace"))
        print(f"done: {output_dir}")
        return 0

    run_labels = [
        args.label if args.repeat_runs == 1 else f"{args.label}-run{index:02d}"
        for index in range(1, args.repeat_runs + 1)
    ]
    raw_logs = [output_dir / f"{label}.log" for label in run_labels]
    analysis_paths = [output_dir / f"{label}-analysis.txt" for label in run_labels]
    derive_paths = [output_dir / f"{label}-derive.txt" for label in run_labels]
    contamination_log = output_dir / f"{args.label}-contamination.log"
    contamination_analysis = output_dir / f"{args.label}-contamination-analysis.txt"

    if args.puf_action != "capture":
        native_log = output_dir / f"{args.label}-{args.puf_action}.txt"
        native_output = bytearray()
        if args.puf_action == "lifecycle":
            native_output.extend(run_native_lifecycle(serial, args, output_dir))
            native_log.write_bytes(bytes(native_output))
            print(native_output.decode("utf-8", errors="replace"))
            print(f"done: {output_dir}")
            return 0
        repl = RawRepl(serial, args.port, args.baud)
        try:
            repl.enter()
            if not args.skip_upload:
                print("uploading probe...")
                upload_probe(repl, PROBE_SOURCE, "rtc_fast_puf_probe.py", args.chunk_size)
                print("uploading puf helper...")
                upload_probe(repl, NATIVE_SOURCE, "rtc_slow_puf_native.py", args.chunk_size)

            if args.helper and args.puf_action in {"identity", "load-helper"}:
                native_output.extend(upload_helper_hex(repl, args.helper, args.chunk_size))
                if args.verify_helper_import:
                    native_output.extend(verify_device_helper_matches(repl, args.helper, args.allow_repo_output, output_dir))

            if args.puf_action == "status":
                native_output.extend(repl.exec(status_exec_code(), timeout=30))
            elif args.puf_action == "erase":
                native_output.extend(repl.exec("import rtc_slow_puf_native as p\nprint(p.erase_helper())\n", timeout=30))
            elif args.puf_action == "enroll":
                threshold_ppm = int(round(args.threshold * 1_000_000))
                code = (
                    "import rtc_slow_puf_native as p\n"
                    "print(p.enroll("
                    f"samples={args.samples}, size={args.size}, selected_bits={args.derive_bits}, "
                    f"threshold_ppm={threshold_ppm}, gc_interval={args.enroll_gc_interval}))\n"
                )
                native_output.extend(repl.exec(code, timeout=args.timeout))
                if args.helper_out:
                    native_output.extend(export_helper_json(repl, args.helper_out, args.allow_repo_output))
            elif args.puf_action == "identity":
                code = (
                    "import rtc_slow_puf_native as p\n"
                    f"print(p.identity(size={args.size}, nonce={args.identity_nonce!r}, attempts={args.identity_attempts}))\n"
                )
                native_output.extend(repl.exec(code, timeout=120))
            elif args.puf_action == "dump-helper":
                if not args.helper_out:
                    raise ValueError("--puf-action dump-helper requires --helper-out")
                native_output.extend(export_helper_json(repl, args.helper_out, args.allow_repo_output))
            elif args.puf_action == "load-helper":
                if not args.helper:
                    raise ValueError("--puf-action load-helper requires --helper")
                native_output.extend(repl.exec(status_exec_code(), timeout=30))
            else:
                raise ValueError(f"unsupported puf action: {args.puf_action}")
            repl.exit()
        finally:
            repl.close()

        native_log.write_bytes(bytes(native_output))
        print(native_output.decode("utf-8", errors="replace"))
        print(f"done: {output_dir}")
        return 0

    print(f"output_dir: {output_dir}")
    print(f"capture_logs: {', '.join(str(path) for path in raw_logs)}")
    print("mode: automatic RTC SLOW register cycling, no USB disconnect required")
    print(f"capture_mode: {args.capture_mode}")
    if args.helper_out:
        print(f"helper_out: {args.helper_out}")
    if args.helper:
        print(f"helper: {args.helper}")

    repl = RawRepl(serial, args.port, args.baud)
    try:
        repl.enter()
        if not args.skip_upload:
            print("uploading probe...")
            upload_probe(repl, PROBE_SOURCE, "rtc_fast_puf_probe.py", args.chunk_size)
            if args.run_contamination:
                print("uploading contamination probe...")
                upload_probe(repl, CONTAMINATION_SOURCE, "micropython_contamination_probe.py", args.chunk_size)

        for index, raw_log in enumerate(raw_logs, start=1):
            entrypoint = "run_slow" if args.capture_mode == "raw" else "run_slow_aggregate"
            code = (
                "import rtc_fast_puf_probe as p\n"
                f"p.{entrypoint}(samples={args.samples}, size={args.size})\n"
            )
            print(f"capturing run {index}/{args.repeat_runs}...")
            repl.exec(code, stdout_path=raw_log, timeout=args.timeout)

        if args.run_contamination:
            code = (
                "import micropython_contamination_probe as c\n"
                f"c.run(size={args.size})\n"
            )
            print("capturing contamination probe...")
            repl.exec(code, stdout_path=contamination_log, timeout=120)
        repl.exit()
    finally:
        repl.close()

    print("analyzing...")
    for raw_log, analysis_path, derive_path in zip(raw_logs, analysis_paths, derive_paths):
        run_host_tool(
            [
                sys.executable,
                "-B",
                str(ANALYZER),
                "--threshold",
                str(args.threshold),
                str(raw_log),
            ],
            analysis_path,
        )

        if args.helper:
            derive_args = [
                sys.executable,
                "-B",
                str(DERIVER),
                "verify",
                str(raw_log),
                "--helper",
                str(args.helper),
                "--max-selected-errors",
                str(args.max_selected_errors),
                "--max-corrected-error-pct",
                str(args.max_corrected_error_pct),
                "--max-codeword-errors",
                str(args.max_codeword_errors),
            ]
        elif args.helper_out and raw_log == raw_logs[0]:
            derive_args = [
                sys.executable,
                "-B",
                str(DERIVER),
                "enroll",
                str(raw_log),
                "--helper-out",
                str(args.helper_out),
                "--threshold",
                str(args.threshold),
                "--bits",
                str(args.derive_bits),
                "--extractor",
                args.extractor,
                "--selection-policy",
                args.selection_policy,
                "--selection-windows",
                str(args.selection_windows),
                "--candidate-pool-per-window",
                str(args.candidate_pool_per_window),
                "--selection-seed",
                args.selection_seed,
            ]
        elif args.helper_out:
            derive_args = [
                sys.executable,
                "-B",
                str(DERIVER),
                "verify",
                str(raw_log),
                "--helper",
                str(args.helper_out),
                "--max-selected-errors",
                str(args.max_selected_errors),
                "--max-corrected-error-pct",
                str(args.max_corrected_error_pct),
                "--max-codeword-errors",
                str(args.max_codeword_errors),
            ]
        else:
            derive_args = [
                sys.executable,
                "-B",
                str(DERIVER),
                str(raw_log),
                "--threshold",
                str(args.threshold),
                "--bits",
                str(args.derive_bits),
            ]
            if args.verify_selected_bits and raw_log == raw_logs[0] and len(raw_logs) > 1:
                derive_args.extend(["--verify-log", str(raw_logs[1])])
        run_host_tool(derive_args, derive_path)

        print(analysis_path.read_text(encoding="utf-8"))
        print(derive_path.read_text(encoding="utf-8"))

    if args.compare_against:
        for raw_log in raw_logs:
            compare_path = output_dir / f"{raw_log.stem}-compare-against.txt"
            run_host_tool(
                [
                    sys.executable,
                    "-B",
                    str(ANALYZER),
                    "--threshold",
                    str(args.threshold),
                    "--compare",
                    str(args.compare_against),
                    str(raw_log),
                ],
                compare_path,
            )
            print(compare_path.read_text(encoding="utf-8"))

    if len(raw_logs) > 1:
        for index in range(1, len(raw_logs)):
            compare_path = output_dir / f"{raw_logs[0].stem}-compare-{raw_logs[index].stem}.txt"
            run_host_tool(
                [
                    sys.executable,
                    "-B",
                    str(ANALYZER),
                    "--threshold",
                    str(args.threshold),
                    "--compare",
                    str(raw_logs[0]),
                    str(raw_logs[index]),
                ],
                compare_path,
            )
            print(compare_path.read_text(encoding="utf-8"))

    if args.run_contamination:
        run_host_tool(
            [
                sys.executable,
                "-B",
                str(ANALYZER),
                "--threshold",
                str(args.threshold),
                str(contamination_log),
            ],
            contamination_analysis,
        )
        print(contamination_analysis.read_text(encoding="utf-8"))

    print(f"done: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
