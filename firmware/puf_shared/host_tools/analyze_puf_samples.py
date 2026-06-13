#!/usr/bin/env python3
"""Analyze RTC memory PUF capture logs from MicroPython or Arduino."""

from __future__ import annotations

import argparse
import json
import math
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


SAMPLE_RE = re.compile(r"^(?:MPUF|APUF|PUF)_SAMPLE\s+(\d+)\s+([0-9a-fA-F]+)\s*$")
PHASE_RE = re.compile(r"^(?:MPUF|APUF|PUF)_PHASE\s+(\d+)\s+(.+?)\s*$")
AGG_META_RE = re.compile(
    r"^MPUF_AGG_META\s+.*?\bsize=(\d+)\s+.*?\bsamples=(\d+)\s+.*?\bcount_width=(\d+)\s+.*?\bendian=(\w+)"
)
COUNTS16_RE = re.compile(r"^MPUF_COUNTS16_CHUNK\s+(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-fA-F]+)\s*$")


@dataclass(frozen=True)
class SampleRecord:
    index: int
    sample: bytes
    phase: str | None = None


@dataclass(frozen=True)
class CaptureLog:
    path: Path
    mode: str
    sample_count: int
    sample_size: int
    counts: list[int]
    records: list[SampleRecord] | None = None

    @property
    def samples(self) -> list[bytes] | None:
        if self.records is None:
            return None
        return [record.sample for record in self.records]


def parse_samples(path: Path) -> list[bytes]:
    return [record.sample for record in parse_sample_records(path)]


def parse_capture(path: Path) -> CaptureLog:
    if is_aggregate_log(path):
        return parse_aggregate_capture(path)

    records = parse_sample_records(path)
    samples = [record.sample for record in records]
    return CaptureLog(
        path=path,
        mode="raw",
        sample_count=len(samples),
        sample_size=len(samples[0]),
        counts=bit_counts(samples),
        records=records,
    )


def is_aggregate_log(path: Path) -> bool:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("MPUF_AGG_META"):
                return True
            if SAMPLE_RE.match(line.strip()):
                return False
    return False


def parse_aggregate_capture(path: Path) -> CaptureLog:
    sample_count: int | None = None
    sample_size: int | None = None
    counts: list[int] | None = None
    seen: list[bool] | None = None

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            meta_match = AGG_META_RE.match(stripped)
            if meta_match:
                sample_size = int(meta_match.group(1))
                sample_count = int(meta_match.group(2))
                count_width = int(meta_match.group(3))
                endian = meta_match.group(4)
                if count_width != 16 or endian != "little":
                    raise ValueError(f"{path}:{line_number}: unsupported aggregate format")
                counts = [0] * (sample_size * 8)
                seen = [False] * len(counts)
                continue

            chunk_match = COUNTS16_RE.match(stripped)
            if not chunk_match:
                continue
            if counts is None or seen is None or sample_count is None or sample_size is None:
                raise ValueError(f"{path}:{line_number}: count chunk before aggregate metadata")

            bit_offset = int(chunk_match.group(2))
            count_count = int(chunk_match.group(3))
            hex_text = chunk_match.group(4)
            payload = bytes.fromhex(hex_text)
            if len(payload) != count_count * 2:
                raise ValueError(f"{path}:{line_number}: chunk length does not match count_count")
            if bit_offset < 0 or bit_offset + count_count > len(counts):
                raise ValueError(f"{path}:{line_number}: chunk range out of bounds")

            for index in range(count_count):
                target = bit_offset + index
                if seen[target]:
                    raise ValueError(f"{path}:{line_number}: duplicate aggregate count at bit {target}")
                value = payload[index * 2] | (payload[index * 2 + 1] << 8)
                if value > sample_count:
                    raise ValueError(f"{path}:{line_number}: count exceeds sample count at bit {target}")
                counts[target] = value
                seen[target] = True

    if sample_count is None or sample_size is None or counts is None or seen is None:
        raise ValueError(f"{path}: no aggregate metadata found")
    if not all(seen):
        missing = seen.index(False)
        raise ValueError(f"{path}: missing aggregate count at bit {missing}")

    return CaptureLog(
        path=path,
        mode="aggregate",
        sample_count=sample_count,
        sample_size=sample_size,
        counts=counts,
        records=None,
    )


def parse_sample_records(path: Path) -> list[SampleRecord]:
    phases: dict[int, str] = {}
    records: list[SampleRecord] = []
    samples: list[bytes] = []
    expected_size: int | None = None

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            phase_match = PHASE_RE.match(stripped)
            if phase_match:
                phases[int(phase_match.group(1))] = phase_match.group(2)
                continue

            sample_match = SAMPLE_RE.match(stripped)
            if not sample_match:
                continue

            sample_index = int(sample_match.group(1))
            hex_text = sample_match.group(2)
            if len(hex_text) % 2 != 0:
                raise ValueError(f"{path}:{line_number}: sample hex length is odd")

            sample = bytes.fromhex(hex_text)
            if expected_size is None:
                expected_size = len(sample)
            elif len(sample) != expected_size:
                raise ValueError(
                    f"{path}:{line_number}: sample size {len(sample)} differs from expected {expected_size}"
                )

            samples.append(sample)
            records.append(SampleRecord(sample_index, sample, phases.get(sample_index)))

    if not samples:
        raise ValueError(f"{path}: no PUF sample lines found")

    return records


def hamming_weight(data: bytes) -> int:
    return sum(value.bit_count() for value in data)


def hamming_distance(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("buffers must have equal length")
    return sum((left[index] ^ right[index]).bit_count() for index in range(len(left)))


def bit_counts(samples: Sequence[bytes]) -> list[int]:
    """Count ones per bit position. Complexity: O(samples * bytes * 8) time, O(bits) space."""
    sample_size = len(samples[0])
    counts = [0] * (sample_size * 8)

    for sample in samples:
        for byte_index, value in enumerate(sample):
            bit_base = byte_index * 8
            for bit_index in range(8):
                if value & (1 << (7 - bit_index)):
                    counts[bit_base + bit_index] += 1

    return counts


def reference_from_counts(counts: Sequence[int], sample_count: int) -> bytearray:
    reference = bytearray(math.ceil(len(counts) / 8))
    half = sample_count / 2

    for bit_position, count in enumerate(counts):
        if count > half:
            byte_index = bit_position // 8
            bit_index = 7 - (bit_position % 8)
            reference[byte_index] |= 1 << bit_index

    return reference


def stable_mask(counts: Sequence[int], sample_count: int, threshold: float) -> list[bool]:
    if not 0.5 < threshold <= 1.0:
        raise ValueError("stable threshold must be > 0.5 and <= 1.0")

    upper = math.ceil(sample_count * threshold)
    lower = math.floor(sample_count * (1.0 - threshold))
    return [count >= upper or count <= lower for count in counts]


def masked_error_count(sample: bytes, reference: bytes, mask: Sequence[bool]) -> int:
    errors = 0
    for bit_position, is_stable in enumerate(mask):
        if not is_stable:
            continue

        byte_index = bit_position // 8
        bit_index = 7 - (bit_position % 8)
        sample_bit = (sample[byte_index] >> bit_index) & 1
        reference_bit = (reference[byte_index] >> bit_index) & 1
        errors += sample_bit != reference_bit

    return errors


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * pct
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def summarize(samples: Sequence[bytes], threshold: float) -> dict[str, object]:
    sample_size = len(samples[0])
    bit_total = sample_size * 8
    weights = [hamming_weight(sample) * 100 / bit_total for sample in samples]

    if len(samples) == 1:
        return {
            "samples": 1,
            "mode": "raw",
            "sample_size_bytes": sample_size,
            "bits_total": bit_total,
            "stable_threshold": threshold,
            "stable_bits": None,
            "stable_bits_pct": None,
            "stable_zeroes": None,
            "stable_ones": None,
            "unstable_bits": None,
            "hamming_weight_pct": {
                "mean": weights[0],
                "min": weights[0],
                "max": weights[0],
            },
            "distance_to_first_pct": None,
            "adjacent_distance_pct": None,
            "stable_error_pct": None,
        }

    counts = bit_counts(samples)
    mask = stable_mask(counts, len(samples), threshold)
    reference = reference_from_counts(counts, len(samples))
    stable_bits = sum(mask)
    stable_ones = sum(1 for bit, is_stable in zip(counts, mask) if is_stable and bit > len(samples) / 2)
    stable_zeroes = stable_bits - stable_ones

    distance_to_first = [hamming_distance(samples[0], sample) * 100 / bit_total for sample in samples[1:]]
    adjacent_distance = [
        hamming_distance(samples[index - 1], samples[index]) * 100 / bit_total
        for index in range(1, len(samples))
    ]

    if stable_bits:
        stable_errors = [
            masked_error_count(sample, reference, mask) * 100 / stable_bits
            for sample in samples
        ]
    else:
        stable_errors = []

    return {
        "samples": len(samples),
        "mode": "raw",
        "sample_size_bytes": sample_size,
        "bits_total": bit_total,
        "stable_threshold": threshold,
        "stable_bits": stable_bits,
        "stable_bits_pct": stable_bits * 100 / bit_total,
        "stable_zeroes": stable_zeroes,
        "stable_ones": stable_ones,
        "unstable_bits": bit_total - stable_bits,
        "hamming_weight_pct": {
            "mean": sum(weights) / len(weights),
            "min": min(weights),
            "max": max(weights),
        },
        "distance_to_first_pct": {
            "mean": sum(distance_to_first) / len(distance_to_first),
            "p95": percentile(distance_to_first, 0.95),
            "max": max(distance_to_first),
        },
        "adjacent_distance_pct": {
            "mean": sum(adjacent_distance) / len(adjacent_distance),
            "p95": percentile(adjacent_distance, 0.95),
            "max": max(adjacent_distance),
        },
        "stable_error_pct": {
            "mean": sum(stable_errors) / len(stable_errors) if stable_errors else None,
            "p95": percentile(stable_errors, 0.95) if stable_errors else None,
            "max": max(stable_errors) if stable_errors else None,
        },
    }


def summarize_capture(capture: CaptureLog, threshold: float) -> dict[str, object]:
    samples = capture.samples
    if samples is not None:
        return summarize(samples, threshold)

    counts = capture.counts
    sample_count = capture.sample_count
    sample_size = capture.sample_size
    bit_total = sample_size * 8
    mask = stable_mask(counts, sample_count, threshold)
    stable_bits = sum(mask)
    stable_ones = sum(1 for count, is_stable in zip(counts, mask) if is_stable and count > sample_count / 2)
    stable_zeroes = stable_bits - stable_ones
    total_ones = sum(counts)

    if stable_bits:
        stable_errors = sum(min(count, sample_count - count) for count, is_stable in zip(counts, mask) if is_stable)
        stable_error_mean = stable_errors * 100 / (stable_bits * sample_count)
    else:
        stable_error_mean = None

    return {
        "samples": sample_count,
        "mode": "aggregate",
        "sample_size_bytes": sample_size,
        "bits_total": bit_total,
        "stable_threshold": threshold,
        "stable_bits": stable_bits,
        "stable_bits_pct": stable_bits * 100 / bit_total,
        "stable_zeroes": stable_zeroes,
        "stable_ones": stable_ones,
        "unstable_bits": bit_total - stable_bits,
        "hamming_weight_pct": {
            "mean": total_ones * 100 / (sample_count * bit_total),
            "min": None,
            "max": None,
        },
        "distance_to_first_pct": None,
        "adjacent_distance_pct": None,
        "stable_error_pct": {
            "mean": stable_error_mean,
            "p95": None,
            "max": None,
        },
    }


def compare_captures(left: CaptureLog, right: CaptureLog, threshold: float) -> dict[str, object]:
    if left.sample_size != right.sample_size:
        raise ValueError("sample sizes must match for comparison")

    left_mask = stable_mask(left.counts, left.sample_count, threshold)
    right_mask = stable_mask(right.counts, right.sample_count, threshold)
    combined_mask = [a and b for a, b in zip(left_mask, right_mask)]
    stable_intersection = sum(combined_mask)

    left_reference = reference_from_counts(left.counts, left.sample_count)
    right_reference = reference_from_counts(right.counts, right.sample_count)
    if stable_intersection == 0:
        distance_pct = None
    else:
        distance = 0
        for bit_position, is_stable in enumerate(combined_mask):
            if not is_stable:
                continue
            byte_index = bit_position // 8
            bit_index = 7 - (bit_position % 8)
            left_bit = (left_reference[byte_index] >> bit_index) & 1
            right_bit = (right_reference[byte_index] >> bit_index) & 1
            distance += left_bit != right_bit
        distance_pct = distance * 100 / stable_intersection

    return {
        "stable_intersection_bits": stable_intersection,
        "stable_intersection_pct": stable_intersection * 100 / (left.sample_size * 8),
        "inter_hamming_pct": distance_pct,
    }


def summarize_phases(records: Sequence[SampleRecord]) -> list[dict[str, object]]:
    if not records or not any(record.phase for record in records):
        return []

    base = records[0].sample
    bit_total = len(base) * 8
    rows: list[dict[str, object]] = []
    for record in records:
        if len(record.sample) != len(base):
            raise ValueError("phase samples must have equal length")
        rows.append(
            {
                "index": record.index,
                "phase": record.phase or "",
                "hamming_weight_pct": hamming_weight(record.sample) * 100 / bit_total,
                "distance_to_base_pct": hamming_distance(base, record.sample) * 100 / bit_total,
            }
        )
    return rows


def print_summary(name: str, summary: dict[str, object]) -> None:
    stable_error = summary["stable_error_pct"]

    print(f"=== {name} ===")
    print(f"mode: {summary['mode']}")
    print(f"samples: {summary['samples']}")
    print(f"sample_size_bytes: {summary['sample_size_bytes']}")
    print(f"stable_threshold: {summary['stable_threshold']}")
    if summary["stable_bits"] is None:
        print("stable_bits: not computed for one-sample smoke log")
        print("stable_zeroes: not computed")
        print("stable_ones: not computed")
        print("unstable_bits: not computed")
    else:
        print(f"stable_bits: {summary['stable_bits']} ({summary['stable_bits_pct']:.3f}%)")
        print(f"stable_zeroes: {summary['stable_zeroes']}")
        print(f"stable_ones: {summary['stable_ones']}")
        print(f"unstable_bits: {summary['unstable_bits']}")

    hamming_weight = summary["hamming_weight_pct"]
    distance_to_first = summary["distance_to_first_pct"]
    adjacent_distance = summary["adjacent_distance_pct"]
    assert isinstance(hamming_weight, dict)

    if hamming_weight["min"] is None or hamming_weight["max"] is None:
        print(f"hamming_weight_pct: mean={hamming_weight['mean']:.3f} min/max not available for aggregate log")
    else:
        print(
            "hamming_weight_pct: mean={mean:.3f} min={min:.3f} max={max:.3f}".format(
                **hamming_weight
            )
        )
    if distance_to_first is None:
        print("distance_to_first_pct: not computed")
    else:
        assert isinstance(distance_to_first, dict)
        print(
            "distance_to_first_pct: mean={mean:.3f} p95={p95:.3f} max={max:.3f}".format(
                **distance_to_first
            )
        )
    if adjacent_distance is None:
        print("adjacent_distance_pct: not computed")
    else:
        assert isinstance(adjacent_distance, dict)
        print(
            "adjacent_distance_pct: mean={mean:.3f} p95={p95:.3f} max={max:.3f}".format(
                **adjacent_distance
            )
        )

    if stable_error is None:
        print("stable_error_pct: not computed")
    elif stable_error["mean"] is None:
        print("stable_error_pct: no stable bits")
    elif stable_error["p95"] is None or stable_error["max"] is None:
        print(f"stable_error_pct: mean={stable_error['mean']:.3f} p95/max not available for aggregate log")
    else:
        assert isinstance(stable_error, dict)
        print(
            "stable_error_pct: mean={mean:.3f} p95={p95:.3f} max={max:.3f}".format(
                **stable_error
            )
        )


def print_phase_summary(name: str, phases: Sequence[dict[str, object]]) -> None:
    if not phases:
        return

    print(f"=== {name} phases ===")
    print("phase_index phase hamming_weight_pct distance_to_base_pct")
    for row in phases:
        print(
            "{index:04d} {phase} hw={hamming_weight_pct:.3f} dist={distance_to_base_pct:.3f}".format(
                **row
            )
        )


def self_test() -> None:
    base = bytes([0x55, 0xAA, 0x00, 0xFF] * 16)
    samples = []
    for index in range(20):
        mutable = bytearray(base)
        mutable[index % len(mutable)] ^= 0x01
        samples.append(bytes(mutable))

    summary = summarize(samples, threshold=0.9)
    if summary["samples"] != 20:
        raise AssertionError("self-test sample count failed")
    if summary["stable_bits"] <= 0:
        raise AssertionError("self-test did not produce stable bits")

    with tempfile.TemporaryDirectory() as temp_dir:
        log_path = Path(temp_dir) / "capture.log"
        lines = ["MPUF_META region=RTC_FAST size=64 samples=2"]
        lines.append("MPUF_PHASE 0000 base")
        lines.extend(
            [
                f"MPUF_SAMPLE {index:04d} {sample.hex()}"
                for index, sample in enumerate(samples[:2])
            ]
        )
        lines.append(f"APUF_SAMPLE {2:04d} {samples[2].hex()}")
        lines.append("MPUF_DONE samples=2")
        log_path.write_text("\n".join(lines), encoding="utf-8")
        parsed = parse_samples(log_path)
        if parsed != samples[:3]:
            raise AssertionError("self-test parser round-trip failed")
        phase_rows = summarize_phases(parse_sample_records(log_path))
        if not phase_rows or phase_rows[0]["phase"] != "base":
            raise AssertionError("self-test phase parser failed")

        aggregate_path = Path(temp_dir) / "aggregate.log"
        payload = bytearray()
        counts = bit_counts(samples)
        for count in counts:
            payload.append(count & 0xFF)
            payload.append((count >> 8) & 0xFF)
        aggregate_path.write_text(
            "\n".join(
                [
                    "MPUF_AGG_META region=RTC_SLOW size=64 samples=20 count_width=16 endian=little",
                    f"MPUF_COUNTS16_CHUNK 0 0 {len(counts)} {payload.hex()}",
                    "MPUF_AGG_DONE chunks=1",
                ]
            ),
            encoding="utf-8",
        )
        aggregate = parse_capture(aggregate_path)
        if aggregate.mode != "aggregate" or aggregate.counts != counts:
            raise AssertionError("self-test aggregate parser failed")
        comparison = compare_captures(parse_capture(log_path), aggregate, threshold=0.9)
        if comparison["inter_hamming_pct"] != 0:
            raise AssertionError("self-test raw-vs-aggregate comparison failed")

    print("self-test OK")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="*", type=Path, help="raw sample logs or aggregate count logs")
    parser.add_argument("--threshold", type=float, default=0.98, help="stable-bit threshold, default: 0.98")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--compare", action="store_true", help="compare first two logs as different devices or runs")
    parser.add_argument("--self-test", action="store_true", help="run built-in parser and metric smoke test")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if not args.logs:
        parser.error("provide at least one log file or use --self-test")

    captures = [(path, parse_capture(path)) for path in args.logs]
    summaries = {str(path): summarize_capture(capture, args.threshold) for path, capture in captures}
    phases = {
        str(path): summarize_phases(capture.records or [])
        for path, capture in captures
    }

    comparison: dict[str, object] | None = None
    if args.compare:
        if len(captures) < 2:
            parser.error("--compare requires at least two logs")
        comparison = compare_captures(captures[0][1], captures[1][1], args.threshold)

    if args.json:
        payload = {"summaries": summaries, "phases": phases}
        if comparison is not None:
            payload["comparison"] = comparison
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    for path, summary in summaries.items():
        print_summary(path, summary)
        print_phase_summary(path, phases[path])

    if comparison is not None:
        print("=== comparison ===")
        print(f"stable_intersection_bits: {comparison['stable_intersection_bits']}")
        print(f"stable_intersection_pct: {comparison['stable_intersection_pct']:.3f}%")
        if comparison["inter_hamming_pct"] is None:
            print("inter_hamming_pct: no stable intersection")
        else:
            print(f"inter_hamming_pct: {comparison['inter_hamming_pct']:.3f}%")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
