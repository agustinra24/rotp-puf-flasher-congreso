#!/usr/bin/env python3
"""Summarize structural leakage in RTC SLOW PUF helper data.

This is a host-only audit tool. It prints metadata, fingerprints and aggregate
statistics, but never prints raw helper bytes, raw PUF samples or derived keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

from derive_puf_identity import (
    DISTRIBUTED_WINDOW_POLICY,
    FIXED_REFERENCE_EXTRACTOR,
    FIRST_STABLE_POLICY,
    REPETITION8_EXTRACTOR,
    REPETITION_WIDTH,
    HelperData,
    helper_to_binary,
    load_helper,
    require_ecc_data,
    resolve_helper_positions,
    write_helper,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WINDOW_BITS = 512


def is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def helper_fingerprint(helper: HelperData, helper_path: Path) -> tuple[str, str, int]:
    if helper.extractor == REPETITION8_EXTRACTOR:
        payload = helper_to_binary(helper)
        return sha256_hex(payload), "native_binary", len(payload)
    payload = helper_path.read_bytes()
    return sha256_hex(payload), "json_file", len(payload)


def position_payload(positions: list[int]) -> bytes:
    payload = bytearray()
    for position in positions:
        payload.extend(position.to_bytes(2, "little"))
    return bytes(payload)


def window_distribution(positions: list[int], bit_total: int, window_bits: int) -> list[int]:
    windows = math.ceil(bit_total / window_bits)
    counts = [0] * windows
    for position in positions:
        counts[position // window_bits] += 1
    return counts


def summarize_windows(counts: list[int]) -> dict[str, float | int]:
    if not counts:
        return {"windows": 0, "min": 0, "max": 0, "mean": 0.0, "nonzero": 0}
    return {
        "windows": len(counts),
        "min": min(counts),
        "max": max(counts),
        "mean": sum(counts) / len(counts),
        "nonzero": sum(1 for count in counts if count > 0),
    }


def concentration_warning(helper: HelperData, windows: dict[str, float | int]) -> str:
    if helper.selection_policy == DISTRIBUTED_WINDOW_POLICY:
        if windows["min"] == windows["max"] and windows["nonzero"] == windows["windows"]:
            return "none"
        return "distributed policy did not produce balanced window counts"
    if helper.selection_policy == FIRST_STABLE_POLICY:
        return "first-stable selection may concentrate positions in early memory ranges"
    return "unknown selection policy"


def ecc_summary(helper: HelperData) -> list[str]:
    if helper.extractor != REPETITION8_EXTRACTOR:
        return [
            "extractor_note: fixed-reference is diagnostic and stores direct packed reference bits",
        ]
    ecc_data = require_ecc_data(helper)
    high_bit_zero = sum(1 for value in ecc_data if (value & 0x80) == 0)
    byte_weight_sum = sum(value.bit_count() for value in ecc_data)
    return [
        f"ecc_bytes: {len(ecc_data)}",
        f"ecc_high_bit_zero_count: {high_bit_zero}",
        f"ecc_mean_hamming_weight_per_byte: {byte_weight_sum / len(ecc_data):.3f}",
    ]


def compare_helpers(
    helper: HelperData,
    other: HelperData,
) -> list[str]:
    try:
        positions = set(resolve_helper_positions(helper))
        other_positions = set(resolve_helper_positions(other))
    except ValueError as exc:
        return [
            "## Other Helper Comparison",
            f"comparison_status: unavailable ({exc})",
        ]
    intersection = len(positions & other_positions)
    union = len(positions | other_positions)
    lines = [
        "## Other Helper Comparison",
        f"other_extractor: {other.extractor}",
        f"other_sample_size: {other.sample_size}",
        f"other_selected_bits: {other.selected_bits}",
        f"position_overlap_count: {intersection}",
        f"position_jaccard_pct: {intersection * 100 / union if union else 0.0:.3f}",
    ]
    if helper.extractor == REPETITION8_EXTRACTOR and other.extractor == REPETITION8_EXTRACTOR:
        left = require_ecc_data(helper)
        right = require_ecc_data(other)
        if len(left) == len(right):
            bit_total = len(left) * 8
            distance = sum((a ^ b).bit_count() for a, b in zip(left, right, strict=True))
            lines.append(f"ecc_hamming_pct_same_length: {distance * 100 / bit_total:.3f}")
    return lines


def build_report(
    helper_path: Path,
    helper: HelperData,
    other: HelperData | None,
    window_bits: int,
) -> str:
    bit_total = helper.sample_size * 8
    helper_sha, helper_sha_source, binary_or_json_size = helper_fingerprint(helper, helper_path)
    json_size = len(helper_path.read_bytes())
    positions = resolve_helper_positions(helper)
    density_pct = len(positions) * 100 / bit_total
    window_counts = window_distribution(positions, bit_total, window_bits)
    windows = summarize_windows(window_counts)
    position_sha = sha256_hex(position_payload(positions))

    lines = [
        "# RTC SLOW PUF Helper Leakage Report",
        "",
        "## Helper Metadata",
        f"helper_sha256: {helper_sha}",
        f"helper_sha256_source: {helper_sha_source}",
        f"schema_version: {helper.version}",
        f"extractor: {helper.extractor}",
        f"selection_policy: {helper.selection_policy}",
        "selection_seed_public: true",
        f"selection_seed: {helper.selection_seed}",
        f"selection_windows: {helper.selection_windows}",
        f"candidate_pool_per_window: {helper.candidate_pool_per_window}",
        f"region: {helper.region}",
        f"sample_size_bytes: {helper.sample_size}",
        f"sample_bits: {bit_total}",
        f"threshold: {helper.threshold:.6f}",
        f"selected_bits: {helper.selected_bits}",
        "selected_positions_public: true",
        f"selected_positions: {len(positions)}",
        f"helper_native_or_json_size_bytes: {binary_or_json_size}",
        f"helper_json_size_bytes: {json_size}",
        f"positions_sha256: {position_sha}",
        "",
        "## Position Leakage",
        "position_analysis_status: available",
        f"position_density_pct: {density_pct:.3f}",
        f"position_min_bit: {min(positions) if positions else -1}",
        f"position_max_bit: {max(positions) if positions else -1}",
        f"position_window_bits: {window_bits}",
        f"position_windows: {windows['windows']}",
        f"position_window_min_count: {windows['min']}",
        f"position_window_max_count: {windows['max']}",
        f"position_window_nonzero_count: {windows['nonzero']}",
        f"position_window_mean_count: {windows['mean']:.3f}",
        f"position_concentration_warning: {concentration_warning(helper, windows)}",
        "",
        "## Extractor Leakage",
    ]
    lines.extend(ecc_summary(helper))
    if helper.extractor == REPETITION8_EXTRACTOR:
        relation_bits = helper.selected_bits * (REPETITION_WIDTH - 1)
        lines.extend(
            [
                f"repetition_width: {REPETITION_WIDTH}",
                f"relation_leakage_bits_upper_bound: {relation_bits}",
                "relation_leakage_interpretation: code-offset helper exposes up to 7 linear relations per output bit",
            "stability_map_leakage: selected positions reveal stable cells and must be treated as helper metadata",
            "stability_value_correlation: not established with two boards",
            ]
        )
    lines.extend(
        [
            "",
            "## Formal Security Position",
            "formal_lower_bound: not established",
            "public_helper_claim: not supported by current evidence",
            "verified_lab_behavior: same-board accept and wrong-board reject support utility, not public-helper security",
            "helper_handling: treat real helper files as identity material and keep them out of public repos",
            "population_limit: two boards are insufficient for defensible min-entropy lower bounds",
        ]
    )
    if other is not None:
        lines.append("")
        lines.extend(compare_helpers(helper, other))
    return "\n".join(lines) + "\n"


def run_self_test() -> None:
    temp_dir = Path("/private/tmp") / "rtc-slow-helper-leakage-self-test"
    temp_dir.mkdir(parents=True, exist_ok=True)
    helper_path = temp_dir / "synthetic-helper.json"
    helper = HelperData(
        version=2,
        extractor=REPETITION8_EXTRACTOR,
        region="RTC_SLOW",
        sample_size=32,
        threshold=0.98,
        selected_bits=8,
        selected_positions=list(range(64)),
        repetition=REPETITION_WIDTH,
        ecc_data=bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
        kdf="HKDF-SHA256",
        salt="DID-PUF-RTC-SLOW-v1",
        context="puf_identity_key",
        created_from_mode="synthetic",
        selection_policy=FIRST_STABLE_POLICY,
    )
    write_helper(helper_path, helper, False)
    report = build_report(helper_path, load_helper(helper_path), None, 64)
    if "relation_leakage_bits_upper_bound: 56" not in report:
        raise AssertionError("self-test did not compute repetition8 relation leakage")
    if "formal_lower_bound: not established" not in report:
        raise AssertionError("self-test did not preserve formal lower-bound statement")
    if "selection_policy: first-stable-v1" not in report:
        raise AssertionError("self-test did not report selection policy")
    print("self-test ok")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, help="helper JSON to analyze")
    parser.add_argument("--other-helper", type=Path, help="optional second helper JSON for aggregate comparison")
    parser.add_argument("--report-out", type=Path, help="optional Markdown report path, recommended under /private/tmp")
    parser.add_argument("--window-bits", type=int, default=DEFAULT_WINDOW_BITS, help="position histogram window size in bits")
    parser.add_argument("--allow-repo-output", action="store_true", help="allow --report-out inside the repo")
    parser.add_argument("--self-test", action="store_true", help="run a synthetic self-test")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if args.helper is None:
        raise ValueError("--helper is required unless --self-test is used")
    if args.window_bits <= 0:
        raise ValueError("--window-bits must be positive")
    if not args.helper.exists():
        raise FileNotFoundError(f"--helper does not exist: {args.helper}")
    if args.other_helper and not args.other_helper.exists():
        raise FileNotFoundError(f"--other-helper does not exist: {args.other_helper}")
    if args.report_out and is_inside(args.report_out, REPO_ROOT) and not args.allow_repo_output:
        raise ValueError("leakage reports should stay outside the repo unless --allow-repo-output is explicit")

    helper = load_helper(args.helper)
    other = load_helper(args.other_helper) if args.other_helper else None
    report = build_report(args.helper, helper, other, args.window_bits)
    if args.report_out:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(report, encoding="utf-8")
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
