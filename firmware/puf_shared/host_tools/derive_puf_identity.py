#!/usr/bin/env python3
"""Derive and verify lab identity keys from stable RTC SLOW PUF bits."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import struct
import sys
from pathlib import Path
from typing import Mapping, Sequence, cast

from analyze_puf_samples import CaptureLog, parse_capture, reference_from_counts, stable_mask


DEFAULT_SALT = "DID-PUF-RTC-SLOW-v1"
DEFAULT_CONTEXT = "puf_identity_key"
DEFAULT_MAX_SELECTED_ERRORS = 8
DEFAULT_MAX_CORRECTED_ERROR_PCT = 5.0
DEFAULT_MAX_CODEWORD_ERRORS = 3
FIXED_REFERENCE_EXTRACTOR = "fixed-reference"
REPETITION8_EXTRACTOR = "repetition8"
FIRST_STABLE_POLICY = "first-stable-v1"
DISTRIBUTED_WINDOW_POLICY = "distributed-window-v1"
DEFAULT_SELECTION_POLICY = DISTRIBUTED_WINDOW_POLICY
DEFAULT_SELECTION_WINDOWS = 64
DEFAULT_CANDIDATE_POOL_PER_WINDOW = 128
DEFAULT_SELECTION_SEED = "DID-PUF-RTC-SLOW-select-v1"
POLICY_MODE_SUFFIX = {
    FIRST_STABLE_POLICY: "first-v1",
    DISTRIBUTED_WINDOW_POLICY: "distwin-v1",
}
HELPER_VERSION_FIXED = 1
HELPER_VERSION_REPETITION8 = 2
REPETITION_WIDTH = 8
REPO_ROOT = Path(__file__).resolve().parents[3]
HELPER_BINARY_MAGIC = b"RSPF"
HELPER_BINARY_VERSION = 1
HELPER_BINARY_HEADER = "<4sBBBBHIHHHHHH"
HELPER_BINARY_HEADER_SIZE = struct.calcsize(HELPER_BINARY_HEADER)
HELPER_REGION_TO_ID = {"unknown": 0, "RTC_SLOW": 1, "RTC_FAST": 2}
HELPER_ID_TO_REGION = {value: key for key, value in HELPER_REGION_TO_ID.items()}
HELPER_EXTRACTOR_TO_ID = {REPETITION8_EXTRACTOR: 2}
HELPER_ID_TO_EXTRACTOR = {value: key for key, value in HELPER_EXTRACTOR_TO_ID.items()}


def is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def bit_from_buffer(data: bytes | bytearray, bit_position: int) -> int:
    byte_index = bit_position // 8
    bit_index = 7 - (bit_position % 8)
    return (data[byte_index] >> bit_index) & 1


def set_packed_bit(target: bytearray, bit_position: int, bit: int) -> None:
    if bit:
        target[bit_position // 8] |= 1 << (7 - (bit_position % 8))


def fnv1a32(data: bytes) -> int:
    value = 0x811C9DC5
    for byte in data:
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
    return value


def mode_with_policy(mode: str, policy: str) -> str:
    suffix = POLICY_MODE_SUFFIX.get(policy)
    if suffix is None:
        raise ValueError(f"unsupported selection policy: {policy}")
    return f"{mode}:{suffix}"


def infer_selection_policy(mode: str, explicit: object = None) -> str:
    if isinstance(explicit, str) and explicit:
        if explicit not in POLICY_MODE_SUFFIX:
            raise ValueError(f"unsupported helper selection_policy: {explicit}")
        return explicit
    if "distwin-v1" in mode or DISTRIBUTED_WINDOW_POLICY in mode:
        return DISTRIBUTED_WINDOW_POLICY
    if "first-v1" in mode or FIRST_STABLE_POLICY in mode:
        return FIRST_STABLE_POLICY
    return FIRST_STABLE_POLICY


def candidate_position(
    window_index: int,
    order: int,
    bit_total: int,
    windows: int,
    selection_seed: str = DEFAULT_SELECTION_SEED,
) -> int:
    start = window_index * bit_total // windows
    end = (window_index + 1) * bit_total // windows
    window_bits = end - start
    if window_bits <= 0:
        raise ValueError("selection window has no bits")

    seed = fnv1a32(f"{selection_seed}|{window_index}".encode("ascii"))
    candidate_count = min(order, window_bits - 1)
    start_offset = seed % window_bits
    stride = ((seed >> 9) % window_bits) or 1
    if stride % 2 == 0:
        stride = (stride + 1) % window_bits or 1
    while math.gcd(stride, window_bits) != 1:
        stride = (stride + 2) % window_bits or 1
    return start + ((start_offset + candidate_count * stride) % window_bits)


def select_first_stable_positions(mask: Sequence[bool], bit_limit: int) -> list[int]:
    positions: list[int] = []
    for bit_position, is_stable in enumerate(mask):
        if not is_stable:
            continue
        positions.append(bit_position)
        if len(positions) == bit_limit:
            return positions
    raise ValueError(f"only {len(positions)} stable bits available, need {bit_limit}")


def select_distributed_window_positions(
    mask: Sequence[bool],
    counts: Sequence[int],
    sample_count: int,
    bit_limit: int,
    windows: int,
    candidate_pool_per_window: int,
    selection_seed: str = DEFAULT_SELECTION_SEED,
) -> list[int]:
    selected = select_distributed_window_candidates(
        mask,
        counts,
        sample_count,
        bit_limit,
        windows,
        candidate_pool_per_window,
        selection_seed,
    )
    return [position for _window_index, _order, position in selected]


def select_distributed_window_candidates(
    mask: Sequence[bool],
    counts: Sequence[int],
    sample_count: int,
    bit_limit: int,
    windows: int,
    candidate_pool_per_window: int,
    selection_seed: str = DEFAULT_SELECTION_SEED,
) -> list[tuple[int, int, int]]:
    if windows <= 0:
        raise ValueError("selection windows must be positive")
    if candidate_pool_per_window <= 0:
        raise ValueError("candidate pool per window must be positive")
    if bit_limit < windows:
        raise ValueError("bit limit must be at least the number of selection windows")
    if len(mask) != len(counts):
        raise ValueError("stable mask and counts length differ")

    bit_total = len(mask)
    base_quota = bit_limit // windows
    remainder = bit_limit % windows
    selected: list[tuple[int, int, int]] = []

    for window_index in range(windows):
        quota = base_quota + (1 if window_index < remainder else 0)
        candidates: list[tuple[int, int, int, int]] = []
        start = window_index * bit_total // windows
        end = (window_index + 1) * bit_total // windows
        window_bits = end - start
        pool = min(candidate_pool_per_window, window_bits)

        for order in range(pool):
            position = candidate_position(window_index, order, bit_total, windows, selection_seed)
            if not mask[position]:
                continue
            count = int(counts[position])
            errors = min(count, sample_count - count)
            bias = abs(count * 2 - sample_count)
            candidates.append((errors, -bias, order, position))

        candidates.sort()
        if len(candidates) < quota:
            raise ValueError(
                "selection window "
                f"{window_index} has only {len(candidates)} stable candidate positions, need {quota}"
            )
        selected.extend((window_index, order, position) for _errors, _bias, order, position in candidates[:quota])

    if len(selected) != bit_limit:
        raise ValueError(f"selection produced {len(selected)} candidates, need {bit_limit}")
    return selected


def select_stable_positions(
    mask: Sequence[bool],
    bit_limit: int,
    *,
    counts: Sequence[int] | None = None,
    sample_count: int | None = None,
    policy: str = FIRST_STABLE_POLICY,
    windows: int = DEFAULT_SELECTION_WINDOWS,
    candidate_pool_per_window: int = DEFAULT_CANDIDATE_POOL_PER_WINDOW,
    selection_seed: str = DEFAULT_SELECTION_SEED,
) -> list[int]:
    if policy == FIRST_STABLE_POLICY:
        return select_first_stable_positions(mask, bit_limit)
    if policy == DISTRIBUTED_WINDOW_POLICY:
        if counts is None or sample_count is None:
            raise ValueError("distributed-window-v1 selection requires counts and sample_count")
        return select_distributed_window_positions(
            mask,
            counts,
            sample_count,
            bit_limit,
            windows,
            candidate_pool_per_window,
            selection_seed,
        )
    raise ValueError(f"unsupported selection policy: {policy}")


def pack_reference_bits(reference: bytes | bytearray, positions: Sequence[int]) -> bytes:
    packed = bytearray(math.ceil(len(positions) / 8))
    for index, bit_position in enumerate(positions):
        set_packed_bit(packed, index, bit_from_buffer(reference, bit_position))
    return bytes(packed)


def extract_selected_bits(reference: bytes, mask: list[bool], bit_limit: int) -> tuple[bytes, int]:
    positions = select_stable_positions(mask, bit_limit)
    return pack_reference_bits(reference, positions), len(positions)


def selected_bits_from_positions(reference: bytes | bytearray, positions: Sequence[int]) -> bytes:
    return pack_reference_bits(reference, positions)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(previous)
        counter += 1
    return bytes(okm[:length])


def info_bytes(context: str, nonce: str) -> bytes:
    return (context + ("\0" + nonce if nonce else "")).encode("utf-8")


def derive_key(selected: bytes, salt: str, context: str, nonce: str, key_bytes: int) -> bytes:
    return hkdf_sha256(selected, salt.encode("utf-8"), info_bytes(context, nonce), key_bytes)


def bit_error_on_selected(sample: bytes, reference: bytes, mask: list[bool], bit_limit: int) -> int:
    errors = 0
    checked = 0
    for bit_position, is_stable in enumerate(mask):
        if not is_stable:
            continue
        if checked >= bit_limit:
            break

        sample_bit = bit_from_buffer(sample, bit_position)
        reference_bit = bit_from_buffer(reference, bit_position)
        errors += sample_bit != reference_bit
        checked += 1
    return errors


def reference_error_on_selected(verify: CaptureLog, reference: bytes, mask: list[bool], bit_limit: int) -> int:
    verify_reference = bytes(reference_from_counts(verify.counts, verify.sample_count))
    return bit_error_on_selected(verify_reference, reference, mask, bit_limit)


def detect_region(path: Path) -> str:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if "MPUF_META" not in line and "MPUF_AGG_META" not in line:
                continue
            for token in line.strip().split():
                if token.startswith("region="):
                    return token.split("=", 1)[1]
    return "unknown"


def validate_positions(positions: object, expected_count: int, bit_total: int) -> list[int]:
    if not isinstance(positions, list):
        raise ValueError("helper selected_positions must be a list")
    if len(positions) != expected_count:
        raise ValueError(
            f"helper selected_positions length {len(positions)} does not match expected {expected_count}"
        )

    parsed: list[int] = []
    seen: set[int] = set()
    for value in positions:
        if not isinstance(value, int):
            raise ValueError("helper selected_positions must contain integers")
        if value < 0 or value >= bit_total:
            raise ValueError(f"helper selected position out of bounds: {value}")
        if value in seen:
            raise ValueError(f"helper duplicate selected position: {value}")
        parsed.append(value)
        seen.add(value)
    return parsed


def require_str(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"helper field {field!r} must be a non-empty string")
    return value


def require_int(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if not isinstance(value, int):
        raise ValueError(f"helper field {field!r} must be an integer")
    return value


def require_float(payload: Mapping[str, object], field: str) -> float:
    value = payload.get(field)
    if not isinstance(value, int | float):
        raise ValueError(f"helper field {field!r} must be numeric")
    return float(value)


class HelperData:
    def __init__(
        self,
        *,
        version: int,
        extractor: str,
        region: str,
        sample_size: int,
        threshold: float,
        selected_bits: int,
        selected_positions: list[int] | None = None,
        reference_bits: bytes | None = None,
        repetition: int | None = None,
        ecc_data: bytes | None = None,
        kdf: str,
        salt: str,
        context: str,
        created_from_mode: str,
        selection_policy: str | None = None,
        selection_seed: str | None = None,
        selection_windows: int | None = None,
        candidate_pool_per_window: int | None = None,
    ) -> None:
        self.version = version
        self.extractor = extractor
        self.region = region
        self.sample_size = sample_size
        self.threshold = threshold
        self.selected_bits = selected_bits
        self.selected_positions = selected_positions
        self.reference_bits = reference_bits
        self.repetition = repetition
        self.ecc_data = ecc_data
        self.kdf = kdf
        self.salt = salt
        self.context = context
        self.created_from_mode = created_from_mode
        self.selection_policy = infer_selection_policy(created_from_mode, selection_policy)
        self.selection_seed = selection_seed or DEFAULT_SELECTION_SEED
        self.selection_windows = selection_windows or DEFAULT_SELECTION_WINDOWS
        self.candidate_pool_per_window = candidate_pool_per_window or DEFAULT_CANDIDATE_POOL_PER_WINDOW

    def to_json_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "version": self.version,
            "extractor": self.extractor,
            "region": self.region,
            "sample_size": self.sample_size,
            "threshold": self.threshold,
            "selected_bits": self.selected_bits,
            "kdf": self.kdf,
            "salt": self.salt,
            "context": self.context,
            "created_from_mode": self.created_from_mode,
            "selection_policy": self.selection_policy,
            "selection_windows": self.selection_windows,
            "candidate_pool_per_window": self.candidate_pool_per_window,
        }
        if self.selected_positions is None:
            raise ValueError("helper missing selected positions")
        payload["selected_positions"] = self.selected_positions
        payload["selection_seed"] = self.selection_seed
        if self.extractor == FIXED_REFERENCE_EXTRACTOR:
            if self.reference_bits is None:
                raise ValueError("fixed-reference helper missing reference bits")
            payload["reference_bits_hex"] = self.reference_bits.hex()
            payload.pop("extractor", None)
        elif self.extractor == REPETITION8_EXTRACTOR:
            if self.repetition is None or self.ecc_data is None:
                raise ValueError("repetition8 helper missing ECC data")
            payload["repetition"] = self.repetition
            payload["ecc_data_hex"] = self.ecc_data.hex()
        else:
            raise ValueError(f"unsupported extractor: {self.extractor}")
        return payload


def load_helper(path: Path) -> HelperData:
    payload_obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload_obj, dict):
        raise ValueError("helper JSON root must be an object")
    payload = cast(Mapping[str, object], payload_obj)

    version = require_int(payload, "version")
    sample_size = require_int(payload, "sample_size")
    selected_bits = require_int(payload, "selected_bits")
    threshold = require_float(payload, "threshold")
    if sample_size <= 0:
        raise ValueError("helper sample_size must be positive")
    if selected_bits <= 0:
        raise ValueError("helper selected_bits must be positive")
    if not 0.5 < threshold <= 1.0:
        raise ValueError("helper threshold must be > 0.5 and <= 1.0")

    region = require_str(payload, "region")
    kdf = require_str(payload, "kdf")
    if kdf != "HKDF-SHA256":
        raise ValueError(f"unsupported helper kdf: {kdf}")
    salt = require_str(payload, "salt")
    context = require_str(payload, "context")
    created_from_mode = require_str(payload, "created_from_mode")
    if any(field in payload for field in ("sid_required", "selected_candidates", "sid_commitment", "sid_kdf", "sid_context")):
        raise ValueError("custom RSPF SID helpers are outside this public package")
    selection_seed_obj = payload.get("selection_seed", DEFAULT_SELECTION_SEED)
    if not isinstance(selection_seed_obj, str) or not selection_seed_obj:
        raise ValueError("helper selection_seed must be a non-empty string")
    selection_windows_obj = payload.get("selection_windows", DEFAULT_SELECTION_WINDOWS)
    candidate_pool_obj = payload.get("candidate_pool_per_window", DEFAULT_CANDIDATE_POOL_PER_WINDOW)
    if not isinstance(selection_windows_obj, int) or selection_windows_obj <= 0:
        raise ValueError("helper selection_windows must be a positive integer")
    if not isinstance(candidate_pool_obj, int) or candidate_pool_obj <= 0:
        raise ValueError("helper candidate_pool_per_window must be a positive integer")

    if version == HELPER_VERSION_FIXED:
        extractor = str(payload.get("extractor") or FIXED_REFERENCE_EXTRACTOR)
        if extractor != FIXED_REFERENCE_EXTRACTOR:
            raise ValueError(f"unsupported helper extractor for version 1: {extractor}")
        positions = validate_positions(payload.get("selected_positions"), selected_bits, sample_size * 8)
        reference_hex = require_str(payload, "reference_bits_hex")
        reference_bits = bytes.fromhex(reference_hex)
        expected_reference_bytes = math.ceil(selected_bits / 8)
        if len(reference_bits) != expected_reference_bytes:
            raise ValueError("helper reference_bits_hex length does not match selected_bits")

        return HelperData(
            version=version,
            extractor=FIXED_REFERENCE_EXTRACTOR,
            region=region,
            sample_size=sample_size,
            threshold=threshold,
            selected_bits=selected_bits,
            selected_positions=positions,
            reference_bits=reference_bits,
            kdf=kdf,
            salt=salt,
            context=context,
            created_from_mode=created_from_mode,
            selection_policy=infer_selection_policy(created_from_mode, payload.get("selection_policy")),
            selection_seed=selection_seed_obj,
            selection_windows=selection_windows_obj,
            candidate_pool_per_window=candidate_pool_obj,
        )

    if version != HELPER_VERSION_REPETITION8:
        raise ValueError(f"unsupported helper version: {version}")

    extractor = require_str(payload, "extractor")
    if extractor != REPETITION8_EXTRACTOR:
        raise ValueError(f"unsupported helper extractor: {extractor}")
    repetition = require_int(payload, "repetition")
    if repetition != REPETITION_WIDTH:
        raise ValueError(f"unsupported repetition width: {repetition}")

    selection_policy = infer_selection_policy(created_from_mode, payload.get("selection_policy"))
    expected_positions = selected_bits * repetition
    positions = validate_positions(payload.get("selected_positions"), expected_positions, sample_size * 8)
    ecc_hex = require_str(payload, "ecc_data_hex")
    ecc_data = bytes.fromhex(ecc_hex)
    if len(ecc_data) != selected_bits:
        raise ValueError("helper ecc_data_hex length must equal selected_bits bytes")

    return HelperData(
        version=version,
        extractor=extractor,
        region=region,
        sample_size=sample_size,
        threshold=threshold,
        selected_bits=selected_bits,
        selected_positions=positions,
        repetition=repetition,
        ecc_data=ecc_data,
        kdf=kdf,
        salt=salt,
        context=context,
        created_from_mode=created_from_mode,
        selection_policy=selection_policy,
        selection_seed=selection_seed_obj,
        selection_windows=selection_windows_obj,
        candidate_pool_per_window=candidate_pool_obj,
    )


def write_helper(path: Path, helper: HelperData, allow_repo_helper: bool) -> None:
    if is_inside(path, REPO_ROOT) and not allow_repo_helper:
        raise ValueError("helper data must stay outside the repo unless --allow-repo-helper is explicit")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(helper.to_json_payload(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def threshold_to_ppm(threshold: float) -> int:
    if not 0.5 < threshold <= 1.0:
        raise ValueError("threshold must be > 0.5 and <= 1.0")
    return int(round(threshold * 1_000_000))


def threshold_from_ppm(threshold_ppm: int) -> float:
    if threshold_ppm <= 500_000 or threshold_ppm > 1_000_000:
        raise ValueError("threshold_ppm must be > 500000 and <= 1000000")
    return threshold_ppm / 1_000_000


def helper_to_binary(helper: HelperData) -> bytes:
    """Pack a repetition8 helper into the compact on-device binary shape."""
    if helper.extractor != REPETITION8_EXTRACTOR:
        raise ValueError("only repetition8 helpers can be packed for device storage")
    if helper.repetition != REPETITION_WIDTH:
        raise ValueError("unsupported helper repetition width")
    ecc_data = require_ecc_data(helper)
    region_id = HELPER_REGION_TO_ID.get(helper.region)
    if region_id is None:
        raise ValueError(f"unsupported helper region for binary export: {helper.region}")
    salt_bytes = helper.salt.encode("utf-8")
    context_bytes = helper.context.encode("utf-8")
    mode_bytes = helper.created_from_mode.encode("utf-8")
    if len(salt_bytes) > 255 or len(context_bytes) > 255 or len(mode_bytes) > 255:
        raise ValueError("helper salt/context/mode are too long for binary export")
    expected_count = helper.selected_bits * REPETITION_WIDTH
    if helper.selected_positions is None:
        raise ValueError("helper missing selected positions")
    if len(helper.selected_positions) != expected_count:
        raise ValueError("helper selected position count does not match selected_bits * repetition")
    selection_payload = b"".join(struct.pack("<H", position) for position in helper.selected_positions)
    selection_count = len(helper.selected_positions)
    if selection_count > 65535 or len(ecc_data) > 65535:
        raise ValueError("helper is too large for device binary export")

    header = struct.pack(
        HELPER_BINARY_HEADER,
        HELPER_BINARY_MAGIC,
        HELPER_BINARY_VERSION,
        HELPER_EXTRACTOR_TO_ID[helper.extractor],
        region_id,
        helper.repetition,
        helper.sample_size,
        threshold_to_ppm(helper.threshold),
        helper.selected_bits,
        selection_count,
        len(ecc_data),
        len(salt_bytes),
        len(context_bytes),
        len(mode_bytes),
    )
    return header + salt_bytes + context_bytes + mode_bytes + selection_payload + ecc_data


def helper_from_binary(payload: bytes) -> HelperData:
    """Unpack the compact device helper format back into helper JSON data."""
    if len(payload) < HELPER_BINARY_HEADER_SIZE:
        raise ValueError("device helper binary is truncated")
    (
        magic,
        binary_version,
        extractor_id,
        region_id,
        repetition,
        sample_size,
        threshold_ppm,
        selected_bits,
        positions_count,
        ecc_len,
        salt_len,
        context_len,
        mode_len,
    ) = struct.unpack(HELPER_BINARY_HEADER, payload[:HELPER_BINARY_HEADER_SIZE])
    if magic != HELPER_BINARY_MAGIC:
        raise ValueError("device helper binary has invalid magic")
    if binary_version != HELPER_BINARY_VERSION:
        raise ValueError(f"unsupported device helper binary version: {binary_version}")
    extractor = HELPER_ID_TO_EXTRACTOR.get(extractor_id)
    if extractor != REPETITION8_EXTRACTOR:
        raise ValueError(f"unsupported device helper extractor id: {extractor_id}")
    region = HELPER_ID_TO_REGION.get(region_id)
    if region is None:
        raise ValueError(f"unsupported device helper region id: {region_id}")
    if repetition != REPETITION_WIDTH:
        raise ValueError(f"unsupported device helper repetition: {repetition}")
    if selected_bits <= 0 or positions_count != selected_bits * repetition:
        raise ValueError("device helper selected entry count is inconsistent")
    if ecc_len != selected_bits:
        raise ValueError("device helper ECC length must equal selected_bits")

    cursor = HELPER_BINARY_HEADER_SIZE
    text_len = salt_len + context_len + mode_len
    selection_len = positions_count * 2
    expected_len = cursor + text_len + selection_len + ecc_len
    if len(payload) != expected_len:
        raise ValueError(f"device helper binary length {len(payload)} does not match expected {expected_len}")

    salt = payload[cursor : cursor + salt_len].decode("utf-8")
    cursor += salt_len
    context = payload[cursor : cursor + context_len].decode("utf-8")
    cursor += context_len
    created_from_mode = payload[cursor : cursor + mode_len].decode("utf-8")
    cursor += mode_len
    selection_payload = payload[cursor : cursor + selection_len]
    cursor += selection_len
    selection_policy = infer_selection_policy(created_from_mode)
    positions = [
        struct.unpack("<H", selection_payload[index : index + 2])[0]
        for index in range(0, len(selection_payload), 2)
    ]
    validate_positions(positions, positions_count, sample_size * 8)
    ecc_data = payload[cursor : cursor + ecc_len]

    return HelperData(
        version=HELPER_VERSION_REPETITION8,
        extractor=REPETITION8_EXTRACTOR,
        region=region,
        sample_size=sample_size,
        threshold=threshold_from_ppm(threshold_ppm),
        selected_bits=selected_bits,
        selected_positions=positions,
        repetition=repetition,
        ecc_data=ecc_data,
        kdf="HKDF-SHA256",
        salt=salt,
        context=context,
        created_from_mode=created_from_mode,
        selection_policy=selection_policy,
    )


def majority_bit_and_errors(code_word: int) -> tuple[int | None, int]:
    ones = code_word.bit_count()
    if ones > REPETITION_WIDTH // 2:
        return 1, REPETITION_WIDTH - ones
    if ones < REPETITION_WIDTH // 2:
        return 0, ones
    return None, ones


def generate_repetition8_ecc(masked_reference: bytes) -> bytes:
    """Generate the same 8x repetition helper shape used by esp32_puflib."""
    ecc_data = bytearray(len(masked_reference))
    for index, value in enumerate(masked_reference):
        ecc_data[index] = (~value & 0xFF) if value & 0x80 else value
    return bytes(ecc_data)


def reconstruct_repetition8(masked_data: bytes, ecc_data: bytes) -> tuple[bytes, dict[str, float | int]]:
    if len(masked_data) != len(ecc_data):
        raise ValueError("masked data and ECC data must have equal length")

    corrected = bytearray(math.ceil(len(masked_data) / 8))
    corrected_errors_total = 0
    max_errors = 0
    uncertain = 0

    for index, (data_byte, ecc_byte) in enumerate(zip(masked_data, ecc_data, strict=True)):
        bit, errors = majority_bit_and_errors(data_byte ^ ecc_byte)
        corrected_errors_total += errors
        max_errors = max(max_errors, errors)
        if bit is None:
            uncertain += 1
            continue
        set_packed_bit(corrected, index, bit)

    bit_total = len(masked_data) * REPETITION_WIDTH
    return bytes(corrected), {
        "corrected_bit_errors_total": corrected_errors_total,
        "corrected_bit_errors_pct": corrected_errors_total * 100 / bit_total if bit_total else 0.0,
        "max_errors_per_codeword": max_errors,
        "uncertain_codewords": uncertain,
    }


def build_fixed_reference_helper(
    capture: CaptureLog,
    region: str,
    threshold: float,
    selected_bits: int,
    salt: str,
    context: str,
    selection_policy: str,
    selection_windows: int,
    candidate_pool_per_window: int,
    selection_seed: str,
) -> HelperData:
    mask = stable_mask(capture.counts, capture.sample_count, threshold)
    positions = select_stable_positions(
        mask,
        selected_bits,
        counts=capture.counts,
        sample_count=capture.sample_count,
        policy=selection_policy,
        windows=selection_windows,
        candidate_pool_per_window=candidate_pool_per_window,
        selection_seed=selection_seed,
    )
    reference = reference_from_counts(capture.counts, capture.sample_count)
    reference_bits = selected_bits_from_positions(reference, positions)
    return HelperData(
        version=HELPER_VERSION_FIXED,
        extractor=FIXED_REFERENCE_EXTRACTOR,
        region=region,
        sample_size=capture.sample_size,
        threshold=threshold,
        selected_bits=selected_bits,
        selected_positions=positions,
        reference_bits=reference_bits,
        kdf="HKDF-SHA256",
        salt=salt,
        context=context,
        created_from_mode=mode_with_policy(capture.mode, selection_policy),
        selection_policy=selection_policy,
        selection_seed=selection_seed,
        selection_windows=selection_windows,
        candidate_pool_per_window=candidate_pool_per_window,
    )


def build_repetition8_helper(
    capture: CaptureLog,
    region: str,
    threshold: float,
    selected_bits: int,
    salt: str,
    context: str,
    selection_policy: str,
    selection_windows: int,
    candidate_pool_per_window: int,
    selection_seed: str,
) -> HelperData:
    mask = stable_mask(capture.counts, capture.sample_count, threshold)
    positions = select_stable_positions(
        mask,
        selected_bits * REPETITION_WIDTH,
        counts=capture.counts,
        sample_count=capture.sample_count,
        policy=selection_policy,
        windows=selection_windows,
        candidate_pool_per_window=candidate_pool_per_window,
        selection_seed=selection_seed,
    )
    reference = reference_from_counts(capture.counts, capture.sample_count)
    masked_reference = selected_bits_from_positions(reference, positions)
    ecc_data = generate_repetition8_ecc(masked_reference)
    return HelperData(
        version=HELPER_VERSION_REPETITION8,
        extractor=REPETITION8_EXTRACTOR,
        region=region,
        sample_size=capture.sample_size,
        threshold=threshold,
        selected_bits=selected_bits,
        selected_positions=positions,
        repetition=REPETITION_WIDTH,
        ecc_data=ecc_data,
        kdf="HKDF-SHA256",
        salt=salt,
        context=context,
        created_from_mode=mode_with_policy(capture.mode, selection_policy),
        selection_policy=selection_policy,
        selection_seed=selection_seed,
        selection_windows=selection_windows,
        candidate_pool_per_window=candidate_pool_per_window,
    )


def build_helper(
    capture: CaptureLog,
    region: str,
    threshold: float,
    selected_bits: int,
    salt: str,
    context: str,
    extractor: str,
    selection_policy: str,
    selection_windows: int,
    candidate_pool_per_window: int,
    selection_seed: str,
) -> HelperData:
    if extractor == FIXED_REFERENCE_EXTRACTOR:
        return build_fixed_reference_helper(
            capture,
            region,
            threshold,
            selected_bits,
            salt,
            context,
            selection_policy,
            selection_windows,
            candidate_pool_per_window,
            selection_seed,
        )
    if extractor == REPETITION8_EXTRACTOR:
        return build_repetition8_helper(
            capture,
            region,
            threshold,
            selected_bits,
            salt,
            context,
            selection_policy,
            selection_windows,
            candidate_pool_per_window,
            selection_seed,
        )
    raise ValueError(f"unsupported extractor: {extractor}")


def validate_capture_against_helper(capture: CaptureLog, region: str, helper: HelperData) -> None:
    if capture.sample_size != helper.sample_size:
        raise ValueError(
            f"capture sample_size {capture.sample_size} does not match helper sample_size {helper.sample_size}"
        )
    if helper.region != "unknown" and region != "unknown" and region != helper.region:
        raise ValueError(f"capture region {region} does not match helper region {helper.region}")


def selected_error_for_reference(reference_bits: bytes, helper: HelperData) -> int:
    if helper.reference_bits is None:
        raise ValueError("fixed-reference helper missing reference bits")
    errors = 0
    for index in range(helper.selected_bits):
        errors += bit_from_buffer(reference_bits, index) != bit_from_buffer(helper.reference_bits, index)
    return errors


def selected_error_for_sample(sample: bytes, helper: HelperData) -> int:
    if helper.reference_bits is None:
        raise ValueError("fixed-reference helper missing reference bits")
    errors = 0
    for index, bit_position in enumerate(resolve_helper_positions(helper)):
        errors += bit_from_buffer(sample, bit_position) != bit_from_buffer(helper.reference_bits, index)
    return errors


def resolve_helper_positions(helper: HelperData) -> list[int]:
    if helper.selected_positions is None:
        raise ValueError("helper missing selected positions")
    return helper.selected_positions


def candidate_bits_from_capture(capture: CaptureLog, helper: HelperData) -> bytes:
    reference = reference_from_counts(capture.counts, capture.sample_count)
    return selected_bits_from_positions(reference, resolve_helper_positions(helper))


def require_ecc_data(helper: HelperData) -> bytes:
    if helper.ecc_data is None:
        raise ValueError("repetition8 helper missing ECC data")
    return helper.ecc_data


def repetition8_material_from_capture(
    capture: CaptureLog,
    helper: HelperData,
) -> tuple[bytes, dict[str, float | int]]:
    selected_positions = resolve_helper_positions(helper)
    selected = selected_bits_from_positions(reference_from_counts(capture.counts, capture.sample_count), selected_positions)
    corrected, summary = reconstruct_repetition8(selected, require_ecc_data(helper))
    summary["reconstructed_bits"] = len(corrected) * 8

    if capture.samples is not None:
        sample_summaries = [
            reconstruct_repetition8(selected_bits_from_positions(sample, selected_positions), require_ecc_data(helper))[1]
            for sample in capture.samples
        ]
        sample_errors = [int(item["corrected_bit_errors_total"]) for item in sample_summaries]
        sample_uncertain = [int(item["uncertain_codewords"]) for item in sample_summaries]
        sample_max_errors = [int(item["max_errors_per_codeword"]) for item in sample_summaries]
        summary["sample_corrected_bit_errors_min"] = min(sample_errors)
        summary["sample_corrected_bit_errors_max"] = max(sample_errors)
        summary["sample_corrected_bit_errors_mean"] = sum(sample_errors) / len(sample_errors)
        summary["sample_uncertain_codewords_max"] = max(sample_uncertain)
        summary["sample_max_errors_per_codeword_max"] = max(sample_max_errors)

    return corrected, summary


def helper_error_summary(capture: CaptureLog, helper: HelperData) -> dict[str, float | int]:
    if helper.extractor == REPETITION8_EXTRACTOR:
        _corrected, summary = repetition8_material_from_capture(capture, helper)
        return summary

    if capture.samples is None:
        candidate = candidate_bits_from_capture(capture, helper)
        return {
            "selected_bit_reference_errors": selected_error_for_reference(candidate, helper),
        }

    errors = [selected_error_for_sample(sample, helper) for sample in capture.samples]
    return {
        "selected_bit_errors_min": min(errors),
        "selected_bit_errors_max": max(errors),
        "selected_bit_errors_mean": sum(errors) / len(errors),
        "selected_bit_reference_errors": selected_error_for_reference(candidate_bits_from_capture(capture, helper), helper),
    }


def derive_material_from_capture(
    capture: CaptureLog,
    helper: HelperData,
) -> tuple[bytes, dict[str, float | int]]:
    selected = candidate_bits_from_capture(capture, helper)
    if helper.extractor == FIXED_REFERENCE_EXTRACTOR:
        return selected, helper_error_summary(capture, helper)
    if helper.extractor == REPETITION8_EXTRACTOR:
        return repetition8_material_from_capture(capture, helper)
    raise ValueError(f"unsupported extractor: {helper.extractor}")


def print_common_enrollment(
    enrollment_log: Path,
    capture: CaptureLog,
    threshold: float,
    stable_bits: int,
    selected_count: int,
    context: str,
    key: bytes,
) -> None:
    print(f"enrollment_log: {enrollment_log}")
    print(f"mode: {capture.mode}")
    print(f"samples: {capture.sample_count}")
    print(f"sample_size_bytes: {capture.sample_size}")
    print(f"stable_threshold: {threshold}")
    print(f"stable_bits: {stable_bits}")
    print(f"selected_bits: {selected_count}")
    print("kdf: HKDF-SHA256")
    print(f"context: {context}")
    print(f"key_sha256: {hashlib.sha256(key).hexdigest()}")


def legacy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("enrollment_log", type=Path, nargs="?", help="log with multiple PUF samples")
    parser.add_argument("--verify-log", type=Path, help="optional later run to measure selected-bit error")
    parser.add_argument("--threshold", type=float, default=0.98, help="stable-bit threshold")
    parser.add_argument("--bits", type=int, default=256, help="number of stable bits to derive from")
    parser.add_argument("--key-bytes", type=int, default=32, help="derived key length")
    parser.add_argument("--salt", default=DEFAULT_SALT, help="HKDF salt")
    parser.add_argument("--context", default=DEFAULT_CONTEXT, help="HKDF context string")
    parser.add_argument("--nonce", default="", help="optional server nonce or session label")
    parser.add_argument("--show-key", action="store_true", help="print the derived key, lab only")
    parser.add_argument("--self-test", action="store_true", help="run built-in helper-data smoke test")
    return parser


def subcommand_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    enroll = subparsers.add_parser("enroll", help="create helper data from an enrollment log")
    enroll.add_argument("enrollment_log", type=Path)
    enroll.add_argument("--helper-out", type=Path, required=True)
    enroll.add_argument(
        "--extractor",
        choices=(FIXED_REFERENCE_EXTRACTOR, REPETITION8_EXTRACTOR),
        default=REPETITION8_EXTRACTOR,
        help="helper extractor, default: repetition8",
    )
    enroll.add_argument("--threshold", type=float, default=0.98)
    enroll.add_argument("--bits", type=int, default=256)
    enroll.add_argument("--key-bytes", type=int, default=32)
    enroll.add_argument("--salt", default=DEFAULT_SALT)
    enroll.add_argument("--context", default=DEFAULT_CONTEXT)
    enroll.add_argument("--nonce", default="")
    enroll.add_argument("--allow-repo-helper", action="store_true")
    enroll.add_argument(
        "--selection-policy",
        choices=(FIRST_STABLE_POLICY, DISTRIBUTED_WINDOW_POLICY),
        default=DEFAULT_SELECTION_POLICY,
        help="stable-position selector for new helpers, default: distributed-window-v1",
    )
    enroll.add_argument("--selection-windows", type=int, default=DEFAULT_SELECTION_WINDOWS)
    enroll.add_argument("--candidate-pool-per-window", type=int, default=DEFAULT_CANDIDATE_POOL_PER_WINDOW)
    enroll.add_argument("--selection-seed", default=DEFAULT_SELECTION_SEED)

    verify = subparsers.add_parser("verify", help="verify a later log against helper data")
    verify.add_argument("capture_log", type=Path)
    verify.add_argument("--helper", type=Path, required=True)
    verify.add_argument("--key-bytes", type=int, default=32)
    verify.add_argument("--nonce", default="")
    verify.add_argument("--max-selected-errors", type=int, default=DEFAULT_MAX_SELECTED_ERRORS)
    verify.add_argument("--max-corrected-error-pct", type=float, default=DEFAULT_MAX_CORRECTED_ERROR_PCT)
    verify.add_argument("--max-codeword-errors", type=int, default=DEFAULT_MAX_CODEWORD_ERRORS)
    verify.set_defaults(allow_repo_helper=False)

    derive = subparsers.add_parser("derive", help="derive a key from a log using helper data")
    derive.add_argument("capture_log", type=Path)
    derive.add_argument("--helper", type=Path, required=True)
    derive.add_argument("--key-bytes", type=int, default=32)
    derive.add_argument("--nonce", default="")
    derive.add_argument("--max-selected-errors", type=int, default=DEFAULT_MAX_SELECTED_ERRORS)
    derive.add_argument("--max-corrected-error-pct", type=float, default=DEFAULT_MAX_CORRECTED_ERROR_PCT)
    derive.add_argument("--max-codeword-errors", type=int, default=DEFAULT_MAX_CODEWORD_ERRORS)
    derive.add_argument("--show-key", action="store_true", help="print the derived key, lab only")
    derive.set_defaults(allow_repo_helper=False)

    return parser


def run_legacy(argv: Sequence[str]) -> int:
    parser = legacy_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if args.enrollment_log is None:
        parser.error("provide enrollment_log or use a subcommand")
    if args.bits <= 0 or args.key_bytes <= 0:
        raise ValueError("--bits and --key-bytes must be positive")

    capture = parse_capture(args.enrollment_log)
    mask = stable_mask(capture.counts, capture.sample_count, args.threshold)
    reference = bytes(reference_from_counts(capture.counts, capture.sample_count))
    stable_bits = sum(mask)
    selected, selected_count = extract_selected_bits(reference, mask, args.bits)
    key = derive_key(selected, args.salt, args.context, args.nonce, args.key_bytes)

    print_common_enrollment(args.enrollment_log, capture, args.threshold, stable_bits, selected_count, args.context, key)
    if args.show_key:
        print(f"derived_key_hex: {key.hex()}")

    if args.verify_log:
        verify_capture = parse_capture(args.verify_log)
        print(f"verify_log: {args.verify_log}")
        print(f"verify_mode: {verify_capture.mode}")
        print(f"verify_samples: {verify_capture.sample_count}")
        if verify_capture.samples is None:
            error_count = reference_error_on_selected(verify_capture, reference, mask, args.bits)
            print(f"selected_bit_reference_errors: {error_count}")
        else:
            errors = [
                bit_error_on_selected(sample, reference, mask, args.bits)
                for sample in verify_capture.samples
            ]
            print(f"selected_bit_errors_min: {min(errors)}")
            print(f"selected_bit_errors_max: {max(errors)}")
            print(f"selected_bit_errors_mean: {sum(errors) / len(errors):.3f}")

    return 0


def run_enroll(args: argparse.Namespace) -> int:
    if args.bits <= 0 or args.key_bytes <= 0:
        raise ValueError("--bits and --key-bytes must be positive")
    if args.selection_windows <= 0:
        raise ValueError("--selection-windows must be positive")
    if args.candidate_pool_per_window <= 0:
        raise ValueError("--candidate-pool-per-window must be positive")
    if not args.selection_seed:
        raise ValueError("--selection-seed must be non-empty")

    capture = parse_capture(args.enrollment_log)
    region = detect_region(args.enrollment_log)
    helper = build_helper(
        capture,
        region,
        args.threshold,
        args.bits,
        args.salt,
        args.context,
        args.extractor,
        args.selection_policy,
        args.selection_windows,
        args.candidate_pool_per_window,
        args.selection_seed,
    )
    write_helper(args.helper_out, helper, args.allow_repo_helper)

    stable_bits = sum(stable_mask(capture.counts, capture.sample_count, args.threshold))
    selected, summary = derive_material_from_capture(capture, helper)
    key = derive_key(selected, helper.salt, helper.context, args.nonce, args.key_bytes)

    print_common_enrollment(
        args.enrollment_log,
        capture,
        args.threshold,
        stable_bits,
        helper.selected_bits,
        helper.context,
        key,
    )
    print(f"extractor: {helper.extractor}")
    print(f"selection_policy: {helper.selection_policy}")
    print(f"selection_seed: {helper.selection_seed}")
    print(f"selection_windows: {helper.selection_windows}")
    print(f"candidate_pool_per_window: {helper.candidate_pool_per_window}")
    print(f"helper_out: {args.helper_out}")
    print(f"helper_region: {helper.region}")
    print(f"helper_selected_positions: {len(helper.selected_positions or [])}")
    if helper.extractor == REPETITION8_EXTRACTOR:
        print(f"repetition: {helper.repetition}")
        print(f"ecc_bytes: {len(require_ecc_data(helper))}")
        print(f"corrected_bit_errors_total: {int(summary['corrected_bit_errors_total'])}")
        print(f"corrected_bit_errors_pct: {float(summary['corrected_bit_errors_pct']):.3f}")
        print(f"max_errors_per_codeword: {int(summary['max_errors_per_codeword'])}")
        print(f"uncertain_codewords: {int(summary['uncertain_codewords'])}")
    return 0


def print_helper_verification(
    capture_log: Path,
    capture: CaptureLog,
    helper: HelperData,
    summary: Mapping[str, float | int],
    max_selected_errors: int,
    max_corrected_error_pct: float,
    max_codeword_errors: int,
) -> bool:
    print(f"capture_log: {capture_log}")
    print(f"mode: {capture.mode}")
    print(f"samples: {capture.sample_count}")
    print(f"sample_size_bytes: {capture.sample_size}")
    print(f"extractor: {helper.extractor}")
    print(f"selection_policy: {helper.selection_policy}")
    print(f"selection_seed: {helper.selection_seed}")
    print(f"selection_windows: {helper.selection_windows}")
    print(f"candidate_pool_per_window: {helper.candidate_pool_per_window}")
    print(f"helper_region: {helper.region}")
    print(f"helper_threshold: {helper.threshold}")
    print(f"selected_bits: {helper.selected_bits}")

    if helper.extractor == FIXED_REFERENCE_EXTRACTOR:
        reference_errors = int(summary["selected_bit_reference_errors"])
        accepted = reference_errors <= max_selected_errors
        if "selected_bit_errors_min" in summary:
            print(f"selected_bit_errors_min: {int(summary['selected_bit_errors_min'])}")
            print(f"selected_bit_errors_max: {int(summary['selected_bit_errors_max'])}")
            print(f"selected_bit_errors_mean: {float(summary['selected_bit_errors_mean']):.3f}")
        print(f"selected_bit_reference_errors: {reference_errors}")
        print(f"max_selected_errors: {max_selected_errors}")
    elif helper.extractor == REPETITION8_EXTRACTOR:
        corrected_pct = float(summary["corrected_bit_errors_pct"])
        max_errors = int(summary["max_errors_per_codeword"])
        uncertain = int(summary["uncertain_codewords"])
        accepted = (
            uncertain == 0
            and max_errors <= max_codeword_errors
            and corrected_pct <= max_corrected_error_pct
        )
        print(f"repetition: {helper.repetition}")
        print(f"selected_positions: {len(helper.selected_positions or [])}")
        print(f"ecc_bytes: {len(require_ecc_data(helper))}")
        print(f"corrected_bit_errors_total: {int(summary['corrected_bit_errors_total'])}")
        print(f"corrected_bit_errors_pct: {corrected_pct:.3f}")
        print(f"max_errors_per_codeword: {max_errors}")
        print(f"uncertain_codewords: {uncertain}")
        if "sample_corrected_bit_errors_min" in summary:
            print(f"sample_corrected_bit_errors_min: {int(summary['sample_corrected_bit_errors_min'])}")
            print(f"sample_corrected_bit_errors_max: {int(summary['sample_corrected_bit_errors_max'])}")
            print(f"sample_corrected_bit_errors_mean: {float(summary['sample_corrected_bit_errors_mean']):.3f}")
            print(f"sample_uncertain_codewords_max: {int(summary['sample_uncertain_codewords_max'])}")
            print(f"sample_max_errors_per_codeword_max: {int(summary['sample_max_errors_per_codeword_max'])}")
        print(f"max_corrected_error_pct: {max_corrected_error_pct:.3f}")
        print(f"max_codeword_errors: {max_codeword_errors}")
    else:
        raise ValueError(f"unsupported extractor: {helper.extractor}")

    return accepted


def run_verify_or_derive(args: argparse.Namespace, show_key: bool) -> int:
    if args.key_bytes <= 0:
        raise ValueError("--key-bytes must be positive")
    if args.max_selected_errors < 0:
        raise ValueError("--max-selected-errors must be non-negative")
    if args.max_corrected_error_pct < 0:
        raise ValueError("--max-corrected-error-pct must be non-negative")
    if args.max_codeword_errors < 0:
        raise ValueError("--max-codeword-errors must be non-negative")

    helper = load_helper(args.helper)
    capture = parse_capture(args.capture_log)
    region = detect_region(args.capture_log)
    validate_capture_against_helper(capture, region, helper)

    selected, summary = derive_material_from_capture(capture, helper)
    accepted = print_helper_verification(
        args.capture_log,
        capture,
        helper,
        summary,
        args.max_selected_errors,
        args.max_corrected_error_pct,
        args.max_codeword_errors,
    )
    if accepted:
        key = derive_key(selected, helper.salt, helper.context, args.nonce, args.key_bytes)
        print(f"key_sha256: {hashlib.sha256(key).hexdigest()}")
        if show_key:
            print(f"derived_key_hex: {key.hex()}")
    print(f"verdict: {'ACCEPT' if accepted else 'REJECT'}")
    return 0 if accepted else 1


def run_subcommand(argv: Sequence[str]) -> int:
    parser = subcommand_parser()
    args = parser.parse_args(argv)
    if args.command == "enroll":
        return run_enroll(args)
    if args.command == "verify":
        return run_verify_or_derive(args, show_key=False)
    if args.command == "derive":
        return run_verify_or_derive(args, show_key=args.show_key)
    raise ValueError(f"unsupported command: {args.command}")


def self_test() -> None:
    base_a = bytes([0x55, 0xAA, 0x00, 0xFF] * 64)
    base_b = bytes((index * 37 + 11) & 0xFF for index in range(len(base_a)))
    temp_root = Path("/private/tmp") / "derive-puf-self-test"
    temp_root.mkdir(parents=True, exist_ok=True)
    enroll_log = temp_root / "enroll.log"
    verify_log = temp_root / "verify.log"
    reject_log = temp_root / "reject.log"
    corrupt3_log = temp_root / "corrupt3.log"
    corrupt4_log = temp_root / "corrupt4.log"
    helper_path = temp_root / "helper.json"
    bad_duplicate_helper = temp_root / "bad-duplicate-helper.json"
    bad_truncated_helper = temp_root / "bad-truncated-helper.json"
    bad_size_helper = temp_root / "bad-size-helper.json"

    def write_log(path: Path, base: bytes, samples: int) -> None:
        lines = [f"MPUF_META source=self-test region=RTC_SLOW size={len(base)} samples={samples} mode=raw"]
        for index in range(samples):
            mutable = bytearray(base)
            if index % 9 == 0:
                mutable[0] ^= 0x01
            lines.append(f"MPUF_SAMPLE {index:04d} {bytes(mutable).hex()}")
        lines.append(f"MPUF_DONE samples={samples}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def write_corrupt_log(path: Path, base: bytes, helper: HelperData, codeword_index: int, flips: int) -> None:
        mutable = bytearray(base)
        offset = codeword_index * REPETITION_WIDTH
        for bit_position in helper.selected_positions[offset : offset + flips]:
            byte_index = bit_position // 8
            bit_index = 7 - (bit_position % 8)
            mutable[byte_index] ^= 1 << bit_index
        lines = [f"MPUF_META source=self-test region=RTC_SLOW size={len(base)} samples=40 mode=raw"]
        lines.extend(f"MPUF_SAMPLE {index:04d} {bytes(mutable).hex()}" for index in range(40))
        lines.append("MPUF_DONE samples=40")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    write_log(enroll_log, base_a, 40)
    write_log(verify_log, base_a, 40)
    write_log(reject_log, base_b, 40)

    enroll_args = [
        "enroll",
        str(enroll_log),
        "--helper-out",
        str(helper_path),
        "--bits",
        "128",
        "--threshold",
        "0.9",
        "--extractor",
        REPETITION8_EXTRACTOR,
    ]
    if run_subcommand(enroll_args) != 0:
        raise AssertionError("self-test enroll failed")

    verify_args = [
        "verify",
        str(verify_log),
        "--helper",
        str(helper_path),
    ]
    if run_subcommand(verify_args) != 0:
        raise AssertionError("self-test verify failed")

    reject_args = [
        "verify",
        str(reject_log),
        "--helper",
        str(helper_path),
    ]
    if run_subcommand(reject_args) == 0:
        raise AssertionError("self-test reject unexpectedly passed")

    helper = load_helper(helper_path)
    helper_binary = helper_to_binary(helper)
    helper_roundtrip = helper_from_binary(helper_binary)
    if helper_roundtrip.to_json_payload() != helper.to_json_payload():
        raise AssertionError("self-test helper binary roundtrip failed")

    write_corrupt_log(corrupt3_log, base_a, helper, codeword_index=0, flips=3)
    corrupt3_args = [
        "verify",
        str(corrupt3_log),
        "--helper",
        str(helper_path),
    ]
    if run_subcommand(corrupt3_args) != 0:
        raise AssertionError("self-test 3-bit correction failed")

    write_corrupt_log(corrupt4_log, base_a, helper, codeword_index=0, flips=4)
    corrupt4_args = [
        "verify",
        str(corrupt4_log),
        "--helper",
        str(helper_path),
    ]
    if run_subcommand(corrupt4_args) == 0:
        raise AssertionError("self-test 4-bit ambiguous codeword unexpectedly passed")

    helper_payload = json.loads(helper_path.read_text(encoding="utf-8"))
    helper_payload["selected_positions"][1] = helper_payload["selected_positions"][0]
    bad_duplicate_helper.write_text(json.dumps(helper_payload), encoding="utf-8")
    try:
        load_helper(bad_duplicate_helper)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test duplicate helper unexpectedly loaded")

    helper_payload = json.loads(helper_path.read_text(encoding="utf-8"))
    helper_payload["ecc_data_hex"] = helper_payload["ecc_data_hex"][:-2]
    bad_truncated_helper.write_text(json.dumps(helper_payload), encoding="utf-8")
    try:
        load_helper(bad_truncated_helper)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test truncated helper unexpectedly loaded")

    helper_payload = json.loads(helper_path.read_text(encoding="utf-8"))
    helper_payload["sample_size"] = helper_payload["sample_size"] + 1
    bad_size_helper.write_text(json.dumps(helper_payload), encoding="utf-8")
    bad_size_args = [
        "verify",
        str(verify_log),
        "--helper",
        str(bad_size_helper),
    ]
    try:
        run_subcommand(bad_size_args)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test mismatched sample_size unexpectedly passed")

    print("self-test OK")


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(argv if argv is not None else sys.argv[1:])
    if raw_args and raw_args[0] in {"enroll", "verify", "derive"}:
        return run_subcommand(raw_args)
    return run_legacy(raw_args)


if __name__ == "__main__":
    raise SystemExit(main())
