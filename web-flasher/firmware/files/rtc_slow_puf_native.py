"""
Native RTC SLOW PUF helper for stock MicroPython on ESP32.

This module keeps the PUF protocol on the board: enrollment selects stable
RTC SLOW bits, stores compact repetition8 helper data, and identity derives a
key from a fresh register-cycled sample. It is still a lab module, not the
production security boundary.
"""

try:
    import array as array_module
    import gc
    import os
    import time as time_module
    import ubinascii
    import uhashlib as hashlib
    import rtc_fast_puf_probe as probe
except ImportError as exc:
    raise ImportError("rtc_slow_puf_native must run on ESP32 MicroPython with rtc_fast_puf_probe.py") from exc

try:
    import esp32
except ImportError:
    esp32 = None


MAGIC = b"RSPF"
BINARY_VERSION = 1
EXTRACTOR_REPETITION8 = 2
REGION_RTC_SLOW = 1
REPETITION = 8
HEADER_SIZE = 26
NVS_NAMESPACE = "rtc_puf"
NVS_CHUNK_SIZE = 512
NVS_MAX_CHUNKS = 16
FILE_FALLBACK = "/puf_helper.bin"
DEFAULT_SAMPLES = 1000
DEFAULT_SIZE = 4096
DEFAULT_SELECTED_BITS = 256
DEFAULT_THRESHOLD_PPM = 980000
DEFAULT_SALT = "DID-PUF-RTC-SLOW-v1"
DEFAULT_CONTEXT = "puf_identity_key"
DEFAULT_MAX_CORRECTED_ERROR_PCT = 5.0
DEFAULT_MAX_CODEWORD_ERRORS = 3
DEFAULT_IDENTITY_ATTEMPTS = 5
KEY_BYTES = 32
SELECTION_WINDOWS = 64
CANDIDATE_POOL_PER_WINDOW = 128
SELECTION_SEED = "DID-PUF-RTC-SLOW-select-v1"
SELECTION_MODE = "puflib-like-rtc-slow:distwin-v1"


def _ticks_ms():
    if hasattr(time_module, "ticks_ms"):
        return time_module.ticks_ms()
    return int(time_module.time() * 1000)


def _ticks_diff(end, start):
    if hasattr(time_module, "ticks_diff"):
        return time_module.ticks_diff(end, start)
    return end - start


def _mem_free():
    if hasattr(gc, "mem_free"):
        return gc.mem_free()
    return None


def _u16(value):
    return bytes((value & 0xFF, (value >> 8) & 0xFF))


def _u32(value):
    return bytes((value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF, (value >> 24) & 0xFF))


def _read_u16(data, offset):
    return data[offset] | (data[offset + 1] << 8)


def _read_u32(data, offset):
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)


def _require_size(size):
    if size <= 0 or size % 4:
        raise ValueError("size must be a positive multiple of 4")
    if size > DEFAULT_SIZE:
        raise ValueError("size must be <= 4096 in this lab module")


def _require_threshold(threshold_ppm):
    if threshold_ppm <= 500000 or threshold_ppm > 1000000:
        raise ValueError("threshold_ppm must be > 500000 and <= 1000000")


def _sha256(data):
    digest = hashlib.sha256()
    digest.update(data)
    return digest.digest()


def _sha256_hex(data):
    return ubinascii.hexlify(_sha256(data)).decode()


def _hmac_sha256(key, message):
    if len(key) > 64:
        key = _sha256(key)
    key = key + b"\x00" * (64 - len(key))
    outer = bytes((value ^ 0x5C) for value in key)
    inner = bytes((value ^ 0x36) for value in key)
    return _sha256(outer + _sha256(inner + message))


def _hkdf_sha256(ikm, salt, info, length):
    prk = _hmac_sha256(salt, ikm)
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = _hmac_sha256(prk, previous + info + bytes((counter,)))
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def _info_bytes(context, nonce):
    if nonce and nonce != "-":
        return (context + "\x00" + nonce).encode()
    return context.encode()


def _bit_from_buffer(data, bit_position):
    return (data[bit_position // 8] >> (7 - (bit_position % 8))) & 1


def _set_packed_bit(target, bit_position, bit):
    if bit:
        target[bit_position // 8] |= 1 << (7 - (bit_position % 8))


def _get_count(counts, count_index):
    offset = count_index * 2
    return counts[offset] | (counts[offset + 1] << 8)


def _increment_count(counts, count_index):
    offset = count_index * 2
    count = counts[offset] | (counts[offset + 1] << 8)
    count += 1
    counts[offset] = count & 0xFF
    counts[offset + 1] = (count >> 8) & 0xFF


def _fnv1a32(text):
    value = 0x811C9DC5
    for byte in text.encode():
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
    return value


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _candidate_position(window_index, order, bit_total, selection_seed=SELECTION_SEED):
    start = window_index * bit_total // SELECTION_WINDOWS
    end = (window_index + 1) * bit_total // SELECTION_WINDOWS
    window_bits = end - start
    if window_bits <= 0:
        raise ValueError("selection window has no bits")

    seed = _fnv1a32("{}|{}".format(selection_seed, window_index))
    candidate_count = min(order, window_bits - 1)
    start_offset = seed % window_bits
    stride = ((seed >> 9) % window_bits) or 1
    if stride % 2 == 0:
        stride = (stride + 1) % window_bits or 1
    while _gcd(stride, window_bits) != 1:
        stride = (stride + 2) % window_bits or 1
    return start + ((start_offset + candidate_count * stride) % window_bits)


def _candidate_count_index(window_index, order):
    return window_index * CANDIDATE_POOL_PER_WINDOW + order


def _candidate_total(bit_total):
    total = 0
    for window_index in range(SELECTION_WINDOWS):
        start = window_index * bit_total // SELECTION_WINDOWS
        end = (window_index + 1) * bit_total // SELECTION_WINDOWS
        window_bits = end - start
        total += min(CANDIDATE_POOL_PER_WINDOW, window_bits)
    return total


def _candidate_tables(bit_total, selection_seed=SELECTION_SEED):
    byte_indexes = array_module.array("H")
    bit_masks = array_module.array("B")
    total_candidates = SELECTION_WINDOWS * CANDIDATE_POOL_PER_WINDOW
    for _index in range(total_candidates):
        byte_indexes.append(0)
        bit_masks.append(0)
    for window_index in range(SELECTION_WINDOWS):
        start = window_index * bit_total // SELECTION_WINDOWS
        end = (window_index + 1) * bit_total // SELECTION_WINDOWS
        window_bits = end - start
        pool = min(CANDIDATE_POOL_PER_WINDOW, window_bits)
        for order in range(pool):
            index = _candidate_count_index(window_index, order)
            position = _candidate_position(window_index, order, bit_total, selection_seed)
            byte_indexes[index] = position // 8
            bit_masks[index] = 1 << (7 - (position % 8))
    return byte_indexes, bit_masks


def _add_candidate_counts(counts, sample, bit_total, byte_indexes, bit_masks):
    if bit_total // SELECTION_WINDOWS >= CANDIDATE_POOL_PER_WINDOW:
        counts_local = counts
        sample_local = sample
        byte_indexes_local = byte_indexes
        bit_masks_local = bit_masks
        for index in range(SELECTION_WINDOWS * CANDIDATE_POOL_PER_WINDOW):
            if sample_local[byte_indexes_local[index]] & bit_masks_local[index]:
                counts_local[index] += 1
        return
    for window_index in range(SELECTION_WINDOWS):
        start = window_index * bit_total // SELECTION_WINDOWS
        end = (window_index + 1) * bit_total // SELECTION_WINDOWS
        window_bits = end - start
        pool = min(CANDIDATE_POOL_PER_WINDOW, window_bits)
        for order in range(pool):
            index = _candidate_count_index(window_index, order)
            if sample[byte_indexes[index]] & bit_masks[index]:
                counts[index] += 1


def _select_distributed_positions(counts, samples, bit_total, needed, threshold_ppm, selection_seed=SELECTION_SEED):
    if needed < SELECTION_WINDOWS:
        raise ValueError("needed positions must be at least selection window count")
    upper = (samples * threshold_ppm + 999999) // 1000000
    lower = (samples * (1000000 - threshold_ppm)) // 1000000
    base_quota = needed // SELECTION_WINDOWS
    remainder = needed % SELECTION_WINDOWS
    positions = []
    masked_reference = bytearray((needed + 7) // 8)

    for window_index in range(SELECTION_WINDOWS):
        start = window_index * bit_total // SELECTION_WINDOWS
        end = (window_index + 1) * bit_total // SELECTION_WINDOWS
        window_bits = end - start
        pool = min(CANDIDATE_POOL_PER_WINDOW, window_bits)
        quota = base_quota + (1 if window_index < remainder else 0)
        candidates = []

        for order in range(pool):
            count = counts[_candidate_count_index(window_index, order)]
            if count < upper and count > lower:
                continue
            errors = min(count, samples - count)
            bias = abs(count * 2 - samples)
            position = _candidate_position(window_index, order, bit_total, selection_seed)
            candidates.append((errors, -bias, order, position, count))

        candidates.sort()
        if len(candidates) < quota:
            raise ValueError(
                "selection window {} has only {} stable candidate positions, need {}".format(
                    window_index,
                    len(candidates),
                    quota,
                )
            )
        for candidate in candidates[:quota]:
            output_index = len(positions)
            positions.append(candidate[3])
            if candidate[4] * 2 > samples:
                _set_packed_bit(masked_reference, output_index, 1)

    if len(positions) != needed:
        raise ValueError("selection produced {} positions, need {}".format(len(positions), needed))
    return positions, bytes(masked_reference)


def _enroll_distributed(samples, size, needed, threshold_ppm, sleep_us, settle_us, gc_interval, selection_seed=SELECTION_SEED):
    bit_total = size * 8
    if bit_total < SELECTION_WINDOWS:
        raise ValueError("sample is too small for distributed-window-v1")
    byte_indexes, bit_masks = _candidate_tables(bit_total, selection_seed)
    counts = array_module.array("H")
    total_candidates = SELECTION_WINDOWS * CANDIDATE_POOL_PER_WINDOW
    for _index in range(total_candidates):
        counts.append(0)
    metrics = {
        "sample_ms_total": 0,
        "count_ms_total": 0,
        "select_ms_total": 0,
        "candidate_count": _candidate_total(bit_total),
        "gc_interval": gc_interval,
    }
    for index in range(samples):
        sample_start = _ticks_ms()
        sample = probe.sample_slow(size=size, sleep_us=sleep_us, settle_us=settle_us)
        metrics["sample_ms_total"] += _ticks_diff(_ticks_ms(), sample_start)
        count_start = _ticks_ms()
        _add_candidate_counts(counts, sample, bit_total, byte_indexes, bit_masks)
        metrics["count_ms_total"] += _ticks_diff(_ticks_ms(), count_start)
        if gc_interval and index % gc_interval == gc_interval - 1:
            gc.collect()
    del sample
    byte_indexes = None
    bit_masks = None
    gc.collect()
    select_start = _ticks_ms()
    positions, masked_reference = _select_distributed_positions(
        counts,
        samples,
        bit_total,
        needed,
        threshold_ppm,
        selection_seed,
    )
    metrics["select_ms_total"] = _ticks_diff(_ticks_ms(), select_start)
    total_ms = metrics["sample_ms_total"] + metrics["count_ms_total"] + metrics["select_ms_total"]
    metrics["enroll_ms_total"] = total_ms
    metrics["samples_per_second"] = samples * 1000 / total_ms if total_ms else 0
    count_ms = metrics["count_ms_total"]
    candidate_checks = samples * metrics["candidate_count"]
    metrics["candidate_checks_per_second"] = candidate_checks * 1000 / count_ms if count_ms else 0
    return positions, masked_reference, metrics


def _selected_bits_from_sample(sample, positions):
    packed = bytearray((len(positions) + 7) // 8)
    for index, bit_position in enumerate(positions):
        _set_packed_bit(packed, index, _bit_from_buffer(sample, bit_position))
    return bytes(packed)


def selection_fingerprint(size=DEFAULT_SIZE, selected_bits=DEFAULT_SELECTED_BITS):
    """Return a deterministic fingerprint of the candidate table, without sampling PUF data."""
    _require_size(size)
    bit_total = size * 8
    payload = bytearray()
    for window_index in range(SELECTION_WINDOWS):
        start = window_index * bit_total // SELECTION_WINDOWS
        end = (window_index + 1) * bit_total // SELECTION_WINDOWS
        window_bits = end - start
        pool = min(CANDIDATE_POOL_PER_WINDOW, window_bits)
        for order in range(pool):
            payload.extend(_u16(_candidate_position(window_index, order, bit_total, SELECTION_SEED)))
    return {
        "selection_policy": "distributed-window-v1",
        "selection_seed": SELECTION_SEED,
        "selection_seed_public": True,
        "selection_windows": SELECTION_WINDOWS,
        "candidate_pool_per_window": CANDIDATE_POOL_PER_WINDOW,
        "candidate_count": _candidate_total(bit_total),
        "table_sha256": _sha256_hex(bytes(payload)),
    }


def _generate_repetition8_ecc(masked_reference):
    ecc = bytearray(len(masked_reference))
    for index, value in enumerate(masked_reference):
        ecc[index] = (~value & 0xFF) if value & 0x80 else value
    return bytes(ecc)


def _majority(codeword):
    ones = 0
    value = codeword
    while value:
        ones += value & 1
        value >>= 1
    if ones > 4:
        return 1, 8 - ones
    if ones < 4:
        return 0, ones
    return None, ones


def _reconstruct(masked_data, ecc_data):
    if len(masked_data) != len(ecc_data):
        raise ValueError("masked data and ECC data lengths differ")
    corrected = bytearray((len(masked_data) + 7) // 8)
    total_errors = 0
    max_errors = 0
    uncertain = 0
    for index in range(len(masked_data)):
        bit, errors = _majority(masked_data[index] ^ ecc_data[index])
        total_errors += errors
        if errors > max_errors:
            max_errors = errors
        if bit is None:
            uncertain += 1
        else:
            _set_packed_bit(corrected, index, bit)
    bit_total = len(masked_data) * 8
    return bytes(corrected), {
        "corrected_bit_errors_total": total_errors,
        "corrected_bit_errors_pct": total_errors * 100 / bit_total if bit_total else 0,
        "max_errors_per_codeword": max_errors,
        "uncertain_codewords": uncertain,
    }


def _add_material_counts(counts, material, selected_bits):
    for bit_position in range(selected_bits):
        if _bit_from_buffer(material, bit_position):
            offset = bit_position * 2
            count = counts[offset] | (counts[offset + 1] << 8)
            count += 1
            counts[offset] = count & 0xFF
            counts[offset + 1] = (count >> 8) & 0xFF


def _material_from_counts(counts, attempts, selected_bits):
    material = bytearray((selected_bits + 7) // 8)
    tie_bits = 0
    half = attempts / 2
    for bit_position in range(selected_bits):
        count = _get_count(counts, bit_position)
        if count > half:
            _set_packed_bit(material, bit_position, 1)
        elif count == half:
            tie_bits += 1
    return bytes(material), tie_bits


def _pack_helper(
    sample_size,
    threshold_ppm,
    selected_bits,
    positions,
    ecc_data,
    salt,
    context,
    mode,
):
    salt_bytes = salt.encode()
    context_bytes = context.encode()
    mode_bytes = mode.encode()
    if len(positions) != selected_bits * REPETITION:
        raise ValueError("positions length must equal selected_bits * 8")
    entry_count = len(positions)
    for position in positions:
        if position < 0 or position >= sample_size * 8:
            raise ValueError("selected position is out of bounds")
    if len(ecc_data) != selected_bits:
        raise ValueError("ecc_data length must equal selected_bits")
    if len(salt_bytes) > 65535 or len(context_bytes) > 65535 or len(mode_bytes) > 65535:
        raise ValueError("helper text fields are too long")
    payload_len = (
        HEADER_SIZE
        + len(salt_bytes)
        + len(context_bytes)
        + len(mode_bytes)
        + (entry_count * 2)
        + len(ecc_data)
    )
    payload = bytearray(payload_len)
    offset = 0
    payload[offset : offset + 4] = MAGIC
    offset += 4
    payload[offset] = BINARY_VERSION
    payload[offset + 1] = EXTRACTOR_REPETITION8
    payload[offset + 2] = REGION_RTC_SLOW
    payload[offset + 3] = REPETITION
    offset += 4
    for field in (
        _u16(sample_size),
        _u32(threshold_ppm),
        _u16(selected_bits),
        _u16(entry_count),
        _u16(len(ecc_data)),
        _u16(len(salt_bytes)),
        _u16(len(context_bytes)),
        _u16(len(mode_bytes)),
    ):
        payload[offset : offset + len(field)] = field
        offset += len(field)
    for field in (salt_bytes, context_bytes, mode_bytes):
        payload[offset : offset + len(field)] = field
        offset += len(field)
    for position in positions:
        field = _u16(position)
        payload[offset : offset + 2] = field
        offset += 2
    payload[offset : offset + len(ecc_data)] = ecc_data
    return payload


def _unpack_helper(payload):
    if len(payload) < HEADER_SIZE:
        raise ValueError("helper payload is truncated")
    if payload[:4] != MAGIC:
        raise ValueError("helper payload has invalid magic")
    version = payload[4]
    extractor = payload[5]
    region = payload[6]
    repetition = payload[7]
    sample_size = _read_u16(payload, 8)
    threshold_ppm = _read_u32(payload, 10)
    selected_bits = _read_u16(payload, 14)
    positions_count = _read_u16(payload, 16)
    ecc_len = _read_u16(payload, 18)
    salt_len = _read_u16(payload, 20)
    context_len = _read_u16(payload, 22)
    mode_len = _read_u16(payload, 24)
    if version != BINARY_VERSION or extractor != EXTRACTOR_REPETITION8:
        raise ValueError("unsupported helper version or extractor")
    if region != REGION_RTC_SLOW or repetition != REPETITION:
        raise ValueError("helper is not RTC_SLOW repetition8")
    _require_size(sample_size)
    _require_threshold(threshold_ppm)
    if selected_bits <= 0 or positions_count != selected_bits * REPETITION or ecc_len != selected_bits:
        raise ValueError("helper counts are inconsistent")

    cursor = HEADER_SIZE
    expected = cursor + salt_len + context_len + mode_len + positions_count * 2 + ecc_len
    if len(payload) != expected:
        raise ValueError("helper payload length mismatch")
    salt = payload[cursor : cursor + salt_len].decode()
    cursor += salt_len
    context = payload[cursor : cursor + context_len].decode()
    cursor += context_len
    mode = payload[cursor : cursor + mode_len].decode()
    cursor += mode_len
    positions = []
    seen = set()
    for _index in range(positions_count):
        position = _read_u16(payload, cursor)
        cursor += 2
        if position >= sample_size * 8 or position in seen:
            raise ValueError("helper selected position is invalid")
        positions.append(position)
        seen.add(position)
    ecc_data = payload[cursor : cursor + ecc_len]
    return {
        "version": version,
        "sample_size": sample_size,
        "threshold_ppm": threshold_ppm,
        "selected_bits": selected_bits,
        "positions": positions,
        "ecc_data": ecc_data,
        "salt": salt,
        "context": context,
        "mode": mode,
    }


def _resolve_helper_positions(helper):
    return helper["positions"]


def _nvs():
    if esp32 is None:
        raise OSError("esp32.NVS is unavailable")
    return esp32.NVS(NVS_NAMESPACE)


def _nvs_get_blob(ns, key, size):
    buf = bytearray(size)
    try:
        used = ns.get_blob(key, buf)
    except TypeError:
        data = ns.get_blob(key)
        return bytes(data)
    if used is None:
        return bytes(buf)
    return bytes(buf[:used])


def _store_nvs(payload):
    ns = _nvs()
    chunks = (len(payload) + NVS_CHUNK_SIZE - 1) // NVS_CHUNK_SIZE
    if chunks > NVS_MAX_CHUNKS:
        raise OSError("helper exceeds NVS chunk budget")
    ns.set_i32("len", len(payload))
    ns.set_i32("chunks", chunks)
    for index in range(chunks):
        chunk = payload[index * NVS_CHUNK_SIZE : (index + 1) * NVS_CHUNK_SIZE]
        ns.set_blob("h{:02d}".format(index), chunk)
    for index in range(chunks, NVS_MAX_CHUNKS):
        try:
            ns.erase_key("h{:02d}".format(index))
        except OSError:
            pass
    ns.commit()


def _load_nvs():
    ns = _nvs()
    length = ns.get_i32("len")
    chunks = ns.get_i32("chunks")
    if length <= 0 or chunks <= 0 or chunks > NVS_MAX_CHUNKS:
        raise OSError("invalid NVS helper metadata")
    out = bytearray()
    for index in range(chunks):
        expected = min(NVS_CHUNK_SIZE, length - len(out))
        out.extend(_nvs_get_blob(ns, "h{:02d}".format(index), expected))
    return bytes(out[:length])


def _erase_nvs():
    ns = _nvs()
    for key in ("len", "chunks"):
        try:
            ns.erase_key(key)
        except OSError:
            pass
    for index in range(NVS_MAX_CHUNKS):
        try:
            ns.erase_key("h{:02d}".format(index))
        except OSError:
            pass
    ns.commit()


def _store_file(payload):
    with open(FILE_FALLBACK, "wb") as handle:
        handle.write(payload)


def _load_file():
    with open(FILE_FALLBACK, "rb") as handle:
        return handle.read()


def _erase_file():
    try:
        os.remove(FILE_FALLBACK)
    except OSError:
        pass


def _store_helper(payload, validate=True):
    if validate:
        _unpack_helper(payload)
    try:
        _store_nvs(payload)
        _erase_file()
        return "nvs"
    except Exception:
        _store_file(payload)
        return "file"


def _load_helper_payload():
    try:
        payload = _load_nvs()
        return payload, "nvs"
    except Exception:
        payload = _load_file()
        return payload, "file"


def _load_helper():
    payload, storage = _load_helper_payload()
    helper = _unpack_helper(payload)
    helper["storage"] = storage
    return helper


def erase_helper():
    """Erase helper data from NVS and the file fallback."""
    try:
        _erase_nvs()
    except Exception:
        pass
    _erase_file()
    return {"erased": True}


def status():
    """Return whether a puflib-like RTC SLOW helper is enrolled on this ESP32."""
    try:
        payload, storage = _load_helper_payload()
        helper = _unpack_helper(payload)
    except Exception as exc:
        return {"enrolled": False, "error": str(exc)}
    return {
        "enrolled": True,
        "storage": storage,
        "region": "RTC_SLOW",
        "sample_size": helper["sample_size"],
        "threshold_ppm": helper["threshold_ppm"],
        "selected_bits": helper["selected_bits"],
        "selected_positions": len(helper["positions"]),
        "repetition": REPETITION,
        "mode": helper["mode"],
        "selection_seed": SELECTION_SEED if "distwin-v1" in helper["mode"] else "",
        "selection_seed_public": True,
        "selection_windows": SELECTION_WINDOWS if "distwin-v1" in helper["mode"] else 0,
        "candidate_pool_per_window": CANDIDATE_POOL_PER_WINDOW if "distwin-v1" in helper["mode"] else 0,
        "helper_sha256": _sha256_hex(payload),
    }


def enroll(
    samples=DEFAULT_SAMPLES,
    size=DEFAULT_SIZE,
    selected_bits=DEFAULT_SELECTED_BITS,
    threshold_ppm=DEFAULT_THRESHOLD_PPM,
    sleep_us=probe.DEFAULT_POWER_OFF_US,
    settle_us=probe.DEFAULT_SETTLE_US,
    salt=DEFAULT_SALT,
    context=DEFAULT_CONTEXT,
    gc_interval=50,
):
    """Enroll RTC SLOW helper data on the device and store it persistently."""
    _require_size(size)
    _require_threshold(threshold_ppm)
    if samples <= 0 or samples > 65535:
        raise ValueError("samples must be between 1 and 65535")
    if selected_bits <= 0:
        raise ValueError("selected_bits must be positive")
    if gc_interval < 0:
        raise ValueError("gc_interval must be non-negative")

    needed = selected_bits * REPETITION
    mode = SELECTION_MODE
    mem_before = _mem_free()
    positions, masked_reference, perf = _enroll_distributed(
        samples,
        size,
        needed,
        threshold_ppm,
        sleep_us,
        settle_us,
        gc_interval,
        SELECTION_SEED,
    )
    mem_after = _mem_free()
    ecc_data = _generate_repetition8_ecc(masked_reference)
    payload = _pack_helper(
        size,
        threshold_ppm,
        selected_bits,
        positions,
        ecc_data,
        salt,
        context,
        mode,
    )
    material, summary = _reconstruct(masked_reference, ecc_data)
    selected_positions_count = len(positions)
    del positions
    del masked_reference
    del ecc_data
    gc.collect()
    storage = _store_helper(payload, validate=False)
    key = _hkdf_sha256(material, salt.encode(), _info_bytes(context, ""), KEY_BYTES)
    summary.update(
        {
            "enrolled": True,
            "storage": storage,
            "samples": samples,
            "sample_size": size,
            "selected_bits": selected_bits,
            "selected_positions": selected_positions_count,
            "mode": mode,
            "selection_seed": SELECTION_SEED,
            "selection_seed_public": True,
            "selection_windows": SELECTION_WINDOWS,
            "candidate_pool_per_window": CANDIDATE_POOL_PER_WINDOW,
            "helper_sha256": _sha256_hex(payload),
            "key_sha256": _sha256_hex(key),
        }
    )
    summary.update(perf)
    if mem_before is not None:
        summary["mem_free_before"] = mem_before
    if mem_after is not None:
        summary["mem_free_after"] = mem_after
    return summary


def _identity_material(size, sleep_us, settle_us, attempts):
    if attempts <= 0 or attempts > 65535:
        raise ValueError("attempts must be between 1 and 65535")
    helper = _load_helper()
    if size is None:
        size = helper["sample_size"]
    if size != helper["sample_size"]:
        raise ValueError("requested size does not match helper sample_size")
    positions = _resolve_helper_positions(helper)
    counts = bytearray(helper["selected_bits"] * 2)
    summary = {
        "corrected_bit_errors_total": 0,
        "corrected_bit_errors_pct": 0,
        "max_errors_per_codeword": 0,
        "uncertain_codewords": 0,
        "attempts": attempts,
    }
    for _index in range(attempts):
        sample = probe.sample_slow(size=size, sleep_us=sleep_us, settle_us=settle_us)
        masked = _selected_bits_from_sample(sample, positions)
        material_once, one_summary = _reconstruct(masked, helper["ecc_data"])
        _add_material_counts(counts, material_once, helper["selected_bits"])
        summary["corrected_bit_errors_total"] += one_summary["corrected_bit_errors_total"]
        if one_summary["max_errors_per_codeword"] > summary["max_errors_per_codeword"]:
            summary["max_errors_per_codeword"] = one_summary["max_errors_per_codeword"]
        summary["uncertain_codewords"] += one_summary["uncertain_codewords"]
        if _index % 5 == 4:
            gc.collect()
    material, tie_bits = _material_from_counts(counts, attempts, helper["selected_bits"])
    bit_total = helper["selected_bits"] * REPETITION * attempts
    summary["corrected_bit_errors_pct"] = summary["corrected_bit_errors_total"] * 100 / bit_total if bit_total else 0
    summary["material_tie_bits"] = tie_bits
    return helper, material, summary


def identity(
    size=None,
    nonce="",
    sleep_us=probe.DEFAULT_POWER_OFF_US,
    settle_us=probe.DEFAULT_SETTLE_US,
    attempts=DEFAULT_IDENTITY_ATTEMPTS,
    max_corrected_error_pct=DEFAULT_MAX_CORRECTED_ERROR_PCT,
    max_codeword_errors=DEFAULT_MAX_CODEWORD_ERRORS,
):
    """Report identity status, releasing a key hash only after acceptance."""
    helper, material, summary = _identity_material(size, sleep_us, settle_us, attempts)
    accepted = (
        summary["uncertain_codewords"] == 0
        and summary["material_tie_bits"] == 0
        and summary["max_errors_per_codeword"] <= max_codeword_errors
        and summary["corrected_bit_errors_pct"] <= max_corrected_error_pct
    )
    summary.update(
        {
            "accepted": accepted,
            "storage": helper["storage"],
            "sample_size": helper["sample_size"],
            "selected_bits": helper["selected_bits"],
        }
    )
    if accepted:
        key = _hkdf_sha256(material, helper["salt"].encode(), _info_bytes(helper["context"], nonce), KEY_BYTES)
        summary["key_sha256"] = _sha256_hex(key)
    return summary


def derive_key(nonce="", size=None):
    """Return the raw derived key to trusted firmware code. REPL callers should use identity()."""
    helper, material, summary = _identity_material(
        size,
        probe.DEFAULT_POWER_OFF_US,
        probe.DEFAULT_SETTLE_US,
        DEFAULT_IDENTITY_ATTEMPTS,
    )
    if (
        summary["uncertain_codewords"] != 0
        or summary["material_tie_bits"] != 0
        or summary["max_errors_per_codeword"] > DEFAULT_MAX_CODEWORD_ERRORS
    ):
        raise ValueError("PUF reconstruction did not pass default acceptance policy")
    return _hkdf_sha256(material, helper["salt"].encode(), _info_bytes(helper["context"], nonce), KEY_BYTES)


def export_helper_hex():
    """Return the compact helper as hex for host-side JSON export."""
    payload, _storage = _load_helper_payload()
    _unpack_helper(payload)
    return ubinascii.hexlify(payload).decode()


def import_helper_hex(hex_payload):
    """Import compact helper hex generated by the host runner."""
    payload = ubinascii.unhexlify(hex_payload)
    helper = _unpack_helper(payload)
    storage = _store_helper(payload)
    return {
        "imported": True,
        "storage": storage,
        "sample_size": helper["sample_size"],
        "selected_bits": helper["selected_bits"],
        "selected_positions": len(helper["positions"]),
        "mode": helper["mode"],
        "selection_seed": SELECTION_SEED if "distwin-v1" in helper["mode"] else "",
        "selection_seed_public": True,
        "selection_windows": SELECTION_WINDOWS if "distwin-v1" in helper["mode"] else 0,
        "candidate_pool_per_window": CANDIDATE_POOL_PER_WINDOW if "distwin-v1" in helper["mode"] else 0,
        "helper_sha256": _sha256_hex(payload),
    }
