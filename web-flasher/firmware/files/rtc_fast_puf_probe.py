"""
RTC FAST SRAM PUF probe for stock MicroPython on ESP32.

This file is a laboratory probe, not production firmware. It tries to answer
one narrow question: can stock MicroPython read enough power-up randomness from
RTC FAST SRAM, through machine.mem32, to build a usable memory PUF without a C
module or deep-sleep wake stub?

Run it manually from the REPL. Do not install it as boot.py or main.py.
"""

try:
    import machine
    import time
    import ubinascii
    import gc
except ImportError as exc:
    raise ImportError("This probe must run on MicroPython for ESP32") from exc


# These constants match ESP32, not ESP32-S2/S3/C3.
RTC_FAST_BASE = 0x3FF80000
RTC_SLOW_BASE = 0x50000000
RTC_CNTL_PWC_REG = 0x3FF48080

DEFAULT_REGION_SIZE = 0x1000
DEFAULT_POWER_OFF_US = 10000
DEFAULT_SETTLE_US = 10000

FAST_FORCE_NOISO = 1 << 0
FAST_FORCE_ISO = 1 << 1
FAST_FORCE_PD = 1 << 12
FAST_FORCE_PU = 1 << 13

SLOW_FORCE_NOISO = 1 << 2
SLOW_FORCE_ISO = 1 << 3
SLOW_FORCE_PD = 1 << 15
SLOW_FORCE_PU = 1 << 16

WORD_SIZE = 4
AGGREGATE_CHUNK_COUNTS = 512


def _require_aligned_size(size):
    if size <= 0:
        raise ValueError("size must be positive")
    if size % WORD_SIZE != 0:
        raise ValueError("size must be a multiple of 4 bytes")


def _read_words(base, size):
    _require_aligned_size(size)
    words = size // WORD_SIZE
    out = bytearray(size)
    offset = 0
    for index in range(words):
        value = machine.mem32[base + index * WORD_SIZE]
        out[offset] = value & 0xFF
        out[offset + 1] = (value >> 8) & 0xFF
        out[offset + 2] = (value >> 16) & 0xFF
        out[offset + 3] = (value >> 24) & 0xFF
        offset += WORD_SIZE
    return out


def _write_words(base, data):
    if len(data) % WORD_SIZE != 0:
        raise ValueError("data length must be a multiple of 4 bytes")
    words = len(data) // WORD_SIZE
    offset = 0
    for index in range(words):
        value = (
            data[offset]
            | (data[offset + 1] << 8)
            | (data[offset + 2] << 16)
            | (data[offset + 3] << 24)
        )
        machine.mem32[base + index * WORD_SIZE] = value
        offset += WORD_SIZE


def _hamming_weight(data):
    total = 0
    for value in data:
        total += bin(value).count("1")
    return total


def _hamming_distance(left, right):
    if len(left) != len(right):
        raise ValueError("buffers must have equal length")
    total = 0
    for index in range(len(left)):
        total += bin(left[index] ^ right[index]).count("1")
    return total


def _force_memory_cycle(power_down_mask, power_up_mask, sleep_us, settle_us):
    """Power-cycle one RTC memory domain while preserving unrelated PWC bits."""
    state = machine.disable_irq()
    try:
        value = machine.mem32[RTC_CNTL_PWC_REG]
        machine.mem32[RTC_CNTL_PWC_REG] = (value & ~power_up_mask) | power_down_mask
        time.sleep_us(sleep_us)

        value = machine.mem32[RTC_CNTL_PWC_REG]
        machine.mem32[RTC_CNTL_PWC_REG] = (value & ~power_down_mask) | power_up_mask
        time.sleep_us(settle_us)
    finally:
        machine.enable_irq(state)


def _cycle_fast(sleep_us, settle_us):
    power_down = FAST_FORCE_PD | FAST_FORCE_ISO
    power_up = FAST_FORCE_PU | FAST_FORCE_NOISO
    _force_memory_cycle(power_down, power_up, sleep_us, settle_us)


def _cycle_slow(sleep_us, settle_us):
    power_down = SLOW_FORCE_PD | SLOW_FORCE_ISO
    power_up = SLOW_FORCE_PU | SLOW_FORCE_NOISO
    _force_memory_cycle(power_down, power_up, sleep_us, settle_us)


def read_fast(size=DEFAULT_REGION_SIZE):
    """Read bytes from ESP32 RTC FAST SRAM."""
    return _read_words(RTC_FAST_BASE, size)


def read_slow(size=DEFAULT_REGION_SIZE):
    """Read bytes from ESP32 RTC SLOW SRAM. This is more likely to be runtime-used."""
    return _read_words(RTC_SLOW_BASE, size)


def sample_fast(size=DEFAULT_REGION_SIZE, sleep_us=DEFAULT_POWER_OFF_US, settle_us=DEFAULT_SETTLE_US):
    """
    Capture one RTC FAST sample after a forced RTC FAST power cycle.

    The previous memory contents are restored after the sample. This mirrors the
    non-deep-sleep method used by esp32_puflib, but from stock MicroPython.
    """
    backup = read_fast(size)
    _cycle_fast(sleep_us, settle_us)
    sample = read_fast(size)
    _write_words(RTC_FAST_BASE, backup)
    return sample


def sample_slow(size=DEFAULT_REGION_SIZE, sleep_us=DEFAULT_POWER_OFF_US, settle_us=DEFAULT_SETTLE_US):
    """
    Capture one RTC SLOW sample after a forced RTC SLOW power cycle.

    RTC SLOW is intentionally a fallback. It may be used by firmware, ULP, or
    MicroPython support code, so contamination is more likely than with FAST.
    """
    backup = read_slow(size)
    _cycle_slow(sleep_us, settle_us)
    sample = read_slow(size)
    _write_words(RTC_SLOW_BASE, backup)
    return sample


def smoke_fast(size=256):
    """
    Confirm basic read, backup, forced power cycle, and restore on RTC FAST.

    Returns a dictionary with Hamming metrics that can be inspected from REPL.
    """
    before = read_fast(size)
    sample = sample_fast(size)
    after = read_fast(size)
    bit_count = size * 8
    return {
        "size": size,
        "before_weight_pct": round(_hamming_weight(before) * 100 / bit_count, 3),
        "sample_weight_pct": round(_hamming_weight(sample) * 100 / bit_count, 3),
        "restore_distance": _hamming_distance(before, after),
        "before_sample_distance_pct": round(_hamming_distance(before, sample) * 100 / bit_count, 3),
    }


def _print_sample(prefix, index, data):
    print(prefix, "{:04d}".format(index), ubinascii.hexlify(data).decode())


def _new_count_array(bit_count):
    try:
        return bytearray(bit_count * 2)
    except MemoryError as exc:
        raise MemoryError(
            "not enough heap for aggregate counters; use raw mode or reduce --size"
        ) from exc


def _add_counts(counts, sample):
    byte_index = 0
    for value in sample:
        offset = byte_index * 16
        if value & 0x80:
            count = counts[offset] | (counts[offset + 1] << 8)
            count += 1
            counts[offset] = count & 0xFF
            counts[offset + 1] = (count >> 8) & 0xFF
        if value & 0x40:
            target = offset + 2
            count = counts[target] | (counts[target + 1] << 8)
            count += 1
            counts[target] = count & 0xFF
            counts[target + 1] = (count >> 8) & 0xFF
        if value & 0x20:
            target = offset + 4
            count = counts[target] | (counts[target + 1] << 8)
            count += 1
            counts[target] = count & 0xFF
            counts[target + 1] = (count >> 8) & 0xFF
        if value & 0x10:
            target = offset + 6
            count = counts[target] | (counts[target + 1] << 8)
            count += 1
            counts[target] = count & 0xFF
            counts[target + 1] = (count >> 8) & 0xFF
        if value & 0x08:
            target = offset + 8
            count = counts[target] | (counts[target + 1] << 8)
            count += 1
            counts[target] = count & 0xFF
            counts[target + 1] = (count >> 8) & 0xFF
        if value & 0x04:
            target = offset + 10
            count = counts[target] | (counts[target + 1] << 8)
            count += 1
            counts[target] = count & 0xFF
            counts[target + 1] = (count >> 8) & 0xFF
        if value & 0x02:
            target = offset + 12
            count = counts[target] | (counts[target + 1] << 8)
            count += 1
            counts[target] = count & 0xFF
            counts[target + 1] = (count >> 8) & 0xFF
        if value & 0x01:
            target = offset + 14
            count = counts[target] | (counts[target + 1] << 8)
            count += 1
            counts[target] = count & 0xFF
            counts[target + 1] = (count >> 8) & 0xFF
        byte_index += 1


def _print_counts16_chunks(counts, chunk_counts=AGGREGATE_CHUNK_COUNTS):
    chunk_index = 0
    bit_offset = 0
    total = len(counts) // 2
    while bit_offset < total:
        count_count = min(chunk_counts, total - bit_offset)
        payload = counts[bit_offset * 2 : (bit_offset + count_count) * 2]
        print(
            "MPUF_COUNTS16_CHUNK {} {} {} {}".format(
                chunk_index,
                bit_offset,
                count_count,
                ubinascii.hexlify(payload).decode(),
            )
        )
        chunk_index += 1
        bit_offset += count_count
    return chunk_index


def capture_fast(samples=100, size=DEFAULT_REGION_SIZE, sleep_us=DEFAULT_POWER_OFF_US, settle_us=DEFAULT_SETTLE_US):
    """
    Print RTC FAST samples as line-oriented hex for host-side analysis.

    Output format:
      MPUF_META region=RTC_FAST ...
      MPUF_SAMPLE 0000 <hex>
      MPUF_DONE samples=N
    """
    _require_aligned_size(size)
    print(
        "MPUF_META region=RTC_FAST size={} samples={} sleep_us={} settle_us={}".format(
            size, samples, sleep_us, settle_us
        )
    )
    for index in range(samples):
        sample = sample_fast(size, sleep_us, settle_us)
        _print_sample("MPUF_SAMPLE", index, sample)
        if index % 10 == 9:
            gc.collect()
    print("MPUF_DONE samples={}".format(samples))


def capture_slow(samples=100, size=DEFAULT_REGION_SIZE, sleep_us=DEFAULT_POWER_OFF_US, settle_us=DEFAULT_SETTLE_US):
    """
    Print RTC SLOW samples as line-oriented hex.

    Use this only after RTC FAST has failed or proved too contaminated.
    """
    _require_aligned_size(size)
    print(
        "MPUF_META region=RTC_SLOW size={} samples={} sleep_us={} settle_us={}".format(
            size, samples, sleep_us, settle_us
        )
    )
    for index in range(samples):
        sample = sample_slow(size, sleep_us, settle_us)
        _print_sample("MPUF_SAMPLE", index, sample)
        if index % 10 == 9:
            gc.collect()
    print("MPUF_DONE samples={}".format(samples))


def capture_slow_aggregate(samples=100, size=DEFAULT_REGION_SIZE, sleep_us=DEFAULT_POWER_OFF_US, settle_us=DEFAULT_SETTLE_US):
    """
    Print compact per-bit counts for RTC SLOW samples.

    The host can reconstruct the stable mask and majority reference without
    receiving every raw sample. Complexity: O(samples * size * 8) time,
    O(size * 8 * uint16) counter space.
    """
    _require_aligned_size(size)
    if samples <= 0:
        raise ValueError("samples must be positive")
    if samples > 65535:
        raise ValueError("aggregate mode uses uint16 counters; samples must be <= 65535")

    counts = _new_count_array(size * 8)
    print(
        "MPUF_AGG_META region=RTC_SLOW size={} samples={} count_width=16 endian=little sleep_us={} settle_us={}".format(
            size, samples, sleep_us, settle_us
        )
    )
    for index in range(samples):
        sample = sample_slow(size, sleep_us, settle_us)
        _add_counts(counts, sample)
        if index % 25 == 24:
            print("MPUF_AGG_PROGRESS samples={}".format(index + 1))
        if index % 10 == 9:
            gc.collect()
    chunks = _print_counts16_chunks(counts)
    print("MPUF_AGG_DONE chunks={}".format(chunks))


def run_fast(samples=100, size=DEFAULT_REGION_SIZE):
    """Convenience entry point for the main laboratory test."""
    capture_fast(samples=samples, size=size)


def run_slow(samples=100, size=DEFAULT_REGION_SIZE):
    """Convenience entry point for the RTC SLOW fallback test."""
    capture_slow(samples=samples, size=size)


def run_slow_aggregate(samples=100, size=DEFAULT_REGION_SIZE):
    """Convenience entry point for compact RTC SLOW aggregate capture."""
    capture_slow_aggregate(samples=samples, size=size)
