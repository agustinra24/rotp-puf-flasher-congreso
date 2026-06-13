# PUF Shared Host Tools

Host-side tooling for the main Arduino and MicroPython RTC SLOW puflib-like
adaptations. This directory does not contain device firmware. It contains
parsers, helper-data logic, KDF logic, and leakage reports for the RTC SLOW
track that imitates `esp32_puflib` helper mechanics without claiming native
compatibility.

## Layout

```text
firmware/puf_shared/
└── host_tools/
    ├── analyze_puf_samples.py
    ├── derive_puf_identity.py
    ├── analyze_helper_leakage.py
    └── capture_serial_power_cycles.py
```

## Variant Tracks

See `PUF_VARIANTS.md` for the conceptual split. `puf_variants.json` in this
directory lists the main RTC SLOW contract and the native ESP-IDF puflib
baseline:

- `puflib-like-rtc-slow`: main Arduino and MicroPython RTC SLOW adaptation.
- `esp32-puflib-native`: original `esp32_puflib` behavior, with native helper
  data in NVS and no `RSPF` interchange.

The experimental `custom-rspf-sid` contract belongs to the broader research
framework and is not included in this package.

## Shared Contracts

- The current extractor is `repetition8`: eight selected positions per output
  bit.
- Identity derivation uses HKDF-SHA256 and reports `key_sha256` only after an
  accepted reconstruction. Rejected identities report metrics without key output.
- The main track uses `distributed-window-v1` by default and does not require
  SID material.
- `sid-window-v1` belongs to the experimental `custom-rspf-sid` copy.
- Main host tools reject helpers carrying SID fields; use the experimental
  shared tools for that track.
- Helper JSON and RSPF helper binaries are compatible between the main Arduino,
  MicroPython, and host analysis paths when the same non-SID policy is used.
- Main non-SID helpers are checked for parse correctness, hash preservation,
  and gross corruption in the lab. They are not cryptographically tamper-safe
  without an external expected hash, signature, or secret MAC.
- `esp32_puflib` uses a distinct internal helper stored in NVS. It is a native
  ESP-IDF baseline, not an RTC SLOW or `RSPF` interchange format. The native
  runner can export and import those NVS blobs as
  `esp32-puflib-blob-bundle-v1` for same-device restore and inter-device
  no-clone tests.
- Real helpers, SID files, raw captures, and derived keys are identity material
  and must not be committed.

## Commands

Run host self-tests:

```bash
cd rotp-puf-flasher-congreso   # repository root

python3 firmware/puf_shared/host_tools/analyze_puf_samples.py --self-test
python3 firmware/puf_shared/host_tools/derive_puf_identity.py --self-test
python3 firmware/puf_shared/host_tools/analyze_helper_leakage.py --self-test
```

Analyze captures:

```bash
python3 firmware/puf_shared/host_tools/analyze_puf_samples.py \
  /private/tmp/device-a-capture.log \
  --json
```

Create a helper from a capture:

```bash
python3 firmware/puf_shared/host_tools/derive_puf_identity.py enroll \
  /private/tmp/device-a-capture.log \
  --helper-out /private/tmp/device-a-helper.json \
  --selection-policy distributed-window-v1
```

Evaluate structural leakage:

```bash
python3 firmware/puf_shared/host_tools/analyze_helper_leakage.py \
  --helper /private/tmp/device-a-helper.json \
  --report-out /private/tmp/device-a-helper-leakage.md
```

## Limits

These tools support lab measurement and auditing. They do not establish a formal
min-entropy lower bound, and they do not prove that helper data is safe to make
public. Treat real helper and SID files as sensitive identity material unless a
dedicated analysis says otherwise.
