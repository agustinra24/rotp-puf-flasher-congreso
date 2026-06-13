# PUF Variant Matrix

> **Scope note:** this package ships only the MicroPython
> `puflib-like-rtc-slow` track (`firmware/micropython_puf/`). The other tracks
> and file paths referenced below describe the broader research framework this
> work originates from and are not included in this repository. The matrix is
> kept as the conceptual contract behind the naming used by the code and the
> paper.

This document separates three similar but non-equivalent PUF tracks. The main
reason they are not equivalent is the memory surface. The original
`esp32_puflib` reads RTC FAST SRAM and its deep-sleep DATA SRAM capture path.
The Arduino and stock MicroPython adaptations read RTC SLOW.

## Track 1: puflib-like-rtc-slow

`puflib-like-rtc-slow` is the main Arduino and MicroPython adaptation. It
imitates the original helper mechanism at the algorithmic level, but it is not
native `esp32_puflib`.

```text
source region:      RTC SLOW
capture method:     runtime-controlled RTC memory cycling
helper mechanism:   stable mask plus repetition8 correction
helper exchange:    host JSON or RSPF serialization for the lab
selector:           distributed-window-v1 by default, no SID
key derivation:     HKDF-SHA256
identity output:    key_sha256 only after accepted identity
helper integrity:   helper hash preservation and gross-corruption rejection only
status:             executable on Arduino and stock MicroPython
```

Runtime locations:

| Runtime | Canonical path | Status |
|---|---|---|
| Arduino | `firmware/arduino_puf/rtc_slow_puf_reader/` | Main RTC SLOW puflib-like firmware |
| MicroPython | `firmware/micropython_puf/device/rtc_slow_puf_native.py` | Main RTC SLOW puflib-like stock MicroPython module |

This track is allowed to say it is puflib-like because it uses stable selection
and repetition8 helper correction. It must not say it is puflib-native because
it does not read the same memory path as the original library.

This track does not claim cryptographic helper tamper resistance. A public,
self-contained helper cannot prove that it was not modified unless an external
expected hash, signature, or secret MAC is added by the caller.

## Track 2: custom-rspf-sid

`custom-rspf-sid` is the experimental line. It extends the RTC SLOW work with
SID-gated selection and explicit helper interchange. Its results must not be
mixed with the main `puflib-like-rtc-slow` evidence.

```text
source region:      RTC SLOW by default
capture method:     runtime-controlled RTC memory cycling
helper magic:       RSPF
extractor:          repetition8
selector:           sid-window-v1
helper auth:        sid-hmac-sha256-v1 over RSPF v3 without the MAC trailer
key derivation:     HKDF-SHA256
identity output:    key_sha256 only after accepted identity
interchange:        Arduino <-> MicroPython, plus ESP-IDF compat when present
status:             experimental
```

Runtime locations:

| Runtime | Canonical path | Status |
|---|---|---|
| Arduino | not included in this public package | Experimental firmware copy |
| MicroPython | not included in this public package | Experimental stock MicroPython copy |
| ESP-IDF compat | not included in this public package | Experimental ESP-IDF compatibility firmware |
| Shared tools | not included in this public package | Experimental helper and SID tools |

## Track 3: esp32-puflib-native

`esp32-puflib-native` means compatibility with the original
`firmware/components/esp32_puflib/` behavior, not compatibility with RTC SLOW
or `RSPF`.

```text
source region:      RTC FAST plus deep-sleep DATA SRAM capture path
capture method:     esp32_puflib RTC SRAM cycle and deep-sleep wake stub
helper storage:     NVS namespace storage
helper blobs:       ECC_DATA, PUF_MASK, ECC_SLEEP_DATA, PUF_SLEEP_MASK
helper bundle:      esp32-puflib-blob-bundle-v1, lab-only raw NVS blobs
extractor:          esp32_puflib stable-mask plus repetition-code ECC
identity output:    response_sha256 and key_sha256 only
interchange:        puflib blob bundle only, not RSPF
```

Runtime locations:

| Runtime | Canonical path | Status |
|---|---|---|
| ESP-IDF | `firmware/espidf_puf/` and `firmware/components/esp32_puflib/` | Executable native reference |
| Arduino | none yet | Requires real C or ESP-IDF integration before executable |
| MicroPython | none yet | Requires a custom MicroPython C module or custom firmware before executable |

## Reporting Rule

- Use `puflib-like-rtc-slow` for the main Arduino and MicroPython RTC SLOW
  adaptations.
- Use `custom-rspf-sid` only for the experimental SID-gated helper line outside
  this public package.
- Use `esp32-puflib-native` only when the evidence comes from
  `esp32_puflib` or a future runtime binding that actually calls the same C
  logic and wake-stub flow.
- Never compare helper SHA-256 values across these tracks as if they were the
  same helper format.
- Native puflib blob bundles are sensitive lab-only helper material. They may be
  used for same-device restore and inter-device no-clone tests, but they must
  stay outside the repository.
- The 2026-05-16 native two-board blob gate showed that foreign native blob
  bundles did not reproduce the source board identity. Treat this as
  device-specific mismatch evidence. Do not claim built-in authenticated
  foreign-helper rejection unless an external expected identity gate is added.
- Never store real helpers, SID values, raw captures, PUF responses, or derived
  keys in the repository.
