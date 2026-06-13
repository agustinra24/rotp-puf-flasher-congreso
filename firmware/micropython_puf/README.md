# MicroPython RTC SLOW PUFLib-Like

Stock MicroPython firmware and host tools for evaluating an RTC SLOW SRAM PUF on
ESP32-class boards, including ESP32-WROOM-32D and ESP32-S3. This is the main MicroPython `puflib-like-rtc-slow`
adaptation: it imitates the original `esp32_puflib` helper mechanics, stable
selection plus repetition8 correction, but reads RTC SLOW instead of the
original library's RTC FAST and deep-sleep DATA SRAM path.

This is experimental laboratory work. The current evidence supports continued
evaluation on a small number of boards, but it does not establish production PUF
behavior, public helper safety, or a formal min-entropy bound.

## Layout

```text
firmware/micropython_puf/
├── device/
│   ├── rtc_fast_puf_probe.py
│   ├── rtc_slow_puf_native.py
│   ├── secure_firmware_loader.py
│   ├── puf_http_ota.py
│   ├── micropython_contamination_probe.py
│   ├── micropython_rtc_slow_boot.py
│   ├── main.py
│   └── protected_app.py
└── tools/
    ├── run_micropython_rtc_slow_auto.py
    ├── upload_micropython_file_raw.py
    ├── build_encrypted_firmware.py
    ├── build_encrypted_firmware_from_device.py
    ├── run_micropython_fwenc_http_ota_demo.py
    └── run_encrypted_mpy_demo_check.py
```

Files in `device/` are uploaded to the ESP32. Their MicroPython filenames remain
stable: `rtc_fast_puf_probe.py`, `rtc_slow_puf_native.py`,
`secure_firmware_loader.py`, and `main.py`.

Files in `tools/` run on the host. Shared analysis, helper-data, HKDF, and
leakage reporting logic lives in `firmware/puf_shared/host_tools/`.

## Variant Tracks

MicroPython has one main executable PUF track:

- `puflib-like-rtc-slow`: `device/rtc_slow_puf_native.py` runs on stock
  MicroPython and uses RTC SLOW register cycling, stable helper selection,
  `repetition8`, HKDF-SHA256, NVS/file persistence, and the shared helper
  contract used by the Arduino RTC SLOW adaptation. The word `native` in that
  filename means native MicroPython execution, not original `esp32_puflib`
  helper format.

Two other tracks are intentionally separate and are not shipped as executable
firmware in this public package:

- `custom-rspf-sid`: an experimental SID-gated line documented conceptually in
  `firmware/puf_shared/PUF_VARIANTS.md`.
- `esp32-puflib-native`: this requires a custom MicroPython C module or
  custom firmware that calls or ports the original `esp32_puflib` C flow,
  including wake-stub behavior and its NVS helper blobs. Stock MicroPython
  cannot honestly claim that path from Python alone.

The shared variant contract lives in `firmware/puf_shared/PUF_VARIANTS.md`.

## Main PUF Flow

The preferred MicroPython experiment uses RTC SLOW memory at `0x50000000` and
software-controlled RTC memory-domain cycling through `machine.mem32`. RTC FAST
is kept as a negative control because tested boards did not expose useful
behavior through that path.

Enrollment example:

```bash
cd rotp-puf-flasher-congreso   # repository root

uv run \
  firmware/micropython_puf/tools/run_micropython_rtc_slow_auto.py \
  --port /dev/cu.usbserial-210 \
  --puf-action enroll \
  --samples 1000 \
  --size 4096 \
  --selection-policy distributed-window-v1 \
  --helper-out /private/tmp/device-a-mpy-helper.json \
  --label device-a-mpy-puflib-like
```

Identity verification example:

```bash
uv run \
  firmware/micropython_puf/tools/run_micropython_rtc_slow_auto.py \
  --port /dev/cu.usbserial-210 \
  --puf-action identity \
  --helper /private/tmp/device-a-mpy-helper.json \
  --size 4096 \
  --identity-nonce validation-nonce-001 \
  --label device-a-mpy-identity
```

Accepted lab identities report `key_sha256`, not raw key material. Rejected
identities must not emit a key hash. Real helpers, SID
files, capture logs, and encrypted payloads must stay outside the repository.

## PUF-Bound Encrypted Payload Demo

The demo encrypts a MicroPython `.mpy` module using AES-256-CBC and
HMAC-SHA256. The envelope key is derived on the device with:

```python
rtc_slow_puf_native.derive_key(nonce="firmware-v1")
```

Build the encrypted payload with a real device-derived key:

```bash
cd rotp-puf-flasher-congreso   # repository root

python3 -B firmware/micropython_puf/tools/build_encrypted_firmware_from_device.py \
  --port /dev/cu.usbserial-0001 \
  --output /private/tmp/protected_app.mpy.enc \
  --mpy-cross /path/to/mpy-cross/build/mpy-cross
```

This builder asks the board for the PUF-derived symmetric root key over raw REPL
and keeps that key only in host RAM while building the envelope. That makes the
flow useful as a laboratory control, but it is not equivalent to the ESP-IDF
ECIES flow, where only a public key is exported.

Run the demo check:

```bash
python3 -B firmware/micropython_puf/tools/run_encrypted_mpy_demo_check.py \
  --port /dev/cu.usbserial-0001 \
  --payload /private/tmp/protected_app.mpy.enc
```

If the available `mpy-cross` version does not match the MicroPython firmware on
the board, use the encrypted `.py` fallback as a lab control instead of forcing a
bytecode mismatch:

```bash
python3 -B firmware/micropython_puf/tools/build_encrypted_firmware_from_device.py \
  --port /dev/cu.usbserial-0001 \
  --no-compile-mpy \
  --output /private/tmp/protected_app.py.enc

python3 -B firmware/micropython_puf/tools/run_encrypted_mpy_demo_check.py \
  --port /dev/cu.usbserial-0001 \
  --payload-kind py \
  --payload /private/tmp/protected_app.py.enc
```

The loader keeps `main.py` and `secure_firmware_loader.py` in clear text. For
`.mpy` payloads it verifies HMAC, decrypts a temporary bytecode module, imports
it once, and removes the temporary file. For `.py` payloads it verifies HMAC and
executes the decrypted source in RAM as a compatibility fallback.

## Minimal HTTP OTA Demo

`device/puf_http_ota.py` adds a local HTTP OTA demo for lab experimentation. The
host serves a small `manifest.json` plus the encrypted payload. The manifest is
authenticated with an HMAC key derived from the same PUF root through HKDF, and
the payload is checked by SHA-256 before it is written to the device filesystem.
The encrypted payload is still executed by `secure_firmware_loader`, so payload
tampering is rejected before decryption or execution.

Scope note: this demo is kept in the repository as experimental code. The
conference paper no longer claims OTA as a contribution or as OWASP/NIST/STRIDE
coverage; authenticated update delivery is treated as future work.

Run it with Wi-Fi credentials supplied by environment variables or CLI flags:

```bash
cd rotp-puf-flasher-congreso   # repository root

PUF_DEMO_WIFI_SSID="YourSSID" \
PUF_DEMO_WIFI_PASS="YourPassword" \
python3 -B firmware/micropython_puf/tools/run_micropython_fwenc_http_ota_demo.py \
  --target esp32 \
  --port /dev/cu.usbserial-0001 \
  --secure-version 1
```

For ESP32-S3, change the target and port:

```bash
PUF_DEMO_WIFI_SSID="YourSSID" \
PUF_DEMO_WIFI_PASS="YourPassword" \
python3 -B firmware/micropython_puf/tools/run_micropython_fwenc_http_ota_demo.py \
  --target esp32s3 \
  --port /dev/cu.usbserial-0001 \
  --secure-version 1
```

Use a 2.4 GHz SSID for these boards. The ESP32-WROOM-32D and ESP32-S3 Wi-Fi
radios do not associate to 5 GHz SSIDs.

Expected markers:

```text
MPY_OTA_WIFI ok=true
MPY_OTA_MANIFEST ok=true
MPY_OTA_DOWNLOAD ok=true
MPY_OTA_INSTALL ok=true
PROTECTED_APP_MPY_OK
MPY_OTA_RUN ok=true
MPY_OTA_TAMPER ok=false
MPY_OTA_MANIFEST_TAMPER ok=false
MPY_HTTP_OTA_DEMO ok=true
```

This is a local demo OTA over HTTP. Its security for tampering comes from the
PUF-authenticated manifest and encrypted payload HMAC, not from HTTP itself.
It is not a production software-update mechanism and is not used as evidence in
the paper's OWASP/NIST/STRIDE evaluation. Production update policy still needs a
remote lifecycle server for epochs, revocation and fleet-wide admission
decisions.

## Controls and Limits

- `micropython_contamination_probe.py` checks whether runtime actions such as
  GC, filesystem operations, or WLAN activity disturb the visible RTC SLOW
  pattern.
- `micropython_rtc_slow_boot.py` is for physical power-up controls only.
- SID-gated helpers are outside this public package; see
  `firmware/puf_shared/PUF_VARIANTS.md` for the conceptual boundary.
- The `4096 bytes` value is the validated lab working region, not a claim about
  the full physical RTC SLOW SRAM size.
- Additional boards, temperature variation, power-cycle validation, and leakage
  analysis are required before making stronger security claims.

## Host Verification

```bash
PYTHONPYCACHEPREFIX=/private/tmp/did-puf-reorg-pycache \
  python3 -m compileall -q firmware/micropython_puf firmware/puf_shared

python3 firmware/micropython_puf/tools/run_micropython_rtc_slow_auto.py --help
python3 firmware/micropython_puf/tools/build_encrypted_firmware.py --help
python3 firmware/micropython_puf/tools/run_micropython_fwenc_http_ota_demo.py --help
```
