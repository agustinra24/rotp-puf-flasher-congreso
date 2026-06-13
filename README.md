# ROTP-PUF-FLASHER

Browser-based secure provisioning and PUF-bound encrypted firmware execution for ESP32 IoT devices.

This repository accompanies the paper **"ROTP-PUF-FLASHER: Browser-Based Secure Provisioning and PUF-Bound Encrypted Firmware Execution for ESP32 IoT Devices"** by Agustin Ahumada Ramirez and Raziel Cesar Campos Sanchez, INAOE, MCyRA 2026, Springer CCIS/LNCS format, 15 pages. It contains the manuscript source and compiled PDF, the code described by the paper, and the measurement scripts and data behind Section 6. This is the repository cited in the paper's *Reproducibility* section.

Public release: 1.0.

Last updated: 2026-06-12.

## Clone

```bash
git clone https://github.com/agustinra24/rotp-puf-flasher-congreso.git
cd rotp-puf-flasher-congreso
```

## Repository Layout

| Directory | Contents |
|---|---|
| `paper/` | The manuscript: `main.pdf`, LaTeX source, BibTeX bibliography, and the architecture figure source. Build instructions are in `paper/README.md`. |
| `firmware/micropython_puf/` | The core firmware research code: RTC SLOW SRAM-PUF support in MicroPython, helper reconstruction, secure verify-before-decrypt loading, and host tools for PUFENC1 envelope generation and checks. |
| `firmware/puf_shared/` | Shared host utilities used by the PUF tooling. |
| `web-flasher/` | The MicroPython Web Flasher described in Section 4.4: a Chrome/Edge Web Serial application that flashes the base firmware, uploads the runtime modules through Raw REPL, enrolls the runtime PUF helper when needed, and writes `config.json` as a PUF-bound encrypted envelope. The Files tab only replaces `.py` files; `config.json` must be handled through the Config workflow so encryption is not bypassed. |
| `measurements/` | Section 6 measurement scripts and data: `measure_paper_timings.py`, `enroll_custom.py`, `identity_custom.py`, and the raw board A timing data in `timings/boardA-paper-timings.json`. |

## Run the Web Flasher

```bash
cd web-flasher
python3 -m http.server 8080
# Open http://localhost:8080 in Chrome or Edge with the ESP32 connected by USB.
```

The six-step flow is guided by the browser interface: chip diagnostics, erase-first base firmware flash, module upload, encrypted configuration, serial monitoring, and a provisioning report. Step 2 uses `esptool-js`: it erases the chip flash, writes the MicroPython base image, and verifies Raw REPL before allowing the flow to continue.

## Reproduce the Paper Measurements

Requirements: `uv` (the scripts declare their dependencies inline using PEP 723) and an ESP32 running MicroPython v1.25.0 with the PUF modules already uploaded.

```bash
cd measurements
# Enrollment for the paper configuration (1000 samples, 256 bits, 50 ms off-time):
uv run enroll_custom.py --port /dev/cu.usbserialXXXX --sleep-us 50000
# Table 6 timings (reconstruction, secure execution, tamper rejection, envelope build):
uv run measure_paper_timings.py --port /dev/cu.usbserialXXXX --reps 5 \
  --out timings/my-timings.json
```

PUF helper data generated during enrollment is device-specific material and is not versioned in this repository.

## Status and Scope

The paper states the system limits explicitly. The decryption key depends on the PUF; server-mediated key origin is future thesis or journal work. `config.json` is encrypted at rest against passive flash reads and the firmware rejects legacy plaintext configuration, but this does not protect against physical loader replacement on a device without Secure Boot. MicroPython is used as a laboratory control, and authenticated OTA delivery remains future work.

The final validation reported by the paper covers two ESP32-WROOM-32D boards with three clean E2E runs per board: encrypted `config.json`, Wi-Fi, NTP, puzzle authentication with HTTP 200, token acquisition, telemetry accepted with HTTP 201, MongoDB readings, and Redis session state. The Web Flasher uploads 18 `.py` modules. The firmware uses `read_interval_s` as the telemetry interval and runs continuously; it does not implement a stop-after-N-readings control.

## Credits

ROTP-PUF-FLASHER is authored by Agustin Ahumada Ramirez and Raziel Cesar Campos Sanchez. The Web Flasher includes firmware modules that build on earlier INAOE IoT platform work by Raziel Campos, Jose Zapata, Alejandro Salinas, and Agustin Ahumada.

## License

See `LICENSE`. Third-party browser dependencies vendored under `web-flasher/vendor/` are documented in `web-flasher/THIRD_PARTY_NOTICES.md`.
