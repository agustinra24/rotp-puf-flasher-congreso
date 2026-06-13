# MicroPython Web Flasher

Browser-based provisioning tool for the ROTP-PUF-FLASHER ESP32 MicroPython
firmware package. It runs from Chrome or Edge and uses the Web Serial API.

This is the browser provisioning tool described in Section 4.4 of the
ROTP-PUF-FLASHER paper (see `../paper/` in this repository). It ships here with
the example device firmware modules it uploads.

## Capabilities

- Flash MicroPython to ESP32 from the browser with `esptool-js`, full-chip erase
  and post-flash Raw REPL verification.
- Upload the 18 platform firmware `.py` files through Raw REPL.
- Generate or deploy `config.json` as a PUF-bound encrypted envelope.
- Scan WiFi networks from the ESP32 and select the SSID in the browser.
- Open a serial monitor with filters and exportable logs.
- Read and edit operational configuration after an explicit trusted-admin confirmation.
- List and replace `.py` files on the ESP32 filesystem.
- Generate a provisioning report for lab tracking.
- Configure `read_interval_s`, the interval between telemetry cycles. The
  firmware runs continuously; the UI does not implement a total-readings
  counter or stop-after-N-readings control.

## Files

```text
web-flasher/
├── index.html
├── styles.css
├── app.js
├── THIRD_PARTY_NOTICES.md
├── vendor/
│   ├── esptool-js-0.5.7.bundle.js
│   ├── esptool-js-0.5.7.LICENSE
│   └── qrcode-generator-1.4.4.min.js
└── firmware/
    ├── ESP32_GENERIC-20250415-v1.25.0.bin
    └── manifest.json
```

The UI is split into separate HTML, CSS, and JavaScript files to keep the tool
maintainable. Browser dependencies are vendored under `vendor/` so the page can
be served locally without CDN access; see `THIRD_PARTY_NOTICES.md`.

## Requirements

- Google Chrome or Microsoft Edge.
- Web Serial API support.
- ESP32 connected by USB.
- A local HTTP server.

Firefox and Safari do not support the Web Serial API required by this workflow.

## Usage

```bash
cd web-flasher
python3 -m http.server 8080
```

Open:

```text
http://localhost:8080
```

Follow the UI steps to flash and verify MicroPython, upload firmware files,
enroll the runtime PUF helper when needed, configure WiFi and API settings, and
monitor the device.

## Operational Notes

- Entering Raw REPL interrupts the running firmware and may trigger a reboot.
- Step 2 uses `esptool-js` directly instead of `esp-web-tools`; success means
  the page wrote the base binary and confirmed that MicroPython accepts Raw REPL.
- If the server still has an active Redis session for the device, a rebooted
  ESP32 can receive HTTP 409 until the session expires or is cleared.
- The firmware files are uploaded as text through Raw REPL. Arbitrary binary
  upload is not part of this tool's current contract.
- The browser derives a temporary PUF configuration key over Raw REPL to encrypt
  `config.json`; the key is not written to flash or local storage.
- Current firmware rejects plaintext `config.json`; provision again if an older
  clear JSON file is present on the device.
- The generic Files management tab refuses `.json` uploads. Use the Config tab
  for `config.json` so the browser derives the PUF-bound key and writes only
  the encrypted envelope.
- The management tab can decrypt the device configuration and bring it into the
  browser after explicit confirmation. Use it only from a trusted local
  workstation; this is an administrator operation, not a defense against a
  compromised host or browser.
- The browser page should be served over `localhost` or a trusted local network
  during lab provisioning.

## Safety Notes

- Review generated configuration before uploading it to a device.
- Do not commit generated `config.json` files containing real credentials.
- Treat serial logs as potentially sensitive when they contain device IDs,
  network names, or error traces.
- Without Secure Boot, a physical attacker can still replace the loader and
  extract runtime material; this flow protects against passive flash reads.
