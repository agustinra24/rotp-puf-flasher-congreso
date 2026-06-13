'use strict';

// ─── CONSTANTS ───────────────────────────────────────────────
var BAUD_RATE = 115200;
var FLASH_BAUD_RATE = 115200;
var MAX_LINES = 2000;
var CHUNK_SIZE = 200;
var SERIAL_DELAY_MS = 300;
var USB_FILTERS = [
  { usbVendorId: 0x10C4 },
  { usbVendorId: 0x1A86 },
  { usbVendorId: 0x0403 },
  { usbVendorId: 0x303A },
];
var TIMEOUTS = {
  REPL_ENTRY: 3000,
  REPL_EXEC: 5000,
  FILE_OP: 8000,
  PUF_DERIVE: 60000,
  PUF_ENROLL: 600000,
  WIFI_SCAN: 15000,
  FETCH: 15000,
  REBOOT_WAIT: 500,
  EXEC_DEFAULT: 10000,
  PORT_SETTLE: 200,
  INTERRUPT_SETTLE: 500,
  RECONNECT_DELAY: 3000,
  RESUME_DELAY: 1500,
};
var MICROPYTHON_VERSION = 'v1.25.0';
var MICROPYTHON_BIN_PATH = 'firmware/ESP32_GENERIC-20250415-v1.25.0.bin';
var MICROPYTHON_FLASH_OFFSET = 0x1000;
var DEFAULT_FLASH_SIZE = '4MB';
var CONFIG_ENVELOPE_FORMAT = 'ROTP-PUF-CONFIG';
var CONFIG_ENVELOPE_VERSION = 1;
var CONFIG_ENVELOPE_ALG = 'AES-256-CBC+HMAC-SHA256';
var CONFIG_ENVELOPE_KDF = 'HKDF-SHA256';
var CONFIG_PUF_NONCE = 'config-json-v1';
var CONFIG_HKDF_INFO = 'ROTP-PUF-CONFIG|keys|v1';

// Python command used to list ESP32 filesystem entries with sizes.
var FS_LIST_CMD = "import os;print('FS_START');[(print(f+'|'+str(os.stat('/'+f)[6]))) for f in sorted(os.listdir('/'))];print('FS_END')";

// ─── STATE ───────────────────────────────────────────────────
var FIRMWARE_FILES = {};
var firmwareLoaded = false;
var KNOWN_FIRMWARE = [];

var serialPort = null;
var serialReader = null;
var monitorRunning = false;
var configData = null;
var operationInProgress = false;

var monitorPort = null;
var lineCount = 0;
var monitorLines = [];
var monitorStartTime = 0;
var showTimestamps = false;
var currentFilter = '';
var autoReconnect = true;
var monitorSuspended = false;
var redisAlertShown = false;

var provisioningData = {};

var mgmtOriginalConfig = null;

var docsPreviousFocus = null;

// ─── HELPERS ──────────────────────────────────────────────────
// Small DOM lookup helper used by event binding and UI updates.
function $(id) { return document.getElementById(id); }

function showStatus(id, msg, type) {
  var el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.className = 'status-msg visible ' + type;
}

function hideStatus(id) {
  var el = $(id);
  if (!el) return;
  el.className = 'status-msg';
  el.textContent = '';
}

function sleep(ms) {
  return new Promise(function(r) { setTimeout(r, ms); });
}

async function safeClosePort(port) {
  if (!port) return;
  try { await port.close(); } catch (_) {}
}

function sanitizeFilename(name) {
  var base = name.replace(/.*[\/\\]/, '');
  if (/['";\\\x00-\x1f]/.test(base)) {
    throw new Error('File name is not allowed: ' + base);
  }
  if (base.length === 0 || base.length > 64) {
    throw new Error('Invalid file name: empty or longer than 64 characters.');
  }
  return base;
}

function escapeForPythonBytes(str) {
  var out = '';
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c === 0x5C) {
      out += '\\\\';
    } else if (c === 0x27) {
      out += "\\'";
    } else if (c === 0x0A) {
      out += '\\n';
    } else if (c === 0x0D) {
      out += '\\r';
    } else if (c === 0x09) {
      out += '\\t';
    } else if (c < 0x20 || c > 0x7E) {
      out += '\\x' + c.toString(16).padStart(2, '0');
    } else {
      out += str[i];
    }
  }
  return out;
}

// Escape text for f.write('...') calls on the ESP32.
// Unlike escapeForPythonBytes (b'...'), this only escapes characters that
// break single-quoted Python string literals.
function escapeForPythonString(str) {
  return str
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

function ensureWebCrypto() {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto is unavailable. Serve this page from localhost or HTTPS.');
  }
}

function bytesToBase64(bytes) {
  var chunkSize = 0x8000;
  var binary = '';
  for (var i = 0; i < bytes.length; i += chunkSize) {
    var chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

function bytesToHex(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

function hexToBytes(hex) {
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error('Invalid PUF key received from the device.');
  }
  var out = new Uint8Array(hex.length / 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function arrayBufferToBinaryString(buffer) {
  var bytes = new Uint8Array(buffer);
  var chunkSize = 0x8000;
  var out = '';
  for (var i = 0; i < bytes.length; i += chunkSize) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return out;
}

async function deriveConfigKeys(pufKeyBytes, saltBytes) {
  ensureWebCrypto();
  var material = await crypto.subtle.importKey('raw', pufKeyBytes, 'HKDF', false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBytes,
      info: new TextEncoder().encode(CONFIG_HKDF_INFO)
    },
    material,
    512
  );
  var okm = new Uint8Array(bits);
  return {
    encKey: okm.slice(0, 32),
    macKey: okm.slice(32, 64)
  };
}

function configAuthString(envelope) {
  return [
    CONFIG_ENVELOPE_FORMAT,
    String(CONFIG_ENVELOPE_VERSION),
    envelope.puf_nonce,
    envelope.salt_b64,
    envelope.iv_b64,
    envelope.ciphertext_b64
  ].join('|');
}

async function hmacSha256Hex(keyBytes, message) {
  ensureWebCrypto();
  var key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  var sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(sig));
}

async function encryptConfigEnvelope(jsonStr, pufKeyHex) {
  ensureWebCrypto();
  var pufKey = hexToBytes(pufKeyHex);
  var salt = crypto.getRandomValues(new Uint8Array(16));
  var iv = crypto.getRandomValues(new Uint8Array(16));
  var keys = await deriveConfigKeys(pufKey, salt);
  var aesKey = await crypto.subtle.importKey('raw', keys.encKey, { name: 'AES-CBC' }, false, ['encrypt']);
  var ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: iv },
    aesKey,
    new TextEncoder().encode(jsonStr)
  ));
  var envelope = {
    format: CONFIG_ENVELOPE_FORMAT,
    version: CONFIG_ENVELOPE_VERSION,
    alg: CONFIG_ENVELOPE_ALG,
    kdf: CONFIG_ENVELOPE_KDF,
    puf_nonce: CONFIG_PUF_NONCE,
    salt_b64: bytesToBase64(salt),
    iv_b64: bytesToBase64(iv),
    ciphertext_b64: bytesToBase64(ciphertext)
  };
  envelope.tag_hex = await hmacSha256Hex(keys.macKey, configAuthString(envelope));
  pufKey.fill(0);
  keys.encKey.fill(0);
  keys.macKey.fill(0);
  return JSON.stringify(envelope, null, 2);
}

function parseFileListing(raw) {
  var lines = raw.split('\n');
  var files = [];
  var capturing = false;
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i].replace(/\r/g, '').trim();
    if (ln.indexOf('FS_START') !== -1) { capturing = true; continue; }
    if (ln.indexOf('FS_END') !== -1) break;
    if (capturing && ln.indexOf('|') !== -1) {
      var parts = ln.split('|');
      var name = parts[0].trim();
      var size = parseInt(parts[1]) || 0;
      if (name.length > 0) files.push({ name: name, size: size });
    }
  }
  return files;
}

// ─── SERIAL: LOW LEVEL ───────────────────────────────────────
async function serialWrite(port, data) {
  var writer = port.writable.getWriter();
  try {
    if (typeof data === 'string') {
      await writer.write(new TextEncoder().encode(data));
    } else {
      await writer.write(data instanceof Uint8Array ? data : new Uint8Array(data));
    }
  } finally {
    writer.releaseLock();
  }
}

async function serialReadUntil(port, sentinel, timeoutMs) {
  // Do not cancel the reader when the sentinel is found: cancel() discards
  // queued bytes and breaks Raw REPL continuity. Cancel only on timeout.
  var reader = port.readable.getReader();
  var decoder = new TextDecoder('utf-8', { fatal: false });
  var buf = '';
  var timedOut = false;
  var timer = setTimeout(function() {
    timedOut = true;
    try { reader.cancel(); } catch (_) {}
  }, timeoutMs);
  try {
    while (!timedOut) {
      var result;
      try {
        result = await reader.read();
      } catch (_) {
        break; // in-flight cancel() can reject the pending read
      }
      if (result.done) break;
      if (result.value) {
        buf += decoder.decode(result.value, { stream: true });
        if (buf.includes(sentinel)) return buf;
      }
    }
  } finally {
    clearTimeout(timer);
    reader.releaseLock();
  }
  return buf;
}

// Drain RX until quietMs of silence, or maxMs total. This is needed before
// Raw REPL negotiation because open() can leave boot logs or driver noise in
// the input buffer.
async function serialDrain(port, quietMs, maxMs) {
  var reader = port.readable.getReader();
  var decoder = new TextDecoder('utf-8', { fatal: false });
  var buf = '';
  var deadline = Date.now() + maxMs;
  try {
    while (Date.now() < deadline) {
      var result = await Promise.race([
        reader.read().catch(function() { return { value: null, done: true }; }),
        sleep(quietMs).then(function() { return { value: null, done: false, quiet: true }; })
      ]);
      if (result.quiet) break; // silence: backlog drained
      if (result.done) break;
      if (result.value) buf += decoder.decode(result.value, { stream: true });
    }
  } finally {
    try { await reader.cancel(); } catch (_) {}
    reader.releaseLock();
  }
  return buf;
}

// ─── SERIAL: REPL ─────────────────────────────────────────────
// DTR state for USB serial adapters that require explicit re-application.
var _dtrStateWeb = false;

// setDTR through Web Serial. DTR controls GPIO0: false means IO0 high, normal boot.
async function setDTRWeb(port, state) {
  _dtrStateWeb = state;
  await port.setSignals({ dataTerminalReady: state });
}

// setRTS through Web Serial. RTS controls EN: true means EN low, chip reset.
// Some USB serial adapters require DTR to be re-applied after RTS changes.
async function setRTSWeb(port, state) {
  await port.setSignals({ requestToSend: state });
  await port.setSignals({ dataTerminalReady: _dtrStateWeb });
}

// Reset into the application, not the bootloader: pulse EN through RTS while
// keeping IO0 high. This mirrors the esptool-js HardReset behavior.
async function resetToApp(port) {
  await setDTRWeb(port, false); // IO0 high: normal boot, not bootloader
  await setRTSWeb(port, true);  // EN low: chip in reset
  await sleep(100);
  await setRTSWeb(port, false); // EN high: app starts
}

// Release DTR/RTS without a reset pulse so the board keeps running. This
// matches the known-good pyserial harness state, dtr/rts=False.
async function releaseSignalsNoReset(port) {
  await setDTRWeb(port, false);
  await setRTSWeb(port, false);
}

async function enterRawRepl(port) {
  // Robust entry for USB serial adapters with different reset behavior:
  // do not reset first. open() already leaves the board running or resets it.
  // Release DTR/RTS, drain boot logs and driver noise, interrupt with Ctrl-C
  // twice, drain again, then request Raw REPL with a long first timeout.
  // resetToApp remains a last resort for stuck boards.
  var serialLog = '';
  for (var attempt = 0; attempt < 3; attempt++) {
    if (attempt === 0) {
      try { await releaseSignalsNoReset(port); } catch (_) {}
      await sleep(200);
    } else if (attempt === 2) {
      // Last resort: clean application reset, then wait for the full boot.
      try { await resetToApp(port); } catch (_) {}
      await sleep(2500);
    }
    serialLog += await serialDrain(port, 150, 2000);
    await serialWrite(port, String.fromCharCode(3)); // Ctrl-C
    await serialWrite(port, String.fromCharCode(3)); // Ctrl-C
    await sleep(400);
    serialLog += await serialDrain(port, 150, 2000);
    await serialWrite(port, String.fromCharCode(1)); // Ctrl-A: enter Raw REPL
    var resp = await serialReadUntil(port, 'raw REPL', attempt === 0 ? 30000 : 10000);
    serialLog += resp;
    if (resp.includes('raw REPL')) {
      return;
    }
  }
  console.error('[enterRawRepl] full serial log (' + serialLog.length + ' chars):\n' + serialLog);
  // Signature of a boot loop caused by truncated flash. Without a bootable app,
  // Raw REPL is impossible.
  if (serialLog.includes('not bootable')) {
    throw new Error('The ESP32 base firmware is incomplete: the board is stuck in a boot loop ' +
      'and cannot enter MicroPython. Repeat Step 2; the flow finishes only after writing ' +
      'MicroPython and verifying Raw REPL.');
  }
  throw new Error('Could not enter Raw REPL after 3 attempts, including one reset pulse. ' +
    'Last 600 response characters:\n' + serialLog.slice(-600) +
    '\n(Full serial log is in the browser console: F12 > Console)');
}

async function execRawRepl(port, code, timeoutMs) {
  await serialWrite(port, code + '\r\n');
  await serialWrite(port, String.fromCharCode(4));
  var result = await serialReadUntil(port, 'OK', timeoutMs || TIMEOUTS.FILE_OP);
  return result;
}

async function execAndCapture(port, code, sentinel, timeout) {
  await serialWrite(port, code + '\r\n');
  await serialWrite(port, String.fromCharCode(4));
  return await serialReadUntil(port, sentinel, timeout || TIMEOUTS.EXEC_DEFAULT);
}

async function connectAndEnterRepl() {
  await suspendMonitor();
  var port = await navigator.serial.requestPort({ filters: USB_FILTERS });
  await port.open({ baudRate: BAUD_RATE });
  await sleep(200);
  // Entrada robusta al raw REPL (espera el boot tras el reset por open()).
  try {
    await enterRawRepl(port);
  } catch (e) {
    await safeClosePort(port);
    throw e;
  }
  return port;
}

async function exitReplAndClose(port, skipReboot) {
  await serialWrite(port, String.fromCharCode(2)); // Ctrl-B: exit raw REPL
  await sleep(200);
  if (!skipReboot) {
    await serialWrite(port, String.fromCharCode(4)); // Ctrl-D: soft reboot firmware
    await sleep(TIMEOUTS.REBOOT_WAIT);
  }
  await safeClosePort(port);
  await sleep(SERIAL_DELAY_MS);
}

// ─── CARD 1: DIAGNOSTICS ─────────────────────────────────────
async function runDiagnostics() {
  if (operationInProgress) {
    showStatus('diagStatus', 'Another operation is running. Wait until it finishes.', 'warn');
    return;
  }
  if (!window.EspLoader || !window.Transport) {
    showStatus('diagStatus', 'Error: esptool-js did not load. Check the local vendor bundle and reload.', 'err');
    return;
  }
  provisioningData = {};
  var btn = $('btnDiag');
  var resultBox = $('diagResult');
  btn.disabled = true;
  btn.classList.add('loading');
  operationInProgress = true;
  hideStatus('diagStatus');
  resultBox.classList.add('hidden');
  resultBox.textContent = '';

  var port = null;
  var transport = null;
  try {
    showStatus('diagStatus', 'Requesting serial port access...', 'ok');
    port = await navigator.serial.requestPort({ filters: USB_FILTERS });
    // Do NOT call port.open() here: Transport opens it internally
    transport = new window.Transport(port, true);
    var loader = new window.EspLoader({
      transport: transport,
      baudrate: BAUD_RATE,
      romBaudrate: BAUD_RATE,
    });

    showStatus('diagStatus', 'Connecting to the chip...', 'ok');
    await loader.main();

    var info = {};

    // Chip name is exposed as a property in esptool-js 0.5.7.
    info.chip = loader.chip.CHIP_NAME || 'Unknown';

    // Features
    try {
      var getFeatures = loader.chip.getChipFeatures || loader.chip.get_chip_features;
      if (getFeatures) {
        var feats = await getFeatures.call(loader.chip, loader);
        info.features = Array.isArray(feats) ? feats.join(', ') : String(feats);
      }
    } catch (_) { info.features = 'Unavailable'; }

    // MAC address
    try {
      var readMac = loader.chip.readMac || loader.chip.read_mac;
      if (readMac) {
        var mac = await readMac.call(loader.chip, loader);
        if (Array.isArray(mac)) {
          info.mac = mac.map(function(b) { return b.toString(16).padStart(2, '0'); }).join(':');
        } else {
          info.mac = String(mac);
        }
      }
    } catch (_) { info.mac = 'Unavailable'; }

    // Tamano de flash
    try {
      var flashSize = await loader.detectFlashSize();
      info.flash = flashSize || 'Not detected';
    } catch (_) {
      try {
        var flashId = await loader.readFlashId();
        info.flash = 'Flash ID: 0x' + flashId.toString(16);
      } catch (__) { info.flash = 'Not detected'; }
    }

    // Frecuencia del cristal
    try {
      var getCrystal = loader.chip.getCrystalFreq || loader.chip.get_crystal_freq;
      if (getCrystal) {
        var freq = await getCrystal.call(loader.chip, loader);
        info.crystal = freq + ' MHz';
      }
    } catch (_) { info.crystal = 'Unavailable'; }

    // Render the diagnostic result as label/value pairs.
    resultBox.textContent = '';
    var fields = [
      ['Chip', info.chip],
      ['Features', info.features || 'N/A'],
      ['MAC', info.mac || 'N/A'],
      ['Flash', info.flash || 'N/A'],
      ['Crystal', info.crystal || 'N/A'],
    ];
    for (var fi = 0; fi < fields.length; fi++) {
      var line = document.createElement('span');
      line.className = 'line';
      var lbl = document.createElement('span');
      lbl.className = 'label';
      lbl.textContent = fields[fi][0] + ': ';
      var val = document.createElement('span');
      val.className = 'value';
      val.textContent = fields[fi][1];
      line.appendChild(lbl);
      line.appendChild(val);
      resultBox.appendChild(line);
    }
    resultBox.classList.remove('hidden');

    showStatus('diagStatus', 'Diagnostics complete. Detected chip: ' + info.chip, 'ok');
    recordProvisioningStep('chip', info.chip);
    recordProvisioningStep('mac', info.mac);
    recordProvisioningStep('flash', info.flash);

  } catch (err) {
    showStatus('diagStatus', 'Error: ' + err.message, 'err');
  } finally {
    // Always release the transport and serial port.
    if (transport) {
      try { await transport.disconnect(); } catch (_) {}
    }
    await safeClosePort(port);
    btn.disabled = false;
    btn.classList.remove('loading');
    operationInProgress = false;
  }
}

// ─── CARD 2: FLASH FIRMWARE ──────────────────────────────────
function setFlashProgress(label, pct) {
  var section = $('flashProgressSection');
  var fill = $('flashProgressFill');
  var file = $('flashProgressFile');
  var percent = $('flashProgressPct');
  if (section) section.classList.remove('hidden');
  if (fill) {
    fill.classList.add('active');
    fill.style.width = pct + '%';
  }
  if (file) file.textContent = label;
  if (percent) percent.textContent = pct + '%';
}

function finishFlashProgress(label, pct) {
  setFlashProgress(label, pct);
  var fill = $('flashProgressFill');
  if (fill) fill.classList.remove('active');
}

async function verifyMicroPythonBoot(port) {
  await sleep(10000);
  await port.open({ baudRate: BAUD_RATE });
  try {
    await enterRawRepl(port);
    await serialWrite(port, String.fromCharCode(2)); // Ctrl-B: exit Raw REPL
    await sleep(200);
  } finally {
    await safeClosePort(port);
  }
}

async function flashMicroPython() {
  if (operationInProgress) {
    showStatus('flashStatus', 'Another operation is running. Wait until it finishes.', 'warn');
    return;
  }
  if (!window.EspLoader || !window.Transport) {
    showStatus('flashStatus', 'Error: esptool-js did not load. Check the local vendor bundle and reload.', 'err');
    return;
  }

  var btn = $('btnFlash');
  var port = null;
  var transport = null;
  operationInProgress = true;
  if (btn) {
    btn.disabled = true;
    btn.classList.add('loading');
  }
  hideStatus('flashStatus');
  setFlashProgress('Preparing...', 0);

  try {
    showStatus('flashStatus', 'Loading MicroPython binary...', 'ok');
    var resp = await fetch(MICROPYTHON_BIN_PATH, { signal: AbortSignal.timeout(TIMEOUTS.FETCH) });
    if (!resp.ok) throw new Error('Could not load MicroPython: HTTP ' + resp.status);
    var firmwareBuffer = await resp.arrayBuffer();
    var firmwareData = arrayBufferToBinaryString(firmwareBuffer);
    if (firmwareData.length < 1024 * 1024) {
      throw new Error('Unexpectedly small MicroPython binary: ' + firmwareData.length + ' bytes');
    }

    showStatus('flashStatus', 'Requesting serial port access...', 'ok');
    port = await navigator.serial.requestPort({ filters: USB_FILTERS });
    transport = new window.Transport(port, true);
    var loader = new window.EspLoader({
      transport: transport,
      baudrate: FLASH_BAUD_RATE,
      romBaudrate: BAUD_RATE,
      terminal: {
        clean: function() {},
        write: function(data) { console.debug('[esptool-js]', data); },
        writeLine: function(data) { console.debug('[esptool-js]', data); }
      }
    });

    showStatus('flashStatus', 'Connecting to the ESP32 bootloader...', 'ok');
    await loader.main();
    // `detectFlashSize()` is useful for diagnostics, but older esptool-js
    // bundles can feed a too-small value into writeFlash on some serial paths.
    // 4MB is the conservative minimum for the target ESP32-WROOM modules and
    // easily fits the 1.6MB MicroPython image at 0x1000.
    var flashSize = DEFAULT_FLASH_SIZE;

    showStatus('flashStatus', 'Erasing full flash and writing MicroPython at 115200 baud...', 'ok');
    await loader.writeFlash({
      fileArray: [{ data: firmwareData, address: MICROPYTHON_FLASH_OFFSET }],
      flashMode: 'dio',
      flashFreq: '40m',
      flashSize: flashSize,
      eraseAll: true,
      compress: true,
      reportProgress: function(fileIndex, written, total) {
        var pct = total ? Math.max(1, Math.min(99, Math.floor((written / total) * 100))) : 1;
        setFlashProgress('Writing MicroPython (' + written + '/' + total + ' bytes)', pct);
      }
    });

    showStatus('flashStatus', 'Rebooting ESP32...', 'ok');
    if (typeof loader.after === 'function') {
      await loader.after('hard_reset');
    }
    if (transport) {
      await transport.disconnect();
      transport = null;
    }

    showStatus('flashStatus', 'Verifying that MicroPython boots and accepts Raw REPL...', 'ok');
    setFlashProgress('Verifying boot...', 99);
    await verifyMicroPythonBoot(port);
    port = null;

    finishFlashProgress('MicroPython verified', 100);
    showStatus('flashStatus', 'MicroPython installed and verified. Continue to Step 3.', 'ok');
    recordProvisioningStep('flash', MICROPYTHON_VERSION + ' verified via esptool-js, flashSize=' + flashSize);
  } catch (err) {
    var message = err && err.message ? err.message : String(err);
    showStatus('flashStatus', 'Error: ' + message, 'err');
    console.error('[flashMicroPython]', err);
    finishFlashProgress('Failed', 0);
  } finally {
    if (transport) {
      try { await transport.disconnect(); } catch (_) {}
    }
    await safeClosePort(port);
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('loading');
    }
    operationInProgress = false;
  }
}

// ─── CARD 3: FILE UPLOAD ─────────────────────────────────────
async function loadFirmwareFiles() {
  if (firmwareLoaded) return FIRMWARE_FILES;
  var resp = await fetch('firmware/files/manifest.json', { signal: AbortSignal.timeout(TIMEOUTS.FETCH) });
  if (!resp.ok) throw new Error('Could not load firmware manifest: HTTP ' + resp.status);
  var manifest = await resp.json();
  var files = manifest.files || [];
  var names = files.map(function(f) {
    var n = typeof f === 'string' ? f : f.name;
    return sanitizeFilename(n);
  });
  // Load all files in parallel to reduce waiting time.
  var results = await Promise.all(names.map(function(name) {
    return fetch('firmware/files/' + name, { signal: AbortSignal.timeout(TIMEOUTS.FETCH) })
      .then(function(r) {
        if (!r.ok) throw new Error('Could not load ' + name + ': HTTP ' + r.status);
        return r.text().then(function(text) { return { name: name, text: text }; });
      });
  }));
  var loadedFiles = {};
  results.forEach(function(r) { loadedFiles[r.name] = r.text; });
  // Assign only after every firmware file has loaded successfully.
  FIRMWARE_FILES = loadedFiles;
  KNOWN_FIRMWARE = names;
  firmwareLoaded = true;
  return FIRMWARE_FILES;
}

async function uploadFiles() {
  if (operationInProgress) {
    showStatus('uploadStatus', 'Another operation is running. Wait until it finishes.', 'warn');
    return;
  }
  operationInProgress = true;
  await suspendMonitor();
  var btn = $('btnUpload');
  var progressSection = $('uploadProgressSection');
  var progressFill = $('uploadProgressFill');
  var progressFile = $('uploadProgressFile');
  var progressPct = $('uploadProgressPct');
  var resultBox = $('uploadResult');

  btn.disabled = true;
  btn.classList.add('loading');

  // Load firmware modules from the local server.
  try {
    showStatus('uploadStatus', 'Loading firmware modules...', 'ok');
    await loadFirmwareFiles();
  } catch (fwErr) {
    showStatus('uploadStatus', 'Error: ' + fwErr.message, 'err');
    btn.disabled = false;
    btn.classList.remove('loading');
    operationInProgress = false;
    resumeMonitor();
    return;
  }
  hideStatus('uploadStatus');
  resultBox.textContent = '';
  resultBox.classList.add('hidden');
  progressSection.classList.remove('hidden');
  progressFill.style.width = '0%';
  progressFill.classList.add('active');
  progressPct.textContent = '0%';

  var skipReboot = false;

  try {
    showStatus('uploadStatus', 'Requesting serial port access...', 'ok');
    serialPort = await navigator.serial.requestPort({ filters: USB_FILTERS });
    await serialPort.open({ baudRate: BAUD_RATE });
    await sleep(200);

    showStatus('uploadStatus', 'Entering Raw REPL...', 'ok');
    await enterRawRepl(serialPort);

    var fileNames = Object.keys(FIRMWARE_FILES);
    var total = fileNames.length + (configData ? 1 : 0);
    var uploaded = 0;
    var results = [];

    for (var fni = 0; fni < fileNames.length; fni++) {
      var fname = fileNames[fni];
      var content = FIRMWARE_FILES[fname];
      if (!content || content.length === 0) {
        results.push(fname + ': SKIP (vacio)');
        uploaded++;
        continue;
      }
      progressFile.textContent = fname + ' (' + (uploaded + 1) + '/' + total + ')';
      showStatus('uploadStatus', 'Uploading ' + fname + '...', 'ok');

      try {
        await execRawRepl(serialPort, "f=open('/" + fname + "','wb')");

        for (var i = 0; i < content.length; i += CHUNK_SIZE) {
          var chunk = content.substring(i, i + CHUNK_SIZE);
          var escaped = escapeForPythonBytes(chunk);
          await execRawRepl(serialPort, "f.write(b'" + escaped + "')");
        }

        await execRawRepl(serialPort, "f.close()");
        results.push(fname + ': OK');
      } catch (fileErr) {
        try { await execRawRepl(serialPort, "f.close()"); } catch (_) {}
        results.push(fname + ': ERROR - ' + fileErr.message);
      }

      uploaded++;
      var pct = Math.round((uploaded / total) * 100);
      progressFill.style.width = pct + '%';
      progressPct.textContent = pct + '%';
    }

    // Upload config.json when one is available.
    if (configData) {
      showStatus('uploadStatus', 'Uploading config.json (' + total + '/' + total + ')...', 'ok');
      try {
        var cfgCopy = JSON.parse(JSON.stringify(configData));
        var uiSsid = $('cfgWifiSsid').value.trim();
        var uiPass = $('cfgWifiPass').value.trim();
        if (uiSsid) cfgCopy.wifi_ssid = uiSsid;
        if (uiPass) cfgCopy.wifi_pass = uiPass;

        var plainJsonStr = JSON.stringify(cfgCopy, null, 2);
        if (plainJsonStr.length > 16384) {
          throw new Error('Plain config.json exceeds the maximum size of 16 KB.');
        }
        var encryptedJsonStr = await prepareEncryptedConfig(serialPort, plainJsonStr, 'uploadStatus');
        await writeConfigJsonOnDevice(serialPort, encryptedJsonStr);
        results.push('config.json: OK');
      } catch (cfgErr) {
        try { await execRawRepl(serialPort, "f.close()"); } catch (_) {}
        results.push('config.json: ERROR - ' + cfgErr.message);
      }
      uploaded++;
      progressFill.style.width = '100%';
    } else {
      // No config loaded: keep Raw REPL open and tell the user.
      skipReboot = true;
    }

    resultBox.textContent = '';
    for (var ri = 0; ri < results.length; ri++) {
      var row = document.createElement('div');
      row.className = 'upload-row';
      var isOk = results[ri].includes(': OK');
      var icon = document.createElement('span');
      icon.className = isOk ? 'check' : 'cross';
      icon.textContent = isOk ? '\u2713' : '\u2717';
      var fnameSpan = document.createElement('span');
      fnameSpan.className = 'fname';
      fnameSpan.textContent = results[ri].split(':')[0];
      var fstatus = document.createElement('span');
      fstatus.className = 'fstatus';
      fstatus.textContent = isOk ? 'OK' : results[ri].split(': ').slice(1).join(': ');
      row.appendChild(icon);
      row.appendChild(fnameSpan);
      row.appendChild(fstatus);
      resultBox.appendChild(row);
    }
    resultBox.classList.remove('hidden');
    progressFile.textContent = 'Verifying...';
    progressPct.textContent = '100%';
    progressFill.style.width = '100%';

    // Filesystem verification: list files on the ESP32.
    try {
      var lsResult = await execRawRepl(serialPort, "import os; print('\\n'.join(os.listdir('/')))");
      var lsParts = lsResult.split('OK');
      var lsOutput = lsParts.length > 1 ? lsParts.slice(1).join('OK') : lsResult;
      var fsFiles = lsOutput.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0 && l.indexOf('>') === -1 && l.indexOf('\x04') === -1; });
      var missing = [];
      var fileNames2 = Object.keys(FIRMWARE_FILES);
      for (var vi = 0; vi < fileNames2.length; vi++) {
        if (fsFiles.indexOf(fileNames2[vi]) === -1) missing.push(fileNames2[vi]);
      }
      if (missing.length > 0) {
        showStatus('uploadStatus', missing.length + ' file(s) not found on the ESP32: ' + missing.join(', '), 'warn');
      }
    } catch (_) { /* verification is best-effort */ }

    progressFile.textContent = 'Complete';
    progressFill.classList.remove('active');

    if (skipReboot) {
      showStatus('uploadStatus', 'Files uploaded. Load config.json in Step 4 before rebooting.', 'warn');
      // Do NOT exit raw REPL or reboot; ESP32 stays in REPL for Card 4
    } else {
      // Exit Raw REPL with Ctrl-B, then reboot with Ctrl-D.
      showStatus('uploadStatus', 'Files uploaded. Rebooting ESP32...', 'ok');
      await serialWrite(serialPort, String.fromCharCode(2));
      await sleep(SERIAL_DELAY_MS);
      await serialWrite(serialPort, String.fromCharCode(4));
      await sleep(TIMEOUTS.REBOOT_WAIT);
      await safeClosePort(serialPort);
      serialPort = null;
    }

    var errCount = results.filter(function(r) { return r.includes('ERROR'); }).length;
    recordProvisioningStep('filesUploaded', results.filter(function(r) { return r.indexOf('OK') !== -1; }).length);
    recordProvisioningStep('filesErrors', errCount);
    if (errCount > 0) {
      showStatus('uploadStatus', errCount + ' file(s) failed. Review the results.', 'err');
    } else if (!skipReboot) {
      showStatus('uploadStatus', 'All files uploaded successfully. ESP32 rebooted.', 'ok');
    }

  } catch (err) {
    showStatus('uploadStatus', 'Error: ' + err.message, 'err');
    if (serialPort) {
      await safeClosePort(serialPort);
      serialPort = null;
    }
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
    operationInProgress = false;
    resumeMonitor();
  }
}

// ─── CARD 4: CONFIGURATION ───────────────────────────────────
function parsePufConfigKey(result) {
  var match = result.match(/PUF_CONFIG_KEY=([0-9a-fA-F]{64})/);
  if (!match) {
    throw new Error('Could not derive the PUF configuration key.');
  }
  return match[1].toLowerCase();
}

async function ensurePufEnrollmentAndKey(port, statusId) {
  showStatus(statusId, 'Checking the PUF helper on the ESP32...', 'ok');
  var statusCode = [
    'import rtc_slow_puf_native',
    's=rtc_slow_puf_native.status()',
    "print('PUF_ENROLLED=' + ('1' if s.get('enrolled') else '0'))",
    "print('PUF_STATUS_END')"
  ].join('\n');
  var statusResult = await execAndCapture(port, statusCode, 'PUF_STATUS_END', TIMEOUTS.PUF_DERIVE);
  if (statusResult.indexOf('PUF_ENROLLED=1') === -1) {
    showStatus(statusId, 'Enrolling the SRAM-PUF. This can take several minutes...', 'ok');
    var enrollCode = [
      'import rtc_slow_puf_native',
      "print('PUF_ENROLL_START')",
      'rtc_slow_puf_native.enroll()',
      "print('PUF_ENROLL_DONE')"
    ].join('\n');
    var enrollResult = await execAndCapture(port, enrollCode, 'PUF_ENROLL_DONE', TIMEOUTS.PUF_ENROLL);
    if (enrollResult.indexOf('PUF_ENROLL_DONE') === -1) {
      throw new Error('PUF enrollment did not finish correctly.');
    }
  }
  showStatus(statusId, 'Deriving the PUF key for config.json encryption...', 'ok');
  var keyCode = [
    'import rtc_slow_puf_native, ubinascii',
    "k=rtc_slow_puf_native.derive_key(nonce='" + CONFIG_PUF_NONCE + "')",
    "print('PUF_CONFIG_KEY=' + ubinascii.hexlify(k).decode())",
    "print('PUF_CONFIG_KEY_END')"
  ].join('\n');
  return parsePufConfigKey(await execAndCapture(port, keyCode, 'PUF_CONFIG_KEY_END', TIMEOUTS.PUF_DERIVE));
}

async function prepareEncryptedConfig(port, jsonStr, statusId) {
  var pufKeyHex = await ensurePufEnrollmentAndKey(port, statusId);
  try {
    showStatus(statusId, 'Encrypting config.json before saving it...', 'ok');
    return await encryptConfigEnvelope(jsonStr, pufKeyHex);
  } finally {
    pufKeyHex = null;
  }
}

async function writeConfigJsonOnDevice(port, encryptedJsonStr) {
  await execRawRepl(port, "f=open('/config.json.tmp','w')");
  try {
    for (var ci = 0; ci < encryptedJsonStr.length; ci += CHUNK_SIZE) {
      var chunk = escapeForPythonString(encryptedJsonStr.slice(ci, ci + CHUNK_SIZE));
      await execRawRepl(port, "f.write('" + chunk + "')");
    }
    await execRawRepl(port, "f.close()");
  } catch (err) {
    try { await execRawRepl(port, "f.close()"); } catch (_) {}
    throw err;
  }
  await execRawRepl(port, "import os;os.rename('/config.json.tmp','/config.json')");
}

function loadConfigFile(file) {
  var reader = new FileReader();
  reader.onload = function(e) {
    try {
      var parsed = JSON.parse(e.target.result);
      configData = parsed;
      showConfigSummary(parsed);
    } catch (err) {
      showStatus('configFileStatus', 'Error parsing JSON: ' + err.message, 'err');
    }
  };
  reader.readAsText(file);
}

function showConfigSummary(cfg) {
  $('configSummary').classList.remove('hidden');
  var pillsEl = $('configPills');
  pillsEl.textContent = '';

  var fields = [
    ['server_url', cfg.server_url],
    ['server_port', cfg.server_port],
    ['device_id', cfg.device_id],
    ['api_key', cfg.api_key ? '***' + cfg.api_key.slice(-6) : null],
    ['device_key_hex', cfg.device_key_hex ? cfg.device_key_hex.slice(0,8) + '...' : null],
    ['server_key_hex', cfg.server_key_hex ? cfg.server_key_hex.slice(0,8) + '...' : null],
    ['read_interval_s', cfg.read_interval_s],
    ['location', cfg.location],
    ['wifi_ssid', cfg.wifi_ssid],
    ['wifi_pass', cfg.wifi_pass ? '***' : null],
  ];

  for (var i = 0; i < fields.length; i++) {
    var key = fields[i][0];
    var val = fields[i][1];
    var row = document.createElement('div');
    row.className = 'cfg-field';
    var lbl = document.createElement('span');
    lbl.className = 'cfg-label';
    lbl.textContent = key;
    var valEl = document.createElement('span');
    var isReplace = typeof val === 'string' && val === 'REPLACE';
    var isPending = val === null || val === undefined || isReplace;
    valEl.className = 'cfg-value' + (isPending ? ' pending' : '');
    valEl.textContent = isPending ? (isReplace ? 'PENDING' : 'N/A') : val;
    row.appendChild(lbl);
    row.appendChild(valEl);
    pillsEl.appendChild(row);
  }

  // Pre-fill WiFi fields if present and not REPLACE
  var ssidInput = $('cfgWifiSsid');
  var passInput = $('cfgWifiPass');
  if (cfg.wifi_ssid && cfg.wifi_ssid !== 'REPLACE') ssidInput.value = cfg.wifi_ssid;
  if (cfg.wifi_pass && cfg.wifi_pass !== 'REPLACE') passInput.value = cfg.wifi_pass;

  // Highlight REPLACE
  if (cfg.wifi_ssid === 'REPLACE') ssidInput.placeholder = 'Enter the SSID';
  if (cfg.wifi_pass === 'REPLACE') passInput.placeholder = 'Enter the password';
}

async function uploadConfigToDevice(jsonStr, statusId) {
  await suspendMonitor();
  var port = serialPort;
  var ownPort = false;

  try {
    if (!port || !port.readable) {
      port = await navigator.serial.requestPort({ filters: USB_FILTERS });
      await port.open({ baudRate: BAUD_RATE });
      ownPort = true;
    }

    // Robust Raw REPL entry after the reset caused by opening the port.
    await enterRawRepl(port);

    var encryptedJsonStr = await prepareEncryptedConfig(port, jsonStr, statusId || 'configFileStatus');
    await writeConfigJsonOnDevice(port, encryptedJsonStr);

    // Exit Raw REPL and reboot.
    await serialWrite(port, String.fromCharCode(2));
    await sleep(SERIAL_DELAY_MS);
    await serialWrite(port, String.fromCharCode(4));
    await sleep(TIMEOUTS.REBOOT_WAIT);

    if (ownPort) {
      await safeClosePort(port);
    } else {
      await safeClosePort(serialPort);
      serialPort = null;
    }

    return true;
  } catch (err) {
    if (ownPort) {
      await safeClosePort(port);
    } else {
      // Shared port state is unknown after an error; close it to avoid corruption.
      await safeClosePort(serialPort);
      serialPort = null;
    }
    throw err;
  }
}

async function uploadConfigFromFile() {
  if (operationInProgress) {
    showStatus('configFileStatus', 'Another operation is running. Wait until it finishes.', 'warn');
    return;
  }
  if (!configData) {
    showStatus('configFileStatus', 'No config.json file has been loaded.', 'err');
    return;
  }
  hideStatus('configFileStatus');
  var btn = $('btnUploadConfig');
  if (btn) { btn.disabled = true; btn.classList.add('loading'); }
  operationInProgress = true;
  try {
    var cfgCopy = JSON.parse(JSON.stringify(configData));
    var uiSsid = $('cfgWifiSsid').value.trim();
    var uiPass = $('cfgWifiPass').value.trim();
    if (uiSsid) cfgCopy.wifi_ssid = uiSsid;
    if (uiPass) cfgCopy.wifi_pass = uiPass;

    showStatus('configFileStatus', 'Encrypting and uploading config.json to the ESP32...', 'ok');
    var jsonStr = JSON.stringify(cfgCopy, null, 2);
    await uploadConfigToDevice(jsonStr, 'configFileStatus');
    showStatus('configFileStatus', 'Encrypted config.json uploaded successfully. ESP32 rebooted.', 'ok');
    recordProvisioningStep('serverUrl', cfgCopy.server_url);
    recordProvisioningStep('serverPort', cfgCopy.server_port);
    recordProvisioningStep('deviceId', cfgCopy.device_id);
    recordProvisioningStep('wifiSsid', cfgCopy.wifi_ssid);
    showProvisioningReport();
  } catch (err) {
    showStatus('configFileStatus', 'Error: ' + err.message, 'err');
  } finally {
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
    operationInProgress = false;
    resumeMonitor();
  }
}

function toggleManualForm() {
  var form = $('manualForm');
  form.classList.toggle('visible');
}

async function uploadManualConfig() {
  if (operationInProgress) {
    showStatus('manualConfigStatus', 'Another operation is running. Wait until it finishes.', 'warn');
    return;
  }
  hideStatus('manualConfigStatus');

  // Validate BEFORE acquiring the lock
  var wifiSsid = $('mWifiSsid').value.trim();
  var wifiPass = $('mWifiPass').value.trim();
  var serverUrl = $('mServerUrl').value.trim().replace(/^(https?:\/\/)+/, '$1');
  if (serverUrl && !/^https?:\/\//.test(serverUrl)) serverUrl = 'http://' + serverUrl;
  var serverPort = parseInt($('mServerPort').value) || 5000;
  var deviceId = $('mDeviceId').value.trim();
  var apiKey = $('mApiKey').value.trim();
  var deviceKeyHex = $('mDeviceKey').value.trim();
  var serverKeyHex = $('mServerKey').value.trim();
  var interval = parseInt($('mInterval').value) || 30;
  var location = $('mLocation').value.trim();

  var hexRegex = /^[0-9a-fA-F]{64}$/;
  if (!wifiSsid) {
    showStatus('manualConfigStatus', 'WiFi SSID is required.', 'err');
    return;
  }
  try { var u = new URL(serverUrl); if (u.protocol !== 'http:' && u.protocol !== 'https:') throw 0; }
  catch (_) { showStatus('manualConfigStatus', 'Invalid server URL, for example http://192.168.1.100.', 'err'); return; }
  if (!apiKey) {
    showStatus('manualConfigStatus', 'API Key is required.', 'err');
    return;
  }
  if (!hexRegex.test(deviceKeyHex)) {
    showStatus('manualConfigStatus', 'Device Key must contain exactly 64 hexadecimal characters, 0-9 and a-f.', 'err');
    return;
  }
  if (!hexRegex.test(serverKeyHex)) {
    showStatus('manualConfigStatus', 'Server Key must contain exactly 64 hexadecimal characters, 0-9 and a-f.', 'err');
    return;
  }

  // Acquire the operation lock only after validation passes.
  var mBtn = $('btnManualUpload');
  if (mBtn) { mBtn.disabled = true; mBtn.classList.add('loading'); }
  operationInProgress = true;

  var cfg = {
    wifi_ssid: wifiSsid,
    wifi_pass: wifiPass,
    server_url: serverUrl,
    server_port: serverPort,
    device_id: deviceId,
    api_key: apiKey,
    device_key_hex: deviceKeyHex.toLowerCase(),
    server_key_hex: serverKeyHex.toLowerCase(),
    read_interval_s: interval,
    location: location,
    thresholds: {
      temp_high: 35,
      temp_low: 18,
      humidity_high: 80,
      noise_high_v: 2.5,
      noise_medium_v: 2.0
    }
  };

  try {
    showStatus('manualConfigStatus', 'Encrypting and uploading config.json to the ESP32...', 'ok');
    var jsonStr = JSON.stringify(cfg, null, 2);
    await uploadConfigToDevice(jsonStr, 'manualConfigStatus');
    showStatus('manualConfigStatus', 'Encrypted config.json uploaded successfully. ESP32 rebooted.', 'ok');
    recordProvisioningStep('serverUrl', cfg.server_url);
    recordProvisioningStep('serverPort', cfg.server_port);
    recordProvisioningStep('deviceId', cfg.device_id);
    recordProvisioningStep('wifiSsid', cfg.wifi_ssid);
    showProvisioningReport();
  } catch (err) {
    showStatus('manualConfigStatus', 'Error: ' + err.message, 'err');
  } finally {
    if (mBtn) { mBtn.disabled = false; mBtn.classList.remove('loading'); }
    operationInProgress = false;
    resumeMonitor();
  }
}

// ─── CARD 5: MONITOR SERIAL ──────────────────────────────────
function classifyLine(line) {
  if (/error|fail|fatal|traceback|exception/i.test(line)) return 'log-error';
  if (/\bok\b|success|connected|readings stored/i.test(line)) return 'log-success';
  if (/warn|retry|409/i.test(line)) return 'log-warn';
  if (/config|device|firmware/i.test(line)) return 'log-info';
  return 'log-default';
}

function sanitizeMonitorLine(text) {
  return String(text)
    .replace(/server=http:\/\/(?:\d{1,3}\.){3}\d{1,3}:\d+/g, 'server=http://<local-ip>:<port>')
    .replace(/Already connected: (?:\d{1,3}\.){3}\d{1,3}/g, 'Already connected: <device-ip>')
    .replace(/Connected: (?:\d{1,3}\.){3}\d{1,3}/g, 'Connected: <device-ip>')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/g, 'Bearer <redacted>');
}

function appendLine(text, cls) {
  text = sanitizeMonitorLine(text);
  var con = $('serialConsole');
  var now = Date.now();
  var elapsed = monitorStartTime ? ((now - monitorStartTime) / 1000).toFixed(1) : '0.0';
  var ts = new Date(now).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

  // Store in the bounded monitor buffer.
  monitorLines.push({ text: text, cls: cls, ts: ts, elapsed: elapsed });
  if (monitorLines.length > MAX_LINES) monitorLines.shift();

  var div = document.createElement('div');
  div.className = 'log-line ' + cls;
  div.setAttribute('data-text', text.toLowerCase());

  if (showTimestamps) {
    var tsSpan = document.createElement('span');
    tsSpan.className = 'log-ts';
    tsSpan.textContent = '+' + elapsed + 's';
    div.appendChild(tsSpan);
  }

  div.appendChild(document.createTextNode(text));

  // Apply filter.
  if (currentFilter && !matchesFilter(text, currentFilter, null)) {
    div.classList.add('filtered');
  }

  con.appendChild(div);
  lineCount++;

  while (lineCount > MAX_LINES) {
    if (con.firstElementChild) { con.removeChild(con.firstElementChild); lineCount--; }
    else break;
  }

  // Batch scrolling through requestAnimationFrame to avoid one reflow per line
  // during bursts of serial output. The flag is stored on this function.
  if (!appendLine._scrollPending) {
    appendLine._scrollPending = true;
    requestAnimationFrame(function() {
      con.scrollTop = con.scrollHeight;
      appendLine._scrollPending = false;
    });
  }

  // Detect Redis 409 stale session error
  if (text.indexOf('409') !== -1 && text.indexOf('stale session') !== -1) showRedisAlert();
  if (text.indexOf('All stale session retries exhausted') !== -1) showRedisAlert();
}

// Accepts plain text substring filters or regex filters written as /pattern/.
// A precompiled RegExp can be passed to avoid recompiling it for each line.
function matchesFilter(text, filter, compiledRe) {
  if (compiledRe) return compiledRe.test(text);
  if (filter.length > 2 && filter[0] === '/' && filter[filter.length - 1] === '/') {
    try { return new RegExp(filter.slice(1, -1), 'i').test(text); } catch (_) { return true; }
  }
  return text.toLowerCase().indexOf(filter.toLowerCase()) !== -1;
}

var _filterTimer = null;
function applyFilter() {
  clearTimeout(_filterTimer);
  _filterTimer = setTimeout(function() {
    currentFilter = $('monFilterInput').value.trim();
    // Compile regex once when the filter is /pattern/.
    var compiledRe = null;
    if (currentFilter.length > 2 && currentFilter[0] === '/' && currentFilter[currentFilter.length - 1] === '/') {
      try { compiledRe = new RegExp(currentFilter.slice(1, -1), 'i'); } catch (_) { return; }
    }
    var lines = $('serialConsole').querySelectorAll('.log-line');
    for (var i = 0; i < lines.length; i++) {
      var lineText = lines[i].getAttribute('data-text') || lines[i].textContent;
      if (!currentFilter || matchesFilter(lineText, currentFilter, compiledRe)) {
        lines[i].classList.remove('filtered');
      } else {
        lines[i].classList.add('filtered');
      }
    }
  }, 150);
}

function toggleTimestamps() {
  showTimestamps = $('monTimestamps').checked;
}

function copyLog() {
  var lines;
  if (currentFilter) {
    lines = monitorLines.filter(function(l) { return matchesFilter(l.text, currentFilter); });
  } else {
    lines = monitorLines;
  }
  if (lines.length === 0) return;
  var text = lines.map(function(l) { return l.text; }).join('\n');
  var btn = $('btnCopyLog');
  navigator.clipboard.writeText(text).then(function() {
    var orig = btn.textContent;
    btn.textContent = ' Copied';
    setTimeout(function() { btn.textContent = orig; }, 2000);
  }).catch(function() {
    prompt('Copy manually:', text.substring(0, 2000));
  });
}

function exportLog() {
  if (monitorLines.length === 0) return;
  var content = monitorLines.map(function(l) {
    return '[' + l.ts + ' +' + l.elapsed + 's] ' + l.text;
  }).join('\n');
  var a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(content);
  a.setAttribute('download', 'serial-log-' + new Date().toISOString().slice(0, 19).replace(/:/g, '') + '.log');
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function showRedisAlert() {
  if (redisAlertShown) return;
  redisAlertShown = true;
  $('redisAlert').classList.add('visible');
}

function copyRedisCmd() {
  var cmd = $('redisCmd').textContent;
  navigator.clipboard.writeText(cmd).then(function() {
    var btn = document.querySelector('.redis-alert__copy');
    btn.textContent = 'Copied';
    setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
  }).catch(function() {
    prompt('Copy this command manually:', cmd);
  });
}

async function startMonitor(existingPort) {
  if (monitorRunning) return;
  autoReconnect = true;
  var btnStart = $('btnMonStart');
  var btnStop = $('btnMonStop');
  monitorStartTime = monitorStartTime || Date.now();

  try {
    if (existingPort) {
      monitorPort = existingPort;
    } else {
      monitorPort = await navigator.serial.requestPort({ filters: USB_FILTERS });
      await monitorPort.open({ baudRate: BAUD_RATE });
    }
    // Release DTR/RTS without resetting the running board, then drain the
    // non-printable byte burst some adapters emit when the port opens.
    try { await releaseSignalsNoReset(monitorPort); } catch (_) {}
    await serialDrain(monitorPort, 150, 1500);

    monitorRunning = true;
    btnStart.disabled = true;
    btnStop.disabled = false;

    var reader = monitorPort.readable.getReader();
    serialReader = reader;
    var decoder = new TextDecoder('utf-8', { fatal: false });
    var lineBuf = '';

    try {
      while (monitorRunning) {
        var result = await reader.read();
        var value = result.value;
        var done = result.done;
        if (done) break;

        lineBuf += decoder.decode(value, { stream: true });
        var parts = lineBuf.split('\n');
        lineBuf = parts.pop(); // keep incomplete fragment

        for (var pi = 0; pi < parts.length; pi++) {
          // Remove non-printable control bytes while preserving visible text.
          var line = parts[pi].replace(/[\x00-\x08\x0B-\x1F\x7F]/g, ''); // preserves \t
          line = sanitizeMonitorLine(line);
          if (line.length === 0) continue;
          appendLine(line, classifyLine(line));
        }
      }
    } catch (readErr) {
      if (monitorRunning) {
        appendLine('[Monitor error: ' + readErr.message + ']', 'log-error');
      }
    }

    // Flush the remaining buffer.
    if (lineBuf.length > 0) {
      var flushed = sanitizeMonitorLine(lineBuf.replace(/\r/g, ''));
      if (flushed.length > 0) {
        appendLine(flushed, classifyLine(flushed));
      }
    }

  } catch (err) {
    appendLine('[Connection error: ' + err.message + ']', 'log-error');
  } finally {
    var shouldReconnect = autoReconnect;
    if (serialReader) {
      try { await serialReader.cancel(); } catch (_) {}
      try { serialReader.releaseLock(); } catch (_) {}
      serialReader = null;
    }
    if (monitorPort) {
      await safeClosePort(monitorPort);
      monitorPort = null;
    }
    monitorRunning = false;
    var bStart = $('btnMonStart');
    var bStop = $('btnMonStop');
    if (bStart) bStart.disabled = false;
    if (bStop) bStop.disabled = true;

    // Auto-reconnect unless the monitor was stopped manually.
    if (shouldReconnect) {
      appendLine('[Monitor disconnected. Retrying in 3s...]', 'log-warn');
      await sleep(3000);
      if (autoReconnect) {
        try {
          await navigator.serial.getPorts();
          appendLine('[Monitor stopped. Press Start to reconnect to the correct port.]', 'log-warn');
        } catch (_) {
          appendLine('[Auto-reconnect unavailable.]', 'log-warn');
        }
      }
    }
  }
}

async function suspendMonitor() {
  if (!monitorRunning) return false;
  await stopMonitor();
  monitorSuspended = true;
  appendLine('[Monitor paused for serial operation]', 'log-warn');
  return true;
}

async function resumeMonitor() {
  if (!monitorSuspended) return;
  appendLine('[Resuming monitor...]', 'log-info');
  await sleep(TIMEOUTS.RESUME_DELAY);
  // Check that resume is still pending; another operation may have changed it.
  if (!monitorSuspended) return;
  monitorSuspended = false;
  // Use getPorts() instead of requestPort() to avoid requiring a user gesture.
  try {
    var ports = await navigator.serial.getPorts();
    if (ports.length > 0) {
      await ports[0].open({ baudRate: BAUD_RATE });
      startMonitor(ports[0]);
    } else {
      appendLine('[No authorized port found. Press Start.]', 'log-warn');
    }
  } catch (e) {
    appendLine('[Could not reconnect: ' + e.message + ']', 'log-warn');
  }
}

async function stopMonitor() {
  autoReconnect = false;
  monitorRunning = false;
  var btnStart = $('btnMonStart');
  var btnStop = $('btnMonStop');

  if (serialReader) {
    try { await serialReader.cancel(); } catch (_) {}
    try { serialReader.releaseLock(); } catch (_) {}
    serialReader = null;
  }
  if (monitorPort) {
    await safeClosePort(monitorPort);
    monitorPort = null;
  }

  btnStart.disabled = false;
  btnStop.disabled = true;
}

async function rebootDevice() {
  if (operationInProgress) return;
  operationInProgress = true;
  await suspendMonitor();
  var port = null;
  try {
    port = await navigator.serial.requestPort({ filters: USB_FILTERS });
    await port.open({ baudRate: BAUD_RATE });
    await sleep(200);
    await serialWrite(port, String.fromCharCode(3));
    await sleep(200);
    await serialWrite(port, String.fromCharCode(3));
    await sleep(200);
    await serialWrite(port, String.fromCharCode(4));
    await sleep(TIMEOUTS.REBOOT_WAIT);
    await safeClosePort(port);
    appendLine('[ESP32 rebooted through serial]', 'log-success');
  } catch (err) {
    if (err.name !== 'NotFoundError') {
      appendLine('[Reboot error: ' + err.message + ']', 'log-error');
    }
    await safeClosePort(port);
  } finally {
    operationInProgress = false;
  }
  await resumeMonitor();
}

function clearMonitor() {
  var con = $('serialConsole');
  con.textContent = '';
  lineCount = 0;
  monitorLines = [];
  redisAlertShown = false;
  $('redisAlert').classList.remove('visible');
}

// ─── CARD 5B: PROVISIONING REPORT ────────────────────────────
function recordProvisioningStep(key, value) {
  provisioningData[key] = value;
  provisioningData.timestamp = new Date().toISOString();
}

function showProvisioningReport() {
  var card = $('cardReport');
  var content = $('reportContent');
  if (!provisioningData.timestamp) return;

  var lines = [];
  lines.push('=== Provisioning Report ===');
  lines.push('Date: ' + provisioningData.timestamp);
  lines.push('');
  if (provisioningData.chip) {
    lines.push('--- Diagnostics ---');
    lines.push('Chip: ' + (provisioningData.chip || 'N/A'));
    lines.push('MAC: ' + (provisioningData.mac || 'N/A'));
    lines.push('Flash: ' + (provisioningData.flash || 'N/A'));
    lines.push('');
  }
  lines.push('--- Firmware ---');
  lines.push('MicroPython: ' + MICROPYTHON_VERSION);
  lines.push('Uploaded files: ' + (provisioningData.filesUploaded || 'N/A'));
  lines.push('Errors: ' + (provisioningData.filesErrors || '0'));
  lines.push('');
  if (provisioningData.serverUrl) {
    lines.push('--- Configuration ---');
    lines.push('Server: ' + provisioningData.serverUrl + ':' + (provisioningData.serverPort || ''));
    lines.push('Device ID: ' + (provisioningData.deviceId || 'N/A'));
    lines.push('WiFi SSID: ' + (provisioningData.wifiSsid || 'N/A'));
    lines.push('');
  }
  lines.push('--- Status ---');
  lines.push('Authentication: ' + (provisioningData.authStatus || 'Not confirmed, check the serial monitor'));

  content.textContent = lines.join('\n');
  card.classList.remove('hidden');
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function downloadReport() {
  var text = $('reportContent').textContent;
  var a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
  var id = provisioningData.deviceId || 'device';
  a.setAttribute('download', 'provisioning-report-' + id + '-' + new Date().toISOString().slice(0, 10) + '.txt');
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function generateQR() {
  if (typeof qrcode === 'undefined') {
    alert('QR library did not load. Check the local vendor bundle.');
    return;
  }
  var text = 'IoT DEVICE\n' +
    'ID: ' + (provisioningData.deviceId || '?') + '\n' +
    'MAC: ' + (provisioningData.mac || '?') + '\n' +
    'FW: MicroPython ' + MICROPYTHON_VERSION + '\n' +
    'Server: ' + (provisioningData.serverUrl || '').replace('http://', '').replace('https://', '') + ':' + (provisioningData.serverPort || '') + '\n' +
    'WiFi: ' + (provisioningData.wifiSsid || '?') + '\n' +
    'Date: ' + (provisioningData.timestamp || new Date().toISOString()).slice(0, 19);
  var qr;
  try {
    qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
  } catch (qrErr) {
    alert('QR generation error: ' + qrErr.message);
    return;
  }

  var canvas = $('qrCanvas');
  var size = 200;
  canvas.width = size;
  canvas.height = size;
  canvas.classList.remove('hidden');
  var ctx = canvas.getContext('2d');
  var cellSize = size / qr.getModuleCount();
  ctx.fillStyle = '#181825';
  ctx.fillRect(0, 0, size, size);
  ctx.fillStyle = '#a78bfa';
  for (var r = 0; r < qr.getModuleCount(); r++) {
    for (var c = 0; c < qr.getModuleCount(); c++) {
      if (qr.isDark(r, c)) {
        ctx.fillRect(c * cellSize, r * cellSize, cellSize + 0.5, cellSize + 0.5);
      }
    }
  }
}

// ─── CARD 6: DEVICE MANAGEMENT ───────────────────────────────
function switchMgmtTab(tabId) {
  var tabs = document.querySelectorAll('.mgmt-tab');
  var panels = document.querySelectorAll('.mgmt-panel');
  for (var i = 0; i < tabs.length; i++) tabs[i].classList.remove('active');
  for (var i = 0; i < panels.length; i++) panels[i].classList.add('hidden');
  $(tabId).classList.remove('hidden');
  var btns = document.querySelectorAll('.mgmt-tab');
  for (var i = 0; i < btns.length; i++) {
    if (btns[i].getAttribute('data-tab') === tabId) btns[i].classList.add('active');
  }
}

// --- Config Tab ---
async function readDeviceConfig() {
  if (operationInProgress) { showStatus('mgmtConfigStatus', 'Another operation is running.', 'warn'); return; }
  var confirmed = window.confirm(
    'This action decrypts the complete ESP32 configuration and brings it into the browser for local administration. Continue only on a trusted workstation.'
  );
  if (!confirmed) { return; }
  operationInProgress = true;
  var btn = $('btnReadConfig');
  btn.disabled = true; btn.classList.add('loading');
  hideStatus('mgmtConfigStatus');
  var port = null;
  try {
    showStatus('mgmtConfigStatus', 'Connecting to the ESP32...', 'ok');
    port = await connectAndEnterRepl();
    showStatus('mgmtConfigStatus', 'Decrypting config.json on the ESP32...', 'ok');
    var code = [
      'import config_manager',
      'try:',
      '    import ujson as json',
      'except ImportError:',
      '    import json',
      'cfg=config_manager.load()',
      "cfg.pop('device_key', None)",
      "cfg.pop('server_key', None)",
      "print('CFG_READ_START')",
      'print(json.dumps(cfg))',
      "print('CFG_READ_END')"
    ].join('\n');
    var result = await execAndCapture(port, code, 'CFG_READ_END', TIMEOUTS.PUF_DERIVE);
    await exitReplAndClose(port);
    port = null;

    // Parse: extract between CFG_READ_START and CFG_READ_END
    var startIdx = result.indexOf('CFG_READ_START');
    var endIdx = result.indexOf('CFG_READ_END');
    if (startIdx === -1 || endIdx === -1) throw new Error('Could not read config.json from the ESP32.');
    var jsonStr = result.substring(startIdx + 14, endIdx).trim();
    // Remove control characters.
    jsonStr = jsonStr.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '').trim();
    if (jsonStr.charAt(0) === '\n') jsonStr = jsonStr.substring(1);

    var cfg = JSON.parse(jsonStr);
    mgmtOriginalConfig = cfg;
    populateConfigForm(cfg);
    showStatus('mgmtConfigStatus', 'Configuration read successfully.', 'ok');
  } catch (err) {
    showStatus('mgmtConfigStatus', 'Error: ' + err.message, 'err');
    await safeClosePort(port);
  } finally {
    btn.disabled = false; btn.classList.remove('loading');
    operationInProgress = false;
    resumeMonitor();
  }
}

function populateConfigForm(cfg) {
  var container = $('mgmtConfigForm');
  container.classList.remove('hidden');
  container.textContent = '';

  var editableFields = [
    { key: 'wifi_ssid', label: 'WiFi SSID', type: 'text' },
    { key: 'wifi_pass', label: 'WiFi Password', type: 'password' },
    { key: 'server_url', label: 'Server URL', type: 'text' },
    { key: 'server_port', label: 'Server Port', type: 'number' },
    { key: 'read_interval_s', label: 'Interval (s)', type: 'number' },
    { key: 'location', label: 'Location', type: 'text' },
  ];
  var readonlyFields = [
    { key: 'device_id', label: 'Device ID' },
    { key: 'api_key', label: 'API Key', truncate: true },
    { key: 'device_key_hex', label: 'Device Key', truncate: true },
    { key: 'server_key_hex', label: 'Server Key', truncate: true },
  ];

  var grid = document.createElement('div');
  grid.className = 'mgmt-config-grid';

  function addField(key, label, type, value, readonly, full) {
    var field = document.createElement('div');
    field.className = 'mgmt-field' + (full ? ' full' : '');
    var lbl = document.createElement('label');
    lbl.textContent = label;
    lbl.setAttribute('for', 'mgmt-' + key);
    var inp = document.createElement('input');
    inp.type = type || 'text';
    inp.id = 'mgmt-' + key;
    inp.value = value !== null && value !== undefined ? value : '';
    if (readonly) { inp.readOnly = true; }
    field.appendChild(lbl);
    field.appendChild(inp);
    grid.appendChild(field);
  }

  for (var i = 0; i < editableFields.length; i++) {
    var f = editableFields[i];
    addField(f.key, f.label, f.type, cfg[f.key], false, f.key === 'server_url');
  }
  for (var i = 0; i < readonlyFields.length; i++) {
    var f = readonlyFields[i];
    var val = cfg[f.key];
    if (f.truncate && typeof val === 'string' && val.length > 12) val = val.substring(0, 8) + '...' + val.substring(val.length - 4);
    addField(f.key, f.label, 'text', val, true, f.key.indexOf('_key') !== -1);
  }

  container.appendChild(grid);
  $('btnSaveConfig').classList.remove('hidden');
}

async function saveDeviceConfig() {
  if (operationInProgress) { showStatus('mgmtConfigStatus', 'Another operation is running.', 'warn'); return; }
  if (!mgmtOriginalConfig) { showStatus('mgmtConfigStatus', 'Read the configuration first.', 'err'); return; }

  // Merge edited fields with the original configuration.
  var cfg = JSON.parse(JSON.stringify(mgmtOriginalConfig));
  cfg.wifi_ssid = $('mgmt-wifi_ssid').value.trim();
  cfg.wifi_pass = $('mgmt-wifi_pass').value;
  var sUrl = $('mgmt-server_url').value.trim().replace(/^(https?:\/\/)+/, '$1');
  if (sUrl && !/^https?:\/\//.test(sUrl)) sUrl = 'http://' + sUrl;
  cfg.server_url = sUrl;
  cfg.server_port = parseInt($('mgmt-server_port').value) || cfg.server_port;
  cfg.read_interval_s = parseInt($('mgmt-read_interval_s').value) || cfg.read_interval_s;
  cfg.location = $('mgmt-location').value.trim();

  if (!cfg.wifi_ssid) { showStatus('mgmtConfigStatus', 'WiFi SSID is required.', 'err'); return; }

  operationInProgress = true;
  var btn = $('btnSaveConfig');
  btn.disabled = true; btn.classList.add('loading');
  try {
    showStatus('mgmtConfigStatus', 'Encrypting and saving configuration on the ESP32...', 'ok');
    var jsonStr = JSON.stringify(cfg, null, 2);
    await uploadConfigToDevice(jsonStr, 'mgmtConfigStatus');
    showStatus('mgmtConfigStatus', 'Configuration updated. ESP32 rebooted.', 'ok');
    mgmtOriginalConfig = cfg;
  } catch (err) {
    showStatus('mgmtConfigStatus', 'Error: ' + err.message, 'err');
  } finally {
    btn.disabled = false; btn.classList.remove('loading');
    operationInProgress = false;
    resumeMonitor();
  }
}

// --- Files Tab ---
async function readDeviceFiles() {
  if (operationInProgress) { showStatus('mgmtFileStatus', 'Another operation is running.', 'warn'); return; }
  operationInProgress = true;
  var btn = $('btnReadFiles');
  btn.disabled = true; btn.classList.add('loading');
  hideStatus('mgmtFileStatus');
  var port = null;
  try {
    showStatus('mgmtFileStatus', 'Connecting to the ESP32...', 'ok');
    port = await connectAndEnterRepl();
    showStatus('mgmtFileStatus', 'Reading filesystem...', 'ok');
    var result = await execAndCapture(port, FS_LIST_CMD, 'FS_END', TIMEOUTS.FILE_OP);
    await exitReplAndClose(port);
    port = null;

    var files = parseFileListing(result);

    displayFileList(files);
    showStatus('mgmtFileStatus', files.length + ' file(s) found.', 'ok');
  } catch (err) {
    showStatus('mgmtFileStatus', 'Error: ' + err.message, 'err');
    await safeClosePort(port);
  } finally {
    btn.disabled = false; btn.classList.remove('loading');
    operationInProgress = false;
    resumeMonitor();
  }
}

function displayFileList(files) {
  var container = $('mgmtFileList');
  container.classList.remove('hidden');
  container.textContent = '';

  var table = document.createElement('div');
  table.className = 'mgmt-file-table';

  var presentNames = files.map(function(f) { return f.name; });
  var missing = KNOWN_FIRMWARE.filter(function(kf) { return presentNames.indexOf(kf) === -1; });

  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    var row = document.createElement('div');
    row.className = 'mgmt-file-row';

    var icon = document.createElement('span');
    icon.className = 'mgmt-file-icon';
    var isFw = KNOWN_FIRMWARE.indexOf(f.name) !== -1;
    var isCfg = f.name === 'config.json';
    icon.textContent = isFw ? '\u2713' : (isCfg ? '\u2699' : '\u25CB');
    icon.style.color = isFw ? 'var(--success)' : (isCfg ? 'var(--warning)' : 'var(--accent-mp)');

    var name = document.createElement('span');
    name.className = 'mgmt-file-name';
    name.textContent = f.name;

    var badge = document.createElement('span');
    badge.className = 'mgmt-badge ' + (isFw ? 'fw' : (isCfg ? 'config' : 'custom'));
    badge.textContent = isFw ? 'firmware' : (isCfg ? 'config' : 'custom');

    var size = document.createElement('span');
    size.className = 'mgmt-file-size';
    size.textContent = f.size < 1024 ? f.size + ' B' : (f.size / 1024).toFixed(1) + ' KB';

    var del = document.createElement('button');
    del.type = 'button';
    del.className = 'mgmt-file-del';
    del.title = 'Delete ' + f.name;
    del.setAttribute('aria-label', 'Delete ' + f.name);
    del.setAttribute('data-file', f.name);
    del.onclick = function() { deleteDeviceFile(this.getAttribute('data-file')); };
    del.textContent = '\u2715';

    row.appendChild(icon);
    row.appendChild(name);
    row.appendChild(badge);
    row.appendChild(size);
    row.appendChild(del);
    table.appendChild(row);
  }

  container.appendChild(table);

  // Show missing firmware files warning.
  if (missing.length > 0) {
    var warn = document.createElement('div');
    warn.className = 'mgmt-missing-list';
    warn.textContent = 'Missing ' + missing.length + ' firmware file(s): ' + missing.join(', ');
    container.appendChild(warn);
  }

  // Show dropzone.
  $('mgmtDropzone').classList.remove('hidden');
}

async function deleteDeviceFile(filename) {
  if (operationInProgress) { showStatus('mgmtFileStatus', 'Another operation is running.', 'warn'); return; }
  try { filename = sanitizeFilename(filename); } catch (e) {
    showStatus('mgmtFileStatus', e.message, 'err'); return;
  }
  if (!confirm('Delete /' + filename + ' from the ESP32?')) return;

  operationInProgress = true;
  hideStatus('mgmtFileStatus');
  var port = null;
  try {
    showStatus('mgmtFileStatus', 'Deleting ' + filename + '...', 'ok');
    port = await connectAndEnterRepl();
    await execRawRepl(port, "import os;os.remove('/" + filename + "')");

    // Refresh file list
    var lsCode = FS_LIST_CMD;
    var lsResult = await execAndCapture(port, lsCode, 'FS_END', TIMEOUTS.FILE_OP);
    await exitReplAndClose(port);
    port = null;

    var files = parseFileListing(lsResult);
    displayFileList(files);
    showStatus('mgmtFileStatus', filename + ' deleted.', 'ok');
  } catch (err) {
    showStatus('mgmtFileStatus', 'Delete error: ' + err.message, 'err');
    await safeClosePort(port);
  } finally {
    operationInProgress = false;
    resumeMonitor();
  }
}

async function uploadMgmtFiles(fileList) {
  if (operationInProgress) { showStatus('mgmtFileStatus', 'Another operation is running.', 'warn'); return; }

  // Validate extensions and sanitize names.
  var validFiles = [];
  for (var i = 0; i < fileList.length; i++) {
    var safeName;
    try { safeName = sanitizeFilename(fileList[i].name); } catch (e) {
      showStatus('mgmtFileStatus', e.message, 'err');
      return;
    }
    if (safeName === 'config.json' || safeName.endsWith('.json')) {
      showStatus('mgmtFileStatus', '.json files must be loaded from the Config tab for PUF-bound encryption: ' + safeName, 'err');
      return;
    }
    if (safeName.endsWith('.py')) {
      validFiles.push({ file: fileList[i], safeName: safeName });
    } else {
      showStatus('mgmtFileStatus', 'Ignored file, only .py is accepted: ' + safeName, 'warn');
    }
  }
  if (validFiles.length === 0) return;

  operationInProgress = true;
  hideStatus('mgmtFileStatus');
  var port = null;
  try {
    showStatus('mgmtFileStatus', 'Connecting to the ESP32...', 'ok');
    port = await connectAndEnterRepl();
    var results = [];

    for (var fi = 0; fi < validFiles.length; fi++) {
      var entry = validFiles[fi];
      var safeName = entry.safeName;
      showStatus('mgmtFileStatus', 'Uploading ' + safeName + ' (' + (fi + 1) + '/' + validFiles.length + ')...', 'ok');

      var content = await entry.file.text();
      var tmpName = '/' + safeName + '.tmp';
      var finalName = '/' + safeName;

      try {
        // Atomic write: write to .tmp first, then rename.
        await execRawRepl(port, "f=open('" + tmpName + "','w')");
        for (var ci = 0; ci < content.length; ci += CHUNK_SIZE) {
          var chunk = escapeForPythonString(content.slice(ci, ci + CHUNK_SIZE));
          await execRawRepl(port, "f.write('" + chunk + "')");
        }
        await execRawRepl(port, "f.close()");
        // Atomic rename: original untouched until this succeeds
        await execRawRepl(port, "import os;os.rename('" + tmpName + "','" + finalName + "')");
        results.push(safeName + ': OK');
      } catch (err) {
        try { await execRawRepl(port, "f.close()"); } catch (_) {}
        // Clean up .tmp if it exists
        try { await execRawRepl(port, "import os;os.remove('" + tmpName + "')"); } catch (_) {}
        results.push(safeName + ': ERROR - ' + err.message);
      }
    }

    // Read the file list again for verification.
    showStatus('mgmtFileStatus', 'Verifying files...', 'ok');
    var lsCode = FS_LIST_CMD;
    var lsResult = await execAndCapture(port, lsCode, 'FS_END', TIMEOUTS.FILE_OP);

    // Soft reboot the ESP32 after file changes.
    showStatus('mgmtFileStatus', 'Rebooting ESP32...', 'ok');
    await serialWrite(port, String.fromCharCode(2)); // Ctrl-B exit raw REPL
    await sleep(200);
    await serialWrite(port, String.fromCharCode(4)); // Ctrl-D soft reboot
    await sleep(1000);
    await safeClosePort(port);
    port = null;

    // Parse and refresh display
    var files = parseFileListing(lsResult);
    displayFileList(files);

    var errCount = results.filter(function(r) { return r.indexOf('ERROR') !== -1; }).length;
    if (errCount > 0) {
      showStatus('mgmtFileStatus', errCount + ' error(s). ' + results.join('; '), 'err');
    } else {
      showStatus('mgmtFileStatus', validFiles.length + ' file(s) uploaded successfully.', 'ok');
    }
  } catch (err) {
    showStatus('mgmtFileStatus', 'Error: ' + err.message, 'err');
    await safeClosePort(port);
  } finally {
    operationInProgress = false;
    resumeMonitor();
  }
}

// ─── WIFI SCANNER ─────────────────────────────────────────────
async function scanWifi(targetInputId) {
  if (operationInProgress) return;
  operationInProgress = true;
  await suspendMonitor();
  var scanPort = null;
  var ownPort = false;
  try {
    // Use existing serialPort or request new one
    if (serialPort && serialPort.readable) {
      scanPort = serialPort;
    } else {
      scanPort = await navigator.serial.requestPort({ filters: USB_FILTERS });
      await scanPort.open({ baudRate: BAUD_RATE });
      ownPort = true;
      await sleep(200);
    }

    // Robust Raw REPL entry after the reset caused by opening the port.
    await enterRawRepl(scanPort);

    // Scan WiFi networks (bypass execRawRepl: need to wait for SCAN_END, not OK)
    var scanCode = "import network; s=network.WLAN(network.STA_IF); s.active(True); nets=s.scan(); print('SCAN_START'); [print(str(n[0],'utf-8')+'|'+str(n[3])+'|'+str(n[4])) for n in sorted(nets,key=lambda x:-x[3])]; print('SCAN_END')";
    await serialWrite(scanPort, scanCode + '\r\n');
    await serialWrite(scanPort, String.fromCharCode(4)); // Ctrl-D execute
    // Wait for SCAN_END (scan takes 3-5s on ESP32)
    var result = await serialReadUntil(scanPort, 'SCAN_END', TIMEOUTS.WIFI_SCAN);

    // Exit Raw REPL.
    await serialWrite(scanPort, String.fromCharCode(2));

    if (ownPort) {
      await safeClosePort(scanPort);
    }

    // Parse results
    var lines = result.split('\n');
    var networks = [];
    var capturing = false;
    for (var si = 0; si < lines.length; si++) {
      var ln = lines[si].replace(/\r/g, '').trim();
      if (ln.indexOf('SCAN_START') !== -1) { capturing = true; continue; }
      if (ln.indexOf('SCAN_END') !== -1) break;
      if (capturing && ln.indexOf('|') !== -1) {
        var parts = ln.split('|');
        var ssid = parts[0].trim();
        var rssi = parseInt(parts[1]) || -99;
        var authMode = parseInt(parts[2]) || 0;
        if (ssid.length > 0) {
          networks.push({ ssid: ssid, rssi: rssi, open: authMode === 0 });
        }
      }
    }

    if (networks.length === 0) {
      alert('No WiFi networks were found. Check that the ESP32 antenna is available.');
      return;
    }

    // Populate select dropdown
    var selectId = targetInputId === 'cfgWifiSsid' ? 'cfgWifiSelect' : 'mWifiSelect';
    var select = $(selectId);
    select.textContent = '';
    var defOpt = document.createElement('option');
    defOpt.value = '';
    defOpt.textContent = networks.length + ' networks found:';
    select.appendChild(defOpt);
    for (var ni = 0; ni < networks.length; ni++) {
      var opt = document.createElement('option');
      opt.value = networks[ni].ssid;
      var bars = networks[ni].rssi > -50 ? '\u2593\u2593\u2593\u2593' : networks[ni].rssi > -70 ? '\u2593\u2593\u2593\u2591' : networks[ni].rssi > -80 ? '\u2593\u2593\u2591\u2591' : '\u2593\u2591\u2591\u2591';
      opt.textContent = networks[ni].ssid + '  ' + bars + '  (' + networks[ni].rssi + ' dBm)' + (networks[ni].open ? ' [OPEN]' : '');
      select.appendChild(opt);
    }
    select.classList.remove('hidden');

  } catch (err) {
    alert('WiFi scan error: ' + err.message);
    if (ownPort && scanPort) {
      await safeClosePort(scanPort);
    }
  } finally {
    operationInProgress = false;
    resumeMonitor();
  }
}

// ─── DOCUMENTATION MODAL ─────────────────────────────────────
function openDocsModal() {
  var overlay = $('docsOverlay');
  docsPreviousFocus = document.activeElement;
  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
  var closeBtn = $('docsCloseBtn');
  if (closeBtn) closeBtn.focus();
}

function closeDocsModal() {
  $('docsOverlay').classList.remove('open');
  document.body.style.overflow = '';
  if (docsPreviousFocus) { docsPreviousFocus.focus(); docsPreviousFocus = null; }
}

// ─── INITIALIZATION ───────────────────────────────────────────
function setupDropzone() {
  // Config dropzone (Card 4)
  var dz = $('configDropzone');
  var fi = $('configFileInput');
  if (dz && fi) {
    dz.addEventListener('click', function() { fi.click(); });
    dz.addEventListener('keydown', function(e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fi.click(); } });
    dz.addEventListener('dragover', function(e) { e.preventDefault(); dz.classList.add('drag-over'); });
    dz.addEventListener('dragleave', function() { dz.classList.remove('drag-over'); });
    dz.addEventListener('drop', function(e) {
      e.preventDefault();
      dz.classList.remove('drag-over');
      var file = e.dataTransfer.files[0];
      if (file) loadConfigFile(file);
    });
    fi.addEventListener('change', function() {
      if (fi.files[0]) loadConfigFile(fi.files[0]);
    });
  }

  // Management file upload dropzone (Card 6)
  var mdz = $('mgmtDropzone');
  var mfi = $('mgmtFileInput');
  if (mdz && mfi) {
    mdz.addEventListener('click', function() { mfi.click(); });
    mdz.addEventListener('keydown', function(e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); mfi.click(); } });
    mdz.addEventListener('dragover', function(e) { e.preventDefault(); mdz.classList.add('drag-over'); });
    mdz.addEventListener('dragleave', function() { mdz.classList.remove('drag-over'); });
    mdz.addEventListener('drop', function(e) {
      e.preventDefault();
      mdz.classList.remove('drag-over');
      if (e.dataTransfer.files.length > 0) uploadMgmtFiles(e.dataTransfer.files);
    });
    mfi.addEventListener('change', function() {
      if (mfi.files.length > 0) uploadMgmtFiles(mfi.files);
      mfi.value = '';
    });
  }
}

function initEventListeners() {
  // Card 1: Diagnostics
  $('btnDiag').addEventListener('click', runDiagnostics);

  // Card 2: Flash MicroPython
  $('btnFlash').addEventListener('click', flashMicroPython);

  // Card 3: Upload files
  $('btnUpload').addEventListener('click', uploadFiles);

  // Docs button
  var docsBtn = document.querySelector('[data-action="open-docs"]');
  if (docsBtn) docsBtn.addEventListener('click', openDocsModal);

  // Card 4: Config WiFi scan buttons
  var wifiScanBtns = document.querySelectorAll('[data-scan-target]');
  for (var i = 0; i < wifiScanBtns.length; i++) {
    (function(btn) {
      btn.addEventListener('click', function() {
        scanWifi(btn.getAttribute('data-scan-target'));
      });
    })(wifiScanBtns[i]);
  }

  // Card 4: WiFi select dropdowns
  $('cfgWifiSelect').addEventListener('change', function() {
    var target = this.getAttribute('data-target-input');
    if (this.value && target) $(target).value = this.value;
  });
  $('mWifiSelect').addEventListener('change', function() {
    var target = this.getAttribute('data-target-input');
    if (this.value && target) $(target).value = this.value;
  });

  // Card 4: Upload config
  $('btnUploadConfig').addEventListener('click', uploadConfigFromFile);

  // Card 4: Manual toggle
  $('manualToggle').addEventListener('click', toggleManualForm);

  // Card 4: Manual upload
  $('btnManualUpload').addEventListener('click', uploadManualConfig);

  // Card 5: Monitor
  $('btnMonStart').addEventListener('click', function() { startMonitor(); });
  $('btnMonStop').addEventListener('click', stopMonitor);
  $('btnClearMon').addEventListener('click', clearMonitor);
  $('btnReboot').addEventListener('click', rebootDevice);
  $('btnExportLog').addEventListener('click', exportLog);
  $('btnCopyLog').addEventListener('click', copyLog);
  $('monTimestamps').addEventListener('change', toggleTimestamps);
  $('monFilterInput').addEventListener('input', applyFilter);

  // Card 5B: Report
  $('btnDownloadReport').addEventListener('click', downloadReport);
  $('btnQR').addEventListener('click', generateQR);
  $('btnRedisCmd').addEventListener('click', copyRedisCmd);

  // Card 6: Management tabs
  var mgmtTabs = document.querySelectorAll('.mgmt-tab[data-tab]');
  for (var ti = 0; ti < mgmtTabs.length; ti++) {
    (function(tab) {
      tab.addEventListener('click', function() {
        switchMgmtTab(tab.getAttribute('data-tab'));
      });
    })(mgmtTabs[ti]);
  }

  // Card 6: Config tab
  $('btnReadConfig').addEventListener('click', readDeviceConfig);
  $('btnSaveConfig').addEventListener('click', saveDeviceConfig);

  // Card 6: Files tab
  $('btnReadFiles').addEventListener('click', readDeviceFiles);

  // Docs overlay: close on background click
  var docsOverlay = $('docsOverlay');
  if (docsOverlay) {
    docsOverlay.addEventListener('click', function(event) {
      if (event.target === this) closeDocsModal();
    });
  }

  // Docs close button
  $('docsCloseBtn').addEventListener('click', closeDocsModal);

  // Escape key closes docs
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeDocsModal();
  });

  // Dropzone setup
  setupDropzone();
}

document.addEventListener('DOMContentLoaded', function() {
  if (!('serial' in navigator)) {
    var c = document.querySelector('.container');
    c.textContent = '';
    var card = document.createElement('div');
    card.className = 'card';
    card.style.cssText = 'text-align:center;padding:3rem';
    var h = document.createElement('h2');
    h.style.color = 'var(--error)';
    h.textContent = 'Unsupported Browser';
    var p = document.createElement('p');
    p.style.cssText = 'color:var(--text-secondary);margin-top:1rem';
    p.textContent = 'This tool requires the Web Serial API. Use Google Chrome or Microsoft Edge on desktop.';
    card.appendChild(h);
    card.appendChild(p);
    c.appendChild(card);
    return;
  }
  initEventListeners();
});
