# ROTP-PUF-FLASHER Manuscript

`main.pdf` is the compiled manuscript for public release 1.0: 15 pages in Springer LNCS/CCIS format. It includes the final validation described in the paper: two ESP32-WROOM-32D boards completed three clean E2E runs per board with encrypted `config.json`, Wi-Fi, NTP, puzzle authentication returning HTTP 200, token acquisition, telemetry accepted with HTTP 201, MongoDB readings, and positive Redis session state.

The central limit remains unchanged: server-mediated key and configuration origin is future thesis or journal work, and the reversible no-Secure-Boot line does not protect against physical loader replacement.

The bibliography has 25 references.

## Requirements

TeX Live with the Springer class. On a minimal BasicTeX installation:

```bash
sudo tlmgr install llncs
```

This provides `llncs.cls` and `splncs04.bst`.

## Build

```bash
pdflatex fig_architecture.tex
latexmk -pdf -interaction=nonstopmode main.tex
```

Expected output: `main.pdf`, 15 pages, 25 references, no undefined citations, and no undefined references.

## Files

| File | Description |
|---|---|
| `main.tex` | Main manuscript source |
| `main.pdf` | Compiled paper |
| `references.bib` | BibTeX bibliography |
| `fig_architecture.tex` | TikZ source for the architecture figure |
| `fig_architecture.pdf` | Compiled figure included by `main.tex` |
