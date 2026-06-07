# NexLog Setup Guide

NexLog is a Python-based, local-first DFIR log investigation cockpit. Source
mode supports Windows, Linux, and macOS. Packaged binaries are built separately
for each operating system.

## Install From Source

```bash
python -m venv .venv
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -B main.py --help
python -B main_gui.py --help
```

Windows activation:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux/macOS activation:

```bash
source .venv/bin/activate
```

## Run The GUI

```bash
python main_gui.py
```

Packaged-resource smoke check:

```bash
python main_gui.py --packaged-check
```

## Run CLI Analysis

```bash
python main.py examples/logs/Apache_2k.log --severity LOW --report none --quiet
```

## Build Release Artifacts

```bash
python scripts/clean_project.py
python scripts/release_check.py
python scripts/package_release.py --source-zip
python scripts/package_release.py --binary
```

On Windows, `--binary` creates a native Windows build. Use `--exe` when you
specifically want to enforce a Windows `.exe` build.

## Environment

Use `.env.example` as a template. Never commit `.env` or real API keys. NexLog
uses `NEXLOG_*` variables for public configuration.
