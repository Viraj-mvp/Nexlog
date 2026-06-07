# NexLog Release & Packaging Guide

This document explains how to package NexLog v1.0.0 for Windows and Linux, build standalone desktop ZIPs, compile the clean source archive, and use GitHub Actions to draft the release.

---

## 1. Release Assets

When preparing the first public release, publish these files:

| File Name Template | Target Audience | Contents |
| :--- | :--- | :--- |
| **`NexLog-v1.0.0-windows-x64.zip`** | **Windows Users (GUI/CLI)** | Standalone compiled `NexLog.exe`, template configs, sample logs, README, and license. No Python installation required. |
| **`NexLog-v1.0.0-linux-x64.zip`** | **Linux / Kali Users (GUI/CLI)** | Portable compiled `NexLog` binary, configuration template, sample logs, README, and license. |
| **`NexLog-v1.0.0-source.zip`** | **Developers & Power Users** | Clean source code without local caches, `.venv`, workspace data, database journals, or secret files. Pip-installable. |

macOS packaging is intentionally skipped for v1.0.0. The source remains portable, but published desktop binaries are Windows and Linux only.

---

## 2. Local Windows Build

Run this from a clean release checkout on Windows:

```powershell
# 1. Activate your virtual environment
.venv\Scripts\Activate.ps1

# 2. Install release dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 3. Remove generated artifacts, keeping .env local
python scripts/clean_project.py --apply

# 4. Run the release gate
python -B scripts/release_check.py --allow-local-env

# 5. Create the Windows standalone ZIP and clean source ZIP
python scripts/package_release.py --all
```

The packaging script builds `release/NexLog-v1.0.0-source.zip` and `release/NexLog-v1.0.0-windows-x64.zip` on Windows. Linux binaries must be built on Linux, normally through GitHub Actions.

---

## 3. Automated GitHub Release

The automated release workflow lives at `.github/workflows/release.yml`. It runs when a version tag is pushed and drafts a GitHub release with Windows, Linux, and source ZIP assets.

```bash
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

The workflow:

1. Builds the clean source ZIP on Ubuntu.
2. Builds the Windows x64 ZIP on `windows-latest`.
3. Builds the Linux x64 ZIP on `ubuntu-latest`.
4. Downloads all build artifacts.
5. Creates a draft GitHub release for review.

Review the draft release, download and smoke-test the assets, then publish it manually.

---

## 4. Unsigned Portable Build Notes

NexLog v1.0.0 ZIPs are unsigned portable builds.

On Windows, SmartScreen may warn before first launch because the executable is not Authenticode signed.

On Linux, users may need to mark the extracted binary executable:

```bash
chmod +x NexLog
```

Code signing and notarization should be added in a later release for smoother OS trust prompts.

---

## 5. Troubleshooting

### PermissionError when generating ZIPs

Close any running `NexLog.exe`, Python sessions, or file browser previews that may be holding files in `release/`, `build/`, or `dist/`.

### Antivirus false positives

Fresh PyInstaller binaries can trigger aggressive antivirus heuristics. For local testing, try the portable folder fallback by running:

```powershell
python scripts/package_release.py --binary
```

For production trust, add code signing in a later release.
