# Contributing To NexLog

Thanks for helping improve NexLog.

## Development Setup

```bash
python -m venv .venv
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -B main.py --help
python -B main_gui.py --help
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

On Linux/macOS:

```bash
source .venv/bin/activate
```

## Before Opening A PR

Run:

```bash
python -B main.py --help
python -B main_gui.py --packaged-check
python -B -m pytest tests/unit/test_security.py -q -p no:cacheprovider
python scripts/release_check.py
```

## Guidelines

- Keep NexLog local-first and privacy-preserving by default.
- Do not commit `.env`, evidence, case databases, generated reports, caches, or virtual environments.
- Keep heavy AI features lazy so GUI startup remains fast.
- Preserve compatibility with legacy `NEXLOG_*` environment variables unless a migration is documented.
