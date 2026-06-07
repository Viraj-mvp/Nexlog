# NexLog Startup Guide

NexLog is a local-first DFIR log investigation cockpit. The desktop GUI, CLI, and web cockpit all use the same backend, case database, detection rules, and export pipeline.

## Quick Start

```powershell
# Desktop GUI
python -B main_gui.py

# Desktop GUI with conservative hardware settings
python -B main_gui.py --hardware-mode conservative

# Full non-interactive GUI launch preflight
python -B main_gui.py --preflight

# CLI analysis
python -B main.py examples/logs/Apache_2k.log --case workspace/smoke.facase --report none

# Local web cockpit
python -B -m interface.web.serve --host 127.0.0.1 --port 8000
```

Open the web cockpit at `http://127.0.0.1:8000`.

If you changed the browser UI source, rebuild it first:

```powershell
cd website
npm install
npm run build
cd ..
```

## Web API Key

For anything beyond local health checks, set a NexLog API key:

```powershell
$env:NEXLOG_API_KEY = (python scripts/generate_api_key.py).Trim()
python -B -m interface.web.serve --host 127.0.0.1 --port 8000
```

To persist a web-only key in `.env.web`, run:

```powershell
python scripts/generate_api_key.py --write-env-web --force
```

For separate web and desktop secrets, copy the example files and keep the real
files local:

```text
.env.web    NEXLOG_WEB_API_KEY, NEXLOG_WEB_GROQ_API_KEY, NEXLOG_WEB_GEMINI_API_KEY
.env.gui    NEXLOG_GUI_GROQ_API_KEY, NEXLOG_GUI_GEMINI_API_KEY, NEXLOG_GUI_OLLAMA_HOST
.env.shared shared non-secret runtime defaults
```

The web browser only stores the NexLog API access key. Provider keys stay in
the Python server process.

For team access, bind explicitly to a trusted interface and put NexLog behind TLS/reverse proxy:

```powershell
$env:NEXLOG_API_KEY = "nexlog_change_this_to_a_long_random_value"
python -B -m interface.web.serve --host 0.0.0.0 --port 8000
```

Use an `X-API-Key` header for protected API calls.

## Hardware Modes

NexLog supports three runtime modes:

| Mode | Best For | Behavior |
|------|----------|----------|
| `adaptive` | Normal laptops and desktops | Balanced workers, bounded graph detail, GPU/QML acceleration when stable, automatic reduced effects under pressure. |
| `performance` | Workstations and demos | More workers, larger batches, smoother graph visuals, higher CPU/GPU use. |
| `conservative` | Low RAM, old GPUs, long evidence runs | Fewer workers, smaller batches, reduced motion, software rendering preference, lower CPU pressure. |

Set the mode with CLI flags or environment variables:

```powershell
$env:NEXLOG_HARDWARE_MODE = "adaptive"
$env:NEXLOG_MAX_WORKERS = "2"
$env:NEXLOG_BATCH_SIZE = "5000"
$env:NEXLOG_MAX_MEMORY_MB = "2048"
$env:NEXLOG_MAX_CPU_PERCENT = "75"
$env:NEXLOG_MAX_LINE_BYTES = "1048576"
$env:NEXLOG_GPU_GUI = "auto"
```

The GUI also exposes a Performance Mode card in Tools so you can switch modes without editing environment variables. Restart the GUI after changing GPU mode if you want Qt to fully reload the renderer.

## Recommended Configs

| Machine | Recommended Mode | Suggested Settings |
|---------|------------------|-------------------|
| Low-end laptop, 4-8 GB RAM | `conservative` | `NEXLOG_MAX_WORKERS=1`, `NEXLOG_BATCH_SIZE=2000`, reduced motion on. |
| Normal laptop, 8-16 GB RAM | `adaptive` | Defaults are usually safe. |
| Workstation, 16-64 GB RAM | `performance` | Increase workers and batch size only if the UI remains responsive. |
| Demo/screenshot machine | `performance` | Use smaller sample logs, keep graph animations enabled. |

## Large Log Safety

NexLog is designed for bounded-memory analysis:

- Logs are parsed in batches.
- Findings are saved to SQLite per batch.
- Resume checkpoints include byte offset, line number, file size, mtime, and fingerprint.
- Enrichment and graph/story building are queued after parsing so the GUI can show results quickly.
- Individual huge lines are capped by `NEXLOG_MAX_LINE_BYTES`.

Resume a plain-text seekable log job:

```powershell
python -B main.py huge.log --case workspace/case.facase --profile fast --report none
python -B main.py huge.log --case workspace/case.facase --resume JOB_ID --report none
```

Compressed archives and binary EVTX files are handled safely, but true byte-offset resume is only available for seekable plain-text style logs.

## Failsafe Notes

NexLog can reduce overload risk with worker limits, bounded batches, line caps, disk checks, software-rendering fallback, and conservative mode. No software can guarantee physical hardware protection. Keep the machine ventilated, avoid running huge jobs on low battery, and use conservative mode for long investigations on laptops.

## Troubleshooting

- GUI does not open: run `python -B main_gui.py --hardware-mode conservative`.
- GUI still does not open: run `python -B main_gui.py --preflight`; NexLog will retry QML in safe software-rendering mode and print diagnostics. The old Widgets GUI is no longer used as a runtime fallback.
- Web says API key missing: set `NEXLOG_API_KEY`.
- Analysis is slow: use `--profile fast`, lower severity filters, or run in `performance` mode on a workstation.
- Machine feels overloaded: switch to `conservative`, reduce `NEXLOG_MAX_WORKERS`, and lower `NEXLOG_BATCH_SIZE`.
- Packaged build check: run `python -B main_gui.py --packaged-check` or the stronger `python -B main_gui.py --preflight`.

## Publishing Checklist

Run the launch gate before sharing the app:

```powershell
python -B scripts/launch_check.py
```

Clean generated local artifacts before GitHub or ZIP publishing:

```powershell
python scripts/clean_project.py
python scripts/clean_project.py --apply
```

The cleaner keeps `.env` by default. Only remove it on a release machine:

```powershell
python scripts/clean_project.py --apply --include-sensitive
```

Run release checks:

```powershell
# Development machine with local .env kept
python -B scripts/release_check.py --allow-local-env

# Strict release machine
python -B scripts/release_check.py --launch-deep
```

Do not publish `node_modules`, `.env`, `workspace`, caches, case databases, journals, generated reports, `build`, `dist`, or `release` contents. See `LAUNCH_CHECKLIST.md` for the full checklist.
