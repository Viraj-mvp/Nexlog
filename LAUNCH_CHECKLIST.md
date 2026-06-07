# NexLog Launch Checklist

Use this checklist before publishing NexLog or sending a build to another user.

## Daily Launch Checks

```powershell
python -B main_gui.py --preflight
python -B scripts/launch_check.py --skip-tests
```

Expected result: all checks print `OK` and the final line says the launch gate passed.

## Full Release Gate

```powershell
python -B scripts/launch_check.py
python -B scripts/release_check.py --allow-local-env
```

Before creating a public ZIP or executable, clean generated files:

```powershell
python scripts/clean_project.py
python scripts/clean_project.py --apply
```

`.env` is local-only and is not removed by default. For a clean release machine only:

```powershell
python scripts/clean_project.py --apply --include-sensitive
python -B scripts/release_check.py --launch-deep
```

## If The GUI Does Not Open

Try the safe renderer first:

```powershell
python -B main_gui.py --hardware-mode conservative
```

If QML still fails, NexLog automatically retries with reduced motion and software rendering, then prints diagnostics. The old Widgets GUI is archived for reference and is no longer a runtime fallback.

Run diagnostics:

```powershell
python -B main_gui.py --preflight
```

## If Findings Do Not Appear

- Use the Dashboard `All Logs` history row to aggregate all analysed sessions.
- Open a specific history session only when you want that log's findings.
- A completed `0 findings` run is not a GUI failure; the selected log simply did not match current rules/severity.
- Try `examples/logs/Android_2k.log` for a smoke sample that currently produces findings.

## Clean Packaging Rules

Release artifacts must never include:

- `.env`
- `workspace/` or `nexlog/workspace/`
- `node_modules/`
- `__pycache__/`
- `.pytest_cache/`, `.ruff_cache/`, `.mypy_cache/`
- `*.facase`, SQLite journals, generated reports, `build/`, `dist/`, or `release/`

Keep reproducible frontend files instead:

- `website/package.json`
- `website/package-lock.json`
- source files under `website/src/`

Install frontend dependencies only on developer machines:

```powershell
cd website
npm install
npm run build
```
