# NexLog Quick Setup

## 1. Create Environment

```bash
python -m venv .venv
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 2. Verify

```bash
python -B main.py --help
python -B main_gui.py --packaged-check
python -B -m pytest tests/unit/test_security.py -q -p no:cacheprovider
```

## 3. Run

```bash
python main_gui.py
```

or:

```bash
python main.py examples/logs/Apache_2k.log --report none --quiet
```

## 4. Package

```bash
python scripts/package_release.py --source-zip
python scripts/package_release.py --binary
```

Source releases are cross-platform. Binary releases must be built on the target
operating system.
