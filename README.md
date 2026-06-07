# NexLog

**Version 1.0.0 - Local-first DFIR log analyzer**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF.svg?logo=github-actions&logoColor=white)](.github/workflows/ci.yml)
[![Release](https://img.shields.io/badge/Release-v1.0.0-0A7F55.svg)](docs/RELEASE_GUIDE.md)

NexLog analyzes security logs offline, detects threats with YAML rules, maps findings to MITRE ATT&CK, exports IOCs and reports, and keeps evidence on the analyst workstation by default.

## Highlights

| Capability | Details |
|:---|:---|
| Log parsing | Apache, Nginx, Syslog, Auth, EVTX, Sysmon, Zeek, Suricata, CloudTrail, VPC Flow, CEF, LEEF, Kubernetes Audit, and more |
| Detection engine | YAML rules with regex, threshold, sequence, and composite matchers |
| Threat mapping | MITRE ATT&CK tactics, techniques, risk scoring, and confidence levels |
| Case storage | Portable SQLite `.facase` case database with sessions, evidence hashes, notes, and findings |
| Reporting | Text, JSON, Markdown, PDF, CSV IOC, and STIX 2.1 exports |
| Interfaces | CLI, PySide6 desktop GUI, FastAPI web cockpit, and REST API |
| AI assistant | Offline template fallback plus optional Ollama, Groq, Gemini, or Anthropic providers |
| Privacy | Local-first by default. Cloud AI and threat-intel enrichment are opt-in. |

## Quick Start

```bash
git clone https://github.com/nexlog/nexlog.git
cd nexlog

python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .\.venv\Scripts\Activate.ps1   # Windows PowerShell

pip install .                    # Core CLI
pip install ".[all]"             # CLI + GUI + Web + AI + Intel
nexlog examples/logs/Apache_2k.log
```

You can also install the full development dependency set directly:

```bash
python -m pip install -r requirements.txt
```

## CLI Usage

```bash
nexlog <LOG [LOG ...]> [options]
```

Common examples:

```bash
nexlog access.log
nexlog access.log --severity HIGH --report all --out ./reports/
nexlog access.log auth.log syslog.log --case investigation.facase
nexlog Security.evtx --format evtx --case windows_ir.facase
nexlog cloudtrail.json --ioc iocs.csv --stix threat_bundle.json --analyst "SOC-Analyst-1"
nexlog large_file.log --resume cli-20260521120000
nexlog access.log --severity CRITICAL --report json --quiet
```

Important options:

| Option | Description |
|:---|:---|
| `--case FILE` | Save results to a `.facase` SQLite case database |
| `--severity LEVEL` | Minimum severity: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--category CAT` | Filter findings to one attack category |
| `--rules DIR` | Use a custom YAML detection rules directory |
| `--format FMT` | Force log format, such as `apache`, `syslog`, `evtx`, `zeek`, `cloudtrail`, or `suricata` |
| `--report FMT` | Output format: `text`, `json`, `markdown`, `all`, or `none` |
| `--out DIR` | Output directory for reports and exports |
| `--ioc FILE` | Export indicators of compromise to CSV |
| `--stix FILE` | Export findings to a STIX 2.1 JSON bundle |
| `--profile MODE` | Analysis profile: `fast`, `balanced`, or `deep` |
| `--no-chain` | Skip attack-chain detection |
| `--no-enrich` | Skip threat-intelligence enrichment |
| `--verify-case` | Verify evidence hashes and case integrity |
| `--demo-mode` | Generate a sample SOC case |
| `--quiet` / `-q` | Suppress progress output |
| `--summary` / `-s` | Print summary only |

Wrapper scripts are available when you do not want to install first:

```bash
./bin/nexlog access.log --severity HIGH      # Linux/macOS
bin\nexlog.bat access.log --severity HIGH    # Windows
```

## Desktop GUI

```bash
python main_gui.py
python main_gui.py --case workspace/nexlog.facase
python main_gui.py --preflight
```

The desktop app includes dashboard KPIs, findings triage, incident timeline, attack graph, MITRE coverage, AI query, and export tools.

## Web Cockpit

```bash
nexlog-serve --host 127.0.0.1 --port 8000
nexlog-serve --port 8000 --key $(python scripts/generate_api_key.py)
nexlog-serve --stdlib --port 8000
```

Open `http://127.0.0.1:8000` after the server starts.

Key endpoints:

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/upload` | Upload a log file for analysis |
| `POST` | `/api/analyse` | Analyze an uploaded file |
| `GET` | `/api/v1/findings` | Retrieve findings with filters |
| `GET` | `/api/v1/timeline` | Retrieve timeline events |
| `GET` | `/api/v1/coverage` | Retrieve MITRE ATT&CK coverage |
| `GET` | `/api/v1/risk/entities` | Retrieve entity risk scores |
| `POST` | `/api/v1/hunt` | Run parameterized hunt queries |
| `POST` | `/api/v1/case/bundle` | Export a case bundle |
| `WS` | `/ws/analysis` | Stream live analysis updates |

## AI Layer

NexLog always has an offline template fallback. Optional providers can be enabled with environment variables:

| Provider | Setup |
|:---|:---|
| Ollama | Set `OLLAMA_HOST` and `NEXLOG_MODEL` after installing a local model |
| Groq | Set `GROQ_API_KEY` |
| Gemini | Set `GEMINI_API_KEY` |
| Anthropic | Set `ANTHROPIC_API_KEY` |

Keep real keys in local `.env`, `.env.gui`, or `.env.web` files. Never commit them.

## Docker

```bash
docker build -f packaging/Dockerfile -t nexlog:latest .
docker run -p 8000:8000 -v /path/to/logs:/data/uploads nexlog:latest
docker compose -f packaging/docker-compose.yml up
```

## Development

```bash
python -m pip install -r requirements.txt
python -B -m pytest tests -q -p no:cacheprovider
python -B scripts/release_check.py --allow-local-env

cd website
npm ci
npm run build
```

Generated files and local evidence are intentionally ignored. Clean before publishing:

```bash
python scripts/clean_project.py
python scripts/clean_project.py --apply
```

## Release Packaging

NexLog v1.0.0 publishes clean source ZIPs and platform-specific portable binary ZIPs through GitHub Actions.

```bash
python scripts/package_release.py --source-zip --skip-check
python scripts/package_release.py --binary
```

See [docs/RELEASE_GUIDE.md](docs/RELEASE_GUIDE.md) for local packaging and GitHub tag-release instructions.

## Security

- Keep `.env`, API keys, case databases, evidence logs, reports, and runtime workspaces out of commits.
- API authentication fails closed when `NEXLOG_API_KEY` is configured.
- API key comparison uses timing-safe checks.
- Uploads are sandboxed with filename sanitization and file validation.
- CI runs tests, security checks, dependency audit, secret scanning, frontend build, and Docker build.

See [SECURITY.md](SECURITY.md), [docs/security.md](docs/security.md), and [docs/web-security.md](docs/web-security.md).

## Project Layout

```text
main.py                         CLI entry point
main_gui.py                     Desktop GUI launcher
nexlog/core/                    Parsers, readers, and analysis engine
nexlog/detection/               Rule engine, findings, matchers, YAML rules
nexlog/storage/                 Case database and chain of custody
nexlog/intelligence/            IOC extraction and optional CTI enrichment
nexlog/output/                  Reports, STIX, IOC CSV, and bundles
nexlog/ai/                      LLM client, embedder, vector store, RAG
nexlog/interface/gui/           PySide6/QML desktop interface
nexlog/interface/web/           FastAPI server and static web assets
website/                        React/Vite web cockpit source
examples/logs/                  Sample logs for tests and demos
scripts/                        Release checks, packaging, and utilities
tests/                          Unit and integration tests
packaging/                      Docker, Compose, and PyInstaller files
docs/                           Setup, security, roadmap, and release docs
```

## Roadmap

NexLog v1.0.0 ships with the core analysis pipeline, GUI, web cockpit, exports, release packaging, and GitHub CI. Planned v1.x improvements:

| Target | Feature |
|:---|:---|
| v1.1 | Sigma import workflow polish and GUI validation |
| v1.1 | Timeline annotations and analyst notes improvements |
| v1.2 | MITRE coverage reporting refinements |
| v1.2 | Case journal and evidence attachment workflow |
| Later | Faster parser core and richer attack-story automation |

See [docs/enterprise-gap-roadmap.md](docs/enterprise-gap-roadmap.md) for the broader roadmap.

## Contributing

1. Fork the repository and create a feature branch.
2. Add or update tests for behavior changes.
3. Run the release-blocker checks.
4. Keep generated forensic data and secrets out of commits.
5. Open a pull request with a concise explanation and verification notes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT License. See [LICENSE](LICENSE).
