<<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&height=230&color=0:031B34,35:005F73,70:0A9396,100:94D2BD&text=NexLog&fontColor=FFFFFF&fontSize=68&fontAlignY=38&desc=Local-first%20DFIR%20log%20analysis%20for%20analysts%20who%20keep%20evidence%20close&descAlignY=58&animation=fadeIn" />
</p>

<p align="center">
  <img src="nexlog/interface/gui/assets/nexlog-logo.png" alt="NexLog Logo" width="260" />
</p>


# NexLog

**Local-First DFIR Log Analyzer**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF.svg?logo=github-actions&logoColor=white)](.github/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

Analyze security logs offline. Detect threats with YAML rules. Map to MITRE ATT&CK.
Export IOCs. Query findings with AI. All data stays on your machine.

[Quick Start](#-quick-start) · [CLI Usage](#-cli-usage) · [Desktop GUI](#-desktop-gui) · [Web Cockpit](#-web-cockpit) · [AI Layer](#-ai-layer) · [Contributing](#-contributing)

</div>

---

## ✨ Highlights

| Capability | Details |
|:---|:---|
| **Log Parsing** | 50+ formats — Apache, Nginx, Syslog, Auth, EVTX, Sysmon, Zeek, Suricata, CloudTrail, VPC Flow, CEF, LEEF, Kubernetes Audit, and more |
| **Detection Engine** | 162 YAML rules across 19 categories with regex, threshold, sequence, and composite matchers |
| **Threat Mapping** | Automatic MITRE ATT&CK tagging with tactics, techniques, risk scoring, and confidence levels |
| **Case Storage** | Portable SQLite `.facase` database with sessions, evidence chain of custody, analyst notes, and findings |
| **Threat Intelligence** | IOC extraction, AbuseIPDB / VirusTotal / AlienVault OTX enrichment with local caching and rate limiting |
| **Reporting** | Text, JSON, Markdown, PDF, CSV IOC, and STIX 2.1 bundle exports |
| **Interfaces** | CLI (`nexlog`), PySide6 desktop GUI, hardened FastAPI web cockpit, and REST API |
| **AI Assistant** | 5-tier LLM integration — Ollama (local), Groq, Gemini, Anthropic, or offline template fallback |
| **Privacy First** | All analysis runs locally by default. Cloud AI is opt-in. No telemetry. No data leaves your machine. |

---

## 🚀 Quick Start

### Install from source

```bash
# Clone the repository
git clone https://github.com/nexlog/nexlog.git
cd nexlog

# Create virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .\.venv\Scripts\Activate.ps1   # Windows PowerShell

# Install NexLog
pip install .                    # Core CLI only (lightweight)
pip install ".[all]"             # Everything: CLI + GUI + Web + AI + Intel
```

### Or install dependencies directly

```bash
pip install -r requirements.txt
```

### Run your first analysis

```bash
nexlog examples/logs/Apache_2k.log
```

---

## 🖥️ CLI Usage

NexLog provides a single-command CLI experience — just like Hayabusa, Chainsaw, or YARA:

```
nexlog <LOG [LOG ...]> [options]
```

### Examples

```bash
# Quick scan of a web server log
nexlog access.log

# Filter to HIGH+ severity, generate all report formats
nexlog access.log --severity HIGH --report all --out ./reports/

# Analyse multiple logs into a single case database
nexlog access.log auth.log syslog.log --case investigation.facase

# Scan Windows event logs with forced format detection
nexlog Security.evtx --format evtx --case windows_ir.facase

# Extract IOCs to CSV and STIX 2.1 bundle
nexlog cloudtrail.json --ioc iocs.csv --stix threat_bundle.json --analyst "SOC-Analyst-1"

# Deep analysis profile with threat intel enrichment
nexlog *.log --profile deep --case deep_scan.facase

# Resume a previously interrupted analysis
nexlog large_file.log --resume cli-20260521120000

# Quiet mode for scripting and pipelines
nexlog access.log --severity CRITICAL --report json --quiet
```

### CLI Options

| Option | Description |
|:---|:---|
| `--case FILE` | Save results to a `.facase` SQLite case database |
| `--severity LEVEL` | Minimum severity filter: `INFO` · `LOW` · `MEDIUM` · `HIGH` · `CRITICAL` |
| `--category CAT` | Filter findings to a specific attack category |
| `--rules DIR` | Use a custom YAML detection rules directory |
| `--format FMT` | Force log format (e.g., `apache`, `syslog`, `evtx`, `zeek`, `cloudtrail`, `suricata`) |
| `--report FMT` | Output format: `text` · `json` · `markdown` · `all` · `none` |
| `--out DIR` | Output directory for reports and exports |
| `--ioc FILE` | Export Indicators of Compromise to CSV |
| `--stix FILE` | Export findings to STIX 2.1 JSON bundle |
| `--analyst NAME` | Analyst name for reports and case notes |
| `--profile MODE` | Analysis profile: `fast` · `balanced` · `deep` |
| `--no-chain` | Skip attack chain detection |
| `--no-enrich` | Skip threat intelligence enrichment |
| `--resume JOB_ID` | Resume a previously interrupted analysis job |
| `--verify-case` | Verify evidence hashes and case integrity |
| `--demo-mode` | Generate a sample SOC case for testing and demos |
| `--quiet` / `-q` | Suppress progress output |
| `--summary` / `-s` | Print summary only |

### Running Without Install

If you prefer not to install, use the wrapper scripts directly from the repository:

```bash
# Linux / macOS / Kali
./bin/nexlog access.log --severity HIGH

# Windows
bin\nexlog.bat access.log --severity HIGH
```

---

## 🎨 Desktop GUI

The PySide6 desktop GUI provides a cinematic investigation cockpit with animated dashboards, 3D attack graphs, and interactive analysis.

```bash
# Launch the GUI
python main_gui.py

# Launch with a specific case file
python main_gui.py --case workspace/nexlog.facase
```

### Views

| View | Description |
|:---|:---|
| **Command Center** | Dashboard with KPIs, severity spectrum, MITRE preview, recent findings, top sources, and attack chains |
| **Findings** | Searchable, filterable detection queue with detail drawer and triage actions |
| **Incident Timeline** | Chronological event stream with severity filters and event inspector |
| **Attack Graph** | 3D-style layered graph with search, path highlighting, story mode, and export |
| **MITRE Coverage** | ATT&CK technique heatmap from stored findings |
| **AI Query** | Offline-first case Q&A powered by RAG with LLM integration |
| **Tools** | PDF / STIX / IOC / Sigma / UEBA / case-bundle workflows |

### Keyboard Shortcuts

| Shortcut | Action |
|:---|:---|
| `Ctrl+K` | Command palette |
| `Ctrl+O` | Open a log file |
| `Ctrl+G` | Jump to Attack Graph |
| `/` | Focus the search box |

---

## 🌐 Web Cockpit

A hardened FastAPI + React web interface for browser-based analysis. No CDN dependencies — all assets are served locally.

```bash
# Start the web server
nexlog-serve --host 127.0.0.1 --port 8000

# With API key authentication
nexlog-serve --port 8000 --key $(python scripts/generate_api_key.py)

# Stdlib mode (no FastAPI dependency required)
nexlog-serve --stdlib --port 8000
```

Then open **http://127.0.0.1:8000** in your browser.

### API Endpoints

Full REST API available at `/docs` (Swagger UI) when running the FastAPI server. Key endpoints:

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/upload` | Upload a log file for analysis |
| `POST` | `/api/analyse` | Run analysis on an uploaded file |
| `GET` | `/api/v1/findings` | Retrieve findings with filters |
| `GET` | `/api/v1/timeline` | Get timeline events |
| `GET` | `/api/v1/coverage` | MITRE ATT&CK coverage matrix |
| `GET` | `/api/v1/risk/entities` | Entity risk scores |
| `POST` | `/api/v1/hunt` | Parameterized threat hunting queries |
| `POST` | `/api/v1/case/bundle` | Export full case bundle |
| `WS` | `/ws/analysis` | Live findings stream via WebSocket |

---

## 🤖 AI Layer

NexLog includes a 5-tier AI assistant that automatically selects the best available provider:

| Tier | Provider | Cost | Setup |
|:---|:---|:---|:---|
| 1 | **Ollama** (local) | Free | [Install Ollama](https://ollama.com) → `ollama pull mistral` |
| 2 | **Groq** | Free | Set `GROQ_API_KEY` — [Get key](https://console.groq.com) |
| 3 | **Google Gemini** | Free | Set `GEMINI_API_KEY` — [Get key](https://aistudio.google.com) |
| 4 | **Anthropic Claude** | Paid | Set `ANTHROPIC_API_KEY` |
| 5 | **Template Fallback** | Free | No setup — deterministic regex-based responses (always available) |

> **Note:** Without any API key or Ollama configured, NexLog defaults to the **template fallback** (Tier 5). This produces structured but repetitive answers. For natural language analysis, configure any free tier above.

### Environment Variables

```bash
# Desktop GUI: use the AI Provider Setup popup or copy .env.gui.example to .env.gui.
# Web/API: copy .env.web.example to .env.web.
# Never commit real keys.

# Key variables
OLLAMA_HOST=http://localhost:11434    # Ollama server URL
NEXLOG_MODEL=mistral                 # Ollama model name
GROQ_API_KEY=                        # Groq API key (free)
GEMINI_API_KEY=                      # Google Gemini API key (free)
ANTHROPIC_API_KEY=                   # Anthropic Claude API key (paid)
```

If an API key was pasted into chat, shared publicly, or committed by mistake,
rotate it with the provider before using it in NexLog.

---

## 📁 Project Structure

```
nexlog/
├── main.py                     # CLI entry point
├── main_gui.py                 # Desktop GUI launcher
├── pyproject.toml              # Python packaging (pip install .)
├── bin/
│   ├── nexlog                  # Unix/Linux/macOS CLI wrapper
│   └── nexlog.bat              # Windows CLI wrapper
├── nexlog/
│   ├── core/                   # Log parsers, format detection, engine
│   ├── detection/              # Rule engine, findings, matchers, YAML rules
│   │   └── rules/              # 162 detection rules across 19 categories
│   ├── storage/                # SQLite case database, chain of custody
│   ├── intelligence/           # IOC extraction, CTI enrichment, AbuseIPDB
│   ├── output/                 # Reports (text/JSON/MD/PDF), STIX, IOC CSV
│   ├── ai/                     # LLM client, embedder, vector store, RAG
│   ├── interface/
│   │   ├── gui/                # PySide6 desktop application (QML)
│   │   └── web/                # FastAPI server, auth, upload, static files
│   └── utils/                  # Runtime config, helpers
├── website/                    # React/Vite source for the web cockpit
├── examples/logs/              # Sample logs for testing and demos
├── scripts/                    # Release checks, packaging, utilities
├── tests/                      # Unit and integration tests
├── packaging/
│   ├── Dockerfile              # Production Docker image
│   ├── docker-compose.yml      # Docker Compose config
│   └── pyinstaller/            # PyInstaller spec for standalone binary
└── docs/                       # Security, roadmap, architecture docs
```

---

## 🐳 Docker

```bash
# Build the image
docker build -f packaging/Dockerfile -t nexlog:latest .

# Run the web cockpit
docker run -p 8000:8000 -v /path/to/logs:/data/uploads nexlog:latest

# Or use Docker Compose
docker compose -f packaging/docker-compose.yml up
```

---

## 🔒 Security

- **No secrets in the repo.** All API keys are configured via `.env` files (gitignored).
- **Fail-closed auth.** API routes return `503` when `NEXLOG_API_KEY` is set but not provided.
- **Timing-safe comparison.** API key validation uses `hmac.compare_digest`.
- **Rate limiting.** Sliding window rate limiter protects API endpoints.
- **Sandboxed uploads.** Uploaded files go to a temporary directory with extension whitelisting, magic byte validation, and filename sanitization.
- **Security headers.** CSP, X-Frame-Options, HSTS-ready, no-sniff, and referrer policy.
- **CI secret scanning.** GitHub Actions runs [Gitleaks](https://github.com/gitleaks/gitleaks) on every push.

See [docs/web-security.md](docs/web-security.md) for full security architecture details.

---

## 🧪 Testing

```bash
# Run the full test suite
python -m pytest tests/ -v

# Run specific test suites
python -m pytest tests/unit/test_security.py -q     # Security tests
python -m pytest tests/unit/test_ai.py -q            # AI layer tests
python -m pytest tests/unit/test_layer5_gui.py -q    # GUI tests (set QT_QPA_PLATFORM=offscreen for headless)

# Smoke test the CLI
nexlog examples/logs/Apache_2k.log --report none --quiet

# Run preflight checks
python main_gui.py --preflight
python scripts/launch_check.py
```

---

## 🧹 Cleanup

```bash
# Dry-run: see what would be removed
python scripts/clean_project.py

# Apply cleanup (caches, journals, temp files)
python scripts/clean_project.py --apply

# Include sensitive files (.env, case databases)
python scripts/clean_project.py --apply --include-sensitive
```

---

## 📦 Packaging

For detailed instructions on compiling the Windows standalone `.exe`, zipping source archives, and setting up automated GitHub release pipelines, see the [NexLog Release & Packaging Guide](docs/RELEASE_GUIDE.md).

### pip install (recommended)

```bash
pip install .                  # Core CLI only
pip install ".[web]"           # + FastAPI web cockpit
pip install ".[gui]"           # + PySide6 desktop GUI
pip install ".[ai]"            # + AI/ML models (sentence-transformers, chromadb)
pip install ".[intel]"         # + Threat intelligence (MaxMind GeoIP)
pip install ".[all]"           # Everything
pip install ".[dev]"           # + Development tools (pytest, pyinstaller)
```

### Standalone binary (PyInstaller)

```bash
python scripts/package_release.py --binary
```

### Source ZIP

```bash
python scripts/package_release.py --source-zip --skip-check
```


---

## 🗺️ Roadmap

NexLog v1 ships with a complete analysis pipeline. The following improvements are planned for future releases:

| Priority | Feature |
|:---|:---|
| **v1.1** | Sigma Import Studio — import, validate, and test Sigma rules in the GUI |
| **v1.1** | Timeline annotations — bookmark, tag, and add analyst notes to events |
| **v1.2** | MITRE coverage matrix — visual heatmap of covered vs. missing techniques |
| **v1.2** | Case journal — investigation notes, assignments, and evidence attachments |
| **v2.0** | Native Rust parsing core (PyO3) — 10–20× performance improvement |
| **v2.0** | Attack Story Mode — auto-generate narrative from detections |
| **v2.0** | Playbooks — guided response workflows for common incident types |

See [docs/enterprise-gap-roadmap.md](docs/enterprise-gap-roadmap.md) for the full roadmap.

---

## 🤝 Contributing

1. Fork the repository and create a feature branch.
2. Add or update tests for any behavior changes.
3. Run the release-blocker checks (`make test` or individual pytest commands).
4. Keep generated forensic data out of commits.
5. Open a pull request with a short explanation.

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

---

## 📄 License

MIT License — see [LICENSE](LICENSE).

---

<div align="center">

**Built for analysts, by a analyst.**

**BUILT BY VIRAJ.**

*NexLog — because your evidence should never leave your machine.*

</div>
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
