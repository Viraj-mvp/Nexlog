# NexLog Enterprise Gap Roadmap

NexLog is strongest as a local-first DFIR log investigation cockpit: fast offline analysis, visual timelines, attack graphing, exports, and AI-assisted explanation without sending evidence to the cloud by default.

## Highest-Value Missing Capabilities

| Area | Missing or weak today | Why it matters |
| --- | --- | --- |
| Detection lifecycle | Sigma import studio, rule testing, rule versioning, false-positive tuning | Detections must be testable and maintainable before enterprise trust |
| Risk engine | Entity, user, host, and IP risk over time | Combines weak signals into stronger investigations |
| Case workflow | Notes, assignments, comments, attachments, saved views, evidence journal | Analysts need investigation memory, not just findings |
| Timeline UX | Annotations, tags, saved timeline filters, bookmarked events | Timelines become useful when context is preserved |
| Data coverage | Verified parser corpus for EVTX, Sysmon, Zeek, Suricata, CloudTrail, IAM, EDR, Kubernetes, VPC, and DNS | Parser names are not enough; enterprise users need proof with samples |
| Query and hunt | Fast query language or visual filter builder over normalized fields | Analysts need questions like "failed SSH by IP over one hour" instantly |
| Detection coverage | MITRE coverage matrix showing covered and missing tactics | Helps mature the detection program |
| Threat intel hub | MISP, OpenCTI, OTX, VirusTotal, and AbuseIPDB enrichment with caching and rate limits | Adds prioritization and context |
| Response actions | Playbooks, containment checklists, and later Jira/Slack/SOAR handoff | Makes NexLog an investigation cockpit, not only a scanner |
| Packaging hardening | Signed builds, installer, update channel, crash logs | Required before serious public or enterprise launch |

## Priority Roadmap

| Priority | Work |
| --- | --- |
| P0 | Clean repo, finish NexLog naming, keep secrets/generated files out of releases, verify launch checks |
| P1 | Polish web/QML Findings, Timeline, Attack Graph, MITRE, AI, and Tools into production views |
| P1 | Add Sigma importer, rule test harness, rule versioning, and false-positive tuning |
| P1 | Add real EVTX/Sysmon parser validation with sample corpus and benchmarks |
| P2 | Add Zeek, Suricata, CloudTrail, IAM, Kubernetes, VPC, DNS, EDR, and Wazuh import coverage |
| P2 | Add entity risk scoring, case journal, annotations, saved views, and case bundle export |
| P3 | Add local AI investigator with source citations to exact findings and log lines |
| P3 | Add signed installers, crash logs, update channel, and optional team/collaboration mode |

## Feature Ideas To Build Next

- Sigma Import Studio: import Sigma rules, validate fields, test against sample logs, and show false-positive risk.
- Rule Test Harness: run rules against fixture logs and produce coverage reports for CI.
- Attack Story Mode: convert detections into a narrative such as recon to exploit to persistence to exfiltration.
- Case Bundle Export: generate a `.nexlogcase` bundle with DB, reports, IOCs, timeline, graph, hashes, and notes.
- Detection Coverage Matrix: show MITRE tactics and techniques covered by rules and findings.
- Local AI Investigator: answer questions with citations to exact finding IDs and evidence lines.
- Timeline Fusion: merge Apache, auth, Sysmon, CloudTrail, Zeek, and Suricata into one normalized timeline.
- Threat Intel Hub: optional MISP, OpenCTI, OTX, VirusTotal, and AbuseIPDB enrichment with cache and rate limits.
- Playbooks: guided workflows for SSH brute force, web shell, cloud key theft, ransomware, and suspicious admin activity.
- Demo/Lab Mode: bundled sample cases for GitHub screenshots, interviews, and product demos.

## Implemented Foundation

These pieces are now available as backend/API/script foundations for the GUI and website to consume:

- Sigma safe-subset importer: `POST /api/v1/sigma/import` and `python scripts/sigma_import.py`.
- Rule validation, rule test harness, and coverage matrix: `/api/v1/rules`, `/api/v1/rules/validate`, `/api/v1/rules/test`, `/api/v1/coverage`, plus `scripts/rule_test.py` and `scripts/coverage_report.py`.
- Entity risk scoring over IPs, users, hosts, and processes: `GET /api/v1/risk/entities`.
- Safe parameterized hunt queries: `POST /api/v1/hunt` and `python scripts/hunt.py`.
- Case bundle export: `POST /api/v1/case/bundle` and `python scripts/case_bundle.py`.
- First-class playbook APIs: `GET /api/v1/playbooks` and `GET /api/v1/playbooks/{category}`.
- Threat-intel provider readiness without network calls: `GET /api/v1/intel/status`.
- NexLog API key generator: `python scripts/generate_api_key.py --print` or `python scripts/generate_api_key.py --write-env-web`.
