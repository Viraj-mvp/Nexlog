# NexLog Roadmap

NexLog is a local-first DFIR log investigation cockpit: fast offline analysis,
beautiful desktop investigation views, attack graphs, timelines, reports,
Sigma/STIX/IOC export, and AI-assisted case explanation without sending
evidence to the cloud.

## v1.0 Current Stabilization

- [x] NexLog QML desktop shell with animated startup and logo branding
- [x] Responsive command dashboard with Analyse, Refresh, Open Case, and exports
- [x] Dedicated QML views for findings, timeline, MITRE, AI, tools, and attack graph
- [x] 162 YAML detection rules across 19 ATT&CK-style categories
- [x] SQLite `.facase` case storage with evidence sessions and finding state
- [x] PDF, text, JSON, Markdown, STIX 2.1, IOC CSV, and Sigma exports
- [x] Local-first AI defaults with heavy semantic backends lazy/opt-in
- [x] Path traversal hardening, API authentication defaults, and rule ReDoS guard
- [x] Safe generated-artifact cleanup tool for GitHub preparation

## v1.1 GUI And Case Workflow

- [ ] Screenshot-ready dashboard, findings, timeline, MITRE, AI, tools, and graph captures
- [ ] Finding notes, tags, assignments, triage queue filters, and saved views
- [ ] Markdown investigation journal linked to findings and timeline events
- [ ] Evidence timeline with analyst actions and chain-of-custody milestones
- [ ] `.nexlogcase` bundle import/export with DB, reports, hashes, graph, and journal
- [ ] More keyboard shortcuts and command-palette actions for analyst flow

## v1.2 Attack Graph Clarity

- [x] 3D-style layered graph: source -> stage -> rule -> MITRE technique
- [x] Graph search, kind filters, selected-node path highlighting, and attack story panel
- [x] Graph exports for JSON, GraphML, SVG/PDF workflow, PNG, and case bundle
- [ ] Dedicated finding/timeline links from selected graph nodes
- [ ] GraphML and Neo4j export presets with richer relationship metadata
- [ ] Attack-story report section with recommended analyst next steps

## v1.3 Detection Quality

- [ ] Sigma rule importer with unsupported-field reporting
- [ ] Rule test harness with positive/negative sample logs
- [ ] Rule coverage dashboard by source, category, tactic, and technique
- [ ] False-positive tuning through per-case suppressions and allowlists
- [ ] Sample-log corpus for regression testing and demo screenshots
- [ ] Rule metadata quality checks for severity, MITRE mapping, and confidence

## v1.4 Parser Coverage

- [ ] Zeek logs
- [ ] Suricata EVE JSON
- [ ] Sysmon XML/JSON
- [ ] Real binary EVTX through optional `python-evtx`
- [ ] AWS CloudTrail
- [ ] Azure audit logs
- [ ] GCP audit logs
- [ ] Super-timeline normalization across host, network, cloud, and application logs

## Later Product Expansion

- [ ] Collaborative cases for trusted internal teams
- [ ] Web dashboard refresh for read-only case review
- [ ] PostgreSQL backend option for team deployments
- [ ] SAML/OIDC auth for enterprise deployments
- [ ] MISP/OpenCTI/OTX intelligence feed ingestion
- [ ] Volatility3 and YARA integrations for deeper endpoint investigations

## Compatibility

NexLog uses `NEXLOG_*` environment variables for public configuration.

## Versioning

NexLog follows [Semantic Versioning](https://semver.org/). Security patches
increment the patch version and are backported to the current minor where
practical.
