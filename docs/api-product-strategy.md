# NexLog Investigation API Strategy

NexLog should expose an API, but the right first product is not a public cloud upload API. The safest and strongest direction is a **local-first/private-team investigation API** that lets other tools automate NexLog without forcing analysts to open the GUI.

## Product Positioning

**NexLog Investigation API** turns NexLog into a DFIR analysis engine:

- Upload or select evidence.
- Start analysis jobs.
- Watch progress.
- Pull findings, timelines, MITRE coverage, IOCs, attack graph, and attack story.
- Export reports, STIX, IOC CSV, Sigma, GraphML, and case bundles.
- Integrate NexLog into SOC scripts, internal dashboards, labs, and case workflows.

This keeps NexLog’s best angle intact:

> Local-first DFIR log investigation cockpit with API automation, beautiful GUI, attack graph, timelines, reports, Sigma/STIX/IOC export, and AI-assisted case explanation without sending evidence to the cloud by default.

## Recommended Rollout

### Phase 1: Local API

Use this for desktop GUI, web cockpit, CLI automation, and analyst scripts on one machine.

Default posture:

- Bind to `127.0.0.1`.
- Require `NEXLOG_API_KEY` for non-health routes.
- Keep evidence and case databases local.
- No public network exposure by default.

### Phase 2: Private Team API

Use this for controlled internal/team access.

Required posture:

- Bind intentionally to a trusted interface.
- Put NexLog behind TLS/reverse proxy.
- Require long random `NEXLOG_API_KEY`.
- Enable strict upload limits, rate limits, and audit logging.
- Do not serve uploaded evidence directly.

### Phase 3: SDK/API Product

Package the API as something other engineers can build against:

- OpenAPI documentation.
- Python SDK.
- Example scripts.
- Stable `/api/v1/*` endpoints.
- Job-based analysis lifecycle.
- Clear error codes and pagination.

### Phase 4: Hosted API Later

Only consider a hosted/cloud API after the local/private API is mature.

Hosted evidence analysis requires:

- Tenant isolation.
- Malware-safe upload quarantine.
- Billing and abuse prevention.
- Strong legal terms and privacy policy.
- Data retention controls.
- Incident response process.
- Secure deletion and export guarantees.

## Core API Capabilities

Recommended stable endpoints:

```text
GET    /api/v1/health
POST   /api/v1/jobs
GET    /api/v1/jobs/{job_id}
POST   /api/v1/jobs/{job_id}/pause
POST   /api/v1/jobs/{job_id}/resume
POST   /api/v1/jobs/{job_id}/cancel

GET    /api/v1/sessions
GET    /api/v1/dashboard
GET    /api/v1/findings
GET    /api/v1/timeline
GET    /api/v1/graph
GET    /api/v1/mitre
GET    /api/v1/iocs
GET    /api/v1/attack-story

POST   /api/v1/export/report
POST   /api/v1/export/stix
POST   /api/v1/export/iocs
POST   /api/v1/export/sigma
POST   /api/v1/export/graph
POST   /api/v1/export/case-bundle

POST   /api/v1/rules/test
POST   /api/v1/sigma/import
POST   /api/v1/notes
GET    /api/v1/notes
```

## Security Requirements

Minimum security before offering this to others:

- Fail closed when `NEXLOG_API_KEY` is missing, except health checks.
- Disable CORS by default.
- Use strict CSP and local frontend assets only.
- Rate-limit auth, upload, analysis, and export endpoints.
- Quarantine uploads with random filenames.
- Validate extension and magic bytes.
- Hash uploaded evidence with SHA-256.
- Enforce max file size and max line size.
- Reject traversal paths, null bytes, control characters, unsafe archives, and archive bombs.
- Never return local filesystem internals in API errors.
- Store audit logs for uploads, job starts, exports, deletes, and auth failures.

## Why This Is Valuable

The API makes NexLog useful beyond its GUI:

- SOC teams can automate local log triage.
- Students can build labs and scripts around it.
- MSPs can run repeatable investigation workflows.
- Other security tools can call NexLog as an offline analysis engine.
- The desktop GUI and web cockpit can share the same backend contract.

The winning product line is:

**private evidence in, explainable investigation artifacts out.**

