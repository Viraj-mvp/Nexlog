# NexLog Web Cockpit Security Guide

NexLog Web Cockpit is designed for local-first DFIR work. Bind to
`127.0.0.1` by default and require an API key before exposing analysis,
upload, export, AI, or case data routes.

## Run Modes

- Local analyst mode: `python -B -m interface.web.serve --host 127.0.0.1 --port 8000 --key <strong-key>`
- Team mode: place NexLog behind a TLS reverse proxy and set `NEXLOG_API_KEY`.
- API authentication: configure `NEXLOG_API_KEY` for protected API routes.

## Upload Protections

Uploads are treated as untrusted evidence and stored in a quarantine workspace.
NexLog validates filename traversal, control characters, extension allowlists,
magic bytes, SHA-256, duplicate status, ZIP paths, archive file counts, archive
nesting, and decompressed size limits. Archives are never auto-extracted by the
web server.

Recommended environment overrides:

```powershell
$env:NEXLOG_API_KEY = "replace-with-a-long-random-secret"
$env:NEXLOG_MAX_UPLOAD_BYTES = "524288000"
$env:NEXLOG_MAX_DECOMPRESSED_BYTES = "1073741824"
$env:NEXLOG_RATE_MAX_REQUESTS = "120"
```

## Browser Hardening

The served cockpit uses local static assets only. It does not load React, Babel,
icons, fonts, or scripts from public CDNs. Security headers deny framing,
disable object loading, restrict scripts to `self`, deny referrers, and keep
responses out of shared caches.

## Remote Access Checklist

- Use HTTPS/TLS at the reverse proxy.
- Set `NEXLOG_API_KEY`; never publish the app without authentication.
- Keep `--host 127.0.0.1` unless a proxy is intentionally forwarding traffic.
- Configure `NEXLOG_TRUSTED_PROXIES` to the exact proxy CIDR before trusting
  `X-Forwarded-For`.
- Keep the quarantine/workspace directory on a local disk with restricted ACLs.
- Do not directly serve uploaded evidence from a static file server.
