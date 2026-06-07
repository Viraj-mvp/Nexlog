import { useCallback, useEffect, useMemo, useState } from "react";

type View =
  | "dashboard"
  | "findings"
  | "time"
  | "graph"
  | "mitre"
  | "iocs"
  | "ai"
  | "export"
  | "rules"
  | "risk"
  | "hunt"
  | "playbooks"
  | "notes"
  | "settings";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type JobStatus = "idle" | "queued" | "running" | "complete" | "failed" | "cancelled" | "cancelling";

type UploadRecord = {
  ok?: boolean;
  path?: string;
  filename?: string;
  original_name?: string;
  sha256?: string;
  size?: number;
  error?: string;
};

type SessionSummary = {
  session_id?: string;
  source_file?: string;
  created_at?: string;
  total_findings?: number;
  critical?: number;
  high?: number;
  max_risk_score?: number;
  avg_risk_score?: number;
};

type Finding = {
  id?: string;
  finding_id?: string;
  rule_id?: string;
  rule_name?: string;
  title?: string;
  description?: string;
  severity?: Severity | string;
  risk_score?: number;
  category?: string;
  source_ip?: string;
  hostname?: string;
  source?: string;
  timestamp?: string;
  mitre_attack?: Array<{ technique_id?: string; tactic?: string; technique?: string }>;
  mitre_ids?: string[];
  raw_line?: string;
  trigger_preview?: string;
};

type TimelineEvent = {
  timestamp?: string;
  severity?: string;
  source?: string;
  rule_name?: string;
  rule_id?: string;
  category?: string;
  summary?: string;
  message?: string;
  mitre?: string;
};

type Snapshot = {
  dashboard?: Record<string, unknown>;
  sessions?: SessionSummary[];
  findings?: Finding[];
  timeline?: TimelineEvent[];
  graph?: { nodes?: unknown[]; edges?: unknown[] };
  mitre?: Array<Record<string, unknown>>;
  chains?: Array<Record<string, unknown>>;
  total_findings?: number;
  total_sessions?: number;
};

type Job = {
  job_id?: string;
  status?: JobStatus;
  progress?: number;
  message?: string;
  result?: { session_id?: string; session_ids?: string[]; snapshot?: Snapshot; summaries?: SessionSummary[] };
  error?: string;
};

type AiStatus = {
  available?: boolean;
  llm_provider?: string;
  llm_tier?: string;
  n_indexed?: number;
  recommendations?: string[];
};

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const API_KEY_STORAGE = "nexlog_web_api_key";

const NAV_ITEMS: Array<{ id: View; label: string; icon: string }> = [
  { id: "dashboard", label: "Dash", icon: "grid" },
  { id: "findings", label: "Findings", icon: "find" },
  { id: "time", label: "Time", icon: "time" },
  { id: "graph", label: "Graph", icon: "graph" },
  { id: "mitre", label: "MITRE", icon: "shield" },
  { id: "iocs", label: "IOCs", icon: "pulse" },
  { id: "ai", label: "AI", icon: "spark" },
  { id: "export", label: "Export", icon: "export" },
  { id: "rules", label: "Rules", icon: "shield" },
  { id: "risk", label: "Risk", icon: "pulse" },
  { id: "hunt", label: "Hunt", icon: "find" },
  { id: "playbooks", label: "Playbooks", icon: "notes" },
  { id: "notes", label: "Notes", icon: "notes" },
  { id: "settings", label: "Set", icon: "set" },
];

function iconPath(kind: string): string {
  switch (kind) {
    case "grid":
      return "M4 4h7v7H4zM13 4h7v5h-7zM13 11h7v9h-7zM4 13h7v7H4z";
    case "find":
      return "M10.5 4a6.5 6.5 0 1 0 4.16 11.5l4.42 4.42 1.42-1.42-4.42-4.42A6.5 6.5 0 0 0 10.5 4z";
    case "time":
      return "M12 3a9 9 0 1 0 9 9 9 9 0 0 0-9-9zm1 4h-2v6l5 3 1-1.73-4-2.27z";
    case "graph":
      return "M5 18h3v-6H5zm5 0h3V6h-3zm5 0h3v-9h-3z";
    case "shield":
      return "M12 3 3 7v5c0 5 3.84 9.74 9 10 5.16-.26 9-5 9-10V7z";
    case "pulse":
      return "M3 12h6l3-8 3 16 3-8h3";
    case "spark":
      return "M12 3l2.3 4.7L19 10l-4.7 2.3L12 17l-2.3-4.7L5 10l4.7-2.3z";
    case "export":
      return "M12 3v10m0 0 4-4m-4 4-4-4M5 19h14v2H5z";
    case "notes":
      return "M6 3h9l3 3v15H6zM9 8h6M9 12h6M9 16h4";
    case "set":
      return "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm9 4-2.1.7a7.4 7.4 0 0 1-.5 1.2l1 2-1.7 1.7-2-1a7.4 7.4 0 0 1-1.2.5L14 21h-4l-.7-2.1a7.4 7.4 0 0 1-1.2-.5l-2 1L4.4 17l1-2a7.4 7.4 0 0 1-.5-1.2L3 12l.7-2.1a7.4 7.4 0 0 1 .5-1.2l-1-2L4.9 5l2 1a7.4 7.4 0 0 1 1.2-.5L10 3h4l.7 2.1a7.4 7.4 0 0 1 1.2.5l2-1 1.7 1.7-1 2a7.4 7.4 0 0 1 .5 1.2z";
    default:
      return "M4 6h16v2H4zm0 5h16v2H4zm0 5h16v2H4z";
  }
}

function Icon({ kind }: { kind: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="icon">
      <path d={iconPath(kind)} fill="currentColor" />
    </svg>
  );
}

function sizeText(size = 0): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

function fileName(path = ""): string {
  return path.split(/[\\/]/).filter(Boolean).pop() || path || "Unknown";
}

function findingKey(item: Finding, index: number): string {
  return item.id || item.finding_id || `${item.rule_id || "finding"}-${index}`;
}

function findingTitle(item: Finding): string {
  return item.rule_name || item.title || item.rule_id || "Detection";
}

function findingSource(item: Finding): string {
  return item.source || item.source_ip || item.hostname || "-";
}

function mitreLabel(item: Finding): string {
  if (item.mitre_ids?.length) return item.mitre_ids.join(", ");
  const mapped = item.mitre_attack?.map((entry) => entry.technique_id || entry.technique || entry.tactic).filter(Boolean);
  return mapped?.length ? mapped.join(", ") : "-";
}

function normalizeError(payload: unknown, fallback: string): string {
  if (payload && typeof payload === "object") {
    const maybe = payload as { error?: string; detail?: string | { message?: string } };
    if (typeof maybe.error === "string") return maybe.error;
    if (typeof maybe.detail === "string") return maybe.detail;
    if (maybe.detail && typeof maybe.detail === "object" && typeof maybe.detail.message === "string") return maybe.detail.message;
  }
  return fallback;
}

function App() {
  const [view, setView] = useState<View>("dashboard");
  const [menuOpen, setMenuOpen] = useState(false);
  const [notice, setNotice] = useState("Connecting to NexLog API...");
  const [query, setQuery] = useState("");
  const [apiKey, setApiKey] = useState(() => localStorage.getItem(API_KEY_STORAGE) || "");
  const [authRequired, setAuthRequired] = useState(false);
  const [offline, setOffline] = useState(false);
  const [uploads, setUploads] = useState<UploadRecord[]>([]);
  const [selectedPaths, setSelectedPaths] = useState<string[]>([]);
  const [snapshot, setSnapshot] = useState<Snapshot>({});
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [findingsPage, setFindingsPage] = useState<Finding[]>([]);
  const [timelinePage, setTimelinePage] = useState<TimelineEvent[]>([]);
  const [job, setJob] = useState<Job>({ status: "idle", progress: 0, message: "Ready" });
  const [activeSession, setActiveSession] = useState("");
  const [minSeverity, setMinSeverity] = useState<Severity>("LOW");
  const [profile, setProfile] = useState("balanced");
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiAnswer, setAiAnswer] = useState("");
  const [aiError, setAiError] = useState("");
  const [aiBusy, setAiBusy] = useState(false);
  const [aiStatus, setAiStatus] = useState<AiStatus>({});
  const [notes, setNotes] = useState("");
  const [exportMessage, setExportMessage] = useState("");
  const [enterprisePanel, setEnterprisePanel] = useState<Record<string, unknown> | null>(null);

  const headers = useMemo(() => {
    const base: Record<string, string> = { Accept: "application/json" };
    if (apiKey.trim()) base["X-API-Key"] = apiKey.trim();
    return base;
  }, [apiKey]);

  const apiFetch = useCallback(
    async <T,>(url: string, init: RequestInit = {}): Promise<T> => {
      const response = await fetch(url, {
        ...init,
        headers: {
          ...headers,
          ...(init.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
          ...(init.headers || {}),
        },
      });
      const text = await response.text();
      let payload: unknown = {};
      try {
        payload = text ? JSON.parse(text) : {};
      } catch {
        payload = { error: text };
      }
      if (!response.ok) {
        if (response.status === 401) setAuthRequired(true);
        throw new Error(normalizeError(payload, `${response.status} ${response.statusText}`));
      }
      return payload as T;
    },
    [headers],
  );

  const refreshAiStatus = useCallback(async () => {
    try {
      const status = await apiFetch<AiStatus>("/api/ai/status");
      setAiStatus(status);
    } catch {
      setAiStatus({ available: false, llm_provider: "unavailable" });
    }
  }, [apiFetch]);

  const refreshSessions = useCallback(async () => {
    try {
      const payload = await apiFetch<SessionSummary[] | { sessions?: SessionSummary[] }>("/api/v1/sessions");
      const rows = Array.isArray(payload) ? payload : payload.sessions || [];
      setSessions(rows);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to refresh sessions.");
    }
  }, [apiFetch]);

  const refreshSnapshot = useCallback(async () => {
    try {
      const suffix = activeSession ? `?session_id=${encodeURIComponent(activeSession)}` : "";
      const snap = await apiFetch<Snapshot>(`/api/v1/snapshot${suffix}`);
      setSnapshot(snap);
      setSessions(snap.sessions || []);
      setOffline(false);
      setNotice(activeSession ? "Session snapshot refreshed." : "All-log snapshot refreshed.");
    } catch (error) {
      setOffline(true);
      setNotice(error instanceof Error ? error.message : "NexLog API is offline.");
    }
  }, [activeSession, apiFetch]);

  const refreshFindings = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: "100", min_severity: minSeverity });
      if (activeSession) params.set("session_id", activeSession);
      if (query.trim()) params.set("query", query.trim());
      const page = await apiFetch<{ findings?: Finding[] }>(`/api/v1/findings-page?${params}`);
      setFindingsPage(page.findings || []);
    } catch {
      setFindingsPage([]);
    }
  }, [activeSession, apiFetch, minSeverity, query]);

  const refreshTimeline = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: "100", min_severity: minSeverity });
      if (activeSession) params.set("session_id", activeSession);
      const page = await apiFetch<{ events?: TimelineEvent[] }>(`/api/v1/timeline-page?${params}`);
      setTimelinePage(page.events || []);
    } catch {
      setTimelinePage([]);
    }
  }, [activeSession, apiFetch, minSeverity]);

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshSnapshot(), refreshSessions(), refreshFindings(), refreshTimeline(), refreshAiStatus()]);
  }, [refreshAiStatus, refreshFindings, refreshSessions, refreshSnapshot, refreshTimeline]);

  useEffect(() => {
    localStorage.setItem(API_KEY_STORAGE, apiKey);
  }, [apiKey]);

  useEffect(() => {
    let cancelled = false;
    async function boot() {
      try {
        const status = await fetch("/api/auth/status").then((r) => r.json());
        if (cancelled) return;
        setAuthRequired(Boolean(status.auth_enabled));
        await refreshAll();
      } catch {
        if (!cancelled) {
          setOffline(true);
          setNotice("NexLog API is not reachable. Start the web server and refresh.");
        }
      }
    }
    void boot();
    return () => {
      cancelled = true;
    };
  }, [refreshAll]);

  useEffect(() => {
    void refreshFindings();
  }, [refreshFindings]);

  useEffect(() => {
    void refreshTimeline();
  }, [refreshTimeline]);

  async function onUploadSelection(event: React.ChangeEvent<HTMLInputElement>) {
    const selected = Array.from(event.target.files || []);
    if (!selected.length) return;
    const form = new FormData();
    selected.forEach((file) => form.append("files", file));
    setNotice(`Uploading ${selected.length} evidence file(s)...`);
    try {
      const payload = await apiFetch<{ uploads?: UploadRecord[]; log_paths?: string[]; accepted?: number }>("/api/v1/uploads", {
        method: "POST",
        body: form,
      });
      const records = payload.uploads || [];
      const accepted = records.filter((item) => item.ok && item.path);
      setUploads((prev) => [...accepted, ...records.filter((item) => !item.ok), ...prev]);
      setSelectedPaths((prev) => [...new Set([...prev, ...(payload.log_paths || accepted.map((item) => item.path || ""))].filter(Boolean))]);
      setNotice(`Upload complete: ${payload.accepted || accepted.length} accepted, ${records.length - accepted.length} rejected.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Upload failed.");
    } finally {
      event.target.value = "";
    }
  }

  async function runAnalysis() {
    if (!selectedPaths.length) {
      setNotice("Upload/select at least one evidence file before analysis.");
      return;
    }
    setJob({ status: "queued", progress: 0, message: "Queued" });
    setNotice("Analysis job submitted.");
    try {
      const created = await apiFetch<Job>("/api/v1/jobs", {
        method: "POST",
        body: JSON.stringify({
          log_paths: selectedPaths,
          min_severity: minSeverity,
          profile,
          batch_size: profile === "fast" ? 8000 : 5000,
          no_enrich: profile !== "deep",
          defer_graph: profile === "fast",
        }),
      });
      setJob(created);
      const jobId = created.job_id;
      if (!jobId) throw new Error("Job did not return an id.");
      const timer = window.setInterval(async () => {
        try {
          const next = await apiFetch<Job>(`/api/v1/jobs/${jobId}`);
          setJob(next);
          if (next.status === "complete" || next.status === "failed" || next.status === "cancelled") {
            window.clearInterval(timer);
            if (next.status === "complete") {
              if (next.result?.snapshot) setSnapshot(next.result.snapshot);
              const newest = next.result?.session_ids?.slice(-1)[0] || next.result?.session_id || "";
              setActiveSession("");
              setNotice(`Analysis complete${newest ? `; latest session ${newest}` : ""}.`);
              await refreshAll();
              setView("dashboard");
            } else {
              setNotice(next.error || next.message || "Analysis did not complete.");
            }
          }
        } catch (error) {
          window.clearInterval(timer);
          setJob({ status: "failed", progress: 100, message: error instanceof Error ? error.message : "Analysis failed" });
        }
      }, 900);
    } catch (error) {
      setJob({ status: "failed", progress: 100, message: error instanceof Error ? error.message : "Analysis failed" });
      setNotice(error instanceof Error ? error.message : "Analysis failed.");
    }
  }

  async function deleteSession(sessionId: string) {
    if (!sessionId || !window.confirm(`Delete session ${sessionId}?`)) return;
    try {
      await apiFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE" });
      if (activeSession === sessionId) setActiveSession("");
      setNotice("Session deleted.");
      await refreshAll();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Delete failed.");
    }
  }

  async function exportReport(format: string) {
    setExportMessage(`Building ${format.toUpperCase()} report...`);
    try {
      const payload = await apiFetch<{ file_path?: string; content?: string; success?: boolean; error?: string }>("/api/report", {
        method: "POST",
        body: JSON.stringify({ format, session_id: activeSession || null, org: "NexLog" }),
      });
      if (payload.error) throw new Error(payload.error);
      setExportMessage(payload.file_path ? `Generated: ${payload.file_path}` : payload.content || "Report generated.");
    } catch (error) {
      setExportMessage(error instanceof Error ? error.message : "Report export failed.");
    }
  }

  async function askAi() {
    setAiError("");
    setAiAnswer("");
    if (!aiPrompt.trim()) {
      setAiError("Question is required.");
      return;
    }
    setAiBusy(true);
    try {
      await apiFetch("/api/ai/index", {
        method: "POST",
        body: JSON.stringify({ session_id: activeSession || null }),
      });
      const answer = await apiFetch<{ text?: string; answer?: string; sources?: unknown[] }>("/api/ai/query", {
        method: "POST",
        body: JSON.stringify({ question: aiPrompt.trim(), session_id: activeSession || null, top_k: 6 }),
      });
      setAiAnswer(answer.text || answer.answer || JSON.stringify(answer, null, 2));
      await refreshAiStatus();
    } catch (error) {
      setAiError(error instanceof Error ? error.message : "AI request failed.");
    } finally {
      setAiBusy(false);
    }
  }

  const findings = findingsPage.length ? findingsPage : snapshot.findings || [];
  const timeline = timelinePage.length ? timelinePage : snapshot.timeline || [];
  const totalFindings = Number(snapshot.total_findings ?? findings.length ?? 0);
  const totalSessions = Number(snapshot.total_sessions ?? sessions.length ?? 0);
  const graphNodes = snapshot.graph?.nodes?.length || 0;
  const graphEdges = snapshot.graph?.edges?.length || 0;
  const severityRows = useMemo(() => {
    return SEVERITIES.map((level) => ({
      level,
      count: findings.filter((item) => String(item.severity || "").toUpperCase() === level).length,
    }));
  }, [findings]);
  const topSources = useMemo(() => {
    const bucket = new Map<string, number>();
    for (const item of findings) {
      const source = findingSource(item);
      bucket.set(source, (bucket.get(source) || 0) + 1);
    }
    return [...bucket.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [findings]);
  const acceptedUploads = uploads.filter((item) => item.ok && item.path);
  const selectedCount = selectedPaths.length;
  const activeSessionLabel = activeSession ? fileName(sessions.find((s) => s.session_id === activeSession)?.source_file || activeSession) : "All Logs";

  async function loadEnterprisePanel(next: View) {
    try {
      if (next === "rules") {
        setEnterprisePanel(await apiFetch<Record<string, unknown>>("/api/v1/coverage"));
      } else if (next === "risk") {
        const suffix = activeSession ? `?session_id=${encodeURIComponent(activeSession)}` : "";
        setEnterprisePanel(await apiFetch<Record<string, unknown>>(`/api/v1/risk/entities${suffix}`));
      } else if (next === "hunt") {
        setEnterprisePanel(await apiFetch<Record<string, unknown>>("/api/v1/hunt", {
          method: "POST",
          body: JSON.stringify({ filters: { min_severity: minSeverity, text: query.trim() }, limit: 25 }),
        }));
      } else if (next === "playbooks") {
        setEnterprisePanel(await apiFetch<Record<string, unknown>>("/api/v1/playbooks"));
      }
    } catch (error) {
      setEnterprisePanel({ error: error instanceof Error ? error.message : "Unable to load panel." });
    }
  }

  function goTo(next: View) {
    setView(next);
    setMenuOpen(false);
    if (["rules", "risk", "hunt", "playbooks"].includes(next)) void loadEnterprisePanel(next);
  }

  return (
    <div className="app-shell">
      <button className="mobile-menu" onClick={() => setMenuOpen((v) => !v)} aria-label="Toggle menu">
        <Icon kind="set" />
      </button>
      {menuOpen ? <button className="mobile-backdrop" onClick={() => setMenuOpen(false)} aria-label="Close menu" /> : null}

      <aside className={`left-rail ${menuOpen ? "open" : ""}`}>
        <div className="logo-block">
          <img src="/static/nexlog-logo.png" alt="NexLog logo" />
          <div className="brand-copy">
            <h2>NexLog</h2>
            <small>Web Cockpit</small>
          </div>
        </div>
        {NAV_ITEMS.map((item) => (
          <button key={item.id} className={view === item.id ? "active" : ""} onClick={() => goTo(item.id)}>
            <Icon kind={item.icon} />
            <span>{item.label}</span>
          </button>
        ))}
      </aside>

      <main className="workspace">
        <header className="top-head">
          <div>
            <p className="eyebrow">NexLog API connected cockpit</p>
            <h1>{view === "dashboard" ? "Mission Dashboard" : NAV_ITEMS.find((item) => item.id === view)?.label}</h1>
            <p>Scope: {activeSessionLabel}</p>
          </div>
          <div className="head-actions">
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings, sources, rules, MITRE..." />
            <button className="accent" onClick={() => goTo("dashboard")}>Dashboard</button>
            <button onClick={() => void refreshAll()}>Refresh</button>
            <button onClick={() => goTo("export")}>Export</button>
            <button onClick={() => goTo("settings")}>Options</button>
          </div>
        </header>

        <div className={`status-line ${offline ? "danger" : ""}`}>
          <span>{notice}</span>
          {authRequired && !apiKey ? <strong>API key required in Options</strong> : null}
        </div>

        {view === "dashboard" && (
          <>
            <section className="hero-card">
              <div>
                <p className="chip">SpiderFoot-style workflow with NexLog backend</p>
                <h2>Upload evidence, run analysis, see the attack story.</h2>
                <p>Evidence is validated by the server, jobs run through the real parser/rule engine, and results stay in the case database.</p>
                <div className="row">
                  <label className="file-button">
                    Upload Evidence
                    <input type="file" multiple accept=".log,.txt,.json,.jsonl,.xml,.evtx,.csv,.gz,.zip" onChange={onUploadSelection} />
                  </label>
                  <button className="accent" disabled={!selectedCount || job.status === "running" || job.status === "queued"} onClick={() => void runAnalysis()}>
                    {job.status === "running" || job.status === "queued" ? `Analysing ${job.progress || 0}%` : "Analyse Selected"}
                  </button>
                  <select value={profile} onChange={(event) => setProfile(event.target.value)}>
                    <option value="fast">Fast</option>
                    <option value="balanced">Balanced</option>
                    <option value="deep">Deep</option>
                  </select>
                  <select value={minSeverity} onChange={(event) => setMinSeverity(event.target.value as Severity)}>
                    {SEVERITIES.map((level) => <option key={level} value={level}>{level}</option>)}
                  </select>
                </div>
              </div>
              <div className="metric-grid">
                <article><span>Findings</span><strong>{totalFindings}</strong></article>
                <article><span>Sessions</span><strong>{totalSessions}</strong></article>
                <article><span>Graph</span><strong>{graphNodes}/{graphEdges}</strong></article>
                <article><span>Queued</span><strong>{selectedCount}</strong></article>
              </div>
            </section>

            {(job.status === "queued" || job.status === "running") && (
              <section className="job-block scanner">
                <strong>{job.message || "Analysis running"}</strong>
                <progress max={100} value={job.progress || 0} />
              </section>
            )}

            <section className="dashboard-grid">
              <article className="card">
                <h3>Selected Evidence</h3>
                <div className="table-wrap compact">
                  <table>
                    <thead><tr><th /><th>File</th><th>Size</th><th>Status</th></tr></thead>
                    <tbody>
                      {acceptedUploads.length ? acceptedUploads.map((item) => (
                        <tr key={item.path}>
                          <td><input type="checkbox" checked={selectedPaths.includes(item.path || "")} onChange={() => {
                            const path = item.path || "";
                            setSelectedPaths((prev) => prev.includes(path) ? prev.filter((p) => p !== path) : [...prev, path]);
                          }} /></td>
                          <td>{item.original_name || item.filename || fileName(item.path)}</td>
                          <td>{sizeText(item.size || 0)}</td>
                          <td>{item.ok ? "Ready" : item.error || "Rejected"}</td>
                        </tr>
                      )) : <tr><td colSpan={4}>Upload logs here to make them visible before analysis.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </article>
              <article className="card">
                <h3>Severity Spectrum</h3>
                <div className="spectrum">
                  {severityRows.map((row) => (
                    <div key={row.level}>
                      <label>{row.level}</label>
                      <progress max={Math.max(1, findings.length)} value={row.count} />
                      <span>{row.count}</span>
                    </div>
                  ))}
                </div>
              </article>
            </section>

            <section className="dashboard-grid">
              <article className="card">
                <h3>Recent Findings</h3>
                <ul className="simple-list">
                  {findings.slice(0, 6).map((item, index) => (
                    <li key={findingKey(item, index)}><span>{findingTitle(item)}</span><strong>{item.severity || "INFO"}</strong></li>
                  ))}
                  {!findings.length ? <li><span>No findings visible. Analyse evidence or switch to All Logs.</span><strong>0</strong></li> : null}
                </ul>
              </article>
              <article className="card">
                <h3>Top Sources</h3>
                <ul className="simple-list">
                  {topSources.length ? topSources.map(([source, count]) => (
                    <li key={source}><span>{source}</span><strong>{count}</strong></li>
                  )) : <li><span>Sources appear after detections are saved.</span><strong>0</strong></li>}
                </ul>
              </article>
            </section>
          </>
        )}

        {view === "findings" && (
          <section className="card">
            <div className="section-head"><h3>Findings</h3><button onClick={() => void refreshFindings()}>Refresh</button></div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Severity</th><th>Rule</th><th>Source</th><th>Risk</th><th>MITRE</th><th>Preview</th></tr></thead>
                <tbody>
                  {findings.map((item, index) => (
                    <tr key={findingKey(item, index)}>
                      <td><span className={`sev ${String(item.severity || "INFO").toLowerCase()}`}>{item.severity || "INFO"}</span></td>
                      <td>{findingTitle(item)}</td>
                      <td>{findingSource(item)}</td>
                      <td>{Number(item.risk_score || 0).toFixed(1)}</td>
                      <td>{mitreLabel(item)}</td>
                      <td>{item.trigger_preview || item.raw_line || item.description || "-"}</td>
                    </tr>
                  ))}
                  {!findings.length ? <tr><td colSpan={6}>No findings in this scope. Analysis can complete with zero detections.</td></tr> : null}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {view === "time" && (
          <section className="card">
            <div className="section-head"><h3>Timeline</h3><button onClick={() => void refreshTimeline()}>Refresh</button></div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Rule / Category</th><th>Summary</th></tr></thead>
                <tbody>
                  {timeline.map((event, index) => (
                    <tr key={`${event.timestamp || index}-${event.rule_id || index}`}>
                      <td>{event.timestamp ? new Date(event.timestamp).toLocaleString() : "-"}</td>
                      <td>{event.severity || "-"}</td>
                      <td>{event.source || "-"}</td>
                      <td>{event.rule_name || event.rule_id || event.category || "-"}</td>
                      <td>{event.summary || event.message || "-"}</td>
                    </tr>
                  ))}
                  {!timeline.length ? <tr><td colSpan={5}>Timeline events appear after findings are saved.</td></tr> : null}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {view === "graph" && (
          <section className="card">
            <div className="section-head"><h3>Attack Graph</h3><button onClick={() => void refreshSnapshot()}>Refresh</button></div>
            <div className="graph-stage">
              <div className="orb core">Case</div>
              {(snapshot.graph?.nodes || []).slice(0, 18).map((node, index) => (
                <div className="orb" key={index} style={{ transform: `rotate(${index * 21}deg) translate(${120 + (index % 4) * 28}px) rotate(-${index * 21}deg)` }}>
                  {String((node as { label?: string; id?: string }).label || (node as { id?: string }).id || index).slice(0, 14)}
                </div>
              ))}
            </div>
            <p>{graphNodes} nodes and {graphEdges} edges in current scope. Full 3D orbit remains in desktop GUI; web keeps a compact investigation map.</p>
          </section>
        )}

        {view === "mitre" && (
          <section className="card">
            <h3>MITRE Coverage</h3>
            <div className="card-grid">
              {(snapshot.mitre || []).map((row, index) => (
                <article className="mini-card" key={index}>
                  <strong>{String(row.technique_id || row.technique || row.id || "Technique")}</strong>
                  <span>{String(row.tactic || row.name || row.insight || "Mapped evidence")}</span>
                  <em>{String(row.count || row.findings || 0)} finding(s)</em>
                </article>
              ))}
              {!snapshot.mitre?.length ? <p>MITRE rows appear when detections map to ATT&CK techniques.</p> : null}
            </div>
          </section>
        )}

        {view === "iocs" && (
          <section className="card">
            <h3>IOCs</h3>
            <p>Export IOC packages from the Export screen. IOC API wiring remains server-side for safe evidence handling.</p>
          </section>
        )}

        {view === "ai" && (
          <section className="card">
            <div className="section-head">
              <h3>AI Investigator</h3>
              <button onClick={() => void refreshAiStatus()}>Status</button>
            </div>
            <p>Provider: {aiStatus.llm_provider || aiStatus.llm_tier || "unknown"} | Indexed: {aiStatus.n_indexed || 0}</p>
            <textarea rows={5} value={aiPrompt} onChange={(event) => setAiPrompt(event.target.value)} placeholder="Ask: summarize likely intrusion sequence and cite the strongest findings." />
            <div className="row">
              <button className="accent" onClick={() => void askAi()} disabled={aiBusy}>{aiBusy ? "Thinking..." : "Ask AI"}</button>
            </div>
            {aiError ? <div className="error-box">{aiError}</div> : null}
            {aiAnswer ? <pre>{aiAnswer}</pre> : null}
          </section>
        )}

        {view === "export" && (
          <section className="card">
            <h3>Reports And Exports</h3>
            <div className="row">
              {["pdf", "markdown", "json", "text"].map((format) => (
                <button key={format} onClick={() => void exportReport(format)}>{format.toUpperCase()} Report</button>
              ))}
            </div>
            {exportMessage ? <pre>{exportMessage}</pre> : null}
          </section>
        )}

        {(view === "rules" || view === "risk" || view === "hunt" || view === "playbooks") && (
          <section className="card">
            <div className="section-head">
              <h3>{NAV_ITEMS.find((item) => item.id === view)?.label}</h3>
              <button onClick={() => void loadEnterprisePanel(view)}>Refresh</button>
            </div>
            <p>
              {view === "rules" && "Detection lifecycle: coverage, MITRE mapping, metadata maturity, and test status."}
              {view === "risk" && "Entity risk: IP/user/host/process scoring across the current investigation scope."}
              {view === "hunt" && "Safe hunt queries over normalized findings using server-side parameterized SQLite."}
              {view === "playbooks" && "Incident response workflows mapped to NexLog finding categories."}
            </p>
            <pre>{JSON.stringify(enterprisePanel || { status: "Loading..." }, null, 2)}</pre>
          </section>
        )}

        {view === "notes" && (
          <section className="card">
            <h3>Case Notes</h3>
            <textarea rows={10} value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Write local browser notes. Server-side case journal is a roadmap item." />
          </section>
        )}

        {view === "settings" && (
          <section className="card">
            <h3>Settings</h3>
            <div className="settings-grid">
              <label><span>NexLog API Key</span><input type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value.trim())} placeholder="Only the server access token is stored here" /></label>
              <label><span>Analysis profile</span><select value={profile} onChange={(event) => setProfile(event.target.value)}><option value="fast">Fast</option><option value="balanced">Balanced</option><option value="deep">Deep</option></select></label>
              <label><span>Minimum severity</span><select value={minSeverity} onChange={(event) => setMinSeverity(event.target.value as Severity)}>{SEVERITIES.map((level) => <option key={level}>{level}</option>)}</select></label>
              <label><span>Scope</span><select value={activeSession} onChange={(event) => setActiveSession(event.target.value)}><option value="">All Logs</option>{sessions.map((session) => <option key={session.session_id} value={session.session_id}>{fileName(session.source_file)} ({session.total_findings || 0})</option>)}</select></label>
            </div>
            <h4>History</h4>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Log</th><th>Findings</th><th>Created</th><th>Actions</th></tr></thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr key={session.session_id}>
                      <td>{fileName(session.source_file)}</td>
                      <td>{session.total_findings || 0}</td>
                      <td>{session.created_at ? new Date(session.created_at).toLocaleString() : "-"}</td>
                      <td><button onClick={() => setActiveSession(session.session_id || "")}>View</button><button onClick={() => void deleteSession(session.session_id || "")}>Delete</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
