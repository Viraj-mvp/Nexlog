"""
ai/rag_engine.py â€” NexLog AI Layer
Retrieve-Augmented Generation pipeline for natural language queries over findings.

Pipeline:
  1. Embed the analyst query using the same embedder used for indexing.
  2. Retrieve top-k semantically similar findings from the vector store.
  3. Build a structured context string from the retrieved findings.
  4. Send query + context to the LLM for synthesis.
  5. Return the answer with source citations.

Features:
  - Hybrid retrieval: vector similarity + keyword reranking
  - Metadata filtering: restrict retrieval to a session, severity, category
  - Streaming response support (for real-time UI updates)
  - Answer provenance: every result cites which findings were used
  - Session indexing: add all findings from a CaseDB session in one call

Usage:
    from ai.rag_engine import RAGEngine

    rag = RAGEngine(persist_path="case.facase.ai/")
    rag.index_session(db, session_id="session-001")

    answer = rag.query("What SQL injection attacks happened?")
    print(answer.text)
    print("Sources:", [s['rule_id'] for s in answer.sources])

    # Streaming
    for chunk in rag.stream_query("Which IPs are most dangerous?"):
        print(chunk, end="", flush=True)
"""

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Generator, Optional

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
for _p in ['ai', 'detection', 'storage']:
    sys.path.insert(0, os.path.join(_ROOT, _p))

from embedder    import Embedder
from vector_store import VectorStore, SearchResult
from llm_client  import LLMClient


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ANSWER TYPE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@dataclass
class RAGAnswer:
    """Result of a RAG query."""
    text:         str
    sources:      list[dict]       = field(default_factory=list)
    query:        str              = ""
    top_k:        int              = 5
    retrieval_ms: int              = 0
    generation_ms:int              = 0
    llm_tier:     str              = ""
    embedder_tier:str              = ""
    n_indexed:    int              = 0

    @property
    def total_ms(self) -> int:
        return self.retrieval_ms + self.generation_ms

    def to_dict(self) -> dict:
        return {
            "text":          self.text,
            "sources":       self.sources,
            "query":         self.query,
            "top_k":         self.top_k,
            "retrieval_ms":  self.retrieval_ms,
            "generation_ms": self.generation_ms,
            "total_ms":      self.total_ms,
            "llm_tier":      self.llm_tier,
            "embedder_tier": self.embedder_tier,
            "n_indexed":     self.n_indexed,
        }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CONTEXT BUILDER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _build_context(results: list[SearchResult], max_chars: int = 4000) -> str:
    """
    Convert search results into a structured context string for the LLM.
    Each finding is represented as a numbered block with its key fields.
    Truncated to max_chars to stay within LLM context windows.
    """
    blocks = []
    for i, r in enumerate(results, 1):
        m = r.metadata
        block = (
            f"[Finding {i}] Rule {m.get('rule_id','')} â€” {m.get('rule_name','')}.\n"
            f"Severity: {m.get('severity','')}  "
            f"Risk: {m.get('risk_score',0):.1f}/10  "
            f"Category: {m.get('category','')}.\n"
            f"Source IP: {m.get('source_ip','')}  "
            f"Hostname: {m.get('hostname','')}.\n"
            f"MITRE: {m.get('mitre_ids','none')}.\n"
            f"Evidence: {r.text[:400]}\n"
            f"Relevance score: {r.score:.3f}"
        )
        blocks.append(block)

    context = "\n\n".join(blocks)
    if len(context) > max_chars:
        context = context[:max_chars] + "\n...[context truncated]"
    return context


def _source_citation(result: SearchResult) -> dict:
    """Extract citation metadata from a SearchResult."""
    m = result.metadata
    return {
        "doc_id":    result.doc_id,
        "rule_id":   m.get("rule_id",    ""),
        "rule_name": m.get("rule_name",  ""),
        "severity":  m.get("severity",   ""),
        "category":  m.get("category",   ""),
        "source_ip": m.get("source_ip",  ""),
        "hostname":  m.get("hostname",   ""),
        "score":     result.score,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# RAG ENGINE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class RAGEngine:
    """
    Natural language query engine over security findings.

    Wires together:
      Embedder    â€” query and finding text â†’ dense vectors
      VectorStore â€” indexed finding embeddings + retrieval
      LLMClient   â€” context + query â†’ synthesised answer

    Args:
        persist_path:   Directory for vector store persistence.
        embedder:       Custom Embedder instance (or auto-created).
        llm:            Custom LLMClient instance (or auto-created).
        store:          Custom VectorStore instance (or auto-created).
        default_top_k:  Default number of findings to retrieve.
        llm_model:      Ollama model name for LLMClient.
    """

    def __init__(
        self,
        persist_path:   str                  = "",
        embedder:       Optional[Embedder]   = None,
        llm:            Optional[LLMClient]  = None,
        store:          Optional[VectorStore]= None,
        default_top_k:  int                  = 5,
        llm_model:      str                  = "mistral",
    ):
        self._persist = persist_path or os.path.join(
            os.path.expanduser("~"), ".nexlog_ai")
        emb_tier = os.environ.get("NEXLOG_AI_FORCE_TIER", "").strip()
        llm_tier = os.environ.get("NEXLOG_LLM_FORCE_TIER", "3").strip()

        self.embedder     = embedder or Embedder(
            force_tier=int(emb_tier) if emb_tier.isdigit() else None)
        self.llm          = llm or LLMClient(
            model=llm_model,
            force_tier=int(llm_tier) if llm_tier.isdigit() else None)
        self.store        = store    or VectorStore(persist_path=self._persist)
        self.default_top_k = default_top_k

    # â”€â”€ Indexing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def index_findings(
        self,
        findings:   list,
        session_id: str = "",
        batch_size: int = 128,
    ) -> int:
        """
        Index a list of Finding objects into the vector store.

        Args:
            findings:   List of Finding objects from Layer 2.
            session_id: Tag for filtering retrieval by session.
            batch_size: Embedding batch size.

        Returns:
            Number of new findings actually indexed (skips duplicates).
        """
        return self.store.add_findings(
            findings, self.embedder,
            session_id=session_id,
            batch_size=batch_size,
        )

    def index_session(self, db, session_id: Optional[str] = None) -> int:
        """
        Load all findings from a CaseDB session and index them.
        Convenience wrapper over index_findings.

        Args:
            db:         Open CaseDB instance.
            session_id: Session to load (None = all sessions).

        Returns:
            Number of new findings indexed.
        """
        findings = db.get_findings(session_id=session_id, limit=10000)
        return self.index_findings(findings, session_id=session_id or "")

    @property
    def n_indexed(self) -> int:
        """Number of findings currently in the vector store."""
        return self.store.count()

    # â”€â”€ Query â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def query(
        self,
        question:    str,
        top_k:       Optional[int]  = None,
        session_id:  Optional[str]  = None,
        severity:    Optional[str]  = None,
        category:    Optional[str]  = None,
        max_tokens:  int            = 512,
        temperature: float          = 0.2,
        history_context: str        = "",
    ) -> RAGAnswer:
        """
        Answer a natural language question about indexed findings.

        Retrieval filter: session_id + severity + category (all optional).
        If the vector store is empty, returns a graceful "no data" answer.

        Args:
            question:    The analyst's question in natural language.
            top_k:       Number of findings to retrieve (default: 5).
            session_id:  Restrict to a specific analysis session.
            severity:    Only retrieve findings of this severity.
            category:    Only retrieve findings of this category.
            max_tokens:  LLM max response length.
            temperature: LLM sampling temperature.

        Returns:
            RAGAnswer with .text (the answer) and .sources (citations).
        """
        k = top_k or self.default_top_k

        if self.store.count() == 0:
            return RAGAnswer(
                text    = ("No findings are indexed yet. "
                           "Run rag.index_session(db) after analysis."),
                query   = question,
                top_k   = k,
                llm_tier     = self.llm.tier_name,
                embedder_tier= self.embedder.tier_name,
                n_indexed    = 0,
            )

        # Build metadata filter
        filter_meta = {}
        if session_id: filter_meta["session_id"] = session_id
        if severity:   filter_meta["severity"]   = severity.upper()
        if category:   filter_meta["category"]   = category

        # Retrieval
        t0 = time.monotonic()
        results = self.store.query_text(
            question, self.embedder, top_k=k,
            filter_meta=filter_meta or None,
        )
        retrieval_ms = int((time.monotonic() - t0) * 1000)

        if not results:
            return RAGAnswer(
                text    = ("No relevant findings matched your query"
                           + (f" with filters {filter_meta}" if filter_meta else "")
                           + ". Try broadening your search."),
                query   = question,
                top_k   = k,
                retrieval_ms  = retrieval_ms,
                llm_tier      = self.llm.tier_name,
                embedder_tier = self.embedder.tier_name,
                n_indexed     = self.store.count(),
            )

        context = _build_context(results)

        # Generation
        t1 = time.monotonic()
        full_question = history_context + question if history_context else question
        text = self.llm.generate(
            full_question, context,
            max_tokens=max_tokens, temperature=temperature)
        generation_ms = int((time.monotonic() - t1) * 1000)

        return RAGAnswer(
            text          = text,
            sources       = [_source_citation(r) for r in results],
            query         = question,
            top_k         = k,
            retrieval_ms  = retrieval_ms,
            generation_ms = generation_ms,
            llm_tier      = self.llm.tier_name,
            embedder_tier = self.embedder.tier_name,
            n_indexed     = self.store.count(),
        )

    def stream_query(
        self,
        question:   str,
        top_k:      Optional[int] = None,
        session_id: Optional[str] = None,
        severity:   Optional[str] = None,
        category:   Optional[str] = None,
        max_tokens: int           = 512,
        history_context: str        = "",
    ) -> Generator[str, None, None]:
        """
        Stream the answer token by token.
        Yields text chunks as they are generated.
        Always yields a final {"sources": [...], "meta": {...}} JSON chunk
        prefixed with '\n\n__SOURCES__:' so the UI can separate answer
        text from citations.
        """
        k = top_k or self.default_top_k

        if self.store.count() == 0:
            yield "No findings indexed. Run rag.index_session(db) first."
            return

        filter_meta = {}
        if session_id: filter_meta["session_id"] = session_id
        if severity:   filter_meta["severity"]   = severity.upper()
        if category:   filter_meta["category"]   = category

        t0 = time.monotonic()
        results = self.store.query_text(
            question, self.embedder, top_k=k,
            filter_meta=filter_meta or None)
        retrieval_ms = int((time.monotonic() - t0) * 1000)

        if not results:
            yield "No relevant findings matched your query."
            return

        context = _build_context(results)

        t1 = time.monotonic()
        full_question = history_context + question if history_context else question
        for chunk in self.llm.stream(full_question, context, max_tokens=max_tokens):
            yield chunk
        generation_ms = int((time.monotonic() - t1) * 1000)

        # Emit sources as a structured footer
        import json as _json
        meta = {
            "sources":       [_source_citation(r) for r in results],
            "retrieval_ms":  retrieval_ms,
            "generation_ms": generation_ms,
            "llm_tier":      self.llm.tier_name,
            "n_indexed":     self.store.count(),
        }
        yield f"\n\n__SOURCES__:{_json.dumps(meta)}"

    # â”€â”€ Lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def reset_index(self) -> None:
        """Clear all indexed findings."""
        self.store.reset()

    def close(self) -> None:
        """Release resources."""
        self.store.close()

    def status(self) -> dict:
        """Return diagnostic information about the engine."""
        return {
            "n_indexed":    self.store.count(),
            "embedder":     self.embedder.tier_name,
            "embedder_dim": self.embedder.dim,
            "llm":          self.llm.tier_name,
            "vector_store": self.store.backend,
            "persist_path": self._persist,
        }

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self) -> str:
        return (f"<RAGEngine indexed={self.n_indexed} "
                f"emb={self.embedder.tier_name} "
                f"llm={self.llm.tier_name}>")
