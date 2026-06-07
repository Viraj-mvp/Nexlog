"""
ai/query_interface.py â€” NexLog AI Layer
Shared high-level query interface for both GUI and web interfaces.

This module provides a single, unified entry point so the PySide6 GUI
and the React web UI use identical business logic â€” no duplication of
session management, indexing, or conversation history.

Features:
  - Singleton-ish session management: one RAGEngine per case database
  - Conversation history (last N turns as context for follow-up questions)
  - Auto-indexing: index a session when first queried, cache for subsequent
  - Progress callback: pass a callable for UI progress updates
  - JSON-serialisable results for REST API responses
  - Both blocking (query) and streaming (stream_query) interfaces

Usage â€” GUI (PySide6):
    from ai.query_interface import AIQueryEngine

    engine = AIQueryEngine(case_db_path="case.facase")
    engine.ensure_indexed(db, session_id="session-001",
                          on_progress=lambda p,m: status_bar.setText(m))

    answer = engine.ask("What SQL injection attacks happened?")
    print(answer.text)
    for source in answer.sources:
        print(source["rule_id"], source["score"])

Usage â€” Web API:
    from ai.query_interface import AIQueryEngine

    engine = AIQueryEngine(case_db_path="case.facase")
    result_dict = engine.ask_dict("What IPs are attacking?", session_id="s1")
    return JSONResponse(result_dict)

Usage â€” Streaming (FastAPI WebSocket):
    async for chunk in engine.ask_stream("What happened?"):
        await websocket.send_text(chunk)
"""

import os
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generator, Optional

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

from embedder   import Embedder
from llm_client import LLMClient
from rag_engine import RAGEngine, RAGAnswer


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CONVERSATION HISTORY
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@dataclass
class ConversationTurn:
    """One question-answer exchange."""
    question: str
    answer:   str
    sources:  list[dict]  = field(default_factory=list)
    ts:       float       = field(default_factory=time.time)
    session_id: str       = ""

    def to_dict(self) -> dict:
        return {
            "question":   self.question,
            "answer":     self.answer,
            "sources":    self.sources,
            "timestamp":  self.ts,
            "session_id": self.session_id,
        }


class ConversationHistory:
    """
    Ring buffer of the last N conversation turns.
    Used to inject prior Q&A as context for follow-up questions.
    """

    def __init__(self, max_turns: int = 6):
        self._turns:    list[ConversationTurn] = []
        self._max      = max_turns

    def add(self, turn: ConversationTurn) -> None:
        self._turns.append(turn)
        if len(self._turns) > self._max:
            self._turns.pop(0)

    def as_context_prefix(self) -> str:
        """
        Format prior turns as a context prefix injected before the
        retrieved findings. Helps the LLM understand follow-up questions
        like "what about the second IP?" or "are those the only findings?".
        """
        if not self._turns:
            return ""
        lines = ["CONVERSATION HISTORY (most recent last):"]
        for t in self._turns[-3:]:  # last 3 turns
            lines.append(f"Q: {t.question}")
            lines.append(f"A: {t.answer[:200]}")
        return "\n".join(lines) + "\n\n"

    def clear(self) -> None:
        self._turns.clear()

    def all_turns(self) -> list[dict]:
        return [t.to_dict() for t in self._turns]

    def __len__(self) -> int:
        return len(self._turns)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# AI QUERY ENGINE (shared by GUI + web)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AIQueryEngine:
    """
    Unified AI query interface for natural language questions over findings.

    One instance per case database. Thread-safe: a lock serialises
    index operations while reads (queries) run concurrently.

    Args:
        case_db_path:  Path to the SQLite .facase database.
        persist_path:  Override vector store directory.
                       Default: {case_db_path}.ai/
        llm_model:     Ollama model name (default: mistral).
        max_history:   Number of Q&A turns kept in conversation history.
        default_top_k: Default retrieval count.
    """

    def __init__(
        self,
        case_db_path:  str            = "",
        persist_path:  str            = "",
        llm_model:     str            = "mistral",
        max_history:   int            = 6,
        default_top_k: int            = 5,
    ):
        self._case_db_path = case_db_path
        self._lock         = threading.Lock()
        self._indexed_sessions: set[str] = set()

        # Determine vector store directory
        if persist_path:
            ai_dir = persist_path
        elif case_db_path:
            ai_dir = str(Path(case_db_path).with_suffix("")) + ".ai"
        else:
            ai_dir = os.path.join(os.path.expanduser("~"), ".nexlog_ai")

        emb_tier = os.environ.get("NEXLOG_AI_FORCE_TIER", "").strip()
        llm_tier = os.environ.get("NEXLOG_LLM_FORCE_TIER", "3").strip()

        self.embedder = Embedder(force_tier=int(emb_tier) if emb_tier.isdigit() else None)
        self.llm      = LLMClient(
            model=llm_model,
            force_tier=int(llm_tier) if llm_tier.isdigit() else None,
        )
        self.rag      = RAGEngine(
            persist_path  = ai_dir,
            embedder      = self.embedder,
            llm           = self.llm,
            default_top_k = default_top_k,
        )
        self.history  = ConversationHistory(max_turns=max_history)
        self._ai_dir  = ai_dir

    # â”€â”€ Indexing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def ensure_indexed(
        self,
        db,
        session_id:  Optional[str]              = None,
        force:       bool                        = False,
        on_progress: Optional[Callable[[int,str], None]] = None,
    ) -> int:
        """
        Index all findings from a CaseDB session if not already indexed.
        Thread-safe â€” safe to call from GUI and API threads simultaneously.

        Args:
            db:          Open CaseDB instance.
            session_id:  Session to index (None = all sessions).
            force:       Re-index even if session was indexed before.
            on_progress: Callback(percent: int, message: str) for UI.

        Returns:
            Number of new findings indexed (0 if already up to date).
        """
        key = session_id or "__all__"
        if not force and key in self._indexed_sessions:
            return 0

        with self._lock:
            # Double-check inside lock
            if not force and key in self._indexed_sessions:
                return 0

            if on_progress:
                on_progress(10, "Loading findings from databaseâ€¦")

            findings = db.get_findings(session_id=session_id, limit=20000)

            if on_progress:
                on_progress(30, f"Embedding {len(findings)} findingsâ€¦")

            n = self.rag.index_findings(
                findings,
                session_id = session_id or "",
                batch_size = 64,
            )

            if on_progress:
                on_progress(100, f"Indexed {n} findings ({self.rag.n_indexed} total)")

            self._indexed_sessions.add(key)
            return n

    def index_findings_directly(
        self,
        findings: list,
        session_id: str = "",
    ) -> int:
        """
        Index a list of Finding objects directly (no CaseDB needed).
        Used when findings are already in memory (e.g. during analysis).
        """
        with self._lock:
            return self.rag.index_findings(findings, session_id=session_id)

    # â”€â”€ Query â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def ask(
        self,
        question:    str,
        session_id:  Optional[str] = None,
        severity:    Optional[str] = None,
        category:    Optional[str] = None,
        top_k:       Optional[int] = None,
        max_tokens:  int           = 512,
        temperature: float         = 0.2,
        use_history: bool          = True,
    ) -> RAGAnswer:
        """
        Answer a natural language question. Adds conversation history context.

        Args:
            question:    The analyst's question.
            session_id:  Restrict retrieval to this session.
            severity:    Restrict retrieval to this severity level.
            category:    Restrict retrieval to this attack category.
            top_k:       Number of findings to retrieve.
            max_tokens:  LLM max response tokens.
            temperature: LLM sampling temperature.
            use_history: Prepend conversation history to query context.

        Returns:
            RAGAnswer with .text and .sources.
        """
        # Extract conversation history prefix without modifying the main question
        history_prefix = ""
        if use_history and len(self.history) > 0:
            history_prefix = self.history.as_context_prefix() + "CURRENT QUESTION: "

        answer = self.rag.query(
            question    = question,
            top_k       = top_k,
            session_id  = session_id,
            severity    = severity,
            category    = category,
            max_tokens  = max_tokens,
            temperature = temperature,
            history_context = history_prefix,
        )

        # Store in history with the original (not augmented) question
        self.history.add(ConversationTurn(
            question   = question,
            answer     = answer.text,
            sources    = answer.sources,
            session_id = session_id or "",
        ))
        return answer

    def ask_dict(
        self,
        question:   str,
        **kwargs,
    ) -> dict:
        """
        Same as ask() but returns a JSON-serialisable dict.
        Convenient for REST API responses.
        """
        answer = self.ask(question, **kwargs)
        return answer.to_dict()

    def ask_stream(
        self,
        question:   str,
        session_id: Optional[str] = None,
        severity:   Optional[str] = None,
        category:   Optional[str] = None,
        top_k:      Optional[int] = None,
        max_tokens: int           = 512,
        use_history: bool         = True,
    ) -> Generator[str, None, None]:
        """
        Stream the answer token by token.
        Yields text chunks, then a final '__SOURCES__:' JSON chunk.
        The last chunk contains sources, timing, and engine metadata.

        Usage â€” collect everything:
            chunks = list(engine.ask_stream("What happened?"))
            text   = "".join(c for c in chunks if not c.startswith("__SOURCES__:"))
            meta   = json.loads(next(c for c in chunks if "__SOURCES__:" in c).split(":")[1])

        Usage â€” async:
            async def ws_handler(ws):
                for chunk in engine.ask_stream("What happened?"):
                    await ws.send_text(chunk)
        """
        history_prefix = ""
        if use_history and len(self.history) > 0:
            history_prefix = self.history.as_context_prefix() + "CURRENT QUESTION: "

        yield from self.rag.stream_query(
            question    = question,
            top_k       = top_k,
            session_id  = session_id,
            severity    = severity,
            category    = category,
            max_tokens  = max_tokens,
            history_context = history_prefix,
        )

    # â”€â”€ Conversation management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def clear_history(self) -> None:
        """Clear conversation history."""
        self.history.clear()

    def get_history(self) -> list[dict]:
        """Return all conversation turns as JSON-serialisable dicts."""
        return self.history.all_turns()

    # â”€â”€ Status + diagnostics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def status(self) -> dict:
        """
        Full status dict â€” suitable for health check and UI display.
        """
        return {
            **self.rag.status(),
            "llm_tier":         self.llm.tier_name,
            "llm_tier_number":  self.llm.tier,
            "embedder_tier":    self.embedder.tier_name,
            "embedder_tier_number": self.embedder.tier,
            "conversation_turns": len(self.history),
            "indexed_sessions": list(self._indexed_sessions),
            "ai_dir":           self._ai_dir,
            "ollama_available": self.llm.tier == 1,
            "recommendations": _tier_recommendations(
                self.embedder.tier, self.llm.tier),
        }

    def reset(self) -> None:
        """Clear vector store index and conversation history."""
        self.rag.reset_index()
        self.history.clear()
        self._indexed_sessions.clear()

    def close(self) -> None:
        """Release resources."""
        self.rag.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self) -> str:
        return (f"<AIQueryEngine indexed={self.rag.n_indexed} "
                f"emb_tier={self.embedder.tier} "
                f"llm_tier={self.llm.tier} "
                f"history={len(self.history)}>")


def _tier_recommendations(emb_tier: int, llm_tier: int) -> list[str]:
    """Human-readable recommendations for improving AI quality."""
    recs = []
    if emb_tier >= 3:
        recs.append(
            "For better semantic search: pip install sentence-transformers")
    if llm_tier == 3:
        recs.append(
            "For natural language answers: install Ollama and run "
            "'ollama pull mistral' (https://ollama.com)")
    if llm_tier == 2:
        recs.append(
            "Using Anthropic API â€” set ANTHROPIC_API_KEY. "
            "Local Ollama is faster and free: ollama pull mistral")
    if emb_tier == 1 and llm_tier == 1:
        recs.append(
            "Running at full quality: sentence-transformers + Ollama local LLM")
    return recs
