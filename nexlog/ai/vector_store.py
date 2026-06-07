"""
ai/vector_store.py â€” NexLog AI Layer
Vector store for semantic retrieval of embedded findings.

Two backends, auto-selected:

  Primary  â€” ChromaDB (persistent, cosine similarity, HNSW index)
             Requires: pip install chromadb
             Collections persist across process restarts.
             Scales to millions of vectors with sub-millisecond retrieval.

  Fallback â€” In-memory numpy store + SQLite FTS5 (always available)
             All vectors held in a numpy matrix.
             Retrieval = batched cosine similarity via numpy matmul.
             FTS5 full-text index provides keyword fallback.
             Reloads from SQLite on restart via serialised float32 blobs.
             Suitable for up to ~50k findings before RAM becomes a concern.

Both backends implement the same VectorStore interface:
  add(ids, texts, vectors, metadata)  â€” index documents
  query(vector, top_k, filter_meta)   â€” semantic search
  query_text(text, embedder, top_k)   â€” embed + search in one call
  delete(ids)                         â€” remove by ID
  count()                             â€” number of indexed documents
  reset()                             â€” drop all data

Usage:
    from ai.vector_store import VectorStore
    from ai.embedder import Embedder

    emb   = Embedder()
    store = VectorStore(persist_path="case.facase.ai/")

    # Index findings
    store.add_findings(findings, emb, session_id="session-001")

    # Semantic search
    results = store.query_text("SQL injection on login page", emb, top_k=5)
    for r in results:
        print(r["rule_id"], r["score"], r["text"][:80])
"""

import json
import hashlib
import os
import sqlite3
import sys
from pathlib import Path
from typing import Optional

import numpy as np

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
sys.path.insert(0, os.path.join(_ROOT, 'ai'))
sys.path.insert(0, os.path.join(_ROOT, 'detection'))


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _workspace_ai_dir() -> str:
    return str(Path(_ROOT) / "workspace" / "ai-store")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# RESULT TYPE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class SearchResult:
    """Single result from a vector search."""
    __slots__ = ("doc_id","text","score","metadata")

    def __init__(self, doc_id: str, text: str,
                 score: float, metadata: dict):
        self.doc_id   = doc_id
        self.text     = text
        self.score    = round(float(score), 4)
        self.metadata = metadata

    def to_dict(self) -> dict:
        return {
            "doc_id":   self.doc_id,
            "text":     self.text,
            "score":    self.score,
            "metadata": self.metadata,
            # Convenience aliases matching Finding fields
            "rule_id":  self.metadata.get("rule_id", ""),
            "severity": self.metadata.get("severity", ""),
            "category": self.metadata.get("category", ""),
            "source_ip":self.metadata.get("source_ip", ""),
            "hostname": self.metadata.get("hostname", ""),
        }

    def __repr__(self) -> str:
        return (f"<SearchResult {self.doc_id[:8]}â€¦ "
                f"score={self.score:.3f} {self.metadata.get('rule_id','')}>"  )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FALLBACK â€” in-memory numpy + SQLite FTS5
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _NumpyStore:
    """
    In-memory cosine search backed by a SQLite database for persistence.

    Schema:
      vectors  (id TEXT, session_id TEXT, vector BLOB, metadata_json TEXT)
      fts      virtual FTS5 table for keyword fallback
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._in_memory = False
        self._ids:    list[str]  = []
        self._texts:  list[str]  = []
        self._meta:   list[dict] = []
        self._matrix: Optional[np.ndarray] = None   # (N, D) float32
        self._dirty   = True
        self._conn    = self._open_db()
        self._load()

    def _open_db(self) -> sqlite3.Connection:
        requested = self._db_path
        digest = hashlib.sha256(requested.encode("utf-8", errors="replace")).hexdigest()[:16]
        fallback = str(Path(_workspace_ai_dir()) / digest / "vectors.db")

        for candidate in [requested, fallback, ":memory:"]:
            conn: Optional[sqlite3.Connection] = None
            try:
                if candidate != ":memory:":
                    Path(candidate).parent.mkdir(parents=True, exist_ok=True)
                conn = sqlite3.connect(candidate)
                conn.row_factory = sqlite3.Row
                try:
                    conn.execute("PRAGMA journal_mode=TRUNCATE")
                except sqlite3.Error:
                    pass
                self._init_schema(conn)
                self._db_path = candidate
                self._in_memory = candidate == ":memory:"
                return conn
            except (OSError, sqlite3.Error):
                if conn is not None:
                    try:
                        conn.close()
                    except sqlite3.Error:
                        pass
                continue

        self._db_path = ":memory:"
        self._in_memory = True
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._init_schema(conn)
        return conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vectors (
                id            TEXT PRIMARY KEY,
                session_id    TEXT DEFAULT '',
                text          TEXT NOT NULL,
                vector        BLOB NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at    TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
                id UNINDEXED, text,
                content='vectors', content_rowid='rowid'
            )
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS vec_ai AFTER INSERT ON vectors BEGIN
                INSERT INTO fts(rowid, id, text) VALUES (new.rowid, new.id, new.text);
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS vec_ad AFTER DELETE ON vectors BEGIN
                INSERT INTO fts(fts, rowid, id, text)
                VALUES ('delete', old.rowid, old.id, old.text);
            END
        """)
        conn.commit()

    def _load(self) -> None:
        """Load all vectors from SQLite into RAM on startup."""
        rows = self._conn.execute(
            "SELECT id, text, vector, metadata_json FROM vectors ORDER BY rowid"
        ).fetchall()
        if not rows:
            return
        self._ids   = [r["id"]   for r in rows]
        self._texts = [r["text"] for r in rows]
        self._meta  = [json.loads(r["metadata_json"]) for r in rows]
        dim = len(rows[0]["vector"]) // 4   # float32 = 4 bytes
        self._matrix = np.frombuffer(
            b"".join(r["vector"] for r in rows),
            dtype=np.float32
        ).reshape(len(rows), dim).copy()
        self._dirty = False

    def add(self, ids: list[str], texts: list[str],
            vectors: np.ndarray, metadata: list[dict],
            session_id: str = "") -> None:
        """Add documents. Skips IDs that already exist."""
        existing = {row[0] for row in self._conn.execute(
            f"SELECT id FROM vectors WHERE id IN "
            f"({','.join('?' * len(ids))})", ids).fetchall()}

        new_ids   = []
        new_texts = []
        new_vecs  = []
        new_meta  = []

        for i, (doc_id, text, vec, meta) in enumerate(
                zip(ids, texts, vectors, metadata)):
            if doc_id in existing:
                continue
            new_ids.append(doc_id)
            new_texts.append(text)
            new_vecs.append(vec)
            new_meta.append(meta)

        if not new_ids:
            return

        self._conn.executemany(
            "INSERT OR IGNORE INTO vectors(id, session_id, text, vector, metadata_json) "
            "VALUES (?, ?, ?, ?, ?)",
            [(did, session_id, text,
              np.array(vec, dtype=np.float32).tobytes(),
              json.dumps(meta, default=str))
             for did, text, vec, meta in zip(new_ids, new_texts, new_vecs, new_meta)]
        )
        self._conn.commit()

        # Update in-memory
        self._ids.extend(new_ids)
        self._texts.extend(new_texts)
        self._meta.extend(new_meta)
        new_matrix = np.stack(new_vecs).astype(np.float32)
        if self._matrix is None:
            self._matrix = new_matrix
        else:
            self._matrix = np.vstack([self._matrix, new_matrix])

    def query(self, vector: np.ndarray, top_k: int = 5,
              filter_meta: Optional[dict] = None) -> list[SearchResult]:
        """Cosine similarity search. Returns top_k results."""
        if self._matrix is None or len(self._ids) == 0:
            return []

        # Normalise query
        q = vector.astype(np.float32)
        norm = np.linalg.norm(q)
        if norm > 0:
            q /= norm

        # Batched cosine similarity = dot product (vectors are unit-norm)
        scores = self._matrix @ q

        # Apply metadata filter if provided
        if filter_meta:
            for i, meta in enumerate(self._meta):
                for k, v in filter_meta.items():
                    if meta.get(k) != v:
                        scores[i] = -999.0
                        break

        # Top-k by score
        k = min(top_k, len(self._ids))
        top_indices = np.argpartition(scores, -k)[-k:]
        top_indices = top_indices[np.argsort(-scores[top_indices])]

        results = []
        for idx in top_indices:
            if scores[idx] <= -999.0:
                continue
            results.append(SearchResult(
                doc_id   = self._ids[idx],
                text     = self._texts[idx],
                score    = float(scores[idx]),
                metadata = self._meta[idx],
            ))
        return results

    def query_keyword(self, text: str, top_k: int = 5) -> list[SearchResult]:
        """FTS5 keyword search fallback."""
        # Sanitise input for FTS5 (escape special chars)
        safe_query = re.sub(r'[^\w\s]', ' ', text) if 'import re' in dir() else text
        try:
            rows = self._conn.execute(
                "SELECT id, text, metadata_json, "
                "       rank * -1 AS score "
                "FROM fts "
                "WHERE fts MATCH ? "
                "ORDER BY rank LIMIT ?",
                (safe_query, top_k)
            ).fetchall()
            return [SearchResult(
                doc_id   = r["id"],
                text     = r["text"],
                score    = float(r["score"]) / 100.0,
                metadata = json.loads(r["metadata_json"]),
            ) for r in rows]
        except Exception:
            return []

    def delete(self, ids: list[str]) -> int:
        """Delete documents by ID. Returns count deleted."""
        if not ids:
            return 0
        cur = self._conn.execute(
            f"DELETE FROM vectors WHERE id IN ({','.join('?'*len(ids))})", ids)
        self._conn.commit()
        # Rebuild in-memory
        removed = set(ids)
        keep = [i for i, d in enumerate(self._ids) if d not in removed]
        self._ids   = [self._ids[i]   for i in keep]
        self._texts = [self._texts[i] for i in keep]
        self._meta  = [self._meta[i]  for i in keep]
        if keep and self._matrix is not None:
            self._matrix = self._matrix[keep]
        else:
            self._matrix = None
        return cur.rowcount

    def count(self) -> int:
        return len(self._ids)

    def reset(self) -> None:
        """Drop all data."""
        self._conn.execute("DELETE FROM vectors")
        self._conn.execute("DELETE FROM fts")
        self._conn.commit()
        self._ids   = []
        self._texts = []
        self._meta  = []
        self._matrix = None

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


import re   # used in query_keyword above


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CHROMADB BACKEND  (optional)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _ChromaStore:
    """Wraps a ChromaDB persistent collection."""

    def __init__(self, persist_dir: str, collection_name: str = "nexlog"):
        import chromadb
        self._client = chromadb.PersistentClient(path=persist_dir)
        self._col    = self._client.get_or_create_collection(
            name     = collection_name,
            metadata = {"hnsw:space": "cosine"},
        )

    def add(self, ids: list[str], texts: list[str],
            vectors: np.ndarray, metadata: list[dict],
            session_id: str = "") -> None:
        vecs_list = vectors.tolist()
        # Add session_id to each metadata dict
        meta_with_sid = [{**m, "session_id": session_id} for m in metadata]
        # ChromaDB silently ignores duplicates with upsert
        self._col.upsert(
            ids        = ids,
            documents  = texts,
            embeddings = vecs_list,
            metadatas  = meta_with_sid,
        )

    def query(self, vector: np.ndarray, top_k: int = 5,
              filter_meta: Optional[dict] = None) -> list[SearchResult]:
        where = filter_meta if filter_meta else None
        r = self._col.query(
            query_embeddings = [vector.tolist()],
            n_results        = min(top_k, max(self._col.count(), 1)),
            where            = where,
            include          = ["documents","metadatas","distances"],
        )
        results = []
        for i, doc_id in enumerate(r["ids"][0]):
            dist  = r["distances"][0][i]
            score = 1.0 - dist   # ChromaDB cosine distance â†’ similarity
            results.append(SearchResult(
                doc_id   = doc_id,
                text     = r["documents"][0][i],
                score    = score,
                metadata = r["metadatas"][0][i],
            ))
        return results

    def delete(self, ids: list[str]) -> int:
        self._col.delete(ids=ids)
        return len(ids)

    def count(self) -> int:
        return self._col.count()

    def reset(self) -> None:
        name = self._col.name
        self._client.delete_collection(name)
        self._col = self._client.get_or_create_collection(
            name=name, metadata={"hnsw:space": "cosine"})

    def close(self) -> None:
        pass


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PUBLIC VECTOR STORE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class VectorStore:
    """
    Auto-selecting vector store for NexLog finding embeddings.

    Args:
        persist_path: Directory for persistent storage.
                      ChromaDB: used as the chroma persist dir.
                      Numpy fallback: {persist_path}/vectors.db (SQLite).
        collection:   ChromaDB collection name (ignored for numpy backend).
        force_numpy:  Force the numpy/SQLite fallback (useful for tests).

    Context manager supported:
        with VectorStore("case.ai/") as store:
            store.add_findings(findings, emb)
            results = store.query_text("SQL injection", emb)
    """

    def __init__(
        self,
        persist_path: str = "",
        collection:   str = "nexlog",
        force_numpy:  bool = False,
    ):
        self._persist_path = persist_path or _workspace_ai_dir()
        self._backend_name = ""
        self._backend      = None

        use_chroma = (
            not force_numpy
            and os.environ.get("NEXLOG_VECTOR_STORE", "numpy").strip().lower()
            in {"chroma", "chromadb"}
        )

        if use_chroma:
            try:
                import chromadb  # noqa: F401
                chroma_dir = os.path.join(self._persist_path, "chroma")
                self._backend      = _ChromaStore(chroma_dir, collection)
                self._backend_name = "chromadb"
            except ImportError:
                pass
            except Exception:
                pass

        if self._backend is None:
            db_path = os.path.join(self._persist_path, "vectors.db")
            self._backend      = _NumpyStore(db_path)
            self._backend_name = "numpy+sqlite-fts5"

    # â”€â”€ Core operations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def add(
        self,
        ids:        list[str],
        texts:      list[str],
        vectors:    np.ndarray,
        metadata:   list[dict],
        session_id: str = "",
    ) -> None:
        """Index documents. Duplicate IDs are silently skipped."""
        self._backend.add(ids, texts, vectors, metadata, session_id)

    def query(
        self,
        vector:      np.ndarray,
        top_k:       int           = 5,
        filter_meta: Optional[dict] = None,
    ) -> list[SearchResult]:
        """Semantic search by embedding vector."""
        return self._backend.query(vector, top_k, filter_meta)

    def query_text(
        self,
        text:    str,
        embedder,
        top_k:   int           = 5,
        filter_meta: Optional[dict] = None,
    ) -> list[SearchResult]:
        """Embed a query string then search â€” convenience wrapper."""
        vec = embedder.embed(text)
        return self.query(vec, top_k, filter_meta)

    def delete(self, ids: list[str]) -> int:
        """Delete documents by ID. Returns count removed."""
        return self._backend.delete(ids)

    def count(self) -> int:
        """Return the number of indexed documents."""
        return self._backend.count()

    def reset(self) -> None:
        """Drop all indexed data."""
        self._backend.reset()

    def close(self) -> None:
        """Release resources (SQLite connection etc.)."""
        try:
            self._backend.close()
        except Exception:
            pass

    # â”€â”€ Finding helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def add_findings(
        self,
        findings:   list,
        embedder,
        session_id: str = "",
        batch_size: int = 256,
    ) -> int:
        """
        Index a list of Finding objects.
        Converts each to text, embeds in batches, stores with metadata.

        Metadata stored per finding (all indexed-column fields):
          rule_id, rule_name, severity, category, source_ip,
          hostname, username, risk_score, session_id, mitre_ids.

        Returns the number of findings actually added (skips duplicates).
        """
        from embedder import finding_to_text

        before = self.count()

        for start in range(0, len(findings), batch_size):
            batch = findings[start : start + batch_size]
            texts = [finding_to_text(f) for f in batch]
            vecs  = embedder.embed_batch(texts)

            ids   = []
            metas = []
            for f in batch:
                # Use a deterministic ID: session_id + rule_id + trigger hash
                trig = getattr(f, "trigger_line", "") or ""
                import hashlib
                h = hashlib.sha256(
                    f"{session_id}:{getattr(f,'rule_id','')}:{trig}".encode()
                ).hexdigest()[:16]
                ids.append(f"f-{h}")

                metas.append({
                    "rule_id":    getattr(f, "rule_id",    ""),
                    "rule_name":  getattr(f, "rule_name",  ""),
                    "severity":   getattr(f.severity, "value",
                                         str(f.severity)) if hasattr(f,"severity") else "",
                    "category":   getattr(f, "category",   ""),
                    "source_ip":  getattr(f, "source_ip",  "") or "",
                    "hostname":   getattr(f, "hostname",   "") or "",
                    "username":   getattr(f, "username",   "") or "",
                    "risk_score": float(getattr(f, "risk_score", 0.0)),
                    "session_id": session_id,
                    "mitre_ids":  ",".join(
                        getattr(t, "full_id", "") for t in
                        getattr(f, "mitre_tags", [])),
                })

            self.add(ids, texts, vecs, metas, session_id=session_id)

        return self.count() - before

    @property
    def backend(self) -> str:
        return self._backend_name

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self) -> str:
        return (f"<VectorStore backend={self._backend_name} "
                f"count={self.count()}>")
