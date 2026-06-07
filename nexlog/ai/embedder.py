"""
ai/embedder.py â€” NexLog AI Layer
Converts Finding objects into dense embedding vectors for semantic search.

Four tiers, auto-selected at construction time in quality order:

  Tier 1 â€” sentence-transformers (all-MiniLM-L6-v2)
            384-dim dense vectors. Best semantic quality.
            Requires: pip install sentence-transformers torch
            Offline after first download. Private â€” no data leaves the machine.

  Tier 2 â€” ChromaDB default embedding function
            Uses ChromaDB's bundled sentence-transformers model.
            Requires: pip install chromadb
            Same quality as Tier 1, slightly easier install.

  Tier 3 â€” TF-IDF via sklearn (DEFAULT â€” always available)
            sklearn 1.8+ is present on this system.
            Fits a corpus vocabulary on first embed_batch() call.
            Vector dimension = min(1024, vocab size).
            Good for keyword-heavy security log text.
            No external downloads required.

  Tier 4 â€” Hash-based deterministic fallback (stdlib only)
            SHA-256 of the text â†’ 256-dim float vector.
            Fast, reproducible, zero dependencies.
            No semantic meaning â€” only used if sklearn fails.

Design decisions:
  - All tiers produce L2-normalised float vectors so cosine similarity
    == dot product, enabling fast numpy-based retrieval.
  - Finding â†’ text conversion is consistent across all tiers:
    a structured prose summary of the finding's most informative fields.
  - Batch embedding is preferred for efficiency: embed_batch(texts) is
    always faster than calling embed() in a loop.
  - The active tier name is exposed via .tier_name for diagnostics.

Usage:
    from ai.embedder import Embedder

    emb  = Embedder()           # auto-selects best available tier
    vecs = emb.embed_batch([    # embed multiple texts at once
        "GET /login?q=sqli", "Failed password for root", ...
    ])

    # Embed a Finding directly
    finding_text = Embedder.finding_to_text(finding)
    vec = emb.embed(finding_text)
"""

import hashlib
import os
import sys
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


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _default_tiers(force_tier: Optional[int]) -> list[int]:
    if force_tier:
        return [force_tier]

    if os.environ.get("NEXLOG_HARDWARE_MODE") == "performance":
        return [1, 2, 3, 4]

    mode = os.environ.get("NEXLOG_AI_EMBEDDER", "fast").strip().lower()
    if mode in {"semantic", "sentence-transformers", "sentence_transformers", "st"}:
        return [1, 3, 4]
    if mode in {"chroma", "chromadb"}:
        return [2, 3, 4]
    if mode in {"auto", "best"} or _env_flag("NEXLOG_ENABLE_HEAVY_AI"):
        return [1, 2, 3, 4]
    if mode in {"hash", "tier4"}:
        return [4]
    return [3, 4]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FINDING â†’ TEXT CONVERSION  (shared across all tiers)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def finding_to_text(finding) -> str:
    """
    Convert a Finding object into a rich natural-language text string
    optimised for semantic embedding.

    The format is designed to capture:
      - Rule identity (ID, name, category)
      - Severity and risk
      - Actor context (source IP, hostname, username, process)
      - MITRE ATT&CK techniques and tactics
      - The actual evidence (trigger line)
      - Temporal context

    This text is what gets embedded â€” more fields = richer semantic space.
    Structured text (with explicit field labels) outperforms raw log lines
    because the embedding model can associate "source_ip" with IP-address
    concepts even when values differ.
    """
    parts = []

    # Rule identity
    parts.append(f"Rule {getattr(finding, 'rule_id', '')} "
                 f"{getattr(finding, 'rule_name', '')}.")
    desc = getattr(finding, 'description', '')
    if desc:
        parts.append(desc)

    # Severity + category
    sev  = getattr(finding.severity, 'value', str(finding.severity)) \
           if hasattr(finding, 'severity') else ''
    cat  = getattr(finding, 'category', '')
    risk = getattr(finding, 'risk_score', 0.0)
    parts.append(f"Severity {sev} category {cat} risk score {risk:.1f}.")

    # Actor context
    src  = getattr(finding, 'source_ip',    '') or ''
    host = getattr(finding, 'hostname',     '') or ''
    user = getattr(finding, 'username',     '') or ''
    proc = getattr(finding, 'process_name', '') or ''
    if src:  parts.append(f"Source IP {src}.")
    if host: parts.append(f"Hostname {host}.")
    if user: parts.append(f"Username {user}.")
    if proc: parts.append(f"Process {proc}.")

    # MITRE ATT&CK
    for tag in getattr(finding, 'mitre_tags', []):
        parts.append(f"MITRE {getattr(tag,'full_id','')} "
                     f"{getattr(tag,'tactic_name','')} "
                     f"{getattr(tag,'technique_name','')}.")

    # Evidence
    trig = getattr(finding, 'trigger_line', '') or ''
    if trig:
        parts.append(f"Trigger line {trig[:300]}.")
    for line in getattr(finding, 'supporting_lines', [])[:3]:
        if line:
            parts.append(str(line)[:200])

    # Timestamp
    ts = getattr(finding, 'timestamp', None)
    if ts:
        parts.append(f"Timestamp {ts.isoformat() if hasattr(ts,'isoformat') else ts}.")

    return " ".join(p for p in parts if p)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TIER 4 â€” Hash-based fallback  (stdlib only)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _hash_embed(text: str, dim: int = 256) -> np.ndarray:
    """
    Deterministic embedding from SHA-256 digest.
    Produces a unit-norm float vector of `dim` dimensions.
    No semantic meaning â€” purely structural. Used only when sklearn fails.
    """
    raw    = hashlib.sha256(text.encode("utf-8", errors="replace")).digest()
    # Tile the 32-byte digest to fill `dim` floats
    tiled  = (raw * ((dim // 32) + 1))[:dim]
    vec    = np.frombuffer(bytes(tiled), dtype=np.uint8).astype(np.float32)
    vec    = vec - 127.5           # centre around zero
    norm   = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TIER 3 â€” TF-IDF with sklearn  (default â€” always available)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _TFIDFEmbedder:
    """
    TF-IDF vectoriser backed by sklearn.
    Fits lazily on first embed_batch() call. Thread-safe after fitting.
    Vector dimension = min(max_features, corpus vocab size).
    """

    def __init__(self, max_features: int = 1024):
        from sklearn.feature_extraction.text import TfidfVectorizer
        self._vectorizer   = TfidfVectorizer(
            max_features   = max_features,
            sublinear_tf   = True,      # log(1+tf) â€” helps for rare terms
            strip_accents  = "unicode",
            analyzer       = "word",
            token_pattern  = r"(?u)\b[a-zA-Z0-9_\-\.]{2,}\b",
            ngram_range    = (1, 2),    # unigrams + bigrams
            min_df         = 1,         # keep rare security terms
        )
        self._fitted       = False
        self._corpus       = []         # cached for incremental refitting
        self._max_features = max_features

    def fit(self, texts: list[str]) -> None:
        """Fit the vectoriser on a corpus. Call before embed()."""
        self._corpus  = list(texts)
        self._vectorizer.fit(self._corpus)
        self._fitted  = True

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        """
        Return an (N, D) float32 array of L2-normalised TF-IDF vectors.
        Fits on the provided texts only if not already fitted.
        After fitting, always uses transform() â€” never refits on query texts.
        """
        if not self._fitted:
            self.fit(texts)

        mat  = self._vectorizer.transform(texts)
        arr  = mat.toarray().astype(np.float32)
        # L2 normalise each row
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)
        return arr / norms

    def embed(self, text: str) -> np.ndarray:
        """Embed a single text. Fits on this text alone if not fitted."""
        return self.embed_batch([text])[0]

    @property
    def dim(self) -> int:
        if self._fitted:
            return len(self._vectorizer.vocabulary_)
        return self._max_features


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TIER 1+2 â€” sentence-transformers / ChromaDB  (optional)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _SentenceTransformerEmbedder:
    """Wraps sentence-transformers. Loaded only if the package is installed."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        import torch
        from sentence_transformers import SentenceTransformer

        device = "cpu"
        if os.environ.get("NEXLOG_HARDWARE_MODE") == "performance":
            if torch.cuda.is_available():
                device = "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                device = "mps"

        self._model = SentenceTransformer(model_name, device=device)
        self._dim   = self._model.get_sentence_embedding_dimension()

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        vecs = self._model.encode(texts, convert_to_numpy=True,
                                  normalize_embeddings=True,
                                  show_progress_bar=False)
        return vecs.astype(np.float32)

    def embed(self, text: str) -> np.ndarray:
        return self.embed_batch([text])[0]

    @property
    def dim(self) -> int:
        return self._dim


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PUBLIC EMBEDDER  (auto-selects tier)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class Embedder:
    """
    Auto-selecting embedding engine for NexLog findings.

    Constructor probes available packages in quality order and selects
    the best available tier. The tier selection is transparent â€”
    callers use the same API regardless of tier.

    Args:
        model_name:   sentence-transformers model name (Tier 1 only).
        max_features: TF-IDF vocabulary size (Tier 3 only).
        force_tier:   Force a specific tier (1-4). Used for testing.
    """

    def __init__(
        self,
        model_name:   str = "all-MiniLM-L6-v2",
        max_features: int = 1024,
        force_tier:   Optional[int] = None,
    ):
        self._impl      = None
        self._tier      = 0
        self._tier_name = ""

        tiers_to_try = _default_tiers(force_tier)

        for tier in tiers_to_try:
            if tier == 1:
                try:
                    self._impl      = _SentenceTransformerEmbedder(model_name)
                    self._tier      = 1
                    self._tier_name = f"sentence-transformers ({model_name})"
                    break
                except Exception:
                    pass

            elif tier == 2:
                try:
                    import chromadb
                    from chromadb.utils.embedding_functions import (
                        DefaultEmbeddingFunction)
                    self._impl      = _ChromaEmbedder(DefaultEmbeddingFunction())
                    self._tier      = 2
                    self._tier_name = "chromadb-default-embedding"
                    break
                except Exception:
                    pass

            elif tier == 3:
                try:
                    import sklearn  # noqa: F401
                    self._impl      = _TFIDFEmbedder(max_features)
                    self._tier      = 3
                    self._tier_name = f"sklearn-tfidf (max_features={max_features})"
                    break
                except ImportError:
                    pass

            elif tier == 4:
                self._impl      = None   # uses _hash_embed directly
                self._tier      = 4
                self._tier_name = "hash-fallback (sha256)"
                break

    @property
    def tier(self) -> int:
        return self._tier

    @property
    def tier_name(self) -> str:
        return self._tier_name

    @property
    def dim(self) -> int:
        if self._impl and hasattr(self._impl, "dim"):
            return self._impl.dim
        return 256   # hash fallback dim

    def embed(self, text: str) -> np.ndarray:
        """Embed a single text string. Returns a 1-D normalised float32 array."""
        if self._tier == 4 or self._impl is None:
            return _hash_embed(text, dim=256)
        return self._impl.embed(text)

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        """
        Embed a list of texts. Returns an (N, D) float32 array.
        Always prefer this over calling embed() in a loop.
        """
        if not texts:
            return np.empty((0, self.dim), dtype=np.float32)
        if self._tier == 4 or self._impl is None:
            return np.stack([_hash_embed(t, 256) for t in texts])
        return self._impl.embed_batch(texts)

    def embed_finding(self, finding) -> np.ndarray:
        """Convert a Finding object to an embedding vector."""
        return self.embed(finding_to_text(finding))

    def embed_findings(self, findings: list) -> np.ndarray:
        """Embed a list of Finding objects. Returns (N, D) array."""
        texts = [finding_to_text(f) for f in findings]
        return self.embed_batch(texts)

    def __repr__(self) -> str:
        return f"<Embedder tier={self._tier} ({self._tier_name}) dim={self.dim}>"


# â”€â”€ Tier 2 ChromaDB helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class _ChromaEmbedder:
    """Wraps a ChromaDB embedding function."""
    def __init__(self, fn):
        self._fn  = fn
        self._dim = 384  # ChromaDB default model dim

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        vecs = np.array(self._fn(texts), dtype=np.float32)
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)
        return vecs / norms

    def embed(self, text: str) -> np.ndarray:
        return self.embed_batch([text])[0]

    @property
    def dim(self) -> int:
        return self._dim


# Public re-export of the text conversion function
__all__ = ["Embedder", "finding_to_text"]
