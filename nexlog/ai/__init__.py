"""
ai/ â€” NexLog AI Query Engine (Layer 5 shared)
Natural language question-answering over security findings.

Architecture (RAG pipeline):
  Embedder       â†’ Finding text â†’ dense vector (TF-IDF/sentence-transformers)
  VectorStore    â†’ indexed embeddings + cosine retrieval (numpy/ChromaDB)
  LLMClient      â†’ synthesis (Ollama / Groq / Gemini / Anthropic / template)
  RAGEngine      â†’ retrieve-then-generate pipeline
  AIQueryEngine  â†’ unified interface for GUI + web, with conversation history

Install profiles
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Minimum (always works â€” TF-IDF + template synthesis):
  No extra packages required. sklearn is already installed.
  Quality: good keyword recall, rule-based answers.

Better embeddings (semantic search):
  pip install sentence-transformers
  Quality: dense semantic vectors, understands paraphrases.

Better LLM (natural language answers):
  Install Ollama: https://ollama.com
  ollama pull mistral          # ~4.1 GB download
  # or: ollama pull llama3.1
  # or: ollama pull gemma3
  Quality: full natural language synthesis.

Best (semantic + local LLM):
  pip install sentence-transformers && ollama pull mistral
  All data stays on-device. Suitable for air-gapped deployments.

Free cloud LLM options (no credit card needed):
  Tier 2 â€” Groq (fastest free option):
    export GROQ_API_KEY=gsk_...   # get at console.groq.com
  Tier 3 â€” Google Gemini (most generous quota):
    export GEMINI_API_KEY=AIza... # get at aistudio.google.com

Paid cloud LLM (highest quality):
  Tier 4 â€” Anthropic:
    export ANTHROPIC_API_KEY=sk-ant-...

ChromaDB (persistent vector store):
  pip install chromadb
  Scales to millions of findings, persistent HNSW index.

Quick start
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  from ai import AIQueryEngine
  from storage.case_db import CaseDB

  with CaseDB('case.facase') as db:
      engine = AIQueryEngine(case_db_path='case.facase')
      engine.ensure_indexed(db, session_id='session-001')

  answer = engine.ask('What SQL injection attacks happened?')
  print(answer.text)
  for src in answer.sources:
      print(f'  {src[\"rule_id\"]} score={src[\"score\"]:.3f}')

  # Status / diagnostics
  print(engine.status())
"""

from .embedder       import Embedder, finding_to_text
from .vector_store   import VectorStore, SearchResult
from .llm_client     import LLMClient
from .rag_engine     import RAGEngine, RAGAnswer
from .query_interface import AIQueryEngine, ConversationHistory, ConversationTurn

__all__ = [
    # Primary interface (use this)
    "AIQueryEngine",
    "ConversationHistory",
    "ConversationTurn",

    # Lower-level building blocks
    "RAGEngine",
    "RAGAnswer",
    "Embedder",
    "VectorStore",
    "SearchResult",
    "LLMClient",

    # Utility
    "finding_to_text",
]
