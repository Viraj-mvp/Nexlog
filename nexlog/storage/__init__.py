"""
storage/ â€” NexLog Layer 3: Case Database + Chain of Custody

Modules:
    case_db            â€” SQLite case database (sessions, findings, notes, chains)
    chain_of_custody   â€” SHA-256 evidence ledger with HMAC tamper detection

Quick imports:
    from storage.case_db import CaseDB
    from storage.chain_of_custody import (
        hash_file, verify_file, multi_hash_file,
        hash_stream, hash_bytes, quick_verify,
        EvidenceLedger,
    )
"""

from .case_db import CaseDB
from .chain_of_custody import (
    hash_file,
    hash_stream,
    hash_bytes,
    verify_file,
    multi_hash_file,
    quick_verify,
    EvidenceLedger,
)

__all__ = [
    # Case database
    "CaseDB",
    # Hash functions
    "hash_file",
    "hash_stream",
    "hash_bytes",
    "verify_file",
    "multi_hash_file",
    "quick_verify",
    # Evidence ledger
    "EvidenceLedger",
]
