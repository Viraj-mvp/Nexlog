"""
interface/web/ — REST API
FastAPI mode (recommended): pip install fastapi uvicorn
Stdlib mode  (zero-deps):   python api.py --stdlib

Modules:
    api     — Full REST API server with 14 endpoints
    schemas — Request/response dataclass schemas
"""
from .schemas import (
    AnalyseRequest, AnalyseResponse, SessionSummary,
    FindingSchema, FindingListResponse,
    IOCSchema, IOCListResponse,
    ReportRequest, ReportResponse,
    HealthResponse, StatsResponse,
    NoteRequest, ErrorResponse,
)

__all__ = [
    "AnalyseRequest", "AnalyseResponse", "SessionSummary",
    "FindingSchema", "FindingListResponse",
    "IOCSchema", "IOCListResponse",
    "ReportRequest", "ReportResponse",
    "HealthResponse", "StatsResponse",
    "NoteRequest", "ErrorResponse",
]
