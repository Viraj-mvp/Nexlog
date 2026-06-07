"""
core/ â€” NexLog Layer 1: Universal Log Parser

Supported formats (50+):
  Web/Proxy:    Apache Combined/Error, Nginx Access/Error, IIS W3C,
                HAProxy, Squid, Caddy, Traefik
  System/OS:    Syslog RFC3164/5424, Auth.log, Auditd, Journald,
                kern.log, dmesg, macOS Unified Log
  Windows:      EVTX, Sysmon, Windows Firewall, DNS, PowerShell Script
  Network/Sec:  Zeek (conn/dns/http/ssl/files/json), Suricata EVE,
                Snort Fast, Cisco ASA/IOS, Palo Alto, Fortinet,
                pfSense, iptables, CEF, LEEF, GELF
  Cloud:        AWS CloudTrail, VPC Flow, ALB; Azure Activity/Sign-in;
                GCP Cloud Audit
  Database:     MySQL Error/General/Slow, PostgreSQL, MSSQL, MongoDB, Redis
  Container:    Docker JSON, Kubernetes Audit, Falco
  Email:        Postfix, Exchange, Sendmail
  DNS:          BIND9 Query, Windows DNS
  Generic:      JSON/JSONL, CSV, XML
  AI Fallback:  Unknown formats parsed by LLM (Groq/Gemini/Ollama free)

Usage:
    from core.engine import Engine
    from core.models import LogFormat

    eng = Engine()
    for entry in eng.parse("access.log"):
        print(entry.source_ip, entry.http_uri, entry.http_status)
"""
from .engine  import Engine, ParseStats
from .models  import LogEntry, LogFormat
from .detector import detect_format, detect_format_from_line, supported_formats
from .parsers  import get_parser

__all__ = [
    "Engine", "ParseStats",
    "LogEntry", "LogFormat",
    "detect_format", "detect_format_from_line", "supported_formats",
    "get_parser",
]
