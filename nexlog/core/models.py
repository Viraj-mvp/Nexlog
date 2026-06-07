"""
models.py â€” NexLog Layer 1
Universal data model. Every parser produces LogEntry objects.
Supports 50+ log formats from web, OS, cloud, network, security tools,
databases, containers, email, DNS, and unknown (AI-parsed).
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class LogFormat(Enum):
    # â”€â”€ Web / Proxy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    APACHE_COMBINED     = "apache_combined"      # Apache/Nginx access log
    APACHE_ERROR        = "apache_error"          # Apache error log
    NGINX_ACCESS        = "nginx_access"          # Nginx access (same as apache_combined)
    NGINX_ERROR         = "nginx_error"           # Nginx error log
    IIS_W3C             = "iis_w3c"               # Microsoft IIS W3C Extended
    HAPROXY             = "haproxy"               # HAProxy access/error log
    SQUID               = "squid"                 # Squid proxy native format
    CADDY               = "caddy"                 # Caddy server JSON log
    TRAEFIK             = "traefik"               # Traefik JSON access log

    # â”€â”€ System / OS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    SYSLOG              = "syslog"                # RFC 3164 syslog
    SYSLOG_RFC5424      = "syslog_rfc5424"        # RFC 5424 structured syslog
    AUTH_LOG            = "auth_log"              # Linux /var/log/auth.log
    AUDITD              = "auditd"                # Linux auditd (audit.log)
    JOURNALD            = "journald"              # systemd journald JSON export
    KERN_LOG            = "kern_log"              # Linux kernel log
    DMESG               = "dmesg"                 # Linux dmesg
    MACOS_UNIFIED       = "macos_unified"         # macOS Unified Logging (JSON)
    MACOS_ASL           = "macos_asl"             # macOS Apple System Log

    # â”€â”€ Windows â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    WINDOWS_EVTX        = "windows_evtx"          # Windows Event Log XML
    WINDOWS_SYSMON      = "windows_sysmon"        # Sysmon XML (subset of EVTX)
    WINDOWS_FIREWALL    = "windows_firewall"      # Windows Firewall WFAS log
    WINDOWS_DNS         = "windows_dns"           # Windows DNS debug log
    POWERSHELL_SCRIPT   = "powershell_script"     # PowerShell ScriptBlock log

    # â”€â”€ Network / Security â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ZEEK_CONN           = "zeek_conn"             # Zeek/Bro conn.log TSV
    ZEEK_DNS            = "zeek_dns"              # Zeek dns.log TSV
    ZEEK_HTTP           = "zeek_http"             # Zeek http.log TSV
    ZEEK_SSL            = "zeek_ssl"              # Zeek ssl.log TSV
    ZEEK_FILES          = "zeek_files"            # Zeek files.log TSV
    ZEEK_JSON           = "zeek_json"             # Zeek JSON log (any type)
    SURICATA_EVE        = "suricata_eve"          # Suricata EVE JSON
    SNORT_FAST          = "snort_fast"            # Snort fast alert format
    CISCO_ASA           = "cisco_asa"             # Cisco ASA syslog
    CISCO_IOS           = "cisco_ios"             # Cisco IOS syslog
    PALOALTO            = "paloalto"              # Palo Alto Networks CSV syslog
    FORTINET            = "fortinet"              # Fortinet FortiGate KV log
    CHECKPOINT          = "checkpoint"            # Check Point syslog
    PFSENSE             = "pfsense"               # pfSense/OPNsense filterlog
    IPTABLES            = "iptables"              # Linux iptables/nftables kernel log
    CEF                 = "cef"                   # Common Event Format (ArcSight)
    LEEF                = "leef"                  # Log Event Extended Format (QRadar)
    GELF                = "gelf"                  # Graylog Extended Log Format

    # â”€â”€ Cloud â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    AWS_CLOUDTRAIL      = "aws_cloudtrail"        # AWS CloudTrail JSON
    AWS_VPC_FLOW        = "aws_vpc_flow"          # AWS VPC Flow Logs
    AWS_ALB             = "aws_alb"               # AWS ALB/ELB access logs
    AWS_WAF             = "aws_waf"               # AWS WAF logs JSON
    AWS_S3_ACCESS       = "aws_s3_access"         # AWS S3 server access log
    AZURE_ACTIVITY      = "azure_activity"        # Azure Activity Log JSON
    AZURE_SIGNIN        = "azure_signin"          # Azure AD Sign-In Log JSON
    AZURE_NSG_FLOW      = "azure_nsg_flow"        # Azure NSG Flow Log JSON
    GCP_AUDIT           = "gcp_audit"             # GCP Cloud Audit Log JSON
    GCP_VPC_FLOW        = "gcp_vpc_flow"          # GCP VPC Flow Log JSON

    # â”€â”€ Database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    MYSQL_ERROR         = "mysql_error"           # MySQL error log
    MYSQL_GENERAL       = "mysql_general"         # MySQL general query log
    MYSQL_SLOW          = "mysql_slow"            # MySQL slow query log
    POSTGRESQL          = "postgresql"            # PostgreSQL log
    MSSQL               = "mssql"                 # SQL Server error log
    MONGODB             = "mongodb"               # MongoDB log (JSON)
    REDIS               = "redis"                 # Redis log

    # â”€â”€ Container / Kubernetes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    DOCKER_JSON         = "docker_json"           # Docker container log JSON
    KUBERNETES_AUDIT    = "kubernetes_audit"      # K8s audit log JSON
    KUBERNETES_POD      = "kubernetes_pod"        # K8s pod log (line wrapped)
    FALCO               = "falco"                 # Falco runtime security JSON

    # â”€â”€ Email â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    POSTFIX             = "postfix"               # Postfix mail log
    EXCHANGE            = "exchange"              # Exchange message tracking CSV
    SENDMAIL            = "sendmail"              # Sendmail log

    # â”€â”€ DNS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    BIND_QUERY          = "bind_query"            # BIND9 query log
    WINDOWS_DNS_QUERY   = "windows_dns_query"     # Windows DNS analytical log

    # â”€â”€ Application â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    JSON_GENERIC        = "json_generic"          # Any JSON/JSONL log
    JSON_LINES          = "json_lines"            # Explicit JSONL (one obj/line)
    CSV_GENERIC         = "csv_generic"           # Generic CSV with header
    XML_GENERIC         = "xml_generic"           # Generic XML event log

    # â”€â”€ Mobile / Embedded \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    ANDROID_LOGCAT      = "android_logcat"
    IOS_SYSLOG          = "ios_syslog"
    # â”€â”€ Big Data / Distributed \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    HADOOP              = "hadoop"
    SPARK               = "spark"
    KAFKA               = "kafka"
    ZOOKEEPER           = "zookeeper"
    ELASTICSEARCH       = "elasticsearch"
    # â”€â”€ Windows Application Logs \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    WINDOWS_CBS         = "windows_cbs"
    WINDOWS_SETUP       = "windows_setup"
    WINDOWS_UPDATE      = "windows_update"
    IIS_HTTPAPI         = "iis_httpapi"
    # â”€â”€ macOS \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    MACOS_INSTALL       = "macos_install"
    MACOS_CRASHREPORTER = "macos_crashreporter"
    # â”€â”€ Cloud / OpenStack \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    OPENSTACK_NOVA      = "openstack_nova"
    OPENSTACK_KEYSTONE  = "openstack_keystone"
    OPENSTACK_NEUTRON   = "openstack_neutron"
    OPENSTACK           = "openstack"
    VMWARE_ESX          = "vmware_esx"
    # â”€â”€ Healthcare / Domain-specific \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    HEALTH_APP          = "health_app"
    LOG4J               = "log4j"
    PYTHON_LOGGING      = "python_logging"
    RAILS               = "rails"
    DJANGO              = "django"
    NODEJS              = "nodejs"
    SPRING_BOOT         = "spring_boot"
    # â”€â”€ Security Tools \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    OSSEC               = "ossec"
    FAIL2BAN            = "fail2ban"
    CROWDSTRIKE         = "crowdstrike"
    CARBONBLACK         = "carbonblack"
    # â”€â”€ Network Devices \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    JUNIPER             = "juniper"
    F5_BIG_IP           = "f5_big_ip"
    OPENVPN             = "openvpn"
    WIREGUARD           = "wireguard"

    # â”€â”€ AI-parsed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    AI_PARSED           = "ai_parsed"             # Unknown â€” parsed by LLM
    UNKNOWN             = "unknown"               # Could not detect or parse


@dataclass
class LogEntry:
    """
    Universal log entry. Shape is identical regardless of source format.
    Fields that don't exist in a given format are None â€” never absent.

    Design rule: downstream code must never do hasattr() checks.
    Always check:  if entry.source_ip is not None
    """

    # â”€â”€ Identity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    raw_line:       str
    line_number:    int
    source_file:    str
    log_format:     LogFormat

    # â”€â”€ Time â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    timestamp:      Optional[datetime] = None
    timestamp_raw:  Optional[str]      = None

    # â”€â”€ Network identity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    source_ip:      Optional[str] = None
    source_port:    Optional[int] = None
    dest_ip:        Optional[str] = None
    dest_port:      Optional[int] = None
    hostname:       Optional[str] = None
    protocol:       Optional[str] = None   # tcp/udp/icmp/http/dns

    # â”€â”€ Auth & user â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    username:       Optional[str] = None
    auth_result:    Optional[str] = None   # "success" | "failure" | None

    # â”€â”€ HTTP specific â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    http_method:    Optional[str] = None
    http_uri:       Optional[str] = None
    http_uri_decoded: Optional[str] = None
    http_status:    Optional[int] = None
    http_bytes:     Optional[int] = None
    http_referrer:  Optional[str] = None
    http_user_agent: Optional[str] = None
    http_version:   Optional[str] = None

    # â”€â”€ OS / process â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    process_name:   Optional[str] = None
    process_id:     Optional[int] = None
    parent_pid:     Optional[int] = None
    event_id:       Optional[str] = None
    message:        Optional[str] = None
    command_line:   Optional[str] = None   # full command line (Sysmon/Auditd)

    # â”€â”€ DNS specific â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    dns_query:      Optional[str] = None
    dns_type:       Optional[str] = None   # A/AAAA/MX/TXT/etc.
    dns_answer:     Optional[str] = None
    dns_rcode:      Optional[str] = None   # NOERROR/NXDOMAIN/etc.

    # â”€â”€ TLS/SSL specific â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    tls_version:    Optional[str] = None
    tls_cipher:     Optional[str] = None
    tls_server_name: Optional[str] = None  # SNI
    tls_ja3:        Optional[str] = None   # JA3 fingerprint (Zeek)

    # â”€â”€ File specific â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    file_hash_md5:  Optional[str] = None
    file_hash_sha1: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_name:      Optional[str] = None
    file_path:      Optional[str] = None
    file_size:      Optional[int] = None

    # â”€â”€ Firewall/ACL specific â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    action:         Optional[str] = None   # allow/deny/drop/reject
    rule_name:      Optional[str] = None   # matched firewall rule
    direction:      Optional[str] = None   # inbound/outbound

    # â”€â”€ Cloud specific â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    cloud_provider: Optional[str] = None   # aws/azure/gcp
    cloud_region:   Optional[str] = None
    cloud_account:  Optional[str] = None
    cloud_service:  Optional[str] = None
    cloud_resource: Optional[str] = None

    # â”€â”€ Computed fields â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    severity:       Optional[str] = None
    tags:           list = field(default_factory=list)
    extra:          dict = field(default_factory=dict)
    ai_confidence:  Optional[float] = None  # 0-1 for AI_PARSED entries

    def to_dict(self) -> dict:
        d = {}
        for f_name, f_val in self.__dict__.items():
            if isinstance(f_val, datetime):
                d[f_name] = f_val.isoformat()
            elif isinstance(f_val, LogFormat):
                d[f_name] = f_val.value
            else:
                d[f_name] = f_val
        return d

    def __repr__(self) -> str:
        ts  = self.timestamp.isoformat() if self.timestamp else self.timestamp_raw
        src = self.source_ip or self.hostname or "?"
        evt = self.http_uri or self.dns_query or self.command_line or self.message or self.raw_line[:60]
        return f"<LogEntry [{self.log_format.value}] {ts} src={src} | {evt}>"


# â”€â”€ Additional formats added from real-world log samples â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Note: LogFormat2 placeholder removed - all formats now in LogFormat enum above
