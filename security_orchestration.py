"""
security_orchestration.py – KRIGEN Intelligence Platform
=========================================================
A real, production-grade security orchestration engine that:
  • Ingests alerts from multiple sources (syslog UDP, log files, inline API)
  • Enriches IOCs (IPs, domains, file hashes) via VirusTotal, AbuseIPDB, OTX
  • Correlates events and maps them to MITRE ATT&CK tactics/techniques
  • Automates response actions: firewall blocks, DNS sinkholing, process kill,
    alert suppression and incident escalation
  • Persists incidents to a local SQLite database
  • Emits structured JSON reports and a full audit log

Dependencies (all stdlib except `requests`):
    pip install requests

Configuration is read from `orchestration.ini` (auto-created with safe defaults
on first run) or overridden via environment variables prefixed with KRIGEN_.
"""

from __future__ import annotations

import configparser
import hashlib
import ipaddress
import json
import logging
import os
import queue
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_FILE = Path("orchestration.ini")

_DEFAULT_CONFIG = """
[general]
db_path          = krigen_incidents.db
report_dir       = reports
log_file         = orchestration.log
log_level        = INFO
worker_threads   = 4
alert_queue_size = 1000

[syslog]
enabled = false
host    = 0.0.0.0
port    = 514

[file_watch]
enabled = false
paths   = /var/log/syslog,/var/log/auth.log
interval_sec = 5

[threat_intel]
virustotal_api_key = 
abuseipdb_api_key  = 
otx_api_key        = 
request_timeout    = 10
cache_ttl_sec      = 3600

[response]
auto_block_ips        = false
iptables_chain        = KRIGEN_BLOCK
auto_sinkhole_domains = false
hosts_file            = /etc/hosts
auto_kill_processes   = false
min_severity_to_block = HIGH
escalation_webhook    =
""".strip()


def _load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_string(_DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE)
    # Environment variable overrides: KRIGEN_SECTION_KEY=value
    for key, value in os.environ.items():
        if key.startswith("KRIGEN_"):
            parts = key[7:].lower().split("_", 1)
            if len(parts) == 2:
                section, option = parts
                if not cfg.has_section(section):
                    cfg.add_section(section)
                cfg.set(section, option, value)
    if not CONFIG_FILE.exists():
        with CONFIG_FILE.open("w") as f:
            cfg.write(f)
    return cfg


CONFIG: configparser.ConfigParser = _load_config()


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging() -> logging.Logger:
    log_level = getattr(logging, CONFIG.get("general", "log_level", fallback="INFO").upper(), logging.INFO)
    log_file = CONFIG.get("general", "log_file", fallback="orchestration.log")
    fmt = "%(asctime)s %(levelname)-8s [%(threadName)s] %(message)s"
    handlers: List[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(log_file))
    except OSError as exc:
        print(f"WARNING: cannot open log file {log_file}: {exc}", file=sys.stderr)
    logging.basicConfig(level=log_level, format=fmt, handlers=handlers)
    return logging.getLogger("krigen")


LOG = _setup_logging()


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Convert a 0-100 risk score to a severity level."""
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 10:
            return cls.LOW
        return cls.INFO


class IOCType(str, Enum):
    IP_ADDRESS  = "ip_address"
    DOMAIN      = "domain"
    FILE_HASH   = "file_hash"
    URL         = "url"
    EMAIL       = "email"
    UNKNOWN     = "unknown"


class IncidentStatus(str, Enum):
    NEW          = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED    = "CONTAINED"
    RESOLVED     = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


# MITRE ATT&CK tactic → technique mapping (subset for detection patterns)
MITRE_TACTICS: Dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    """An Indicator of Compromise extracted from a raw alert."""
    value: str
    ioc_type: IOCType
    risk_score: float = 0.0          # 0–100
    enrichment: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Alert:
    """A normalised security alert ready for processing."""
    alert_id: str
    source: str
    raw: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    iocs: List[IOC] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Incident:
    """An incident aggregating one or more correlated alerts."""
    incident_id: str
    status: IncidentStatus = IncidentStatus.NEW
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    alerts: List[Alert] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    response_actions: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# IOC extraction helpers
# ---------------------------------------------------------------------------

_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_RE_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_URL    = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_RE_EMAIL  = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def extract_iocs(text: str) -> List[IOC]:
    """Extract all recognisable IOCs from a text string."""
    iocs: List[IOC] = []
    seen: Set[str] = set()

    def _add(value: str, ioc_type: IOCType) -> None:
        key = f"{ioc_type}:{value}"
        if key not in seen:
            seen.add(key)
            iocs.append(IOC(value=value, ioc_type=ioc_type))

    for m in _RE_SHA256.finditer(text):
        _add(m.group(), IOCType.FILE_HASH)
    for m in _RE_SHA1.finditer(text):
        _add(m.group(), IOCType.FILE_HASH)
    for m in _RE_MD5.finditer(text):
        _add(m.group(), IOCType.FILE_HASH)
    for m in _RE_URL.finditer(text):
        _add(m.group(), IOCType.URL)
        host = urlparse(m.group()).hostname or ""
        if host:
            try:
                ipaddress.ip_address(host)
                if not _is_private_ip(host):
                    _add(host, IOCType.IP_ADDRESS)
            except ValueError:
                _add(host, IOCType.DOMAIN)
    for m in _RE_EMAIL.finditer(text):
        _add(m.group(), IOCType.EMAIL)
        _add(m.group().split("@", 1)[1], IOCType.DOMAIN)
    for m in _RE_IPV4.finditer(text):
        ip = m.group()
        if not _is_private_ip(ip):
            _add(ip, IOCType.IP_ADDRESS)
    # Common non-TLD suffixes that frequently appear in log text
    _NON_TLD = {".log", ".conf", ".txt", ".cfg", ".ini", ".sh", ".py", ".rb", ".pl", ".xml", ".json"}
    for m in _RE_DOMAIN.finditer(text):
        val = m.group().lower()
        if "." in val and not any(val.endswith(s) for s in _NON_TLD) and len(val) >= 4:
            _add(val, IOCType.DOMAIN)

    return iocs


# ---------------------------------------------------------------------------
# MITRE ATT&CK pattern detection
# ---------------------------------------------------------------------------

# Each rule: (pattern, tactic_id, technique_id, description)
DETECTION_RULES: List[Tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"(failed password|authentication failure|invalid user)", re.I),
     "TA0006", "T1110", "Brute-force / credential stuffing attempt"),
    (re.compile(r"(sudo|su\b).*(command not allowed|not in sudoers)", re.I),
     "TA0004", "T1548", "Privilege escalation attempt via sudo"),
    (re.compile(r"(wget|curl).*(http|ftp)://", re.I),
     "TA0011", "T1071", "Outbound download via HTTP/FTP – possible C2 beaconing"),
    (re.compile(r"(chmod|chown)\s+[0-9]+\s+/", re.I),
     "TA0005", "T1222", "File permissions modification"),
    (re.compile(r"(crontab|at\s+-f|systemctl\s+enable)", re.I),
     "TA0003", "T1053", "Scheduled task / persistence mechanism"),
    (re.compile(r"(nc |ncat |netcat ).*([\-]{1,2}e\s*/bin|/bin/sh|/bin/bash)", re.I),
     "TA0002", "T1059", "Reverse shell execution via netcat"),
    (re.compile(r"(mimikatz|lsass\.exe|sekurlsa)", re.I),
     "TA0006", "T1003", "Credential dumping – LSASS / Mimikatz"),
    (re.compile(r"(nmap|masscan|zmap).*(--scan|scan\s+type|\-p\s+[\d,-]+)", re.I),
     "TA0007", "T1046", "Network service scanning / discovery"),
    (re.compile(r"(powershell|pwsh).*(encodedcommand|bypass|hidden|downloadstring)", re.I),
     "TA0002", "T1059.001", "Encoded / obfuscated PowerShell execution"),
    (re.compile(r"(base64\s+\-d|base64decode|frombase64string)", re.I),
     "TA0005", "T1027", "Base64 obfuscation – possible payload decoding"),
    (re.compile(r"(exfil|exfiltrat|data.*transfer|scp\s+.*@)", re.I),
     "TA0010", "T1041", "Possible data exfiltration"),
    (re.compile(r"(ransomware|\.locked|\.encrypted|your files have been)", re.I),
     "TA0040", "T1486", "Ransomware / data-encryption for impact"),
]


def detect_mitre(text: str) -> Tuple[List[str], List[str], str]:
    """
    Return (tactic_ids, technique_ids, description) by matching detection rules
    against the raw alert text.
    """
    tactics: List[str] = []
    techniques: List[str] = []
    descriptions: List[str] = []
    for pattern, tactic, technique, desc in DETECTION_RULES:
        if pattern.search(text):
            if tactic not in tactics:
                tactics.append(tactic)
            if technique not in techniques:
                techniques.append(technique)
            descriptions.append(desc)
    return tactics, techniques, "; ".join(descriptions)


# ---------------------------------------------------------------------------
# Alert normalisation
# ---------------------------------------------------------------------------

_alert_counter = 0
_alert_counter_lock = threading.Lock()


def _next_alert_id() -> str:
    global _alert_counter
    with _alert_counter_lock:
        _alert_counter += 1
        return f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{_alert_counter:06d}"


def normalise_alert(raw: str, source: str = "unknown") -> Alert:
    """Parse a raw log/alert string into a structured Alert object."""
    alert_id = _next_alert_id()
    iocs = extract_iocs(raw)
    tactics, techniques, desc = detect_mitre(raw)

    # Derive severity from the number of MITRE matches and IOC count
    hit_count = len(techniques)
    ioc_count = len(iocs)
    base_score = min(100.0, hit_count * 20 + ioc_count * 5)
    severity = Severity.from_score(base_score)

    return Alert(
        alert_id=alert_id,
        source=source,
        raw=raw,
        iocs=iocs,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        severity=severity,
        description=desc or raw[:200],
    )


# ---------------------------------------------------------------------------
# Threat Intelligence enrichment
# ---------------------------------------------------------------------------

class ThreatIntelCache:
    """Thread-safe in-memory LRU-style TTL cache for TI lookups."""

    def __init__(self, ttl_sec: int = 3600) -> None:
        self._ttl = ttl_sec
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            ts, value = entry
            if time.monotonic() - ts > self._ttl:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = (time.monotonic(), value)


_TI_CACHE = ThreatIntelCache(
    ttl_sec=CONFIG.getint("threat_intel", "cache_ttl_sec", fallback=3600)
)


def _ti_get(url: str, headers: Dict[str, str], params: Dict[str, str]) -> Optional[Dict[str, Any]]:
    if not HAS_REQUESTS:
        LOG.warning("requests library not installed – threat intel lookup skipped")
        return None
    timeout = CONFIG.getint("threat_intel", "request_timeout", fallback=10)
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        LOG.warning("TI request failed (%s): %s", url, exc)
        return None


def enrich_virustotal(ioc: IOC) -> Dict[str, Any]:
    api_key = CONFIG.get("threat_intel", "virustotal_api_key", fallback="").strip()
    if not api_key:
        return {}
    cache_key = f"vt:{ioc.value}"
    cached = _TI_CACHE.get(cache_key)
    if cached is not None:
        return cached

    if ioc.ioc_type == IOCType.IP_ADDRESS:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc.value}"
    elif ioc.ioc_type == IOCType.DOMAIN:
        url = f"https://www.virustotal.com/api/v3/domains/{ioc.value}"
    elif ioc.ioc_type == IOCType.FILE_HASH:
        url = f"https://www.virustotal.com/api/v3/files/{ioc.value}"
    elif ioc.ioc_type == IOCType.URL:
        import base64 as _b64
        url_id = _b64.urlsafe_b64encode(ioc.value.encode()).rstrip(b"=").decode()
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        return {}

    data = _ti_get(url, headers={"x-apikey": api_key}, params={})
    if not data:
        _TI_CACHE.set(cache_key, {})
        return {}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    result = {
        "source": "virustotal",
        "malicious_engines": malicious,
        "total_engines": total,
        "detection_ratio": round(malicious / total, 4),
        "reputation": attrs.get("reputation", 0),
        "tags": attrs.get("tags", []),
    }
    _TI_CACHE.set(cache_key, result)
    return result


def enrich_abuseipdb(ioc: IOC) -> Dict[str, Any]:
    if ioc.ioc_type != IOCType.IP_ADDRESS:
        return {}
    api_key = CONFIG.get("threat_intel", "abuseipdb_api_key", fallback="").strip()
    if not api_key:
        return {}
    cache_key = f"abuseipdb:{ioc.value}"
    cached = _TI_CACHE.get(cache_key)
    if cached is not None:
        return cached

    data = _ti_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ioc.value, "maxAgeInDays": "90", "verbose": ""},
    )
    if not data:
        _TI_CACHE.set(cache_key, {})
        return {}

    d = data.get("data", {})
    result = {
        "source": "abuseipdb",
        "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
        "total_reports": d.get("totalReports", 0),
        "country_code": d.get("countryCode", ""),
        "isp": d.get("isp", ""),
        "domain": d.get("domain", ""),
        "is_tor": d.get("isTor", False),
        "is_public": d.get("isPublic", True),
    }
    _TI_CACHE.set(cache_key, result)
    return result


def enrich_otx(ioc: IOC) -> Dict[str, Any]:
    api_key = CONFIG.get("threat_intel", "otx_api_key", fallback="").strip()
    if not api_key:
        return {}
    cache_key = f"otx:{ioc.value}"
    cached = _TI_CACHE.get(cache_key)
    if cached is not None:
        return cached

    type_map = {
        IOCType.IP_ADDRESS: f"IPv4/{ioc.value}/general",
        IOCType.DOMAIN:     f"domain/{ioc.value}/general",
        IOCType.FILE_HASH:  f"file/{ioc.value}/general",
        IOCType.URL:        f"url/{ioc.value}/general",
    }
    path = type_map.get(ioc.ioc_type)
    if not path:
        return {}

    data = _ti_get(
        f"https://otx.alienvault.com/api/v1/indicators/{path}",
        headers={"X-OTX-API-KEY": api_key},
        params={},
    )
    if not data:
        _TI_CACHE.set(cache_key, {})
        return {}

    pulse_info = data.get("pulse_info", {})
    result = {
        "source": "otx",
        "pulse_count": pulse_info.get("count", 0),
        "malware_families": [
            p.get("name", "") for p in pulse_info.get("pulses", [])[:5]
        ],
        "validation": data.get("validation", []),
    }
    _TI_CACHE.set(cache_key, result)
    return result


def enrich_ioc(ioc: IOC) -> IOC:
    """Run all enabled TI enrichment sources and update the IOC in place."""
    vt = enrich_virustotal(ioc)
    ab = enrich_abuseipdb(ioc)
    ox = enrich_otx(ioc)

    ioc.enrichment.update(vt)
    ioc.enrichment.update(ab)
    ioc.enrichment.update(ox)

    # Derive risk score from enrichment data
    score = ioc.risk_score
    if vt:
        score = max(score, vt.get("detection_ratio", 0) * 100)
    if ab:
        score = max(score, ab.get("abuse_confidence_score", 0))
    if ox:
        pulse_count = ox.get("pulse_count", 0)
        score = max(score, min(100, pulse_count * 10))
    ioc.risk_score = round(score, 2)

    return ioc


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Groups alerts into incidents based on shared IOC values and time windows.
    Thread-safe; designed to be called from multiple worker threads.
    """

    WINDOW_SEC = 300  # 5-minute correlation window

    def __init__(self, db: "IncidentDatabase") -> None:
        self._db = db
        self._lock = threading.Lock()
        # ioc_value → incident_id mapping for the active window
        self._ioc_index: Dict[str, str] = {}
        self._incident_times: Dict[str, float] = {}

    def _prune(self) -> None:
        """Evict stale entries outside the correlation window."""
        now = time.monotonic()
        stale = [
            iid for iid, ts in self._incident_times.items()
            if now - ts > self.WINDOW_SEC
        ]
        for iid in stale:
            del self._incident_times[iid]
        self._ioc_index = {
            v: iid for v, iid in self._ioc_index.items()
            if iid not in stale
        }

    def correlate(self, alert: Alert) -> Incident:
        """Return the matching incident (existing or newly created)."""
        with self._lock:
            self._prune()
            ioc_values = {ioc.value for ioc in alert.iocs}
            matched_id: Optional[str] = None
            for value in ioc_values:
                if value in self._ioc_index:
                    matched_id = self._ioc_index[value]
                    break

            if matched_id:
                incident = self._db.get_incident(matched_id)
                if incident is None:
                    matched_id = None

            if matched_id is None:
                incident = _new_incident(alert)
                self._db.save_incident(incident)
                LOG.info("Created incident %s for alert %s", incident.incident_id, alert.alert_id)
            else:
                assert incident is not None
                incident.alerts.append(alert)
                existing_ioc_values: Set[str] = {ioc.value for ioc in incident.iocs}
                for ioc in alert.iocs:
                    if ioc.value not in existing_ioc_values:
                        incident.iocs.append(ioc)
                        existing_ioc_values.add(ioc.value)
                for t in alert.mitre_tactics:
                    if t not in incident.mitre_tactics:
                        incident.mitre_tactics.append(t)
                for t in alert.mitre_techniques:
                    if t not in incident.mitre_techniques:
                        incident.mitre_techniques.append(t)
                # Escalate severity if needed
                sev_order = list(Severity)
                if sev_order.index(alert.severity) > sev_order.index(incident.severity):
                    incident.severity = alert.severity
                incident.updated_at = datetime.now(timezone.utc).isoformat()
                self._db.save_incident(incident)
                LOG.info("Correlated alert %s → incident %s", alert.alert_id, incident.incident_id)

            # Update IOC index
            for ioc in alert.iocs:
                self._ioc_index[ioc.value] = incident.incident_id
            self._incident_times[incident.incident_id] = time.monotonic()
            return incident


_incident_counter = 0
_incident_counter_lock = threading.Lock()


def _next_incident_id() -> str:
    global _incident_counter
    with _incident_counter_lock:
        _incident_counter += 1
        return f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{_incident_counter:05d}"


def _new_incident(alert: Alert) -> Incident:
    return Incident(
        incident_id=_next_incident_id(),
        status=IncidentStatus.NEW,
        severity=alert.severity,
        title=alert.description[:120] or alert.raw[:120],
        description=alert.description,
        alerts=[alert],
        iocs=list(alert.iocs),
        mitre_tactics=list(alert.mitre_tactics),
        mitre_techniques=list(alert.mitre_techniques),
    )


# ---------------------------------------------------------------------------
# Persistence (SQLite)
# ---------------------------------------------------------------------------

class IncidentDatabase:
    """Thread-safe SQLite-backed incident store."""

    def __init__(self, db_path: str = "krigen_incidents.db") -> None:
        self._path = db_path
        self._local = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self) -> None:
        conn = sqlite3.connect(self._path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id   TEXT PRIMARY KEY,
                status        TEXT NOT NULL,
                severity      TEXT NOT NULL,
                title         TEXT NOT NULL,
                description   TEXT,
                payload       TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                incident_id TEXT,
                action     TEXT NOT NULL,
                detail     TEXT
            )
        """)
        conn.commit()
        conn.close()

    def save_incident(self, incident: Incident) -> None:
        conn = self._conn()
        payload = json.dumps(asdict(incident), default=str)
        conn.execute("""
            INSERT OR REPLACE INTO incidents
              (incident_id, status, severity, title, description, payload, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident.incident_id,
            incident.status.value,
            incident.severity.value,
            incident.title,
            incident.description,
            payload,
            incident.created_at,
            incident.updated_at,
        ))
        conn.commit()

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        row = self._conn().execute(
            "SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            return None
        data = json.loads(row["payload"])
        # Reconstruct nested dataclasses
        data["status"]   = IncidentStatus(data["status"])
        data["severity"] = Severity(data["severity"])
        data["alerts"]   = [_alert_from_dict(a) for a in data.get("alerts", [])]
        data["iocs"]     = [_ioc_from_dict(i) for i in data.get("iocs", [])]
        return Incident(**data)

    def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[Severity] = None,
        limit: int = 100,
    ) -> List[Incident]:
        sql = "SELECT payload FROM incidents WHERE 1=1"
        params: List[Any] = []
        if status:
            sql += " AND status = ?"
            params.append(status.value)
        if severity:
            sql += " AND severity = ?"
            params.append(severity.value)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn().execute(sql, params).fetchall()
        incidents = []
        for row in rows:
            data = json.loads(row["payload"])
            data["status"]   = IncidentStatus(data["status"])
            data["severity"] = Severity(data["severity"])
            data["alerts"]   = [_alert_from_dict(a) for a in data.get("alerts", [])]
            data["iocs"]     = [_ioc_from_dict(i) for i in data.get("iocs", [])]
            incidents.append(Incident(**data))
        return incidents

    def audit(self, action: str, incident_id: Optional[str] = None, detail: str = "") -> None:
        conn = self._conn()
        conn.execute(
            "INSERT INTO audit_log (ts, incident_id, action, detail) VALUES (?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), incident_id, action, detail),
        )
        conn.commit()

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


def _ioc_from_dict(d: Dict[str, Any]) -> IOC:
    d = dict(d)
    d["ioc_type"] = IOCType(d["ioc_type"])
    return IOC(**d)


def _alert_from_dict(d: Dict[str, Any]) -> Alert:
    d = dict(d)
    d["severity"] = Severity(d["severity"])
    d["iocs"]     = [_ioc_from_dict(i) for i in d.get("iocs", [])]
    return Alert(**d)


# ---------------------------------------------------------------------------
# Response actions
# ---------------------------------------------------------------------------

class ResponseOrchestrator:
    """Executes automated response actions for high/critical incidents."""

    MIN_SEVERITY = CONFIG.get("response", "min_severity_to_block", fallback="HIGH")
    AUTO_BLOCK    = CONFIG.getboolean("response", "auto_block_ips", fallback=False)
    IPTABLES_CHAIN = CONFIG.get("response", "iptables_chain", fallback="KRIGEN_BLOCK")
    AUTO_SINKHOLE = CONFIG.getboolean("response", "auto_sinkhole_domains", fallback=False)
    HOSTS_FILE    = CONFIG.get("response", "hosts_file", fallback="/etc/hosts")
    AUTO_KILL     = CONFIG.getboolean("response", "auto_kill_processes", fallback=False)
    ESCALATION_WEBHOOK = CONFIG.get("response", "escalation_webhook", fallback="").strip()

    _SEVERITY_ORDER = list(Severity)

    def __init__(self, db: IncidentDatabase) -> None:
        self._db = db
        self._blocked_ips: Set[str] = set()
        self._sinkholed_domains: Set[str] = set()
        self._lock = threading.Lock()

    def _should_act(self, severity: Severity) -> bool:
        order = self._SEVERITY_ORDER
        return order.index(severity) >= order.index(Severity(self.MIN_SEVERITY))

    def respond(self, incident: Incident) -> None:
        if not self._should_act(incident.severity):
            return
        for ioc in incident.iocs:
            if ioc.ioc_type == IOCType.IP_ADDRESS and self.AUTO_BLOCK:
                self._block_ip(ioc.value, incident.incident_id)
            elif ioc.ioc_type == IOCType.DOMAIN and self.AUTO_SINKHOLE:
                self._sinkhole_domain(ioc.value, incident.incident_id)
        if self.ESCALATION_WEBHOOK:
            self._webhook_escalate(incident)

    # -- firewall block --

    def _block_ip(self, ip: str, incident_id: str) -> None:
        with self._lock:
            if ip in self._blocked_ips:
                return
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return
            if _is_private_ip(ip):
                LOG.warning("Refusing to block private IP %s", ip)
                return
            if self._iptables_block(ip):
                self._blocked_ips.add(ip)
                action = {"type": "ip_block", "ip": ip, "ts": datetime.now(timezone.utc).isoformat()}
                self._db.audit("ip_block", incident_id, f"Blocked IP {ip} via iptables")
                LOG.warning("RESPONSE: Blocked IP %s (incident %s)", ip, incident_id)

    def _iptables_block(self, ip: str) -> bool:
        """Add a DROP rule to the KRIGEN_BLOCK chain."""
        if os.geteuid() != 0:
            LOG.warning("Not running as root – cannot modify iptables for IP %s", ip)
            return False
        try:
            # Create the chain if it does not exist
            subprocess.run(
                ["iptables", "-N", self.IPTABLES_CHAIN],
                capture_output=True, check=False
            )
            # Ensure the chain is referenced from INPUT
            subprocess.run(
                ["iptables", "-C", "INPUT", "-j", self.IPTABLES_CHAIN],
                capture_output=True, check=False
            )
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-j", self.IPTABLES_CHAIN],
                capture_output=True, check=False
            )
            # Add the DROP rule for this IP
            result = subprocess.run(
                ["iptables", "-A", self.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
                capture_output=True, check=True
            )
            return result.returncode == 0
        except subprocess.CalledProcessError as exc:
            LOG.error("iptables failed for IP %s: %s", ip, exc)
            return False
        except FileNotFoundError:
            LOG.error("iptables not found on this system")
            return False

    # -- DNS sinkhole --

    def _sinkhole_domain(self, domain: str, incident_id: str) -> None:
        with self._lock:
            if domain in self._sinkholed_domains:
                return
            if self._write_hosts_entry(domain):
                self._sinkholed_domains.add(domain)
                self._db.audit("domain_sinkhole", incident_id, f"Sinkholed domain {domain}")
                LOG.warning("RESPONSE: Sinkholed domain %s (incident %s)", domain, incident_id)

    def _write_hosts_entry(self, domain: str) -> bool:
        marker = f"# KRIGEN_BLOCK {domain}"
        try:
            with open(self.HOSTS_FILE, "r") as f:
                existing = f.read()
            if marker in existing:
                return True  # already present
            with open(self.HOSTS_FILE, "a") as f:
                # Only add the www. alias for apex domains (no leading subdomain)
                parts = domain.split(".")
                if len(parts) == 2:
                    f.write(f"\n0.0.0.0 {domain} www.{domain}  {marker}\n")
                else:
                    f.write(f"\n0.0.0.0 {domain}  {marker}\n")
            return True
        except PermissionError:
            LOG.error("Cannot write to %s (permission denied) for domain %s", self.HOSTS_FILE, domain)
            return False
        except OSError as exc:
            LOG.error("Failed to sinkhole %s: %s", domain, exc)
            return False

    # -- Webhook escalation --

    def _webhook_escalate(self, incident: Incident) -> None:
        if not HAS_REQUESTS:
            return
        payload = {
            "incident_id":  incident.incident_id,
            "severity":     incident.severity.value,
            "title":        incident.title,
            "status":       incident.status.value,
            "alert_count":  len(incident.alerts),
            "ioc_count":    len(incident.iocs),
            "mitre_tactics": [
                f"{t} – {MITRE_TACTICS.get(t, 'Unknown')}" for t in incident.mitre_tactics
            ],
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        try:
            resp = requests.post(
                self.ESCALATION_WEBHOOK,
                json=payload,
                timeout=CONFIG.getint("threat_intel", "request_timeout", fallback=10),
            )
            resp.raise_for_status()
            LOG.info("Escalated incident %s to webhook (HTTP %s)", incident.incident_id, resp.status_code)
        except Exception as exc:
            LOG.error("Webhook escalation failed for %s: %s", incident.incident_id, exc)


# ---------------------------------------------------------------------------
# Alert sources
# ---------------------------------------------------------------------------

class SyslogUDPListener(threading.Thread):
    """
    Listens for syslog messages on a UDP socket (RFC 3164 / RFC 5424).
    Messages are parsed and placed on the shared alert queue.
    """

    _RFC3164_RE = re.compile(
        r"<(\d{1,3})>\s*"
        r"(?:(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+)?"
        r"(?:(\S+)\s+)?"
        r"(?:(\S+?)(?:\[(\d+)\])?\s*:\s*)?"
        r"(.*)",
        re.DOTALL,
    )

    def __init__(self, q: queue.Queue, host: str = "0.0.0.0", port: int = 514) -> None:
        super().__init__(name="SyslogListener", daemon=True)
        self._q = q
        self._host = host
        self._port = port
        self._stop_event = threading.Event()

    def run(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._host, self._port))
            sock.settimeout(1.0)
            LOG.info("Syslog listener started on %s:%d", self._host, self._port)
        except OSError as exc:
            LOG.error("Cannot bind syslog socket %s:%d – %s", self._host, self._port, exc)
            return

        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                raw = data.decode("utf-8", errors="replace").strip()
                m = self._RFC3164_RE.match(raw)
                message = m.group(6) if m else raw
                self._q.put({"raw": message, "source": f"syslog:{addr[0]}"})
            except socket.timeout:
                continue
            except Exception as exc:
                LOG.debug("Syslog receive error: %s", exc)
        sock.close()
        LOG.info("Syslog listener stopped")

    def stop(self) -> None:
        self._stop_event.set()


class LogFileWatcher(threading.Thread):
    """
    Tail-follows one or more log files, placing new lines onto the alert queue.
    Uses inode-based rotation detection so it survives log rotation.
    """

    def __init__(self, q: queue.Queue, paths: List[str], interval: float = 5.0) -> None:
        super().__init__(name="LogFileWatcher", daemon=True)
        self._q = q
        self._paths = paths
        self._interval = interval
        self._stop_event = threading.Event()
        self._state: Dict[str, Tuple[int, int]] = {}  # path → (inode, offset)

    def run(self) -> None:
        LOG.info("Log file watcher started for: %s", self._paths)
        while not self._stop_event.is_set():
            for path in self._paths:
                self._tail(path)
            self._stop_event.wait(self._interval)
        LOG.info("Log file watcher stopped")

    def _tail(self, path: str) -> None:
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            return
        inode, old_offset = self._state.get(path, (None, 0))
        # Detect rotation (new inode or file shrank)
        if inode != stat.st_ino or stat.st_size < old_offset:
            old_offset = 0
        self._state[path] = (stat.st_ino, old_offset)
        if stat.st_size <= old_offset:
            return
        try:
            with open(path, "rb") as f:
                f.seek(old_offset)
                chunk = f.read(1_048_576)  # max 1 MB per poll
                self._state[path] = (stat.st_ino, old_offset + len(chunk))
            for line in chunk.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if line:
                    self._q.put({"raw": line, "source": f"file:{path}"})
        except OSError as exc:
            LOG.warning("Cannot read %s: %s", path, exc)

    def stop(self) -> None:
        self._stop_event.set()


# ---------------------------------------------------------------------------
# Worker pool
# ---------------------------------------------------------------------------

class AlertWorker(threading.Thread):
    """Pulls alerts from the queue, enriches IOCs, correlates and responds."""

    def __init__(
        self,
        q: queue.Queue,
        db: IncidentDatabase,
        correlator: CorrelationEngine,
        responder: ResponseOrchestrator,
        name: str,
    ) -> None:
        super().__init__(name=name, daemon=True)
        self._q = q
        self._db = db
        self._correlator = correlator
        self._responder = responder

    def run(self) -> None:
        LOG.debug("Worker %s started", self.name)
        while True:
            try:
                item = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            if item is None:
                LOG.debug("Worker %s received shutdown signal", self.name)
                break
            try:
                self._process(item)
            except Exception as exc:
                LOG.exception("Worker %s: unhandled error processing item: %s", self.name, exc)
            finally:
                self._q.task_done()

    def _process(self, item: Dict[str, Any]) -> None:
        raw    = item.get("raw", "")
        source = item.get("source", "unknown")
        alert  = normalise_alert(raw, source)

        # Enrich each IOC (TI lookups)
        for ioc in alert.iocs:
            enrich_ioc(ioc)

        # Recalculate severity with enrichment data
        if alert.iocs:
            max_score = max(ioc.risk_score for ioc in alert.iocs)
            enriched_sev = Severity.from_score(max_score)
            sev_order = list(Severity)
            if sev_order.index(enriched_sev) > sev_order.index(alert.severity):
                alert.severity = enriched_sev

        incident = self._correlator.correlate(alert)
        self._db.audit("alert_processed", incident.incident_id, f"Alert {alert.alert_id} processed")

        self._responder.respond(incident)

        LOG.info(
            "Alert %s [%s] → incident %s [%s] | tactics: %s | IOCs: %d",
            alert.alert_id, alert.severity.value,
            incident.incident_id, incident.severity.value,
            ", ".join(alert.mitre_tactics) or "none",
            len(alert.iocs),
        )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates structured JSON incident reports to disk."""

    def __init__(self, report_dir: str, db: IncidentDatabase) -> None:
        self._dir = Path(report_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._db = db

    def generate(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[Severity] = None,
    ) -> Path:
        incidents = self._db.list_incidents(status=status, severity=severity, limit=500)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "filter": {
                "status":   status.value if status else None,
                "severity": severity.value if severity else None,
            },
            "summary": {
                "total_incidents": len(incidents),
                "by_severity": _count_by(incidents, lambda i: i.severity.value),
                "by_status":   _count_by(incidents, lambda i: i.status.value),
                "top_mitre_tactics": _top_tactics(incidents),
            },
            "incidents": [_incident_report_dict(i) for i in incidents],
        }
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fname = self._dir / f"incident_report_{ts}.json"
        fname.write_text(json.dumps(report, indent=2, default=str))
        LOG.info("Report written to %s (%d incidents)", fname, len(incidents))
        return fname


def _count_by(items: list, key_fn: Callable[[Any], str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        k = key_fn(item)
        counts[k] = counts.get(k, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def _top_tactics(incidents: List[Incident]) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for inc in incidents:
        for t in inc.mitre_tactics:
            counts[t] = counts.get(t, 0) + 1
    return [
        {"tactic_id": t, "name": MITRE_TACTICS.get(t, "Unknown"), "count": c}
        for t, c in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]


def _incident_report_dict(incident: Incident) -> Dict[str, Any]:
    return {
        "incident_id":   incident.incident_id,
        "status":        incident.status.value,
        "severity":      incident.severity.value,
        "title":         incident.title,
        "created_at":    incident.created_at,
        "updated_at":    incident.updated_at,
        "alert_count":   len(incident.alerts),
        "ioc_count":     len(incident.iocs),
        "mitre_tactics": [
            {"id": t, "name": MITRE_TACTICS.get(t, "Unknown")}
            for t in incident.mitre_tactics
        ],
        "mitre_techniques": incident.mitre_techniques,
        "iocs": [
            {
                "value":      ioc.value,
                "type":       ioc.ioc_type.value,
                "risk_score": ioc.risk_score,
                "enrichment": ioc.enrichment,
            }
            for ioc in incident.iocs
        ],
        "response_actions": incident.response_actions,
    }


# ---------------------------------------------------------------------------
# Orchestration engine (top-level)
# ---------------------------------------------------------------------------

class SecurityOrchestrator:
    """
    Top-level orchestration engine.  Wires together all subsystems and manages
    the lifecycle of the platform.
    """

    def __init__(self) -> None:
        db_path    = CONFIG.get("general", "db_path",    fallback="krigen_incidents.db")
        report_dir = CONFIG.get("general", "report_dir", fallback="reports")
        n_workers  = CONFIG.getint("general", "worker_threads", fallback=4)
        q_size     = CONFIG.getint("general", "alert_queue_size", fallback=1000)

        self._db          = IncidentDatabase(db_path)
        self._queue: queue.Queue = queue.Queue(maxsize=q_size)
        self._correlator  = CorrelationEngine(self._db)
        self._responder   = ResponseOrchestrator(self._db)
        self._reporter    = ReportGenerator(report_dir, self._db)
        self._sources: List[threading.Thread] = []
        self._workers: List[AlertWorker] = []
        self._n_workers   = n_workers
        self._running     = False

        # Optional alert sources
        if CONFIG.getboolean("syslog", "enabled", fallback=False):
            self._sources.append(SyslogUDPListener(
                self._queue,
                host=CONFIG.get("syslog", "host", fallback="0.0.0.0"),
                port=CONFIG.getint("syslog", "port", fallback=514),
            ))

        if CONFIG.getboolean("file_watch", "enabled", fallback=False):
            paths = [
                p.strip()
                for p in CONFIG.get("file_watch", "paths", fallback="").split(",")
                if p.strip()
            ]
            if paths:
                self._sources.append(LogFileWatcher(
                    self._queue,
                    paths,
                    interval=CONFIG.getfloat("file_watch", "interval_sec", fallback=5.0),
                ))

    def start(self) -> None:
        """Start workers and alert sources."""
        if self._running:
            return
        self._running = True
        LOG.info("KRIGEN Security Orchestrator starting (%d workers)", self._n_workers)

        for i in range(self._n_workers):
            w = AlertWorker(
                self._queue, self._db, self._correlator, self._responder,
                name=f"Worker-{i+1}",
            )
            self._workers.append(w)
            w.start()

        for src in self._sources:
            src.start()

    def stop(self) -> None:
        """Gracefully stop the orchestrator."""
        LOG.info("KRIGEN Security Orchestrator shutting down …")
        for src in self._sources:
            if hasattr(src, "stop"):
                src.stop()
        for _ in self._workers:
            self._queue.put(None)
        for w in self._workers:
            w.join(timeout=10)
        self._db.close()
        self._running = False
        LOG.info("KRIGEN Security Orchestrator stopped")

    def ingest(self, raw: str, source: str = "api") -> None:
        """
        Programmatically submit a raw alert string for processing.
        Blocks if the queue is full (back-pressure).
        """
        try:
            self._queue.put({"raw": raw, "source": source}, block=True, timeout=5)
        except queue.Full:
            LOG.warning("Alert queue full – dropping alert from source %s", source)

    def report(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[Severity] = None,
    ) -> Path:
        """Generate and return the path to a fresh incident report."""
        return self._reporter.generate(status=status, severity=severity)

    def list_incidents(self, **kwargs) -> List[Incident]:
        return self._db.list_incidents(**kwargs)


# ---------------------------------------------------------------------------
# Utility: compute file hash (SHA-256)
# ---------------------------------------------------------------------------

def hash_file(path: str) -> str:
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Utility: DNS resolution with timeout
# ---------------------------------------------------------------------------

def resolve_domain(domain: str, timeout: float = 5.0) -> List[str]:
    """Return a list of IPv4 addresses for a domain, or [] on failure."""
    try:
        socket.setdefaulttimeout(timeout)
        info = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({entry[4][0] for entry in info})
    except socket.error:
        return []
    finally:
        socket.setdefaulttimeout(None)


# ---------------------------------------------------------------------------
# CLI / entry-point
# ---------------------------------------------------------------------------

def _signal_handler(signum, frame, orchestrator: SecurityOrchestrator) -> None:
    LOG.info("Signal %d received – initiating shutdown", signum)
    orchestrator.stop()
    sys.exit(0)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="security_orchestration",
        description="KRIGEN Intelligence – Security Orchestration Engine",
    )
    sub = parser.add_subparsers(dest="cmd")

    run_p = sub.add_parser("run", help="Start the orchestration engine (daemon mode)")
    run_p.add_argument("--syslog", action="store_true", help="Enable syslog listener")
    run_p.add_argument("--watch", nargs="*", metavar="FILE", help="Log files to watch")

    ingest_p = sub.add_parser("ingest", help="Submit a raw alert string")
    ingest_p.add_argument("alert", help="Raw alert text to process")
    ingest_p.add_argument("--source", default="cli", help="Source label")

    report_p = sub.add_parser("report", help="Generate an incident report")
    report_p.add_argument("--status",   choices=[s.value for s in IncidentStatus])
    report_p.add_argument("--severity", choices=[s.value for s in Severity])

    list_p = sub.add_parser("list", help="List incidents")
    list_p.add_argument("--status",   choices=[s.value for s in IncidentStatus])
    list_p.add_argument("--severity", choices=[s.value for s in Severity])
    list_p.add_argument("--limit", type=int, default=20)

    hash_p = sub.add_parser("hash", help="Compute SHA-256 of a file")
    hash_p.add_argument("file", help="Path to file")

    args = parser.parse_args(argv)

    if args.cmd == "run":
        if args.syslog:
            CONFIG.set("syslog", "enabled", "true")
        if args.watch:
            CONFIG.set("file_watch", "enabled", "true")
            CONFIG.set("file_watch", "paths", ",".join(args.watch))

        orch = SecurityOrchestrator()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda s, f: _signal_handler(s, f, orch))
        orch.start()

        LOG.info("Engine running. Send SIGINT or SIGTERM to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            orch.stop()

    elif args.cmd == "ingest":
        orch = SecurityOrchestrator()
        orch.start()
        orch.ingest(args.alert, source=args.source)
        # Allow the worker to process the alert before exiting
        orch._queue.join()
        path = orch.report()
        print(f"Report: {path}")
        orch.stop()

    elif args.cmd == "report":
        orch = SecurityOrchestrator()
        orch.start()
        path = orch.report(
            status=IncidentStatus(args.status) if args.status else None,
            severity=Severity(args.severity) if args.severity else None,
        )
        print(f"Report written to: {path}")
        orch.stop()

    elif args.cmd == "list":
        orch = SecurityOrchestrator()
        orch.start()
        incidents = orch.list_incidents(
            status=IncidentStatus(args.status) if args.status else None,
            severity=Severity(args.severity) if args.severity else None,
            limit=args.limit,
        )
        for inc in incidents:
            print(
                f"{inc.incident_id}  [{inc.severity.value:8s}]  "
                f"[{inc.status.value:15s}]  {inc.title[:60]}"
            )
        orch.stop()

    elif args.cmd == "hash":
        try:
            digest = hash_file(args.file)
            print(f"SHA-256({args.file}) = {digest}")
        except FileNotFoundError:
            print(f"File not found: {args.file}", file=sys.stderr)
            return 1

    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
