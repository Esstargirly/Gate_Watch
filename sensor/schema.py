from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

# ---------------------------------------------------------------- collections
USERS = "users"
ALERTS = "alerts"
ALERT_NOTES = "notes"          
ALERT_TIMELINE = "timeline"   
TRAFFIC = "traffic"
DEVICES = "devices"
WATCHLIST = "watchlist"
SENSORS = "sensors"
AUDIT_LOG = "auditLog"
STATS = "stats"


# ---------------------------------------------------------------------- enums
class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertType(str, Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    SYN_FLOOD = "syn_flood"
    SUSPICIOUS_CONNECTION = "suspicious_connection"
    TRAFFIC_SPIKE = "traffic_spike"
    WATCHLIST_HIT = "watchlist_hit"
    UNKNOWN_DEVICE = "unknown_device"


class DetectionMethod(str, Enum):
    RULE = "rule"                  # fixed rule, e.g. 20+ ports in 10s
    BASELINE = "baseline"          # compared against normal traffic
    THREAT_INTEL = "threat_intel"  # IP found on a blocklist / watchlist


class InferenceMode(str, Enum):
    ON_DEVICE = "on_device"
    CLOUD = "cloud"


class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"


# ------------------------------------------------------------ document shapes
@dataclass
class User:                        # users/{uid}
    email: str
    displayName: str
    role: str = Role.ANALYST.value
    mfaEnabled: bool = False
    createdAt: Optional[datetime] = None
    lastLoginAt: Optional[datetime] = None


@dataclass
class Alert:                       # alerts/{alertId}
    type: str
    severity: str
    srcIp: str
    dstIp: str
    description: str               # what happened
    reason: str                    # why it was flagged
    detectionMethod: str
    detectedAt: datetime
    status: str = AlertStatus.NEW.value
    dstPort: Optional[int] = None
    protocol: Optional[str] = None
    deviceId: Optional[str] = None     # affected device (devices/{deviceId})
    srcCountry: Optional[str] = None
    srcReputation: Optional[int] = None  # 0-100, higher = worse
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendedActions: list[str] = field(default_factory=list)
    dedupKey: str = ""
    count: int = 1                     # how many times it repeated (dedup)
    lastSeenAt: Optional[datetime] = None
    acknowledgedBy: Optional[str] = None
    acknowledgedAt: Optional[datetime] = None
    resolvedBy: Optional[str] = None
    resolvedAt: Optional[datetime] = None
    # cached AI explanation: {"text": str, "mode": InferenceMode, "generatedAt": datetime}
    aiSummary: Optional[dict[str, Any]] = None


@dataclass
class AlertNote:                   # alerts/{id}/notes/{noteId}
    authorUid: str
    authorName: str
    text: str
    createdAt: datetime


@dataclass
class TimelineEntry:               # alerts/{id}/timeline/{entryId}
    at: datetime
    title: str
    detail: str = ""


@dataclass
class TrafficRecord:               # traffic/{id}  (deleted automatically by TTL)
    ts: datetime
    srcIp: str
    dstIp: str
    protocol: str                  # TCP / UDP / DNS / HTTP / ICMP ...
    size: int
    expireAt: datetime
    srcPort: Optional[int] = None
    dstPort: Optional[int] = None
    flags: Optional[str] = None    # e.g. "S", "SA", "R"
    sensorId: Optional[str] = None


@dataclass
class Device:                      # devices/{deviceId}
    name: str
    ip: str
    mac: str
    firstSeen: datetime
    lastSeen: datetime
    status: str = DeviceStatus.ONLINE.value
    known: bool = False            # False = unknown device, gets flagged
    vendor: Optional[str] = None
    lastActivity: str = ""


@dataclass
class WatchlistEntry:              # watchlist/{ipDocId}
    ip: str
    addedAt: datetime
    reason: str = ""
    reputationScore: Optional[int] = None   # 0-100, higher = worse
    country: Optional[str] = None
    hits: int = 0                  # connections seen from this IP
    lastSeen: Optional[datetime] = None
    blocked: bool = False
    addedBy: Optional[str] = None  # uid, or "system"


@dataclass
class Sensor:                      # sensors/{sensorId}
    name: str
    interface: str
    lastHeartbeat: datetime
    status: str = "online"
    version: str = "0.1.0"


@dataclass
class AuditEntry:                  # auditLog/{id}
    actorUid: str
    actorEmail: str
    action: str                    # e.g. "alert.resolve", "ip.block", "user.role_change"
    targetType: str                # "alert" | "ip" | "user" | "device" | "setting"
    targetId: str
    timestamp: datetime
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DailyStats:                  # stats/{YYYY-MM-DD}
    date: str
    totalAlerts: int = 0
    bySeverity: dict[str, int] = field(default_factory=dict)
    byType: dict[str, int] = field(default_factory=dict)
    resolved: int = 0
    falsePositives: int = 0
    blockedIps: int = 0
    packets: int = 0
    bytes: int = 0


# ------------------------------------------------------------------- helpers
def now() -> datetime:
    return datetime.now(timezone.utc)


def to_firestore(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        obj = asdict(obj)
    if isinstance(obj, dict):
        return {k: to_firestore(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, (list, tuple)):
        return [to_firestore(v) for v in obj]
    if isinstance(obj, Enum):
        return obj.value
    return obj


def dedup_key(alert_type: str, src_ip: str, dst_ip: str = "") -> str:
    return f"{alert_type}|{src_ip}|{dst_ip}"


def ip_doc_id(ip: str) -> str:
    return ip.replace(".", "_").replace(":", "-").replace("/", "_")


def traffic_expiry(hours: int = 24) -> datetime:
    return now() + timedelta(hours=hours)


def today_id() -> str:
    return now().strftime("%Y-%m-%d")


REMOTE_CONFIG_DEFAULTS: dict[str, Any] = {
    "port_scan_ports": 20,            # distinct ports from one IP...
    "port_scan_window_sec": 10,       # ...within this many seconds
    "brute_force_attempts": 5,        # failed logins from one IP...
    "brute_force_window_sec": 60,     # ...within this many seconds
    "syn_flood_packets_per_sec": 100,
    "traffic_spike_multiplier": 3.0,  # x the normal packets per minute
    "alert_dedup_window_sec": 300,
    "traffic_retention_hours": 24,
    "prefer_on_device_ai": True,
}