from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud import firestore as gcf
from google.cloud.firestore_v1.base_query import FieldFilter

import schema as s

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

# statuses where an alert is still "open" (used for dedup)
OPEN_STATUSES = [
    s.AlertStatus.NEW.value,
    s.AlertStatus.ACKNOWLEDGED.value,
    s.AlertStatus.INVESTIGATING.value,
]

_db = None


def workspace_id() -> str:
    wid = os.environ.get("GATEWATCH_WORKSPACE", "").strip()
    if not wid:
        raise RuntimeError(
            "No workspace set. Add GATEWATCH_WORKSPACE=<your id> to sensor/.env "
            "(the app shows it on the More page, under 'Connect a sensor')."
        )
    return wid


class _Workspace:
    """The Firestore client, scoped to one workspace. Everything else in the
    sensor keeps saying collection("alerts"); this makes that mean
    workspaces/<id>/alerts, so one sensor can only ever write to one workspace."""

    def __init__(self, client, wid: str) -> None:
        self._client = client
        self.workspace = wid

    def collection(self, name: str):
        return self._client.collection("workspaces").document(self.workspace).collection(name)

    def batch(self):
        return self._client.batch()


def get_db():
    """Connects on first use and returns the Firestore client for your workspace."""
    global _db
    if _db is None:
        key_path = os.environ.get("FIREBASE_SERVICE_ACCOUNT") or os.environ.get(
            "GOOGLE_APPLICATION_CREDENTIALS"
        )
        if not key_path:
            raise RuntimeError(
                "No service account key. Set FIREBASE_SERVICE_ACCOUNT in sensor/.env"
            )
        if not os.path.isfile(key_path):
            raise RuntimeError(f"Service account key not found at: {key_path}")
        wid = workspace_id()
        if not firebase_admin._apps:
            firebase_admin.initialize_app(credentials.Certificate(key_path))
        _db = _Workspace(firestore.client(), wid)
    return _db


def load_thresholds() -> dict[str, Any]:
    """Detection thresholds (port scan size, windows, etc.).

    For now these are the defaults from schema.py. Pulling them live from
    Remote Config on the server side can be added later without changing
    any caller.
    """
    return dict(s.REMOTE_CONFIG_DEFAULTS)


# ---------------------------------------------------------------------- alerts
def find_open_alert(dedup: str, window_sec: int) -> Optional[tuple[str, dict]]:
    """Is there already an open alert for this incident, seen recently?
    Returns (alert_id, data) or None. Used so one port scan = one alert."""
    cutoff = s.now() - timedelta(seconds=window_sec)
    query = (
        get_db()
        .collection(s.ALERTS)
        .where(filter=FieldFilter("dedupKey", "==", dedup))
        .where(filter=FieldFilter("status", "in", OPEN_STATUSES))
        .limit(10)
    )
    for doc in query.stream():
        data = doc.to_dict()
        last_seen = data.get("lastSeenAt") or data.get("detectedAt")
        if last_seen and last_seen >= cutoff:
            return doc.id, data
    return None


def create_alert(alert: s.Alert) -> str:
    """Saves a new alert, starts its timeline, and counts it in today's stats.
    Returns the new alert's ID."""
    if alert.lastSeenAt is None:
        alert.lastSeenAt = alert.detectedAt
    data = s.to_firestore(alert)

    ref = get_db().collection(s.ALERTS).document()
    ref.set(data)

    add_timeline(ref.id, "Alert created", alert.reason, at=alert.detectedAt)
    _bump_alert_stats(data["severity"], data["type"])
    return ref.id


def record_repeat(alert_id: str, at: Optional[datetime] = None) -> None:
    """The same incident happened again: count it instead of making a new alert."""
    get_db().collection(s.ALERTS).document(alert_id).update(
        {"count": gcf.Increment(1), "lastSeenAt": at or s.now()}
    )


def raise_alert_severity(alert_id: str, severity: str, reason: str = "") -> None:
    """An open alert got worse (for example a brute force that keeps going).
    Raises its severity and writes it into the alert's timeline."""
    get_db().collection(s.ALERTS).document(alert_id).update({"severity": severity})
    add_timeline(alert_id, f"Severity raised to {severity.capitalize()}", reason)


def add_timeline(
    alert_id: str, title: str, detail: str = "", at: Optional[datetime] = None
) -> None:
    entry = s.TimelineEntry(at=at or s.now(), title=title, detail=detail)
    (
        get_db()
        .collection(s.ALERTS)
        .document(alert_id)
        .collection(s.ALERT_TIMELINE)
        .add(s.to_firestore(entry))
    )


# --------------------------------------------------------------------- traffic
def add_traffic(records: Iterable[s.TrafficRecord], chunk: int = 400) -> int:
    """Saves packet/flow summaries in batches (Firestore allows 500 per batch).
    Returns how many were written.

    Every record is a billable write, so summarise before calling this
    (one record per flow per second, not one per packet).
    """
    db = get_db()
    batch = db.batch()
    pending = 0
    total = 0
    for record in records:
        batch.set(db.collection(s.TRAFFIC).document(), s.to_firestore(record))
        pending += 1
        total += 1
        if pending == chunk:
            batch.commit()
            batch = db.batch()
            pending = 0
    if pending:
        batch.commit()
    return total


# --------------------------------------------------------------------- devices
def device_id(mac: str) -> str:
    return mac.lower().replace(":", "-")


def upsert_device(
    mac: str, ip: str, name: Optional[str] = None, activity: str = ""
) -> tuple[str, bool]:
    """Records that a device was seen. New devices start as unknown (known=False)
    so the UI can flag them. Returns (device_id, is_new)."""
    ref = get_db().collection(s.DEVICES).document(device_id(mac))
    now = s.now()

    if ref.get().exists:
        update: dict[str, Any] = {
            "ip": ip,
            "lastSeen": now,
            "status": s.DeviceStatus.ONLINE.value,
        }
        if activity:
            update["lastActivity"] = activity
        ref.update(update)
        return ref.id, False

    device = s.Device(
        name=name or f"Device {ip}",
        ip=ip,
        mac=mac,
        firstSeen=now,
        lastSeen=now,
        known=False,
        lastActivity=activity,
    )
    ref.set(s.to_firestore(device))
    return ref.id, True


def mark_stale_devices_offline(minutes: int = 5) -> int:
    """Devices not seen for a while become offline. Returns how many changed."""
    db = get_db()
    cutoff = s.now() - timedelta(minutes=minutes)
    batch = db.batch()
    changed = 0
    query = db.collection(s.DEVICES).where(
        filter=FieldFilter("status", "==", s.DeviceStatus.ONLINE.value)
    )
    for doc in query.stream():
        last_seen = doc.to_dict().get("lastSeen")
        if last_seen and last_seen < cutoff:
            batch.update(doc.reference, {"status": s.DeviceStatus.OFFLINE.value})
            changed += 1
    if changed:
        batch.commit()
    return changed


def find_device_by_ip(ip: str) -> Optional[str]:
    """ID of the device currently using this IP, or None if we haven't seen it."""
    query = (
        get_db()
        .collection(s.DEVICES)
        .where(filter=FieldFilter("ip", "==", ip))
        .limit(1)
    )
    for doc in query.stream():
        return doc.id
    return None


# ------------------------------------------------------------------- watchlist
def get_watchlist() -> dict[str, dict]:
    """The whole watchlist as {ip: entry}. Small, so the sensor can load it
    once a minute and check packets against it in memory."""
    result: dict[str, dict] = {}
    for doc in get_db().collection(s.WATCHLIST).stream():
        data = doc.to_dict()
        if data.get("ip"):
            result[data["ip"]] = data
    return result


def record_watchlist_hit(
    ip: str,
    reason: str = "",
    reputation: Optional[int] = None,
    country: Optional[str] = None,
) -> None:
    """An IP was seen doing something suspicious. Adds it to the watchlist if
    it's new, otherwise bumps its hit count."""
    ref = get_db().collection(s.WATCHLIST).document(s.ip_doc_id(ip))
    now = s.now()

    if ref.get().exists:
        ref.update({"hits": gcf.Increment(1), "lastSeen": now})
        return

    entry = s.WatchlistEntry(
        ip=ip,
        addedAt=now,
        reason=reason,
        reputationScore=reputation,
        country=country,
        hits=1,
        lastSeen=now,
        blocked=False,
        addedBy="system",
    )
    ref.set(s.to_firestore(entry))


# --------------------------------------------------------------- stats + status
def _bump_alert_stats(severity: str, alert_type: str) -> None:
    get_db().collection(s.STATS).document(s.today_id()).set(
        {
            "date": s.today_id(),
            "totalAlerts": gcf.Increment(1),
            "bySeverity": {severity: gcf.Increment(1)},
            "byType": {alert_type: gcf.Increment(1)},
        },
        merge=True,
    )


def bump_traffic_stats(packets: int, nbytes: int) -> None:
    """Adds to today's packet and byte counters (call once per batch)."""
    get_db().collection(s.STATS).document(s.today_id()).set(
        {
            "date": s.today_id(),
            "packets": gcf.Increment(packets),
            "bytes": gcf.Increment(nbytes),
        },
        merge=True,
    )


def heartbeat(
    sensor_id: str, name: str, interface: str, version: str = "0.1.0"
) -> None:
    """Tells the dashboard this sensor is alive. Call every 30 seconds or so."""
    sensor = s.Sensor(
        name=name,
        interface=interface,
        lastHeartbeat=s.now(),
        status="online",
        version=version,
    )
    get_db().collection(s.SENSORS).document(sensor_id).set(s.to_firestore(sensor))