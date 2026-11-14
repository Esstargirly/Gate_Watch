from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

import firebase_client as fc
from detection.base import Detection

log = logging.getLogger("gatewatch.alerts")

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_LAN_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
]


def is_real_ip(value: str) -> bool:
    """False for things like the "multiple" source of a spoofed SYN flood."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_external(value: str) -> bool:
    """A real IP that is not on the local network. Only these get a threat
    intel lookup and a watchlist entry."""
    if not is_real_ip(value):
        return False
    ip = ipaddress.ip_address(value)
    return not any(ip in net for net in _LAN_NETWORKS if net.version == ip.version)


@dataclass
class AlertResult:
    alertId: str
    action: str            # "created" | "repeated" | "escalated"
    detection: Detection


class AlertManager:
    def __init__(
        self,
        enrich: Optional[Callable[[str], Optional[dict]]] = None,
        notify: Optional[Callable[[str, str, Detection], None]] = None,
    ) -> None:
        self.enrich = enrich
        self.notify = notify

    # ------------------------------------------------------------------ public
    def handle(
        self, detections: list[Detection], thresholds: dict[str, Any]
    ) -> list[AlertResult]:
        """Process a batch of detections. Returns what happened to each one."""
        window_sec = int(thresholds["alert_dedup_window_sec"])
        results: list[AlertResult] = []
        for detection in detections:
            try:
                result = self._handle_one(detection, window_sec)
            except Exception:
                log.exception(
                    "Could not save alert for %s from %s",
                    detection.type,
                    detection.srcIp,
                )
                continue
            results.append(result)
        return results

    # ----------------------------------------------------------------- private
    def _handle_one(self, d: Detection, window_sec: int) -> AlertResult:
        existing = fc.find_open_alert(d.dedup_key, window_sec)
        if existing:
            return self._repeat(d, *existing)
        return self._create(d)

    def _repeat(self, d: Detection, alert_id: str, data: dict) -> AlertResult:
        fc.record_repeat(alert_id, d.at)
        self._watchlist(d, reputation=None, country=None)

        old = SEVERITY_RANK.get(data.get("severity", "low"), 0)
        new = SEVERITY_RANK.get(d.severity, 0)
        if new > old:
            fc.raise_alert_severity(alert_id, d.severity, d.description)
            self._notify("escalated", alert_id, d)
            return AlertResult(alert_id, "escalated", d)
        return AlertResult(alert_id, "repeated", d)

    def _create(self, d: Detection) -> AlertResult:
        country = reputation = None
        if self.enrich and is_external(d.srcIp):
            try:
                info = self.enrich(d.srcIp) or {}
                country = info.get("country")
                reputation = info.get("reputation")
            except Exception:
                log.warning("Threat intel lookup failed for %s", d.srcIp, exc_info=True)

        device_id = None
        if is_real_ip(d.dstIp):
            try:
                device_id = fc.find_device_by_ip(d.dstIp)
            except Exception:
                log.warning("Device lookup failed for %s", d.dstIp, exc_info=True)

        alert_id = fc.create_alert(d.to_alert(device_id, country, reputation))
        self._watchlist(d, reputation, country)
        self._notify("created", alert_id, d)
        return AlertResult(alert_id, "created", d)

    def _watchlist(
        self, d: Detection, reputation: Optional[int], country: Optional[str]
    ) -> None:
        if not is_external(d.srcIp):
            return
        try:
            fc.record_watchlist_hit(
                d.srcIp,
                reason=d.description[:200],
                reputation=reputation,
                country=country,
            )
        except Exception:
            log.warning("Watchlist update failed for %s", d.srcIp, exc_info=True)

    def _notify(self, event: str, alert_id: str, d: Detection) -> None:
        if not self.notify:
            return
        try:
            self.notify(event, alert_id, d)
        except Exception:
            log.warning("Notification hook failed", exc_info=True)