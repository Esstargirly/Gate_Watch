from __future__ import annotations

from collections import deque
from datetime import timedelta
from typing import Any

import schema as s
from detection.base import Detection, Rule

AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}
ESCALATE_FACTOR = 5      # High severity at this many times the threshold
MAX_TRACKED = 5000       # keeps memory bounded if sources are spoofed


def _is_login_attempt(r: s.TrafficRecord) -> bool:
    """A new connection (SYN, no ACK) to a login port."""
    return (
        r.protocol == "TCP"
        and r.flags is not None
        and "S" in r.flags
        and "A" not in r.flags
        and r.dstPort in AUTH_PORTS
    )


def _is_reset_from_login_service(r: s.TrafficRecord) -> bool:
    """The server closing a connection on a login port (RST)."""
    return (
        r.protocol == "TCP"
        and r.flags is not None
        and "R" in r.flags
        and r.srcPort in AUTH_PORTS
    )


def _attempts(queue: deque) -> int:
    return sum(1 for _, is_reset in queue if not is_reset)


class BruteForceRule(Rule):
    name = "brute_force"

    def __init__(self) -> None:
        # (attacker, target, port) -> recent (timestamp, is_reset) entries
        self._seen: dict[tuple[str, str, int], deque] = {}
        # 1 = raised at the threshold, 2 = escalated to High
        self._level: dict[tuple[str, str, int], int] = {}

    def process(self, records, thresholds: dict[str, Any]) -> list[Detection]:
        if not records:
            return []

        need = int(thresholds["brute_force_attempts"])
        window = timedelta(seconds=float(thresholds["brute_force_window_sec"]))
        escalate_at = need * ESCALATE_FACTOR
        now = max(r.ts for r in records)

        # 1. forget old entries BEFORE adding the new batch, so a quiet gap
        #    is noticed and a returning attacker raises a fresh detection
        cutoff = now - window
        for key in list(self._seen):
            queue = self._seen[key]
            while queue and queue[0][0] < cutoff:
                queue.popleft()
            if not queue:
                del self._seen[key]
                self._level.pop(key, None)
            elif self._level.get(key) and _attempts(queue) < need:
                self._level.pop(key, None)

        # 2. add this batch: new connection attempts first...
        touched: set[tuple[str, str, int]] = set()
        for r in records:
            if not _is_login_attempt(r):
                continue
            key = (r.srcIp, r.dstIp, r.dstPort)
            queue = self._seen.get(key)
            if queue is None:
                if len(self._seen) >= MAX_TRACKED:
                    continue
                queue = self._seen[key] = deque()
            queue.append((r.ts, False))
            touched.add(key)

        #    ...then resets from the server, only for attackers already tracked
        for r in records:
            if _is_reset_from_login_service(r):
                queue = self._seen.get((r.dstIp, r.srcIp, r.srcPort))
                if queue is not None:
                    queue.append((r.ts, True))

        # 3. check the attackers we just heard from
        detections: list[Detection] = []
        for key in touched:
            queue = self._seen[key]
            attempts = _attempts(queue)
            level = self._level.get(key, 0)

            if attempts >= escalate_at and level < 2:
                self._level[key] = 2
                detections.append(
                    self._detection(key, queue, attempts, need, window, now,
                                    s.Severity.HIGH)
                )
            elif attempts >= need and level < 1:
                self._level[key] = 1
                detections.append(
                    self._detection(key, queue, attempts, need, window, now,
                                    s.Severity.MEDIUM)
                )

        return detections

    def _detection(self, key, queue, attempts, need, window, now, severity) -> Detection:
        src, dst, port = key
        service = AUTH_PORTS[port]
        window_sec = int(window.total_seconds())
        resets = len(queue) - attempts
        first, last = queue[0][0], queue[-1][0]
        span_min = max((last - first).total_seconds(), 1.0) / 60

        return Detection(
            type=s.AlertType.BRUTE_FORCE.value,
            severity=severity.value,
            srcIp=src,
            dstIp=dst,
            dstPort=port,
            protocol="TCP",
            detectionMethod=s.DetectionMethod.RULE.value,
            at=now,
            description=(
                f"{src} made {attempts} connection attempts to {service} "
                f"(port {port}) on {dst} within {window_sec} seconds."
            ),
            reason=(
                f"Rule: {need}+ new connections from one IP to the same login "
                f"service within {window_sec} seconds. People log in once; "
                f"password-guessing tools reconnect over and over. This is "
                f"judged from the connection pattern, so confirm it in the "
                f"server's login logs."
            ),
            evidence={
                "service": service,
                "port": port,
                "attempts": attempts,
                "connectionsClosedByServer": resets,
                "threshold": need,
                "windowSeconds": window_sec,
                "attemptsPerMinute": round(attempts / span_min, 1),
                "firstSeen": first.isoformat(),
                "lastSeen": last.isoformat(),
            },
            recommendedActions=[
                f"Check the {service} login logs on {dst} for failed logins from {src}.",
                f"If it isn't an authorized user or tool, block {src} at the firewall.",
                f"If any login from {src} succeeded after the failures, treat "
                f"{dst} as compromised and reset its credentials.",
                f"Harden {service} on {dst}: strong passwords or key-only login, "
                f"MFA where possible, and rate limiting (for example fail2ban).",
            ],
        )