from __future__ import annotations

from collections import deque
from datetime import timedelta
from typing import Any

import schema as s
from detection.base import Detection, Rule

# Don't let a spoofed flood of sources grow our memory without limit.
MAX_TRACKED = 5000


def _is_syn_probe(r: s.TrafficRecord) -> bool:
    """A SYN with no ACK is a brand new connection attempt."""
    return (
        r.protocol in ("TCP", "HTTP")
        and r.flags is not None
        and "S" in r.flags
        and "A" not in r.flags
        and r.dstPort is not None
    )


class PortScanRule(Rule):
    name = "port_scan"

    def __init__(self) -> None:
        # (src, dst) -> recent (timestamp, port) pairs
        self._seen: dict[tuple[str, str], deque] = {}
        # keys that already raised a detection and are still above the threshold
        self._fired: set[tuple[str, str]] = set()

    def process(self, records, thresholds: dict[str, Any]) -> list[Detection]:
        if not records:
            return []

        need = int(thresholds["port_scan_ports"])
        window = timedelta(seconds=float(thresholds["port_scan_window_sec"]))
        now = max(r.ts for r in records)

        cutoff = now - window
        for key in list(self._seen):
            queue = self._seen[key]
            while queue and queue[0][0] < cutoff:
                queue.popleft()
            if not queue:
                del self._seen[key]
                self._fired.discard(key)
            elif key in self._fired and len({p for _, p in queue}) < need:
                self._fired.discard(key)   # calmed down: can fire again later

        touched: set[tuple[str, str]] = set()
        for r in records:
            if not _is_syn_probe(r):
                continue
            key = (r.srcIp, r.dstIp)
            queue = self._seen.get(key)
            if queue is None:
                if len(self._seen) >= MAX_TRACKED:
                    continue
                queue = self._seen[key] = deque()
            queue.append((r.ts, r.dstPort))
            touched.add(key)

        # 3. check the sources we just heard from, plus ones already flagged
        detections: list[Detection] = []
        for key in touched | self._fired:
            queue = self._seen.get(key)
            if not queue:
                continue
            ports = {port for _, port in queue}

            if len(ports) < need:
                self._fired.discard(key)   # calmed down: can fire again later
                continue
            if key in self._fired:
                continue                   # same burst, already reported

            self._fired.add(key)
            detections.append(self._detection(key, queue, ports, need, window, now))

        return detections

    def _detection(self, key, queue, ports, need, window, now) -> Detection:
        src, dst = key
        count = len(ports)
        window_sec = int(window.total_seconds())
        first, last = queue[0][0], queue[-1][0]
        span = max((last - first).total_seconds(), 0.001)

        # twice the threshold or more is a determined scan
        severity = s.Severity.HIGH if count >= 2 * need else s.Severity.MEDIUM

        return Detection(
            type=s.AlertType.PORT_SCAN.value,
            severity=severity.value,
            srcIp=src,
            dstIp=dst,
            protocol="TCP",
            detectionMethod=s.DetectionMethod.RULE.value,
            at=now,
            description=(
                f"{src} probed {count} different ports on {dst} "
                f"within {window_sec} seconds."
            ),
            reason=(
                f"Rule: one IP tried {need}+ different ports on the same host "
                f"within {window_sec} seconds. Normal clients use one or two "
                f"ports; scanners try many to find open services."
            ),
            evidence={
                "distinctPorts": count,
                "threshold": need,
                "windowSeconds": window_sec,
                "packets": len(queue),
                "packetsPerSecond": round(len(queue) / span, 1),
                "firstSeen": first.isoformat(),
                "lastSeen": last.isoformat(),
                "samplePorts": sorted(ports)[:15],
            },
            recommendedActions=[
                f"Check whether {src} is a known scanner or an authorized security test.",
                f"If it isn't authorized, block {src} at the firewall.",
                f"Review which ports on {dst} are open and close any that aren't needed.",
                f"Watch for follow-up connections from {src} to the ports that answered.",
            ],
        )