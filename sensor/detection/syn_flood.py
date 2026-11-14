from __future__ import annotations

from collections import Counter, deque
from datetime import timedelta
from typing import Any

import schema as s
from detection.base import Detection, Rule

SRC_MULTIPLE = "multiple"

WINDOW = timedelta(seconds=2)   # the rate is measured over the last 2 seconds
COMPLETION_MAX = 0.30           # flood only if fewer than 30% of handshakes finish
SINGLE_SOURCE_SHARE = 0.80      # one IP sending this share = "single source"
HIGH_FACTOR = 2
CRITICAL_FACTOR = 10

MAX_TARGETS = 1000              # memory limits for very large floods
MAX_PER_TARGET = 50_000

# entry layout in a target's deque: [timestamp, srcIp, srcPort, completed]
_TS, _SRC, _SPORT, _DONE = 0, 1, 2, 3


def _is_tcp(r: s.TrafficRecord) -> bool:
    return r.protocol in ("TCP", "HTTP") and r.flags is not None


def _is_syn(r: s.TrafficRecord) -> bool:
    """A new connection request: SYN without ACK."""
    return _is_tcp(r) and "S" in r.flags and "A" not in r.flags and r.dstPort is not None


def _is_handshake_ack(r: s.TrafficRecord) -> bool:
    """A client answering with ACK (the third step of the handshake)."""
    return _is_tcp(r) and "A" in r.flags and "S" not in r.flags and r.dstPort is not None


class _Target:
    """Recent SYNs aimed at one host:port."""

    __slots__ = ("syns", "pending", "done")

    def __init__(self) -> None:
        self.syns: deque = deque()
        self.pending: dict[tuple[str, int], list] = {}   # (src, sport) -> entry
        self.done = 0                                     # completed entries in syns

    def rate(self) -> float:
        n = len(self.syns)
        if n == 0:
            return 0.0
        span = (self.syns[-1][_TS] - self.syns[0][_TS]).total_seconds()
        return n / max(span, 1.0)

    def prune(self, cutoff) -> None:
        while self.syns and self.syns[0][_TS] < cutoff:
            entry = self.syns.popleft()
            if entry[_DONE]:
                self.done -= 1
            key = (entry[_SRC], entry[_SPORT])
            if self.pending.get(key) is entry:
                del self.pending[key]


class SynFloodRule(Rule):
    name = "syn_flood"

    def __init__(self) -> None:
        self._targets: dict[tuple[str, int], _Target] = {}
        self._fired: set[tuple[str, int]] = set()

    def process(self, records, thresholds: dict[str, Any]) -> list[Detection]:
        if not records:
            return []

        need = float(thresholds["syn_flood_packets_per_sec"])
        now = max(r.ts for r in records)

        # 1. forget old SYNs BEFORE adding the new batch, so a quiet gap is
        #    noticed and a returning flood raises a fresh detection
        cutoff = now - WINDOW
        for key in list(self._targets):
            target = self._targets[key]
            target.prune(cutoff)
            if not target.syns:
                del self._targets[key]
                self._fired.discard(key)
            elif key in self._fired and target.rate() < need:
                self._fired.discard(key)

        # 2. add this batch: SYNs first...
        touched: set[tuple[str, int]] = set()
        for r in records:
            if not _is_syn(r):
                continue
            key = (r.dstIp, r.dstPort)
            target = self._targets.get(key)
            if target is None:
                if len(self._targets) >= MAX_TARGETS:
                    continue
                target = self._targets[key] = _Target()
            if len(target.syns) >= MAX_PER_TARGET:
                touched.add(key)
                continue
            entry = [r.ts, r.srcIp, r.srcPort, False]
            target.syns.append(entry)
            if r.srcPort is not None:
                target.pending[(r.srcIp, r.srcPort)] = entry
            touched.add(key)

        #    ...then handshake ACKs, which mark those connections as completed
        for r in records:
            if not _is_handshake_ack(r) or r.srcPort is None:
                continue
            target = self._targets.get((r.dstIp, r.dstPort))
            if target is None:
                continue
            entry = target.pending.get((r.srcIp, r.srcPort))
            if entry is not None and not entry[_DONE]:
                entry[_DONE] = True
                target.done += 1

        # 3. judge the targets we just heard from
        detections: list[Detection] = []
        for key in touched:
            if key in self._fired:
                continue                       # same flood, already reported
            target = self._targets[key]
            rate = target.rate()
            if rate < need:
                continue
            completion = target.done / len(target.syns)
            if completion >= COMPLETION_MAX:
                continue                       # busy but healthy: clients finish
            self._fired.add(key)
            detections.append(self._detection(key, target, rate, completion, need, now))

        return detections

    def _detection(self, key, target, rate, completion, need, now) -> Detection:
        dst, port = key
        n = len(target.syns)
        sources = Counter(entry[_SRC] for entry in target.syns)
        top_src, top_count = sources.most_common(1)[0]
        single = top_count / n >= SINGLE_SOURCE_SHARE
        src = top_src if single else SRC_MULTIPLE

        if rate >= need * CRITICAL_FACTOR:
            severity = s.Severity.CRITICAL
        elif rate >= need * HIGH_FACTOR:
            severity = s.Severity.HIGH
        else:
            severity = s.Severity.MEDIUM

        first, last = target.syns[0][_TS], target.syns[-1][_TS]
        who = (
            f"{top_src}" if single
            else f"{len(sources)} different source addresses"
        )

        if single:
            actions = [
                f"Block {top_src} at the firewall.",
                f"Turn on SYN cookies (or SYN protection) on {dst} and check that the service on port {port} is still responding.",
                f"Set a firewall rate limit on new connections to {dst}:{port}.",
            ]
        else:
            actions = [
                f"Turn on SYN cookies (or SYN protection) on {dst} and check that the service on port {port} is still responding.",
                f"Set a firewall rate limit on new connections to {dst}:{port}.",
                "Don't bother blocking the source addresses one by one: they are probably spoofed (fake).",
                "If it keeps going, contact your ISP or put the service behind DDoS protection.",
            ]

        return Detection(
            type=s.AlertType.SYN_FLOOD.value,
            severity=severity.value,
            srcIp=src,
            dstIp=dst,
            dstPort=port,
            protocol="TCP",
            detectionMethod=s.DetectionMethod.RULE.value,
            at=now,
            description=(
                f"{dst}:{port} received about {int(rate)} new connection requests "
                f"per second from {who}, and only {round(completion * 100)}% "
                f"completed the handshake."
            ),
            reason=(
                f"Rule: {int(need)}+ new connection requests (SYN) per second to "
                f"one service, with fewer than {round(COMPLETION_MAX * 100)}% "
                f"of them finishing the handshake. A busy server also gets many "
                f"SYNs, but real clients complete the connection; flood traffic "
                f"doesn't."
            ),
            evidence={
                "synPerSecond": round(rate, 1),
                "threshold": int(need),
                "handshakeCompletionPercent": round(completion * 100, 1),
                "distinctSources": len(sources),
                "topSource": top_src,
                "topSourceShare": round(top_count / n, 2),
                "synPackets": n,
                "firstSeen": first.isoformat(),
                "lastSeen": last.isoformat(),
            },
            recommendedActions=actions,
        )