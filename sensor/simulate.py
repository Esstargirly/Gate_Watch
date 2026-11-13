from __future__ import annotations

import argparse
import random
import time
from collections import Counter
from datetime import datetime, timedelta
from typing import Callable, Iterable, Iterator, Optional

import schema as s

SENSOR_ID = "simulator"

# ------------------------------------------------------------ made-up network
TARGET_IP = "192.168.1.20"                              # the "file server"
LAN_HOSTS = [f"192.168.1.{n}" for n in (10, 11, 12, 13, 14)]
WEB_SERVERS = [f"198.18.0.{n}" for n in (10, 11, 12, 13, 14)]   # benign sites

ATTACKER_IP = "203.0.113.45"       # port scanner
BRUTE_IP = "198.51.100.23"         # SSH password guesser
FLOOD_PREFIX = "192.0.2."          # spoofed sources for the SYN flood
WATCHLIST_IP = "203.0.113.99"      # pre-listed bad IP (seeded with --write)

# (mac, ip, name, known)
DEMO_DEVICES = [
    ("aa:bb:cc:00:00:10", "192.168.1.10", "Admin laptop", True),
    ("aa:bb:cc:00:00:11", "192.168.1.11", "Front desk PC", True),
    ("aa:bb:cc:00:00:12", "192.168.1.12", "Lab workstation", True),
    ("aa:bb:cc:00:00:20", TARGET_IP, "File server", True),
    ("de:ad:be:ef:00:99", "192.168.1.77", None, False),  # shows up as unknown
]


# --------------------------------------------------------------------- helpers
def _pkt(
    ts: datetime,
    src: str,
    dst: str,
    protocol: str,
    size: int,
    sport: Optional[int] = None,
    dport: Optional[int] = None,
    flags: Optional[str] = None,
) -> s.TrafficRecord:
    return s.TrafficRecord(
        ts=ts,
        srcIp=src,
        dstIp=dst,
        protocol=protocol,
        size=size,
        expireAt=s.traffic_expiry(),
        srcPort=sport,
        dstPort=dport,
        flags=flags,
        sensorId=SENSOR_ID,
    )


def _at(start: datetime, seconds: float) -> datetime:
    return start + timedelta(seconds=seconds)


# ------------------------------------------------------------------- scenarios
# Every scenario takes (start, rng) and yields TrafficRecords.

def normal_traffic(
    start: datetime,
    rng: random.Random,
    duration_sec: float = 30,
    per_sec: float = 3.0,
    size_range: tuple[int, int] = (60, 1400),
) -> Iterator[s.TrafficRecord]:
    """Everyday browsing, DNS and time-sync between the LAN and the internet."""
    services = [(443, "TCP"), (80, "HTTP"), (53, "DNS"), (123, "UDP")]
    weights = [0.5, 0.2, 0.2, 0.1]
    t = 0.0
    while True:
        t += rng.expovariate(per_sec)
        if t >= duration_sec:
            return
        host = rng.choice(LAN_HOSTS)
        server = rng.choice(WEB_SERVERS)
        port, proto = rng.choices(services, weights)[0]
        ephemeral = rng.randint(49152, 65535)
        flags = rng.choice(["A", "PA", "A"]) if proto in ("TCP", "HTTP") else None
        size = rng.randint(70, 150) if proto == "DNS" else rng.randint(*size_range)
        if rng.random() < 0.5:   # request
            yield _pkt(_at(start, t), host, server, proto, size, ephemeral, port, flags)
        else:                    # reply
            yield _pkt(_at(start, t), server, host, proto, size, port, ephemeral, flags)


def port_scan(
    start: datetime,
    rng: random.Random,
    attacker: str = ATTACKER_IP,
    target: str = TARGET_IP,
    ports: int = 100,
    per_sec: float = 40,
) -> Iterator[s.TrafficRecord]:
    """One IP sends SYNs to many different ports, fast."""
    for i, port in enumerate(rng.sample(range(1, 1025), ports)):
        yield _pkt(
            _at(start, i / per_sec),
            attacker, target, "TCP", 60,
            rng.randint(40000, 60000), port, "S",
        )


def brute_force(
    start: datetime,
    rng: random.Random,
    attacker: str = BRUTE_IP,
    target: str = TARGET_IP,
    port: int = 22,
    attempts: int = 40,
    per_sec: float = 2,
) -> Iterator[s.TrafficRecord]:
    """Repeated short connections to SSH: connect, get closed, try again."""
    for i in range(attempts):
        t = i / per_sec
        sport = rng.randint(40000, 60000)
        yield _pkt(_at(start, t), attacker, target, "TCP", 60, sport, port, "S")
        yield _pkt(_at(start, t + 0.2), target, attacker, "TCP", 54, port, sport, "R")


def syn_flood(
    start: datetime,
    rng: random.Random,
    target: str = TARGET_IP,
    port: int = 80,
    packets: int = 600,
    per_sec: float = 300,
) -> Iterator[s.TrafficRecord]:
    """Lots of SYNs per second from many (spoofed) sources at one service."""
    for i in range(packets):
        src = f"{FLOOD_PREFIX}{rng.randint(1, 254)}"
        yield _pkt(
            _at(start, i / per_sec),
            src, target, "TCP", 60,
            rng.randint(1024, 65535), port, "S",
        )


def watchlist_hit(
    start: datetime,
    rng: random.Random,
    source: str = WATCHLIST_IP,
    target: str = TARGET_IP,
) -> Iterator[s.TrafficRecord]:
    """A few web requests from an IP that's already on the watchlist."""
    for i in range(3):
        yield _pkt(
            _at(start, i),
            source, target, "HTTP", rng.randint(300, 900),
            rng.randint(40000, 60000), 80, "PA",
        )


def traffic_spike(
    start: datetime, rng: random.Random, duration_sec: float = 10
) -> Iterator[s.TrafficRecord]:
    """Several times the usual volume, with big packets (unusual data transfer)."""
    return normal_traffic(start, rng, duration_sec, per_sec=20, size_range=(900, 1500))


def demo_timeline(start: datetime, rng: random.Random) -> list[s.TrafficRecord]:
    """About 75 seconds: calm traffic, then each attack in turn.
       +10s port scan, +25s brute force, +45s SYN flood,
       +55s watchlist hit, +62s traffic spike."""
    records: list[s.TrafficRecord] = list(normal_traffic(start, rng, 75))
    records += port_scan(_at(start, 10), rng)
    records += brute_force(_at(start, 25), rng)
    records += syn_flood(_at(start, 45), rng)
    records += watchlist_hit(_at(start, 55), rng)
    records += traffic_spike(_at(start, 62), rng)
    return sorted(records, key=lambda r: r.ts)


SCENARIOS: dict[str, Callable[[datetime, random.Random], Iterable[s.TrafficRecord]]] = {
    "normal": normal_traffic,
    "port_scan": port_scan,
    "brute_force": brute_force,
    "syn_flood": syn_flood,
    "watchlist_hit": watchlist_hit,
    "traffic_spike": traffic_spike,
    "demo": demo_timeline,
}


# ---------------------------------------------------------------------- replay
def _wait_until(offset_sec: float, wall_start: float, speed: float) -> None:
    delay = offset_sec / speed - (time.monotonic() - wall_start)
    if delay > 0:
        time.sleep(delay)


def replay(
    records: Iterable[s.TrafficRecord], realtime: bool = True, speed: float = 1.0
) -> Iterator[list[s.TrafficRecord]]:
    """Hands out the records one second at a time, as a list per second.
    With realtime=True it actually waits, so it behaves like a live feed.
    The detection engine can consume this the same way it will consume the
    real capture."""
    ordered = sorted(records, key=lambda r: r.ts)
    if not ordered:
        return
    first = ordered[0].ts
    wall_start = time.monotonic()
    batch: list[s.TrafficRecord] = []
    window = 1  # batch covers seconds [window-1, window) after the first packet

    for rec in ordered:
        offset = (rec.ts - first).total_seconds()
        while offset >= window:
            if batch:
                if realtime:
                    _wait_until(window, wall_start, speed)
                yield batch
                batch = []
            window += 1
        batch.append(rec)

    if batch:
        if realtime:
            _wait_until(window, wall_start, speed)
        yield batch


# ------------------------------------------------------------- Firestore seeding
def seed_demo_data(fc) -> None:
    """Adds the demo devices (one of them unknown) and the pre-listed bad IP."""
    for mac, ip, name, known in DEMO_DEVICES:
        fc.upsert_device(mac, ip, name)
        if known:
            (
                fc.get_db()
                .collection(s.DEVICES)
                .document(fc.device_id(mac))
                .update({"known": True})
            )
    fc.record_watchlist_hit(
        WATCHLIST_IP, reason="Known-bad IP (demo seed)", reputation=95
    )


# ------------------------------------------------------------------------- CLI
def main() -> None:
    parser = argparse.ArgumentParser(description="GateWatch traffic simulator")
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--instant", action="store_true",
                        help="don't wait, print everything straight away")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="2.0 = twice as fast (ignored with --instant)")
    parser.add_argument("--seed", type=int, default=None,
                        help="same seed = same traffic every time")
    parser.add_argument("--write", action="store_true",
                        help="also write the traffic and demo devices to Firestore")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    start = s.now()
    records = list(SCENARIOS[args.scenario](start, rng))

    fc = None
    if args.write:
        import firebase_client as fc  # only needed (and imported) for --write
        seed_demo_data(fc)
        print("Seeded demo devices and watchlist.")

    print(f"{args.scenario}: {len(records)} packets")
    first = records[0].ts if records else start
    for batch in replay(records, realtime=not args.instant, speed=args.speed):
        if fc:
            fc.add_traffic(batch)
            fc.bump_traffic_stats(len(batch), sum(r.size for r in batch))
        top_src, top_n = Counter(r.srcIp for r in batch).most_common(1)[0]
        offset = int((batch[0].ts - first).total_seconds())
        print(f"[+{offset:>3}s] {len(batch):>4} packets, top source {top_src} ({top_n})")


if __name__ == "__main__":
    main()