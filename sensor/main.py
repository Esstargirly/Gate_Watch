from __future__ import annotations

import argparse
import logging
import os
import platform
import random
import time
from collections import Counter
from typing import Callable, Optional

import schema as s
import simulate as sim
from detection.base import Detection
from detection.brute_force import BruteForceRule
from detection.port_scan import PortScanRule
from detection.syn_flood import SynFloodRule

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

log = logging.getLogger("gatewatch")

HEARTBEAT_SEC = 30          # "I'm alive" + housekeeping
THRESHOLD_REFRESH_SEC = 60  # re-read detection thresholds


def build_rules():
    """Add new detection rules here."""
    return [PortScanRule(), BruteForceRule(), SynFloodRule()]


def describe(d: Detection) -> str:
    target = f"{d.dstIp}:{d.dstPort}" if d.dstPort else d.dstIp
    return f"{d.type:<13} {d.severity.upper():<9} {d.srcIp} -> {target}"


class Sensor:
    def __init__(
        self,
        dry_run: bool,
        write_traffic: bool,
        sensor_id: str,
        name: str,
        interface: str,
        on_heartbeat: Optional[Callable] = None,
    ) -> None:
        self.dry_run = dry_run
        self.write_traffic = write_traffic and not dry_run
        self.sensor_id, self.name, self.interface = sensor_id, name, interface
        self.on_heartbeat = on_heartbeat
        self.rules = build_rules()
        self.counts: Counter = Counter()

        if dry_run:
            self.fc = None
            self.manager = None
            self.thresholds = dict(s.REMOTE_CONFIG_DEFAULTS)
        else:
            # imported here so --dry-run works without Firebase installed
            import firebase_client as fc
            from alerts import AlertManager

            self.fc = fc
            self.manager = AlertManager()
            self.thresholds = fc.load_thresholds()

        self._last_beat = float("-inf")
        self._last_refresh = time.monotonic()

    # -------------------------------------------------------------- per batch
    def on_batch(self, batch: list[s.TrafficRecord]) -> None:
        """Handles about one second of traffic."""
        self.counts["packets"] += len(batch)
        self._save_alerts(self._detect(batch))
        self._save_traffic(batch)

    def _detect(self, batch) -> list[Detection]:
        found: list[Detection] = []
        for rule in self.rules:
            try:
                found += rule.process(batch, self.thresholds)
            except Exception:
                # one buggy rule must not take the whole sensor down
                log.exception("Rule %s crashed on a batch, skipping it", rule.name)
        return found

    def _save_alerts(self, detections: list[Detection]) -> None:
        if not detections:
            return
        if self.dry_run:
            for d in detections:
                self.counts["detections"] += 1
                self.counts[f"type:{d.type}"] += 1
                log.info("DETECTED   %s", describe(d))
            return

        for result in self.manager.handle(detections, self.thresholds):
            self.counts[result.action] += 1
            self.counts[f"type:{result.detection.type}"] += 1
            log.info(
                "%-10s %s  [%s]",
                result.action.upper(),
                describe(result.detection),
                result.alertId[:8],
            )

    def _save_traffic(self, batch) -> None:
        if not self.write_traffic:
            return
        try:
            self.fc.add_traffic(batch)
            self.fc.bump_traffic_stats(len(batch), sum(r.size for r in batch))
        except Exception:
            log.warning("Could not save traffic", exc_info=True)

    # ----------------------------------------------------------- housekeeping
    def housekeeping(self) -> None:
        """Heartbeat, stale devices, threshold refresh. Cheap to call every batch."""
        if self.dry_run:
            return
        now = time.monotonic()

        if now - self._last_beat >= HEARTBEAT_SEC:
            self._last_beat = now
            try:
                if self.on_heartbeat:
                    self.on_heartbeat()
                self.fc.heartbeat(self.sensor_id, self.name, self.interface)
                self.fc.mark_stale_devices_offline()
            except Exception:
                log.warning("Heartbeat failed", exc_info=True)

        if now - self._last_refresh >= THRESHOLD_REFRESH_SEC:
            self._last_refresh = now
            try:
                self.thresholds = self.fc.load_thresholds()
            except Exception:
                log.warning("Could not refresh thresholds, keeping the old ones")

    # ---------------------------------------------------------------- summary
    def summary(self) -> str:
        c = self.counts
        by_type = ", ".join(
            f"{k[5:]} {v}" for k, v in sorted(c.items()) if k.startswith("type:")
        )
        if self.dry_run:
            outcome = f"{c['detections']} detections (dry run, nothing saved)"
        else:
            outcome = (
                f"{c['created']} alerts created, {c['repeated']} repeats, "
                f"{c['escalated']} escalations"
            )
        return f"{c['packets']} packets processed, {outcome}" + (
            f" [{by_type}]" if by_type else ""
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="GateWatch sensor")
    parser.add_argument("scenario", nargs="?", default="demo", choices=sorted(sim.SCENARIOS))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-traffic", action="store_true")
    parser.add_argument("--no-seed", action="store_true")
    parser.add_argument("--instant", action="store_true")
    parser.add_argument("--speed", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S"
    )

    # ---- traffic source: the simulator for now -----------------------------
    # When capture.py is ready, replace these lines with a source that yields
    # one list of TrafficRecords per second, like sim.replay() does.
    records = list(sim.SCENARIOS[args.scenario](s.now(), random.Random(args.seed)))
    batches = sim.replay(records, realtime=not args.instant, speed=args.speed)
    interface = "simulated"
    # -------------------------------------------------------------------------

    sensor = Sensor(
        dry_run=args.dry_run,
        write_traffic=not args.no_traffic,
        sensor_id=os.environ.get("SENSOR_ID", "sensor-1"),
        name=os.environ.get("SENSOR_NAME", platform.node() or "GateWatch sensor"),
        interface=interface,
    )

    if not args.dry_run:
        fc = sensor.fc
        if not args.no_seed:
            sim.seed_demo_data(fc)
            log.info("Seeded demo devices and watchlist.")

        def keep_demo_devices_online() -> None:
            for mac, ip, name, _ in sim.DEMO_DEVICES:
                fc.upsert_device(mac, ip, name)

        sensor.on_heartbeat = keep_demo_devices_online

    mode = "DRY RUN, nothing is saved" if args.dry_run else "saving to Firestore"
    log.info("GateWatch sensor starting: %s, %d packets, %s", args.scenario, len(records), mode)

    try:
        for batch in batches:
            sensor.on_batch(batch)
            sensor.housekeeping()
    except KeyboardInterrupt:
        log.info("Stopped.")
    finally:
        log.info("Done: %s", sensor.summary())


if __name__ == "__main__":
    main()