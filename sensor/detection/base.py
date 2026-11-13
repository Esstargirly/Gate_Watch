from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import schema as s


@dataclass
class Detection:
    type: str                      # an AlertType value
    severity: str                  # a Severity value
    srcIp: str
    dstIp: str
    description: str               # what happened
    reason: str                    # why it was flagged
    detectionMethod: str           # a DetectionMethod value
    at: datetime                   # when it was detected
    dstPort: Optional[int] = None
    protocol: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendedActions: list[str] = field(default_factory=list)

    @property
    def dedup_key(self) -> str:
        return s.dedup_key(self.type, self.srcIp, self.dstIp)

    def to_alert(
        self,
        device_id: Optional[str] = None,
        src_country: Optional[str] = None,
        src_reputation: Optional[int] = None,
    ) -> s.Alert:
        """Builds the Firestore alert. The alert layer fills in the device and
        the IP reputation/country once it has looked them up."""
        return s.Alert(
            type=self.type,
            severity=self.severity,
            srcIp=self.srcIp,
            dstIp=self.dstIp,
            description=self.description,
            reason=self.reason,
            detectionMethod=self.detectionMethod,
            detectedAt=self.at,
            lastSeenAt=self.at,
            dstPort=self.dstPort,
            protocol=self.protocol,
            deviceId=device_id,
            srcCountry=src_country,
            srcReputation=src_reputation,
            evidence=self.evidence,
            recommendedActions=self.recommendedActions,
            dedupKey=self.dedup_key,
            count=1,
        )


class Rule:
    """Base class. Subclass it and implement process()."""

    name = "rule"

    def process(
        self, records: list[s.TrafficRecord], thresholds: dict[str, Any]
    ) -> list[Detection]:
        raise NotImplementedError