"""
Generic Timeout Detection Framework for NGAP/NAS procedures.
"""

import logging
from typing import List, Dict
from ..models import Procedure, ProtocolEvent

logger = logging.getLogger(__name__)


class TimeoutDetector:
    """
    Scans procedures to detect timeouts based on configurable thresholds.
    Adds root cause observations to incomplete procedures.
    """

    def __init__(self, thresholds: Dict[str, float] = None):
        # Default thresholds in seconds
        self.thresholds = {
            "Registration": 6.0,
            "Authentication": 4.0,
            "Security Mode": 4.0,
            "Service Request": 5.0,
            "PDU Session Resource Setup": 5.0,
            "Handover": 10.0,
            "Paging": 5.0,
            "UE Associated NRPPa Transport": 5.0,
            "Non-UE Associated NRPPa Transport": 5.0,
            "UE Configuration Update": 4.0,
            "AMF Configuration Update": 4.0,
            "RAN Configuration Update": 4.0,
            "Identity Procedure": 4.0
        }
        if thresholds:
            self.thresholds.update(thresholds)

    def detect_timeouts(self, procedures: List[Procedure], events: List[ProtocolEvent]):
        if not events:
            return

        latest_timestamp = max(e.timestamp for e in events)

        for p in procedures:
            if p.status == p.status.INCOMPLETE:
                threshold = self.thresholds.get(p.name, 5.0)  # default 5s
                elapsed = latest_timestamp - p.start_time

                if elapsed > threshold:
                    p.observations.append(
                        f"Timeout warning: Procedure did not receive a response within {threshold}s (elapsed: {elapsed:.3f}s)."
                    )
                    p.observations.append(
                        "Most likely root cause: RAN/UE response timeout, cell reselection, or network signaling loss."
                    )
