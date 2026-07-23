"""
Unclassified Event Collector.
Surfaces messages with unmapped procedure codes ("Unknown Signalling") as their
own category rather than silently swallowing them.
"""

from typing import List
from ..models import ProtocolEvent, Procedure, ProcedureStatus


class UnclassifiedEventCollector:
    """
    Collects events whose message_type is "Unknown Signalling" (unmapped
    procedure code) and returns them as a single INCOMPLETE procedure so
    they are visible in the diagnostic report.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        unclassified = [
            e for e in events
            if e.message_type == "Unknown Signalling"
        ]
        if not unclassified:
            return []

        proc = Procedure(
            name="Unclassified Signalling",
            status=ProcedureStatus.INCOMPLETE,
            start_time=unclassified[0].timestamp,
            end_time=unclassified[-1].timestamp,
            events=unclassified,
            last_observed_msg="Unknown Signalling",
            observations=[
                f"{len(unclassified)} message(s) with unmapped procedure codes — "
                f"these are not counted as success or failure."
            ],
            evidence=[
                f"Frame {e.frame_number}: procedure_code={e.procedure_code}"
                for e in unclassified
            ],
        )
        return [proc]
