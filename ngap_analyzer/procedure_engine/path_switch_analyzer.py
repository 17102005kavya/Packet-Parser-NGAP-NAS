"""
NGAP Path Switch Request Procedure Analyzer.
Reconstructs Path Switch Request -> Acknowledge / Failure lifecycle.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class PathSwitchAnalyzer:
    """
    Analyzes NGAP Path Switch Request procedures.
    Calculates path switch latency, detects failures, and correlates with handovers.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        current_proc: Optional[Procedure] = None

        has_handover = any(e.message_type in ["Handover Required", "Handover Request", "Handover Notify"] for e in events)

        for event in events:
            msg = event.message_type

            if msg == "Path Switch Request":
                if current_proc is not None:
                    # Flush previous incomplete
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.failure_cause = "Superseded / Incomplete"
                    procedures.append(current_proc)

                current_proc = Procedure(
                    name="Path Switch",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="Path Switch Request Acknowledge / Failure"
                )
                if has_handover:
                    current_proc.observations.append("Path Switch request correlated with active Handover procedure.")

            elif current_proc is not None:
                current_proc.events.append(event)
                current_proc.last_observed_msg = msg

                if msg == "Path Switch Request Acknowledge":
                    current_proc.end_time = event.timestamp
                    current_proc.status = ProcedureStatus.COMPLETED
                    current_proc.expected_next_msg = None
                    latency = event.timestamp - current_proc.start_time
                    current_proc.observations.append(f"Path Switch request completed successfully (latency: {latency:.3f}s).")
                    procedures.append(current_proc)
                    current_proc = None

                elif msg == "Path Switch Request Failure":
                    current_proc.end_time = event.timestamp
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.expected_next_msg = None
                    cause = event.cause_code or "Path Switch Failure"
                    current_proc.failure_cause = cause
                    current_proc.evidence.append(f"Path Switch Failure in frame {event.frame_number} with cause: {cause}")
                    procedures.append(current_proc)
                    current_proc = None

        if current_proc is not None:
            current_proc.status = ProcedureStatus.FAILED
            current_proc.failure_cause = "Timeout / No Response"
            current_proc.evidence.append(f"Path Switch starting in frame {current_proc.events[0].frame_number} remained incomplete.")
            procedures.append(current_proc)

        return procedures
