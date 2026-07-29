"""
NGAP Handover Procedure Analyzer.
Reconstructs Handover Required -> Request -> Request Ack -> Command -> Notify lifecycle.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class HandoverAnalyzer:
    """
    Analyzes NGAP Handover procedures (TS 38.413).
    Tracks Handover states, execution phase latency, failures, and cancellations.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        current_proc: Optional[Procedure] = None

        for event in events:
            msg = event.message_type

            if msg in ["Handover Required", "Handover Request"]:
                if current_proc is not None:
                    # Flush previous incomplete handover
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.failure_cause = "Superseded / Incomplete"
                    procedures.append(current_proc)

                current_proc = Procedure(
                    name="Handover",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="Handover Command / Handover Request Acknowledge"
                )

            elif current_proc is not None:
                current_proc.events.append(event)
                current_proc.last_observed_msg = msg

                if msg in ["Handover Command", "Handover Request Acknowledge"]:
                    prep_latency = event.timestamp - current_proc.start_time
                    current_proc.observations.append(f"Handover preparation successful (latency: {prep_latency:.3f}s).")
                    current_proc.expected_next_msg = "Handover Notify"

                elif msg == "Handover Notify":
                    current_proc.end_time = event.timestamp
                    current_proc.status = ProcedureStatus.COMPLETED
                    current_proc.expected_next_msg = None
                    total_latency = event.timestamp - current_proc.start_time
                    current_proc.observations.append(f"Handover executed successfully (total latency: {total_latency:.3f}s).")
                    procedures.append(current_proc)
                    current_proc = None

                elif msg in ["Handover Failure", "Handover Preparation Failure"]:
                    current_proc.end_time = event.timestamp
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.expected_next_msg = None
                    cause = event.cause_code or "Handover Prep Failure"
                    current_proc.failure_cause = cause
                    current_proc.evidence.append(f"Handover Failure in frame {event.frame_number} with cause: {cause}")
                    procedures.append(current_proc)
                    current_proc = None

                elif msg == "Handover Cancel":
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.failure_cause = "Handover Cancelled"
                    current_proc.evidence.append(f"Handover Cancelled in frame {event.frame_number}")
                    current_proc.expected_next_msg = "Handover Cancel Acknowledge"

                elif msg == "Handover Cancel Acknowledge" and current_proc.failure_cause == "Handover Cancelled":
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    procedures.append(current_proc)
                    current_proc = None

        if current_proc is not None:
            # Capture ended
            current_proc.status = ProcedureStatus.FAILED
            current_proc.failure_cause = "No Handover Response / Timeout"
            current_proc.evidence.append(f"Handover starting in frame {current_proc.events[0].frame_number} remained incomplete.")
            procedures.append(current_proc)

        return procedures
