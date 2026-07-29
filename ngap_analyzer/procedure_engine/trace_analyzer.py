"""
NGAP Trace Analyzer.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class TraceAnalyzer:
    """
    Analyzes Trace Control procedures (Trace Start, Deactivate Trace, Trace Failure, Cell Traffic Trace).
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        active_trace_proc: Optional[Procedure] = None

        for event in events:
            msg = event.message_type

            if msg == "Trace Start":
                if active_trace_proc is not None:
                    procedures.append(active_trace_proc)

                active_trace_proc = Procedure(
                    name="Trace Control",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="Deactivate Trace / Trace Failure Indication"
                )

            elif msg == "Deactivate Trace" and active_trace_proc is not None:
                active_trace_proc.events.append(event)
                active_trace_proc.last_observed_msg = msg
                active_trace_proc.end_time = event.timestamp
                active_trace_proc.status = ProcedureStatus.COMPLETED
                active_trace_proc.expected_next_msg = None
                active_trace_proc.observations.append("Trace deactivated successfully.")
                procedures.append(active_trace_proc)
                active_trace_proc = None

            elif msg == "Trace Failure Indication" and active_trace_proc is not None:
                active_trace_proc.events.append(event)
                active_trace_proc.last_observed_msg = msg
                active_trace_proc.end_time = event.timestamp
                active_trace_proc.status = ProcedureStatus.FAILED
                active_trace_proc.expected_next_msg = None
                cause = event.cause_code or "Trace Failure Indication"
                active_trace_proc.failure_cause = cause
                active_trace_proc.evidence.append(f"Trace Failure Indication in frame {event.frame_number} with cause: {cause}")
                procedures.append(active_trace_proc)
                active_trace_proc = None

            elif msg == "Cell Traffic Trace":
                proc = Procedure(
                    name="Cell Traffic Trace",
                    status=ProcedureStatus.COMPLETED,
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg
                )
                proc.evidence.append(f"Cell Traffic Trace observed in frame {event.frame_number}")
                procedures.append(proc)

        if active_trace_proc is not None:
            active_trace_proc.status = ProcedureStatus.COMPLETED
            active_trace_proc.confidence = "INFERRED"
            active_trace_proc.observations.append("Trace session inferred as active/running indefinitely.")
            procedures.append(active_trace_proc)

        return procedures
