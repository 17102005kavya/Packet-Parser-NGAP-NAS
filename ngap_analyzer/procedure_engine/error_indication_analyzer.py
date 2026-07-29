"""
NGAP Error Indication Analyzer.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class ErrorIndicationAnalyzer:
    """
    Analyzes NGAP Error Indication messages.
    Correlates with the triggering NGAP procedure based on timeline history.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []

        for idx, event in enumerate(events):
            msg = event.message_type

            if msg == "Error Indication":
                cause = event.cause_code or "Protocol Error"
                proc = Procedure(
                    name="Error Indication",
                    status=ProcedureStatus.FAILED,
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    failure_cause=cause
                )
                proc.evidence.append(f"Error Indication observed in frame {event.frame_number} with cause: {cause}")

                # Find the preceding triggering procedure/message
                trigger_msg: Optional[str] = None
                trigger_frame: Optional[int] = None
                for prev_event in reversed(events[:idx]):
                    if prev_event.message_type != "Error Indication":
                        trigger_msg = prev_event.message_type
                        trigger_frame = prev_event.frame_number
                        break

                if trigger_msg:
                    proc.observations.append(f"Protocol error triggered by preceding message: {trigger_msg} (frame {trigger_frame}).")
                else:
                    proc.observations.append("Protocol error observed with no preceding message context.")

                procedures.append(proc)

        return procedures
