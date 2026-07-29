"""
NAS Identity Procedure Analyzer.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class IdentityProcedureAnalyzer:
    """
    Analyzes NAS Identity Request and Response procedures.
    Correlates with active Registration and Authentication flows.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        current_proc: Optional[Procedure] = None

        has_reg = any(e.message_type in ["Registration Request", "Registration Accept", "Registration Reject"] for e in events)
        has_auth = any(e.message_type in ["Authentication Request", "Authentication Response", "Authentication Failure"] for e in events)

        for event in events:
            msg = event.message_type

            if msg == "Identity Request":
                if current_proc is not None:
                    # Timeout/unanswered previous request
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.failure_cause = "Response Timeout / Superseded"
                    current_proc.evidence.append(f"Identity Request in frame {current_proc.events[0].frame_number} was superseded without response.")
                    procedures.append(current_proc)

                current_proc = Procedure(
                    name="Identity Procedure",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="Identity Response"
                )
                
                corr = []
                if has_reg:
                    corr.append("Registration")
                if has_auth:
                    corr.append("Authentication")
                if corr:
                    current_proc.observations.append(f"Identity procedure initiated during NAS flow(s): {', '.join(corr)}")

            elif msg == "Identity Response" and current_proc is not None:
                current_proc.events.append(event)
                current_proc.last_observed_msg = msg
                current_proc.end_time = event.timestamp
                current_proc.status = ProcedureStatus.COMPLETED
                current_proc.expected_next_msg = None
                
                latency = event.timestamp - current_proc.start_time
                current_proc.observations.append(f"Identity response received successfully (latency: {latency:.3f}s).")
                
                procedures.append(current_proc)
                current_proc = None

        if current_proc is not None:
            # Capture ended or timeout
            current_proc.status = ProcedureStatus.FAILED
            current_proc.failure_cause = "No Identity Response"
            current_proc.evidence.append(f"Identity Request in frame {current_proc.events[0].frame_number} remained unanswered.")
            current_proc.observations.append("Identity procedure unanswered (timeout).")
            procedures.append(current_proc)

        return procedures
