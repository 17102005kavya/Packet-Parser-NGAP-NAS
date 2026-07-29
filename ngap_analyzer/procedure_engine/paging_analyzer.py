"""
Paging Procedure Analyzer.
Reconstructs NGAP Paging Signalling: Paging -> Initial UE Message / Service Request / Registration Request.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class PagingAnalyzer:
    """
    Analyzes NGAP Paging procedures for a UE context.
    Tracks Paging requests, maps subsequent responses (Service Request/Initial UE Message/Registration Request),
    detects unanswered pages, and calculates paging response latency.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        current_paging_proc: Optional[Procedure] = None

        for event in events:
            msg = event.message_type

            if msg == "Paging":
                if current_paging_proc is None:
                    current_paging_proc = Procedure(
                        name="Paging",
                        status=ProcedureStatus.INCOMPLETE,
                        start_time=event.timestamp,
                        events=[event],
                        last_observed_msg=msg,
                        expected_next_msg="Initial UE Message / Service Request / Registration Request"
                    )
                else:
                    # Retransmission
                    current_paging_proc.events.append(event)
                    current_paging_proc.last_observed_msg = msg
                    current_paging_proc.observations.append(
                        f"Paging retransmission observed in frame {event.frame_number}."
                    )

            elif current_paging_proc is not None:
                # Check for a response
                if msg in ["Initial UE Message", "Service Request", "Registration Request"]:
                    current_paging_proc.events.append(event)
                    current_paging_proc.last_observed_msg = msg
                    current_paging_proc.end_time = event.timestamp
                    current_paging_proc.status = ProcedureStatus.COMPLETED
                    current_paging_proc.expected_next_msg = None
                    
                    latency = event.timestamp - current_paging_proc.start_time
                    current_paging_proc.observations.append(
                        f"Paging answered by UE with {msg} (latency: {latency:.3f}s)."
                    )
                    
                    procedures.append(current_paging_proc)
                    current_paging_proc = None

        if current_paging_proc is not None:
            # Capture ended without response -> unanswered paging event
            current_paging_proc.status = ProcedureStatus.FAILED
            current_paging_proc.failure_cause = "No Paging Response"
            current_paging_proc.evidence.append(
                f"Paging request in frame {current_paging_proc.events[0].frame_number} remained unanswered."
            )
            current_paging_proc.observations.append("Paging unanswered (timeout/no response).")
            procedures.append(current_paging_proc)

        return procedures
