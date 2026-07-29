"""
NAS Non-Delivery Indication and Reroute NAS Request Analyzer.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class NASNonDeliveryAnalyzer:
    """
    Analyzes NAS Non-Delivery Indication and Reroute NAS Request procedures.
    Correlates failure indications with Registration and Service Request procedures.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []

        # Find Registration and Service Request events for correlation
        has_reg = any(e.message_type in ["Registration Request", "Registration Accept", "Registration Reject"] for e in events)
        has_srv = any(e.message_type in ["Service Request", "Service Accept", "Service Reject"] for e in events)

        for event in events:
            msg = event.message_type

            if msg == "NAS Non-Delivery Indication":
                cause = event.cause_code or "Unknown Non-Delivery Cause"
                proc = Procedure(
                    name="NAS Non-Delivery Indication",
                    status=ProcedureStatus.FAILED,
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    failure_cause=cause
                )
                proc.evidence.append(f"NAS Non-Delivery Indication in frame {event.frame_number} with cause: {cause}")
                
                corr = []
                if has_reg:
                    corr.append("Registration")
                if has_srv:
                    corr.append("Service Request")
                if corr:
                    proc.observations.append(f"Non-delivery correlated with active/historical NAS procedure(s): {', '.join(corr)}")
                else:
                    proc.observations.append("Non-delivery observed with no active Registration/Service Request in timeline.")
                
                procedures.append(proc)

            elif msg == "Reroute NAS Request":
                proc = Procedure(
                    name="Reroute NAS Request",
                    status=ProcedureStatus.COMPLETED,
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg
                )
                proc.evidence.append(f"Reroute NAS Request in frame {event.frame_number}")
                
                corr = []
                if has_reg:
                    corr.append("Registration")
                if has_srv:
                    corr.append("Service Request")
                if corr:
                    proc.observations.append(f"Reroute correlated with NAS procedure(s): {', '.join(corr)}")
                
                procedures.append(proc)

        return procedures
