"""
NGAP RAN Status Transfer Procedure Analyzer.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class RANStatusTransferAnalyzer:
    """
    Analyzes Uplink RAN Status Transfer and Downlink RAN Status Transfer procedures.
    Correlates with active handover execution.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []

        has_handover = any(e.message_type in ["Handover Required", "Handover Request", "Handover Notify"] for e in events)

        for event in events:
            msg = event.message_type

            if msg == "Uplink RAN Status Transfer":
                proc = Procedure(
                    name="Uplink RAN Status Transfer",
                    status=ProcedureStatus.COMPLETED,
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg
                )
                proc.evidence.append(f"Uplink RAN Status Transfer in frame {event.frame_number}")
                if has_handover:
                    proc.observations.append("Status transfer correlated with active Handover procedure.")
                procedures.append(proc)

            elif msg == "Downlink RAN Status Transfer":
                proc = Procedure(
                    name="Downlink RAN Status Transfer",
                    status=ProcedureStatus.COMPLETED,
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg
                )
                proc.evidence.append(f"Downlink RAN Status Transfer in frame {event.frame_number}")
                if has_handover:
                    proc.observations.append("Status transfer correlated with active Handover procedure.")
                procedures.append(proc)

        return procedures
