"""
NGAP NRPPa Transport Procedure Analyzer.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class NRPPaTransportAnalyzer:
    """
    Analyzes UE Associated and Non-UE Associated NRPPa Transport flows.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        active_ue_proc: Optional[Procedure] = None
        active_non_ue_proc: Optional[Procedure] = None

        for event in events:
            msg = event.message_type

            # --- UE Associated NRPPa Transport ---
            if msg == "Downlink UE Associated NRPPa Transport":
                if active_ue_proc is not None:
                    if (active_ue_proc.last_observed_msg == "Downlink UE Associated NRPPa Transport"
                            and event.timestamp - active_ue_proc.events[-1].timestamp < 4.0):
                        active_ue_proc.events.append(event)
                        continue
                    else:
                        active_ue_proc.status = ProcedureStatus.COMPLETED
                        active_ue_proc.confidence = "INFERRED"
                        procedures.append(active_ue_proc)
                
                active_ue_proc = Procedure(
                    name="UE Associated NRPPa Transport",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="Uplink UE Associated NRPPa Transport"
                )

            elif msg == "Uplink UE Associated NRPPa Transport":
                if active_ue_proc is not None and active_ue_proc.last_observed_msg in ["Downlink UE Associated NRPPa Transport", "Uplink UE Associated NRPPa Transport"]:
                    active_ue_proc.events.append(event)
                    active_ue_proc.last_observed_msg = msg
                    active_ue_proc.end_time = event.timestamp
                    active_ue_proc.status = ProcedureStatus.COMPLETED
                    active_ue_proc.expected_next_msg = None
                    latency = event.timestamp - active_ue_proc.start_time
                    active_ue_proc.observations.append(f"UE Associated NRPPa Transport completed (latency: {latency:.3f}s).")
                    procedures.append(active_ue_proc)
                    active_ue_proc = None
                else:
                    if active_ue_proc is not None:
                        active_ue_proc.status = ProcedureStatus.COMPLETED
                        active_ue_proc.confidence = "INFERRED"
                        procedures.append(active_ue_proc)
                    
                    active_ue_proc = Procedure(
                        name="UE Associated NRPPa Transport",
                        status=ProcedureStatus.INCOMPLETE,
                        start_time=event.timestamp,
                        events=[event],
                        last_observed_msg=msg,
                        expected_next_msg="Downlink UE Associated NRPPa Transport"
                    )

            # --- Non-UE Associated NRPPa Transport ---
            elif msg == "Downlink Non-UE Associated NRPPa Transport":
                if active_non_ue_proc is not None:
                    if (active_non_ue_proc.last_observed_msg == "Downlink Non-UE Associated NRPPa Transport"
                            and event.timestamp - active_non_ue_proc.events[-1].timestamp < 4.0):
                        active_non_ue_proc.events.append(event)
                        continue
                    else:
                        active_non_ue_proc.status = ProcedureStatus.COMPLETED
                        active_non_ue_proc.confidence = "INFERRED"
                        procedures.append(active_non_ue_proc)
                
                active_non_ue_proc = Procedure(
                    name="Non-UE Associated NRPPa Transport",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="Uplink Non-UE Associated NRPPa Transport"
                )

            elif msg == "Uplink Non-UE Associated NRPPa Transport":
                if active_non_ue_proc is not None and active_non_ue_proc.last_observed_msg in ["Downlink Non-UE Associated NRPPa Transport", "Uplink Non-UE Associated NRPPa Transport"]:
                    active_non_ue_proc.events.append(event)
                    active_non_ue_proc.last_observed_msg = msg
                    active_non_ue_proc.end_time = event.timestamp
                    active_non_ue_proc.status = ProcedureStatus.COMPLETED
                    active_non_ue_proc.expected_next_msg = None
                    latency = event.timestamp - active_non_ue_proc.start_time
                    active_non_ue_proc.observations.append(f"Non-UE Associated NRPPa Transport completed (latency: {latency:.3f}s).")
                    procedures.append(active_non_ue_proc)
                    active_non_ue_proc = None
                else:
                    if active_non_ue_proc is not None:
                        active_non_ue_proc.status = ProcedureStatus.COMPLETED
                        active_non_ue_proc.confidence = "INFERRED"
                        procedures.append(active_non_ue_proc)
                    
                    active_non_ue_proc = Procedure(
                        name="Non-UE Associated NRPPa Transport",
                        status=ProcedureStatus.INCOMPLETE,
                        start_time=event.timestamp,
                        events=[event],
                        last_observed_msg=msg,
                        expected_next_msg="Downlink Non-UE Associated NRPPa Transport"
                    )

        # Flush active
        if active_ue_proc is not None:
            procedures.append(active_ue_proc)
        if active_non_ue_proc is not None:
            procedures.append(active_non_ue_proc)

        return procedures
