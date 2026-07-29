"""
Configuration Update Procedure Analyzer (AMF, RAN, and UE Configuration Updates).
"""

import logging
from typing import List, Optional, Dict
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class ConfigUpdateAnalyzer:
    """
    Analyzes AMF Configuration Update, RAN Configuration Update, and NAS UE Configuration Update.
    Handles completion, failure outcomes, timeout detection, and latency analysis.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        
        # Track multiple concurrent or sequential updates by name
        active_updates: Dict[str, Procedure] = {}

        for event in events:
            msg = event.message_type

            # --- UE Configuration Update ---
            if msg == "Configuration Update Command":
                p_name = "UE Configuration Update"
                if p_name in active_updates:
                    old = active_updates.pop(p_name)
                    old.status = ProcedureStatus.FAILED
                    old.failure_cause = "Superseded"
                    old.evidence.append("UE Configuration Update superseded by new command.")
                    procedures.append(old)
                
                active_updates[p_name] = Procedure(
                    name=p_name,
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="Configuration Update Complete"
                )

            elif msg == "Configuration Update Complete":
                p_name = "UE Configuration Update"
                proc = active_updates.pop(p_name, None)
                if proc is not None:
                    proc.events.append(event)
                    proc.last_observed_msg = msg
                    proc.end_time = event.timestamp
                    proc.status = ProcedureStatus.COMPLETED
                    proc.expected_next_msg = None
                    latency = event.timestamp - proc.start_time
                    proc.observations.append(f"UE Configuration Update completed successfully (latency: {latency:.3f}s).")
                    procedures.append(proc)

            # --- AMF Configuration Update ---
            elif msg == "AMF Configuration Update":
                p_name = "AMF Configuration Update"
                if p_name in active_updates:
                    old = active_updates.pop(p_name)
                    old.status = ProcedureStatus.FAILED
                    old.failure_cause = "Superseded"
                    procedures.append(old)

                active_updates[p_name] = Procedure(
                    name=p_name,
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="AMF Configuration Update Acknowledge / Failure"
                )

            elif msg == "AMF Configuration Update Acknowledge":
                p_name = "AMF Configuration Update"
                proc = active_updates.pop(p_name, None)
                if proc is not None:
                    proc.events.append(event)
                    proc.last_observed_msg = msg
                    proc.end_time = event.timestamp
                    proc.status = ProcedureStatus.COMPLETED
                    proc.expected_next_msg = None
                    latency = event.timestamp - proc.start_time
                    proc.observations.append(f"AMF Configuration Update acknowledged (latency: {latency:.3f}s).")
                    procedures.append(proc)

            elif msg == "AMF Configuration Update Failure":
                p_name = "AMF Configuration Update"
                proc = active_updates.pop(p_name, None)
                if proc is not None:
                    proc.events.append(event)
                    proc.last_observed_msg = msg
                    proc.end_time = event.timestamp
                    proc.status = ProcedureStatus.FAILED
                    proc.expected_next_msg = None
                    cause = event.cause_code or "Unspecified AMF Update Failure"
                    proc.failure_cause = cause
                    proc.evidence.append(f"AMF Configuration Update Failure in frame {event.frame_number} with cause: {cause}")
                    procedures.append(proc)

            # --- RAN Configuration Update ---
            elif msg == "RAN Configuration Update":
                p_name = "RAN Configuration Update"
                if p_name in active_updates:
                    old = active_updates.pop(p_name)
                    old.status = ProcedureStatus.FAILED
                    old.failure_cause = "Superseded"
                    procedures.append(old)

                active_updates[p_name] = Procedure(
                    name=p_name,
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="RAN Configuration Update Acknowledge / Failure"
                )

            elif msg == "RAN Configuration Update Acknowledge":
                p_name = "RAN Configuration Update"
                proc = active_updates.pop(p_name, None)
                if proc is not None:
                    proc.events.append(event)
                    proc.last_observed_msg = msg
                    proc.end_time = event.timestamp
                    proc.status = ProcedureStatus.COMPLETED
                    proc.expected_next_msg = None
                    latency = event.timestamp - proc.start_time
                    proc.observations.append(f"RAN Configuration Update acknowledged (latency: {latency:.3f}s).")
                    procedures.append(proc)

            elif msg == "RAN Configuration Update Failure":
                p_name = "RAN Configuration Update"
                proc = active_updates.pop(p_name, None)
                if proc is not None:
                    proc.events.append(event)
                    proc.last_observed_msg = msg
                    proc.end_time = event.timestamp
                    proc.status = ProcedureStatus.FAILED
                    proc.expected_next_msg = None
                    cause = event.cause_code or "Unspecified RAN Update Failure"
                    proc.failure_cause = cause
                    proc.evidence.append(f"RAN Configuration Update Failure in frame {event.frame_number} with cause: {cause}")
                    procedures.append(proc)

        # Flush any incomplete updates
        for p_name, proc in active_updates.items():
            proc.status = ProcedureStatus.FAILED
            proc.failure_cause = "Timeout / Incomplete"
            proc.evidence.append(f"No response observed for {p_name} starting in frame {proc.events[0].frame_number}")
            procedures.append(proc)

        return procedures
