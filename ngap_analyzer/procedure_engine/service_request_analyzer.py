"""
Service Request Analyzer for 5GMM Service Request procedures (3GPP TS 24.501).

Reconstructs 5GMM Service Request procedures on a per-UE timeline:
- Initiating: Service Request, Control Plane Service Request
- Successful Completion: Service Accept
- Failure: Service Reject (with 5GMM cause classification)
- Incomplete: Service Request without terminal response before capture end/timeout
- Detects retransmissions, duplicate requests, and calculates procedure latency.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class ServiceRequestAnalyzer:
    """
    Analyzes 5GMM Service Request procedures per UE context.
    """

    INITIATING_MSGS = {"Service Request", "Control Plane Service Request"}
    SUCCESS_MSGS = {"Service Accept"}
    FAILURE_MSGS = {"Service Reject"}

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        """
        Analyzes a chronological timeline of events for a UE and returns
        reconstructed Service Request Procedure instances.
        """
        procedures: List[Procedure] = []
        current_proc: Optional[Procedure] = None

        for event in events:
            msg_type = event.message_type

            # Check if this event initiates a new Service Request procedure
            if msg_type in self.INITIATING_MSGS:
                # If a previous Service Request procedure was open, flush it as INCOMPLETE (superseded / retransmitted)
                if current_proc is not None:
                    current_proc.status = ProcedureStatus.INCOMPLETE
                    current_proc.expected_next_msg = "Service Accept / Service Reject"
                    current_proc.observations.append(
                        f"Superseded by new {msg_type} in frame {event.frame_number}."
                    )
                    procedures.append(current_proc)

                # Check if this request is marked as a retransmission
                is_retrans = getattr(event, "is_retransmission", False)

                current_proc = Procedure(
                    name="Service Request",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg_type,
                    expected_next_msg="Service Accept / Service Reject",
                    evidence=[
                        f"Frame #{event.frame_number} ({event.timestamp_str}): {msg_type}"
                        + (" [Retransmission]" if is_retrans else "")
                    ],
                    observations=[]
                )

                if is_retrans:
                    current_proc.observations.append("Retransmitted Service Request observed.")

                continue

            # If we are tracking an active Service Request procedure
            if current_proc is not None:
                # Terminal Success: Service Accept
                if msg_type in self.SUCCESS_MSGS:
                    current_proc.events.append(event)
                    current_proc.end_time = event.timestamp
                    current_proc.status = ProcedureStatus.COMPLETED
                    current_proc.confidence = "DIRECT"
                    current_proc.last_observed_msg = msg_type
                    current_proc.expected_next_msg = None
                    latency_ms = (event.timestamp - current_proc.start_time) * 1000.0
                    current_proc.evidence.append(
                        f"Frame #{event.frame_number} ({event.timestamp_str}): {msg_type} (Latency: {latency_ms:.2f}ms)"
                    )
                    current_proc.observations.append(
                        f"Service Request completed successfully in {latency_ms:.2f}ms."
                    )
                    procedures.append(current_proc)
                    current_proc = None

                # Terminal Failure: Service Reject
                elif msg_type in self.FAILURE_MSGS:
                    current_proc.events.append(event)
                    current_proc.end_time = event.timestamp
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.confidence = "DIRECT"
                    current_proc.last_observed_msg = msg_type
                    current_proc.expected_next_msg = None
                    cause_str = event.cause_code or "Unspecified 5GMM Cause"
                    current_proc.failure_cause = cause_str
                    latency_ms = (event.timestamp - current_proc.start_time) * 1000.0
                    current_proc.evidence.append(
                        f"Frame #{event.frame_number} ({event.timestamp_str}): {msg_type} (Cause: {cause_str})"
                    )
                    current_proc.observations.append(
                        f"Service Request rejected by AMF (Cause: {cause_str})."
                    )
                    procedures.append(current_proc)
                    current_proc = None

        # Flush open procedure at capture end as INCOMPLETE or INFERRED
        if current_proc is not None:
            if self._can_infer_completion(current_proc, events):
                current_proc.status = ProcedureStatus.COMPLETED
                current_proc.confidence = "INFERRED"
                current_proc.end_time = events[-1].timestamp
                current_proc.expected_next_msg = None
                current_proc.evidence.append(
                    "Service Request completion inferred from subsequent Initial Context Setup / PDU Session establishment."
                )
                current_proc.observations.append(
                    "Service Request COMPLETED (inferred from subsequent Context Setup / PDU Session establishment)."
                )
            else:
                current_proc.status = ProcedureStatus.INCOMPLETE
                current_proc.confidence = "PARTIAL"
                current_proc.expected_next_msg = "Service Accept / Service Reject"
                current_proc.observations.append("Capture ended before Service Request reached a terminal state.")
            procedures.append(current_proc)

        return procedures

    def _can_infer_completion(self, proc: Procedure, events: List[ProtocolEvent]) -> bool:
        """
        Infers Service Request completion if explicit Service Accept was unavailable/ciphered,
        but subsequent procedures requiring an active user-plane / context setup
        (Initial Context Setup, PDU Session setup) succeeded without failure.
        """
        start_idx = 0
        if proc.events and proc.events[0] in events:
            start_idx = events.index(proc.events[0])

        proc_events = events[start_idx:]
        has_failure = False
        has_subsequent_activity = False

        for evt in proc_events:
            msg = evt.message_type
            if msg in ["Service Reject", "Registration Reject", "Authentication Reject", "SCTP Abort"]:
                has_failure = True
                break

            if msg in [
                "Initial Context Setup Request",
                "Initial Context Setup Response",
                "PDU Session Resource Setup Request",
                "PDU Session Resource Setup Response",
                "PDU Session Establishment Accept"
            ]:
                has_subsequent_activity = True

        return (not has_failure) and has_subsequent_activity
