"""
Registration Procedure Analyzer.
Reconstructs 5G Registration Signalling: Initial UE Message / Registration Request -> Reg Accept / Reject.

Per TS 24.501 §5.5.1.2, the full initial registration sequence is:
  Registration Request -> Registration Accept -> Registration Complete
For mobility/periodic registration updates, Registration Complete is not sent.
"""

from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus


class RegistrationAnalyzer:
    """
    Analyzes Registration procedures for a UE context.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        current_proc: Optional[Procedure] = None

        for event in events:
            msg = event.message_type

            # Check for Registration start
            if msg in ["Registration Request", "Initial UE Message"]:
                if current_proc is not None:
                    if current_proc.status == ProcedureStatus.INCOMPLETE:
                        current_proc.observations.append("Registration incomplete (superseded by a new Request).")
                    procedures.append(current_proc)
                    current_proc = None

                current_proc = Procedure(
                    name="Registration",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="Registration Accept / Reject"
                )

            elif current_proc is not None:
                if current_proc.status == ProcedureStatus.COMPLETED and msg != "Registration Complete":
                    # Non-Complete message after Accept -> flush completed registration
                    procedures.append(current_proc)
                    current_proc = None
                    continue

                current_proc.events.append(event)
                current_proc.last_observed_msg = msg

                if msg == "Registration Accept":
                    current_proc.status = ProcedureStatus.COMPLETED
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = "Registration Complete (optional)"
                    current_proc.observations.append("Registration accepted by AMF.")
                    # Don't append yet — wait to see if Registration Complete follows

                elif msg == "Registration Complete" and current_proc.status == ProcedureStatus.COMPLETED:
                    # Full 3-step handshake observed (TS 24.501 §5.5.1.2.5)
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    current_proc.observations.append("Registration Complete received — full handshake.")
                    procedures.append(current_proc)
                    current_proc = None

                elif msg == "Registration Reject":
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    cause = event.cause_code or "Unspecified Registration Reject Cause"
                    current_proc.failure_cause = cause
                    current_proc.evidence.append(f"Registration Reject observed in frame {event.frame_number} with {cause}")
                    current_proc.observations.append(f"Registration Failed: {cause}")
                    procedures.append(current_proc)
                    current_proc = None

                elif msg == "SCTP Abort":
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    cause = event.cause_code or "SCTP Abort"
                    current_proc.failure_cause = cause
                    current_proc.evidence.append(f"SCTP Abort observed in frame {event.frame_number} with cause: {cause}")
                    current_proc.observations.append(f"Registration aborted due to SCTP Abort: {cause}")
                    procedures.append(current_proc)
                    current_proc = None

        if current_proc is not None:
            if current_proc.status == ProcedureStatus.COMPLETED:
                # Accept seen but no Complete — still COMPLETED since Complete is
                # optional for mobility/periodic registration updates.
                current_proc.expected_next_msg = None
                current_proc.observations.append(
                    "Registration Accept observed without Registration Complete "
                    "(normal for mobility/periodic registration updates)."
                )
            else:
                current_proc.evidence.append(
                    f"Capture ended after frame {current_proc.events[-1].frame_number} "
                    f"({current_proc.last_observed_msg}) before Registration Accept/Reject."
                )
                current_proc.observations.append("Registration procedure incomplete.")
            procedures.append(current_proc)

        return procedures
