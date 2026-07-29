"""
Security Mode Procedure Analyzer.
Reconstructs NAS Security Mode Command -> Security Mode Complete / Reject.
"""

from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus


class SecurityAnalyzer:
    """
    Analyzes Security Mode procedures for a UE context.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        current_proc: Optional[Procedure] = None

        for event in events:
            msg = event.message_type

            if msg == "Security Mode Command":
                is_retrans = getattr(event, 'is_retransmission', False)
                if current_proc is not None and current_proc.status == ProcedureStatus.INCOMPLETE:
                    if is_retrans:
                        current_proc.events.append(event)
                        current_proc.last_observed_msg = msg
                        current_proc.observations.append(
                            f"Security Mode Command retransmitted in frame {event.frame_number}."
                        )
                    else:
                        procedures.append(current_proc)
                        current_proc = Procedure(
                            name="Security Mode",
                            status=ProcedureStatus.INCOMPLETE,
                            start_time=event.timestamp,
                            events=[event],
                            last_observed_msg=msg,
                            expected_next_msg="Security Mode Complete"
                        )
                else:
                    current_proc = Procedure(
                        name="Security Mode",
                        status=ProcedureStatus.INCOMPLETE,
                        start_time=event.timestamp,
                        events=[event],
                        last_observed_msg=msg,
                        expected_next_msg="Security Mode Complete"
                    )

            elif current_proc is not None:
                current_proc.events.append(event)
                current_proc.last_observed_msg = msg

                if msg == "Security Mode Complete":
                    current_proc.status = ProcedureStatus.COMPLETED
                    current_proc.confidence = "DIRECT"
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    current_proc.observations.append("Security Completed")
                    procedures.append(current_proc)
                    current_proc = None

                elif msg == "Security Mode Reject":
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.confidence = "DIRECT"
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    cause = event.cause_code or "UE returned Security Mode Reject"
                    current_proc.failure_cause = cause
                    current_proc.evidence.append(
                        f"Security Mode Reject observed in frame {event.frame_number} with cause: {cause}"
                    )
                    current_proc.observations.append(f"Security Mode Failed: {cause}")
                    procedures.append(current_proc)
                    current_proc = None

                elif msg == "SCTP Abort":
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.confidence = "DIRECT"
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    cause = event.cause_code or "SCTP Abort"
                    current_proc.failure_cause = cause
                    current_proc.evidence.append(
                        f"SCTP Abort observed in frame {event.frame_number} with cause: {cause}"
                    )
                    current_proc.observations.append(f"Security Mode procedure aborted due to SCTP Abort: {cause}")
                    procedures.append(current_proc)
                    current_proc = None

        if current_proc is not None:
            if self._can_infer_completion(current_proc, events):
                current_proc.status = ProcedureStatus.COMPLETED
                current_proc.confidence = "INFERRED"
                current_proc.end_time = events[-1].timestamp
                current_proc.expected_next_msg = None
                current_proc.evidence.append(
                    "Security Mode completion inferred from subsequent Initial Context Setup / PDU Session establishment."
                )
                current_proc.observations.append(
                    "Security Completed (inferred from subsequent Context Setup / PDU Session establishment)."
                )
            else:
                current_proc.confidence = "PARTIAL"
                current_proc.evidence.append(
                    f"Capture ended after frame {current_proc.events[-1].frame_number} without Security Mode Complete."
                )
                current_proc.observations.append("Security Mode procedure incomplete.")
            procedures.append(current_proc)

        return procedures

    def _can_infer_completion(self, proc: Procedure, events: List[ProtocolEvent]) -> bool:
        """
        Infers Security Mode completion if explicit Security Mode Complete was not visible,
        but subsequent Initial Context Setup or PDU Session procedures progressed successfully.
        Never infers completion if Security Mode Reject or SCTP Abort occurred.
        """
        start_idx = 0
        if proc.events and proc.events[0] in events:
            start_idx = events.index(proc.events[0])

        proc_events = events[start_idx:]
        has_failure = False
        has_subsequent_activity = False

        for evt in proc_events:
            msg = evt.message_type
            if msg in ["Security Mode Reject", "Registration Reject", "Authentication Reject", "SCTP Abort"]:
                has_failure = True
                break

            if msg in [
                "Initial Context Setup Request",
                "Initial Context Setup Response",
                "PDU Session Establishment Accept",
                "PDU Session Resource Setup Request",
                "PDU Session Resource Setup Response"
            ]:
                has_subsequent_activity = True

        return (not has_failure) and has_subsequent_activity
