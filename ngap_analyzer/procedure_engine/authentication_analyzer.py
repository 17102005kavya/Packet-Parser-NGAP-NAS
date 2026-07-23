"""
Authentication Procedure Analyzer.
Reconstructs 5G Authentication Signalling: Authentication Request -> Authentication Response / Failure / Reject.

Per TS 24.501 §5.4.1.3.4 and TS 33.501 §6.1.3.4, an Authentication Failure
with cause #21 "synch failure" is not a resolved outcome — it is the start of
a retry sequence.  The procedure stays open, and the subsequent Authentication
Request from the AMF continues it.  Authentication is only truly complete when
a real Authentication Response arrives, or truly failed when a non-resync
Authentication Failure or Authentication Reject is received.
"""

from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus
from .nas_cause_classifier import is_synch_failure


class AuthenticationAnalyzer:
    """
    Analyzes Authentication procedures for a UE context.

    State machine
    -------------
    IDLE            no open procedure
    INCOMPLETE      Auth Request seen, waiting for response
    RESYNCING       synch-failure received; same procedure stays open,
                    waiting for the AMF's retry Auth Request

    Transitions
    -----------
    IDLE        + Auth Request                  -> INCOMPLETE (new proc)
    INCOMPLETE  + Auth Response                 -> COMPLETED  (close proc)
    INCOMPLETE  + Auth Reject                   -> FAILED     (close proc)
    INCOMPLETE  + Auth Failure(synch)           -> RESYNCING  (stay open)
    INCOMPLETE  + Auth Failure(non-synch)       -> FAILED     (close proc)
    RESYNCING   + Auth Request                  -> INCOMPLETE (same proc, retry)
    RESYNCING   + anything else                 -> as INCOMPLETE
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        current_proc: Optional[Procedure] = None
        # True while the open procedure is waiting for the AMF's retry
        # Auth Request after a synch-failure.
        awaiting_resync_retry: bool = False

        for event in events:
            msg = event.message_type

            if msg == "Authentication Request":
                if current_proc is None:
                    # Normal start — no open procedure.
                    current_proc = self._new_proc(event)
                    awaiting_resync_retry = False

                elif awaiting_resync_retry:
                    # This Auth Request is the AMF's retry after a
                    # synch-failure.  Continue the SAME procedure rather than
                    # starting a fresh one: append the event, update the
                    # state fields, and transition back to INCOMPLETE so the
                    # retry response is handled normally.
                    current_proc.events.append(event)
                    current_proc.last_observed_msg = msg
                    current_proc.expected_next_msg = "Authentication Response"
                    current_proc.status = ProcedureStatus.INCOMPLETE
                    current_proc.observations.append(
                        f"AMF retry Authentication Request received in frame "
                        f"{event.frame_number} — resync retry in progress."
                    )
                    awaiting_resync_retry = False

                else:
                    # A new Auth Request while a non-resync procedure is still
                    # open — the previous one was never completed.  Flush it as
                    # INCOMPLETE and start fresh.
                    procedures.append(current_proc)
                    current_proc = self._new_proc(event)
                    awaiting_resync_retry = False

            elif current_proc is not None:
                current_proc.events.append(event)
                current_proc.last_observed_msg = msg

                if msg == "Authentication Response":
                    current_proc.status = ProcedureStatus.COMPLETED
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    current_proc.observations.append("Authentication Successful")
                    procedures.append(current_proc)
                    current_proc = None
                    awaiting_resync_retry = False

                elif msg == "Authentication Reject":
                    # Authentication Reject (AMF -> UE) is always terminal.
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    cause = event.cause_code or "Authentication Reject"
                    current_proc.failure_cause = cause
                    current_proc.evidence.append(
                        f"Authentication Reject in frame {event.frame_number} with cause: {cause}"
                    )
                    current_proc.observations.append(f"Authentication Failed: {cause}")
                    procedures.append(current_proc)
                    current_proc = None
                    awaiting_resync_retry = False

                elif msg == "Authentication Failure":
                    cause = event.cause_code or ""
                    if is_synch_failure(cause):
                        # SQN resync — keep the procedure open.
                        # Do NOT close or mark COMPLETED: authentication has
                        # not succeeded.  Annotate and wait for the retry.
                        # Status stays INCOMPLETE until resolved.
                        current_proc.expected_next_msg = "Authentication Request (resync retry)"
                        current_proc.observations.append(
                            f"SQN resynchronisation triggered (synch failure in frame "
                            f"{event.frame_number}) — awaiting AMF retry Auth Request."
                        )
                        awaiting_resync_retry = True
                    else:
                        # Genuine auth failure (MAC failure, etc.)
                        current_proc.status = ProcedureStatus.FAILED
                        current_proc.end_time = event.timestamp
                        current_proc.expected_next_msg = None
                        current_proc.failure_cause = cause or "MAC failure / Authentication Failure"
                        current_proc.evidence.append(
                            f"Authentication Failure in frame {event.frame_number} with cause: {cause}"
                        )
                        current_proc.observations.append(f"Authentication Failed: {cause}")
                        procedures.append(current_proc)
                        current_proc = None
                        awaiting_resync_retry = False

                elif msg == "SCTP Abort":
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None
                    cause = event.cause_code or "SCTP Abort"
                    current_proc.failure_cause = cause
                    current_proc.evidence.append(
                        f"SCTP Abort observed in frame {event.frame_number} with cause: {cause}"
                    )
                    current_proc.observations.append(f"Authentication procedure aborted due to SCTP Abort: {cause}")
                    procedures.append(current_proc)
                    current_proc = None
                    awaiting_resync_retry = False

        # Flush any still-open procedure at end of capture.
        if current_proc is not None:
            current_proc.evidence.append(
                f"Capture ended after frame {current_proc.events[-1].frame_number} "
                f"without receiving Authentication Response."
            )
            if awaiting_resync_retry:
                current_proc.observations.append(
                    "Authentication procedure incomplete: capture ended during SQN resync "
                    "(synch failure observed, no retry Auth Request received)."
                )
            else:
                current_proc.observations.append("Authentication procedure incomplete.")
            procedures.append(current_proc)

        return procedures

    @staticmethod
    def _new_proc(event: ProtocolEvent) -> Procedure:
        return Procedure(
            name="Authentication",
            status=ProcedureStatus.INCOMPLETE,
            start_time=event.timestamp,
            events=[event],
            last_observed_msg=event.message_type,
            expected_next_msg="Authentication Response",
        )

