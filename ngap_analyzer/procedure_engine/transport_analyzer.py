"""
Transport Analyzer for SCTP association lifecycle and NG Reset procedures.

SCTP classification:
  - Init:     normal association startup -> COMPLETED
  - Shutdown: graceful teardown          -> COMPLETED
  - Abort:    abrupt teardown            -> FAILED

NG Reset is a Request/Acknowledge pair (TS 38.413 §8.7.4.2):
  - Reset + Acknowledge -> COMPLETED
  - Reset alone         -> INCOMPLETE
"""

from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus


class TransportAnalyzer:
    """
    Analyzes SCTP transport layer events and NG Reset procedures.
    """

    def analyze(self, global_events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        pending_reset: Optional[Procedure] = None

        for event in global_events:
            msg = event.message_type

            # --- NG Reset pairing (TS 38.413 §8.7.4) ---
            if msg == "NG Reset":
                if pending_reset is not None:
                    # Previous reset never got an Acknowledge
                    pending_reset.observations.append(
                        "NG Reset without Acknowledge before next Reset"
                    )
                    procedures.append(pending_reset)

                pending_reset = Procedure(
                    name="NG Reset",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="NG Reset Acknowledge",
                    failure_cause=event.cause_code,
                    evidence=[f"NG Reset observed in frame {event.frame_number}"],
                    observations=[f"NG Reset initiated in frame {event.frame_number}"],
                )

            elif msg == "NG Reset Acknowledge":
                if pending_reset is not None:
                    pending_reset.events.append(event)
                    pending_reset.status = ProcedureStatus.COMPLETED
                    pending_reset.end_time = event.timestamp
                    pending_reset.last_observed_msg = msg
                    pending_reset.expected_next_msg = None
                    pending_reset.observations.append(
                        f"NG Reset acknowledged in frame {event.frame_number}"
                    )
                    procedures.append(pending_reset)
                    pending_reset = None
                else:
                    # Orphaned acknowledge (no preceding Reset in this capture)
                    proc = Procedure(
                        name="NG Reset (orphaned Acknowledge)",
                        status=ProcedureStatus.COMPLETED,
                        start_time=event.timestamp,
                        end_time=event.timestamp,
                        events=[event],
                        last_observed_msg=msg,
                        evidence=[f"NG Reset Acknowledge in frame {event.frame_number} without preceding NG Reset"],
                    )
                    procedures.append(proc)

            # --- SCTP events ---
            elif "SCTP" in msg:
                if msg == "SCTP Abort":
                    status = ProcedureStatus.FAILED
                    cause = event.cause_code
                else:
                    # SCTP Init = normal startup, SCTP Shutdown = graceful teardown
                    status = ProcedureStatus.COMPLETED
                    cause = None

                proc = Procedure(
                    name=f"Transport Event: {msg}",
                    status=status,
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    failure_cause=cause,
                    evidence=[f"{msg} observed in frame {event.frame_number}"],
                    observations=[f"Transport layer event {msg} in frame {event.frame_number}"],
                )
                procedures.append(proc)

        # Flush any pending reset at end of capture
        if pending_reset is not None:
            pending_reset.observations.append(
                "NG Reset without Acknowledge (capture ended)"
            )
            procedures.append(pending_reset)

        return procedures
