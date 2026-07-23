"""
NG Setup Procedure Analyzer.

Implements the NG Setup procedure per TS 38.413 §8.7.1:

  Initiating message:   NG SETUP REQUEST        (gNB → AMF)
  Successful outcome:   NG SETUP RESPONSE        (AMF → gNB)
  Unsuccessful outcome: NG SETUP FAILURE         (AMF → gNB)

Key spec behaviours modelled here
----------------------------------
1. TimeToWait IE (TS 38.413 §9.3.1.68 / §8.7.1.3):
   If the AMF includes the TimeToWait IE in an NG Setup Failure, the gNB
   SHALL wait at least that duration before retrying.  A Failure that carries
   TimeToWait is classified as "retryable" (congestion / overload); one
   without TimeToWait is "hard" (misconfiguration, unrecognised PLMN, etc.).

2. Cause category (TS 38.413 §9.3.1.2):
   The Cause IE is mandatory in NG Setup Failure.  Its top-level choice is:
     radioNetwork | transport | nas | protocol | misc
   The category is parsed from the raw cause string and recorded separately
   so the report surface shows which layer the AMF blames.

3. Retry linkage:
   When a capture contains Failure → (wait) → Request → Response, the retry
   Request is appended to the *same* procedure object (observations note it
   as a retry) rather than opening a new independent procedure.  This keeps
   the full NG Setup attempt history in one procedure entry.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


# TS 38.413 §9.3.1.2 — top-level Cause IE choice alternatives.
# The raw cause string from tshark looks like:
#   "NGAP cause (misc): unspecified (6)"
#   "NGAP cause (radioNetwork): unknown-PLMN-or-SNPN (0)"
_CAUSE_CATEGORIES = (
    "radioNetwork",
    "transport",
    "nas",
    "protocol",
    "misc",
)

# Cause values that indicate a hard (non-retryable) failure regardless of
# whether TimeToWait is present.  These represent fundamental configuration
# errors that will not resolve by waiting.
#
# TS 38.413 Table 9.3.1.2-1 / Table 9.3.1.2-2:
_HARD_FAILURE_SUBSTRINGS = {
    "unknown-plmn",          # radioNetwork — wrong PLMN configured
    "unknown-plmn-or-snpn",  # radioNetwork — Rel-16+ variant
    "not-supported",         # misc — capability mismatch
    "unrecognised-message",  # protocol
    "missing-ie",            # protocol
}


def _parse_cause_category(raw_cause: Optional[str]) -> Optional[str]:
    """
    Extract the NGAP Cause category from a raw tshark cause string.

    E.g. "NGAP cause (misc): unspecified (6)"  →  "misc"
         "NGAP cause (radioNetwork): ..."       →  "radioNetwork"
    Returns None if the category cannot be determined.
    """
    if not raw_cause:
        return None
    lower = raw_cause.lower()
    for cat in _CAUSE_CATEGORIES:
        if cat.lower() in lower:
            return cat
    return None


def _is_hard_failure(raw_cause: Optional[str]) -> bool:
    """
    True when the cause value indicates a configuration error that won't be
    resolved by waiting and retrying (as opposed to transient congestion).
    """
    if not raw_cause:
        return False
    lower = raw_cause.lower()
    return any(marker in lower for marker in _HARD_FAILURE_SUBSTRINGS)


def _extract_time_to_wait(event: ProtocolEvent) -> Optional[str]:
    """
    Return the TimeToWait value if present in the event's cause or
    in any field tshark surfaces as 'timeToWait'.

    In real tshark JSON the field is ngap.timeToWait.  The ProtocolEvent
    model doesn't have a dedicated field for it yet, so we probe the
    cause_code string for the pattern tshark uses when it folds the IE
    value into the cause display string (tshark >= 3.6 sometimes does this).
    This is a best-effort extraction; the absence of a value here does NOT
    mean the IE was absent in the PDU.
    """
    if event.cause_code and "timetowait" in event.cause_code.lower():
        # tshark occasionally emits combined strings; surface what we see
        return event.cause_code
    # Extend here if ProtocolEvent gains a dedicated time_to_wait field
    return None


class NGSetupAnalyzer:
    """
    Analyzes global interface-level NG Setup procedures per TS 38.413 §8.7.1.

    State machine
    -------------
    IDLE          → NG Setup Request received → PENDING
    PENDING       → NG Setup Response         → COMPLETED  (emit procedure)
    PENDING       → NG Setup Failure
                      with TimeToWait         → RETRYABLE  (stay open, note TTW)
                      without TimeToWait /
                      hard-failure cause      → FAILED      (emit procedure)
    RETRYABLE     → NG Setup Request          → PENDING    (append retry event)
    RETRYABLE     → end-of-capture            → INCOMPLETE (emit with TTW note)
    """

    def analyze(self, global_events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        current_proc: Optional[Procedure] = None
        awaiting_retry: bool = False
        retry_count: int = 0

        for event in global_events:
            msg = event.message_type

            # ------------------------------------------------------------------
            # NG Setup Request — initiating message (TS 38.413 §8.7.1.2)
            # ------------------------------------------------------------------
            if msg == "NG Setup Request":
                is_fresh = getattr(event, 'is_fresh', False)
                if current_proc is not None and awaiting_retry and not is_fresh:
                    # This Request is the retry after a retryable Failure.
                    # Append it to the existing procedure; stay open (PENDING).
                    current_proc.events.append(event)
                    current_proc.last_observed_msg = msg
                    current_proc.status = ProcedureStatus.INCOMPLETE
                    current_proc.expected_next_msg = "NG Setup Response / Failure"
                    retry_count += 1
                    current_proc.observations.append(
                        f"NG Setup retried in frame {event.frame_number} "
                        f"after AMF-indicated TimeToWait (attempt #{retry_count + 1})."
                    )
                    awaiting_retry = False

                elif current_proc is not None:
                    # A new Request while one is still pending or superseded during retry window.
                    # Flush the old one as INCOMPLETE.
                    current_proc.evidence.append(
                        f"New NG Setup Request in frame {event.frame_number} "
                        f"arrived before previous one resolved — flushing as incomplete."
                    )
                    current_proc.observations.append(
                        "NG Setup incomplete (superseded by a new Request)."
                    )
                    procedures.append(current_proc)
                    current_proc = None
                    awaiting_retry = False
                    retry_count = 0

                    current_proc = Procedure(
                        name="NG Setup",
                        status=ProcedureStatus.INCOMPLETE,
                        start_time=event.timestamp,
                        events=[event],
                        last_observed_msg=msg,
                        expected_next_msg="NG Setup Response / Failure",
                    )

                else:
                    retry_count = 0
                    current_proc = Procedure(
                        name="NG Setup",
                        status=ProcedureStatus.INCOMPLETE,
                        start_time=event.timestamp,
                        events=[event],
                        last_observed_msg=msg,
                        expected_next_msg="NG Setup Response / Failure",
                    )

            # ------------------------------------------------------------------
            # NG Setup Response — successful outcome (TS 38.413 §8.7.1.3)
            # ------------------------------------------------------------------
            elif msg == "NG Setup Response":
                if current_proc is not None:
                    current_proc.events.append(event)
                    current_proc.last_observed_msg = msg
                    current_proc.end_time = event.timestamp
                    current_proc.status = ProcedureStatus.COMPLETED
                    current_proc.expected_next_msg = None
                    retry_note = " (after retry)" if any(
                        "retried" in o for o in current_proc.observations
                    ) else ""
                    current_proc.observations.append(
                        f"NG Setup completed successfully{retry_note}."
                    )
                    procedures.append(current_proc)
                    current_proc = None
                    awaiting_retry = False
                    retry_count = 0
                else:
                    logger.debug(
                        "NG Setup Response in frame %d with no open procedure.",
                        event.frame_number,
                    )

            # ------------------------------------------------------------------
            # NG Setup Failure — unsuccessful outcome (TS 38.413 §8.7.1.3)
            # ------------------------------------------------------------------
            elif msg == "NG Setup Failure":
                if current_proc is not None:
                    current_proc.events.append(event)
                    current_proc.last_observed_msg = msg
                    current_proc.end_time = event.timestamp
                    current_proc.expected_next_msg = None

                    raw_cause = event.cause_code or "Cause IE absent or unparsed"
                    cause_cat = _parse_cause_category(raw_cause)
                    hard = _is_hard_failure(raw_cause)
                    ttw = _extract_time_to_wait(event)

                    current_proc.failure_cause = raw_cause
                    current_proc.evidence.append(
                        f"NG Setup Failure in frame {event.frame_number}: "
                        f"cause={raw_cause!r}"
                        + (f", category={cause_cat}" if cause_cat else "")
                        + (f", TimeToWait={ttw!r}" if ttw else "")
                    )

                    MAX_NG_SETUP_RETRIES = 3
                    if ttw and not hard:
                        if retry_count >= MAX_NG_SETUP_RETRIES:
                            # Retry limit exhausted -> terminal FAILED
                            current_proc.status = ProcedureStatus.FAILED
                            current_proc.failure_cause = f"NG Setup retry limit ({MAX_NG_SETUP_RETRIES}) exhausted"
                            current_proc.observations.append(
                                f"NG Setup retry limit ({MAX_NG_SETUP_RETRIES}) exhausted after repeated failures with TimeToWait."
                            )
                            procedures.append(current_proc)
                            current_proc = None
                            awaiting_retry = False
                            retry_count = 0
                        else:
                            # RETRYABLE — AMF asked gNB to wait and retry.
                            # Keep the procedure open in INCOMPLETE state.
                            awaiting_retry = True
                            current_proc.status = ProcedureStatus.INCOMPLETE
                            current_proc.expected_next_msg = "NG Setup Request (retry after TimeToWait)"
                            current_proc.observations.append(
                                f"NG Setup rejected by AMF with TimeToWait={ttw!r} "
                                f"(cause: {raw_cause}, category: {cause_cat or 'unknown'}) — "
                                f"retryable; awaiting gNB retry Request."
                            )
                    else:
                        # HARD FAILURE or Failure with no TimeToWait.
                        current_proc.status = ProcedureStatus.FAILED
                        failure_kind = "hard failure" if hard else "non-retryable failure"
                        current_proc.name = (
                            f"NG Setup ({cause_cat or 'unknown'} failure)"
                        )
                        current_proc.observations.append(
                            f"NG Setup {failure_kind}: {raw_cause}"
                            + (f" [category: {cause_cat}]" if cause_cat else "")
                            + (" — no TimeToWait IE; gNB should not auto-retry." if not ttw else "")
                        )
                        procedures.append(current_proc)
                        current_proc = None
                        awaiting_retry = False
                        retry_count = 0
                else:
                    logger.debug(
                        "NG Setup Failure in frame %d with no open procedure.",
                        event.frame_number,
                    )

            elif msg == "SCTP Abort":
                if current_proc is not None:
                    current_proc.events.append(event)
                    current_proc.status = ProcedureStatus.FAILED
                    current_proc.end_time = event.timestamp
                    cause = event.cause_code or "SCTP Abort"
                    current_proc.failure_cause = cause
                    current_proc.evidence.append(f"SCTP Abort in frame {event.frame_number} with cause: {cause}")
                    current_proc.observations.append(f"NG Setup aborted due to SCTP Abort: {cause}")
                    procedures.append(current_proc)
                    current_proc = None
                    awaiting_retry = False
                    retry_count = 0

        # ------------------------------------------------------------------
        # Flush anything still open at end of capture
        # ------------------------------------------------------------------
        if current_proc is not None:
            if awaiting_retry:
                current_proc.observations.append(
                    "NG Setup capture ended while awaiting gNB retry "
                    "(AMF returned TimeToWait but no retry Request seen)."
                )
            else:
                current_proc.evidence.append(
                    f"Capture ended after frame {current_proc.events[-1].frame_number} "
                    f"without NG Setup response."
                )
                current_proc.observations.append("NG Setup incomplete.")
            procedures.append(current_proc)

        return procedures

