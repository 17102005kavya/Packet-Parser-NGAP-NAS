"""
PDU Session Procedure Analyzer.

Tracks two distinct procedure layers per PDU session ID — they are independent
signalling flows and must never share tracking state:

NAS-layer (TS 24.501 §6.4.1):
  PDU Session Establishment Request  ->  Establishment Accept / Reject

NGAP-layer (TS 38.413 §8.2.2 / §8.2.4):
  PDU Session Resource Setup Request ->  Resource Setup Response / Unsuccessful
  PDU Session Resource Release Command -> Resource Release Response

Design: keyed by (pdu_session_id, layer_tag) so that a NAS Accept clearing
entry ("nas", 5) never makes ("ngap", 5) invisible — which was Bug B.
Starting a Resource Setup Request while a NAS Request is still open no longer
overwrites the NAS entry — which was Bug A.
"""

import logging
from typing import List, Dict, Tuple, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)

# Composite key: (pdu_session_id, layer)
_Key = Tuple[int, str]

# Cause substrings that indicate a PDU Session Release was triggered for a
# normal/expected reason rather than a network error.  This mirrors the
# 3GPP-based set used by ue_context_analyzer.NORMAL_RELEASE_CAUSE_SUBSTRINGS.
# The values below are the benign/expected cause names from TS 38.413
# CauseRadioNetwork / CauseNas and are matched as substrings after stripping
# the parser's prefix.
NORMAL_RELEASE_CAUSE_SUBSTRINGS = {
    "normal-release",
    "user-inactivity",
    "release-due-to-ngran-generated-reason",
    "release-due-to-5gc-generated-reason",
    "successful-handover",
    "ue-context-transfer",
    "deregister",
    "ng-intra-system-handover-triggered",
    "ng-inter-system-handover-triggered",
    "xn-handover-triggered",
    "redirection",
    "ims-voice-eps-fallback-or-rat-fallback-triggered",
    # transport / protocol / misc — none are benign; not listed here so they
    # fall through to "abnormal" by default.
}


def _is_normal_release(raw_cause: Optional[str]) -> bool:
    """
    True if *raw_cause* is a benign PDU Session Release cause.

    Cause IE is carried on the Release Command and is mandatory per
    TS 38.413 §9.2.2.7.  An absent cause likely indicates a parsing gap —
    default to abnormal (False) so it surfaces for investigation.
    """
    if not raw_cause:
        logger.warning(
            "PDU Session Release has no cause_code — Cause IE is mandatory "
            "per TS 38.413 §9.2.2.7.  Possible parsing gap; defaulting to ABNORMAL."
        )
        return False
    value = raw_cause.split(":", 1)[-1].strip().lower()
    return any(marker in value for marker in NORMAL_RELEASE_CAUSE_SUBSTRINGS)


class PDUSessionAnalyzer:
    """
    Analyzes PDU Session Establishment and Release procedures for a UE context.

    Tracking state
    --------------
    _nas_active   : Dict[_Key, Procedure]
        Open NAS-layer Establishment procedures, keyed by (pdu_id, "nas").

    _ngap_active  : Dict[_Key, Procedure]
        Open NGAP-layer Resource Setup procedures, keyed by (pdu_id, "ngap").

    _release_open : Dict[_Key, Procedure]
        Open PDU Session Release procedures, keyed by (pdu_id, "release").

    Each dict is independent — accepting/rejecting one layer never removes
    entries from another layer's dict.
    """

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []
        nas_active:     Dict[_Key, Procedure] = {}
        ngap_active:    Dict[_Key, Procedure] = {}
        release_open:   Dict[_Key, Procedure] = {}

        for event in events:
            msg    = event.message_type
            pdu_id = event.pdu_session_id or 1

            # ------------------------------------------------------------------
            # NAS layer — Establishment (TS 24.501 §6.4.1)
            # ------------------------------------------------------------------
            if msg == "PDU Session Establishment Request":
                key = (pdu_id, "nas")
                if key in nas_active:
                    # Starter arrived while one is already open — flush old one
                    # as INCOMPLETE rather than silently overwriting it.
                    old = nas_active.pop(key)
                    old.observations.append(
                        "New PDU Session Establishment Request arrived before "
                        "previous one resolved — flushing as incomplete."
                    )
                    procedures.append(old)

                nas_active[key] = Procedure(
                    name=f"PDU Session Establishment/NAS (ID: {pdu_id})",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="PDU Session Establishment Accept / Reject",
                )

            elif msg == "PDU Session Establishment Accept":
                key  = (pdu_id, "nas")
                proc = nas_active.pop(key, None)
                if proc is not None:
                    proc.events.append(event)
                    proc.last_observed_msg = msg
                    proc.end_time          = event.timestamp
                    proc.status            = ProcedureStatus.COMPLETED
                    proc.expected_next_msg = None
                    proc.observations.append("NAS PDU Session Establishment Accepted")
                    procedures.append(proc)
                else:
                    logger.debug(
                        "PDU Session Establishment Accept (pdu_id=%d, frame %d) "
                        "has no matching open NAS procedure.", pdu_id, event.frame_number
                    )

            elif msg == "PDU Session Establishment Reject":
                key  = (pdu_id, "nas")
                proc = nas_active.pop(key, None)
                if proc is not None:
                    proc.events.append(event)
                    proc.last_observed_msg = msg
                    proc.end_time          = event.timestamp
                    proc.status            = ProcedureStatus.FAILED
                    proc.expected_next_msg = None
                    cause = event.cause_code or "PDU Session Establishment Reject"
                    proc.failure_cause = cause
                    proc.evidence.append(
                        f"PDU Session Establishment Reject in frame "
                        f"{event.frame_number} with cause: {cause}"
                    )
                    proc.observations.append(f"NAS PDU Session Failed: {cause}")
                    procedures.append(proc)
                else:
                    logger.debug(
                        "PDU Session Establishment Reject (pdu_id=%d, frame %d) "
                        "has no matching open NAS procedure.", pdu_id, event.frame_number
                    )

            # ------------------------------------------------------------------
            # NGAP layer — Resource Setup (TS 38.413 §8.2.2)
            # ------------------------------------------------------------------
            elif msg == "PDU Session Resource Setup Request":
                key = (pdu_id, "ngap")
                if key in ngap_active:
                    old = ngap_active.pop(key)
                    old.observations.append(
                        "New PDU Session Resource Setup Request arrived before "
                        "previous one resolved — flushing as incomplete."
                    )
                    procedures.append(old)

                ngap_active[key] = Procedure(
                    name=f"PDU Session Resource Setup/NGAP (ID: {pdu_id})",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="PDU Session Resource Setup Response / Unsuccessful",
                )

            elif msg == "PDU Session Resource Setup Response":
                key  = (pdu_id, "ngap")
                proc = ngap_active.pop(key, None)
                if proc is not None:
                    proc.events.append(event)
                    proc.last_observed_msg = msg
                    proc.end_time          = event.timestamp
                    proc.status            = ProcedureStatus.COMPLETED
                    proc.expected_next_msg = None
                    proc.observations.append("NGAP PDU Session Resource Setup succeeded")
                    procedures.append(proc)
                else:
                    logger.debug(
                        "PDU Session Resource Setup Response (pdu_id=%d, frame %d) "
                        "has no matching open NGAP procedure.", pdu_id, event.frame_number
                    )

            elif msg == "PDU Session Resource Setup Unsuccessful":
                key  = (pdu_id, "ngap")
                proc = ngap_active.pop(key, None)
                if proc is None:
                    # Bug B scenario: NGAP failure arrived after the NAS Accept
                    # already closed its entry.  Create a standalone failure record
                    # so it is NEVER silently dropped.
                    proc = Procedure(
                        name=f"PDU Session Resource Setup/NGAP (ID: {pdu_id})",
                        status=ProcedureStatus.INCOMPLETE,
                        start_time=event.timestamp,
                        events=[],
                        last_observed_msg="(no preceding NGAP Setup Request seen)",
                        expected_next_msg=None,
                    )
                    proc.observations.append(
                        f"NGAP Resource Setup Unsuccessful arrived in frame "
                        f"{event.frame_number} without a preceding Resource Setup Request "
                        f"in this capture window."
                    )

                proc.events.append(event)
                proc.last_observed_msg = msg
                proc.end_time          = event.timestamp
                proc.status            = ProcedureStatus.FAILED
                proc.expected_next_msg = None
                cause = event.cause_code or "PDU Session Resource Setup Unsuccessful"
                proc.failure_cause = cause
                proc.evidence.append(
                    f"PDU Session Resource Setup Unsuccessful in frame "
                    f"{event.frame_number} with cause: {cause}"
                )
                proc.observations.append(f"NGAP PDU Session Resource Setup Failed: {cause}")
                procedures.append(proc)

            # ------------------------------------------------------------------
            # NGAP layer — Resource Release (TS 38.413 §8.2.4)
            # ------------------------------------------------------------------
            elif msg == "PDU Session Resource Release Command":
                key = (pdu_id, "release")
                if key in release_open:
                    old = release_open.pop(key)
                    old.observations.append(
                        "New Release Command arrived before previous release completed "
                        "— flushing as incomplete."
                    )
                    procedures.append(old)

                proc = Procedure(
                    name=f"PDU Session Release (ID: {pdu_id})",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="PDU Session Resource Release Response",
                    failure_cause=event.cause_code or None,
                )
                release_open[key] = proc

            elif msg == "PDU Session Resource Release Response":
                key   = (pdu_id, "release")
                rproc = release_open.pop(key, None)
                if rproc is not None:
                    rproc.events.append(event)
                    rproc.last_observed_msg = msg
                    rproc.end_time          = event.timestamp
                    rproc.expected_next_msg = None
                    raw_cause = rproc.failure_cause  # set from the Command

                    if _is_normal_release(raw_cause):
                        rproc.status       = ProcedureStatus.COMPLETED
                        rproc.failure_cause = None
                        rproc.observations.append(
                            f"PDU Session released normally ({raw_cause or 'no cause'})"
                        )
                    else:
                        rproc.status = ProcedureStatus.FAILED
                        rproc.evidence.append(
                            f"PDU Session Release triggered by abnormal cause "
                            f"'{raw_cause}' (Release Response in frame {event.frame_number})"
                        )
                        rproc.observations.append(
                            f"PDU Session Release — abnormal cause: {raw_cause}"
                        )
                    procedures.append(rproc)
                else:
                    logger.debug(
                        "PDU Session Resource Release Response (pdu_id=%d, frame %d) "
                        "has no matching open Release procedure.", pdu_id, event.frame_number
                    )

            elif msg == "SCTP Abort":
                cause = event.cause_code or "SCTP Abort"
                for k, proc in list(nas_active.items()):
                    proc.events.append(event)
                    proc.status = ProcedureStatus.FAILED
                    proc.end_time = event.timestamp
                    proc.failure_cause = cause
                    proc.evidence.append(f"SCTP Abort in frame {event.frame_number} with cause: {cause}")
                    proc.observations.append(f"NAS PDU Session Establishment aborted due to SCTP Abort: {cause}")
                    procedures.append(proc)
                nas_active.clear()

                for k, proc in list(ngap_active.items()):
                    proc.events.append(event)
                    proc.status = ProcedureStatus.FAILED
                    proc.end_time = event.timestamp
                    proc.failure_cause = cause
                    proc.evidence.append(f"SCTP Abort in frame {event.frame_number} with cause: {cause}")
                    proc.observations.append(f"NGAP PDU Session Resource Setup aborted due to SCTP Abort: {cause}")
                    procedures.append(proc)
                ngap_active.clear()

                for k, proc in list(release_open.items()):
                    proc.events.append(event)
                    proc.status = ProcedureStatus.FAILED
                    proc.end_time = event.timestamp
                    proc.failure_cause = cause
                    proc.evidence.append(f"SCTP Abort in frame {event.frame_number} with cause: {cause}")
                    proc.observations.append(f"PDU Session Release aborted due to SCTP Abort: {cause}")
                    procedures.append(proc)
                release_open.clear()

        # ------------------------------------------------------------------
        # Flush anything still open at end of capture
        # ------------------------------------------------------------------
        for proc in nas_active.values():
            proc.evidence.append(
                f"Capture ended after frame {proc.events[-1].frame_number} "
                f"without NAS PDU Session response."
            )
            proc.observations.append("NAS PDU Session Establishment incomplete.")
            procedures.append(proc)

        for proc in ngap_active.values():
            proc.evidence.append(
                f"Capture ended after frame {proc.events[-1].frame_number} "
                f"without NGAP PDU Session Resource Setup response."
            )
            proc.observations.append("NGAP PDU Session Resource Setup incomplete.")
            procedures.append(proc)

        for rproc in release_open.values():
            rproc.observations.append("PDU Session Release incomplete (no Response).")
            procedures.append(rproc)

        return procedures

