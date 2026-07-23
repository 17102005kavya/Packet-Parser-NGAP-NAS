"""
UE Context Analyzer.
Tracks Initial Context Setup & Context Release procedures for a UE context.
"""

import logging
from typing import List, Optional
from ..models import ProtocolEvent, Procedure, ProcedureStatus

logger = logging.getLogger(__name__)


class UEContextAnalyzer:
    """
    Analyzes UE Context Setup and UE Context Release lifecycle events.
    """

    # PROVISIONAL - not yet validated against real capture data.
    # These substrings are based on 3GPP TS 38.413 CauseRadioNetwork /
    # CauseNas enum names for benign release reasons. Validate against
    # actual `ngap.cause*` field values from tshark JSON output (e.g.
    # `tshark -r your.pcap -Y "ngap.procedureCode == 41" -T json`) and
    # adjust before relying on this in production triage.
    #
    # Matched as substrings against the lowercased raw cause value,
    # after stripping the "NGAP cause: " / "5GMM/5GSM cause: " prefix
    # that PacketParser._extract_cause() always adds.
    # Cause values classified as benign/expected release reasons.
    # Deliberately organized by NGAP cause category.
    #
    # radioNetwork category (TS 38.413 §9.3.1.2):
    NORMAL_RELEASE_CAUSE_SUBSTRINGS = {
        "normal-release",
        "user-inactivity",
        "release-due-to-ngran-generated-reason",
        "release-due-to-5gc-generated-reason",
        "successful-handover",
        "ue-context-transfer",
        # nas category (TS 38.413 §9.3.1.2):
        "deregister",
        # transport category — none are benign (resource-unavailable etc. = real problem)
        # protocol category — none are benign (all indicate protocol violations)
        # misc category — none are benign (hardware-failure etc. = real problem)
    }

    # Messages relevant to the Initial Context Setup procedure.
    # Only these will be folded into the setup procedure's event list.
    _SETUP_RELEVANT_MSGS = {
        "Initial Context Setup Request",
        "Initial Context Setup Response",
        "Initial Context Setup Failure",
    }

    def analyze(self, events: List[ProtocolEvent]) -> List[Procedure]:
        procedures: List[Procedure] = []

        # Track Initial Context Setup
        ctx_setup_proc: Optional[Procedure] = None
        for event in events:
            msg = event.message_type

            if msg == "Initial Context Setup Request":
                if ctx_setup_proc is not None and ctx_setup_proc.status == ProcedureStatus.INCOMPLETE:
                    # Previous setup never completed — flush as incomplete
                    ctx_setup_proc.observations.append("Initial Context Setup Incomplete (superseded)")
                    procedures.append(ctx_setup_proc)

                ctx_setup_proc = Procedure(
                    name="Initial Context Setup",
                    status=ProcedureStatus.INCOMPLETE,
                    start_time=event.timestamp,
                    events=[event],
                    last_observed_msg=msg,
                    expected_next_msg="Initial Context Setup Response / Failure"
                )

            elif ctx_setup_proc is not None and msg in self._SETUP_RELEVANT_MSGS:
                ctx_setup_proc.events.append(event)
                ctx_setup_proc.last_observed_msg = msg

                if msg == "Initial Context Setup Response":
                    ctx_setup_proc.status = ProcedureStatus.COMPLETED
                    ctx_setup_proc.end_time = event.timestamp
                    ctx_setup_proc.expected_next_msg = None
                    ctx_setup_proc.observations.append("Initial Context Setup Completed")
                    procedures.append(ctx_setup_proc)
                    ctx_setup_proc = None

                elif msg == "Initial Context Setup Failure":
                    ctx_setup_proc.status = ProcedureStatus.FAILED
                    ctx_setup_proc.end_time = event.timestamp
                    ctx_setup_proc.expected_next_msg = None
                    cause = event.cause_code or "Initial Context Setup Failure"
                    ctx_setup_proc.failure_cause = cause
                    ctx_setup_proc.evidence.append(
                        f"Initial Context Setup Failure in frame {event.frame_number} with cause: {cause}"
                    )
                    procedures.append(ctx_setup_proc)
                    ctx_setup_proc = None

        if ctx_setup_proc is not None:
            ctx_setup_proc.observations.append("Initial Context Setup Incomplete")
            procedures.append(ctx_setup_proc)

        # Track Context Release
        #
        # NOTE: branching here is keyed purely on whether a release
        # procedure is already open (`ctx_release_proc is None`), NOT on
        # message type. This matters because a release can legitimately
        # be a two-step sequence - e.g. RAN sends
        # "UE Context Release Request", then AMF replies with
        # "UE Context Release Command" before the RAN finally sends
        # "UE Context Release Complete". If we branched on message type
        # (checking `msg in [...]` unconditionally), a second
        # Command/Request arriving after the procedure was already
        # opened would incorrectly fall into the "start new procedure"
        # branch's guard and be silently dropped - never appended to
        # `events`, never updating `last_observed_msg`, and potentially
        # discarding a more authoritative cause value carried on the
        # Command. Keying on "is a procedure already open" ensures every
        # event after the first Command/Request is correctly folded into
        # the same in-progress procedure.
        ctx_release_proc: Optional[Procedure] = None
        release_cause: Optional[str] = None

        for event in events:
            msg = event.message_type

            if ctx_release_proc is None:
                if msg in ["UE Context Release Command", "UE Context Release Request"]:
                    ctx_release_proc = Procedure(
                        name="UE Context Release",
                        status=ProcedureStatus.INCOMPLETE,
                        start_time=event.timestamp,
                        events=[event],
                        last_observed_msg=msg,
                        expected_next_msg="UE Context Release Complete"
                    )
                    # Capture the cause here - this is where NGAP actually
                    # carries it (AMF -> RAN Command, or RAN -> AMF Request).
                    if event.cause_code:
                        release_cause = event.cause_code
                continue

            # A release procedure is already open - every subsequent event
            # (including a later Command/Request in a Request -> Command ->
            # Complete sequence, or a retransmission) belongs to it.
            ctx_release_proc.events.append(event)
            ctx_release_proc.last_observed_msg = msg

            # Some captures also carry a cause on a later message (e.g. the
            # Command, or the Complete). First non-empty cause seen wins;
            # see accompanying discussion if you need Command-over-Request
            # priority instead of first-seen-wins.
            if event.cause_code and not release_cause:
                release_cause = event.cause_code

            if msg == "UE Context Release Complete":
                ctx_release_proc.end_time = event.timestamp
                ctx_release_proc.expected_next_msg = None

                cause = release_cause or "Normal Release"

                if self._is_normal_release(release_cause):
                    ctx_release_proc.status = ProcedureStatus.COMPLETED
                    ctx_release_proc.observations.append(
                        f"UE Context Released normally ({cause})"
                    )
                else:
                    # Signalling completed, but the *reason* for release
                    # was abnormal - flag it as an explicit failure so it
                    # surfaces in ue.explicit_failures downstream.
                    ctx_release_proc.status = ProcedureStatus.FAILED
                    ctx_release_proc.failure_cause = cause
                    ctx_release_proc.evidence.append(
                        f"UE Context Release triggered by abnormal cause "
                        f"'{cause}' (frame {event.frame_number})"
                    )
                    ctx_release_proc.observations.append(
                        f"UE Context Released due to error condition: {cause}"
                    )

                procedures.append(ctx_release_proc)
                ctx_release_proc = None
                release_cause = None

        if ctx_release_proc is not None:
            ctx_release_proc.observations.append("UE Context Release Incomplete")
            procedures.append(ctx_release_proc)

        return procedures

    def _is_normal_release(self, raw_cause: Optional[str]) -> bool:
        """
        Classifies a UE Context Release cause as normal (expected/benign)
        or abnormal (should be surfaced as an explicit failure).

        raw_cause is expected in the form produced by
        PacketParser._extract_cause(), e.g.
            "NGAP cause (radioNetwork): user-inactivity (20)"
            "NGAP cause (nas): deregister (2)"
            "5GMM/5GSM cause: some-value"

        If no cause was observed at all, we default to ABNORMAL since the
        Cause IE is mandatory in UE Context Release Command per
        TS 38.413 §9.2.2.4 — its absence likely indicates a parsing gap
        that should be surfaced rather than hidden.
        """
        if not raw_cause:
            logger.warning(
                "UE Context Release has no cause_code — Cause IE is mandatory "
                "per TS 38.413 §9.2.2.4. Possible parsing gap. "
                "Defaulting to ABNORMAL to surface for review."
            )
            return False

        value = raw_cause.split(":", 1)[-1].strip().lower()
        is_normal = any(
            marker in value for marker in self.NORMAL_RELEASE_CAUSE_SUBSTRINGS
        )

        logger.debug(
            f"Release cause classification: raw='{raw_cause}' -> "
            f"{'NORMAL' if is_normal else 'ABNORMAL'}"
        )
        return is_normal