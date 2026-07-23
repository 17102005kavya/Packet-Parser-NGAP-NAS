"""
Rule-Based Diagnostic Engine for NGAP / NAS Wireshark Diagnostic Analyzer.
Evaluates higher-level protocol rules, cross-procedure correlations, and interface-wide observations.
"""

from typing import List
from .models import (
    UEContext,
    Procedure,
    ProcedureStatus,
    DiagnosticObservation,
    ProtocolEvent
)
from .procedure_engine.nas_cause_classifier import is_benign_nas_cause


class DiagnosticEngine:
    """
    Applies deterministic diagnostic rules to analyzed UE contexts and global events.
    """

    def evaluate(self, ue_contexts: List[UEContext], global_procs: List[Procedure], global_events: List[ProtocolEvent]) -> List[DiagnosticObservation]:
        observations: List[DiagnosticObservation] = []

        # Check Global Interface Reset / Transport Interruptions
        reset_events = [e for e in global_events if e.message_type in ["NG Reset", "SCTP Abort", "SCTP Shutdown"]]
        if reset_events:
            incomplete_ue_count = sum(1 for ue in ue_contexts if any(p.status == ProcedureStatus.INCOMPLETE for p in ue.procedures))
            obs = DiagnosticObservation(
                rule_id="RULE_GLOBAL_01",
                title="Interface-Wide Transport Interruption",
                severity="WARNING" if incomplete_ue_count > 0 else "INFO",
                description="NG Reset or SCTP transport reset observed on N2 interface.",
                evidence=[f"{e.message_type} observed in frame {e.frame_number}" for e in reset_events],
                related_frames=[e.frame_number for e in reset_events]
            )
            observations.append(obs)

        # Process per-UE diagnostic rules
        for ue in ue_contexts:
            self._evaluate_ue_rules(ue)

        return observations

    def _evaluate_ue_rules(self, ue: UEContext):
        # A procedure counts as a genuine auth failure only if it is FAILED
        # AND the cause is not a benign NAS cause (e.g. synch-failure resync).
        # After Finding 1 is applied, synch-failures are already COMPLETED,
        # so this check is defence-in-depth for any future code path changes.
        def _is_genuine_auth_failure(p: Procedure) -> bool:
            if p.name != "Authentication" or p.status != ProcedureStatus.FAILED:
                return False
            # If the failure_cause is a known-benign NAS cause, don't count it.
            if p.failure_cause and is_benign_nas_cause(p.failure_cause):
                return False
            return True

        auth_failed = any(_is_genuine_auth_failure(p) for p in ue.procedures)
        sec_failed = any(p.name == "Security Mode" and p.status == ProcedureStatus.FAILED for p in ue.procedures)
        reg_failed = any(p.name == "Registration" and p.status == ProcedureStatus.FAILED for p in ue.procedures)
        ctx_released = any(p.name == "UE Context Release" for p in ue.procedures)

        # Rule: Authentication Failure caused Registration termination
        if auth_failed and (reg_failed or ctx_released):
            obs_msg = "Authentication Failure caused Registration termination."
            if obs_msg not in ue.observations:
                ue.observations.append(obs_msg)

        # Rule: Security Mode Reject caused Registration termination
        if sec_failed and (reg_failed or ctx_released):
            obs_msg = "Security Mode Failure caused Registration termination."
            if obs_msg not in ue.observations:
                ue.observations.append(obs_msg)

        # Rule: Incomplete procedure with no explicit failure
        incomplete_procs = [p for p in ue.procedures if p.status == ProcedureStatus.INCOMPLETE]
        if incomplete_procs and not ue.explicit_failures:
            obs_msg = "Insufficient evidence to classify outcome."
            if obs_msg not in ue.observations:
                ue.observations.append(obs_msg)

        # Rule: Successful UE - no anomalies
        if not ue.explicit_failures and not incomplete_procs:
            if "NG Setup completed successfully." not in ue.observations:
                ue.observations.append("NG Setup completed successfully.")
            if "Identifier continuity maintained." not in ue.observations:
                ue.observations.append("Identifier continuity maintained.")
            if "No protocol anomalies detected." not in ue.observations:
                ue.observations.append("No protocol anomalies detected.")
