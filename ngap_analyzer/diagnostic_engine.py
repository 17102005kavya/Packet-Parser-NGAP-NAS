"""
Rule-Based Diagnostic Engine for NGAP / NAS Wireshark Diagnostic Analyzer.

Evaluates higher-level protocol rules, cross-procedure correlations, and interface-wide observations.
"""

from typing import List

from .models import (
    DiagnosticObservation,
    Procedure,
    ProcedureStatus,
    ProtocolEvent,
    UEContext,
)
from .procedure_engine.nas_cause_classifier import is_benign_nas_cause

# Rule Identifiers
RULE_GLOBAL_INTERFACE_INTERRUPTION: str = "RULE_GLOBAL_01"
RULE_GLOBAL_PAGING_STATS: str = "RULE_GLOBAL_PAGING"

# Diagnostic Severity Levels
SEVERITY_INFO: str = "INFO"
SEVERITY_WARNING: str = "WARNING"

# Procedure Names
PROC_AUTHENTICATION: str = "Authentication"
PROC_SECURITY_MODE: str = "Security Mode"
PROC_REGISTRATION: str = "Registration"
PROC_UE_CONTEXT_RELEASE: str = "UE Context Release"
PROC_SERVICE_REQUEST: str = "Service Request"
PROC_PAGING: str = "Paging"
PROC_ERROR_INDICATION: str = "Error Indication"
PROC_HANDOVER: str = "Handover"
PROC_PATH_SWITCH: str = "Path Switch"
PROC_TRACE_CONTROL: str = "Trace Control"
PROC_NAS_NON_DELIVERY: str = "NAS Non-Delivery Indication"
PROC_UE_CONFIG_UPDATE: str = "UE Configuration Update"
PROC_IDENTITY: str = "Identity Procedure"
PROC_NRPPA_TRANSPORT: str = "UE Associated NRPPa Transport"


class DiagnosticEngine:
    """Applies deterministic diagnostic rules to analyzed UE contexts and global events."""

    def evaluate(
        self,
        ue_contexts: List[UEContext],
        global_procs: List[Procedure],
        global_events: List[ProtocolEvent],
    ) -> List[DiagnosticObservation]:
        """
        Evaluates interface-wide and per-UE diagnostic rules against collected contexts and procedures.

        Args:
            ue_contexts: List of reconstructed UE context objects.
            global_procs: List of global interface procedures (e.g., NG Setup).
            global_events: List of non-UE specific interface events (e.g., SCTP resets).

        Returns:
            List of generated DiagnosticObservation objects.
        """
        observations: List[DiagnosticObservation] = []

        # Check Global Interface Reset / Transport Interruptions
        reset_events = [
            e
            for e in global_events
            if e.message_type in ["NG Reset", "SCTP Abort", "SCTP Shutdown"]
        ]
        if reset_events:
            incomplete_ue_count = sum(
                1 for ue in ue_contexts if any(p.status == ProcedureStatus.INCOMPLETE for p in ue.procedures)
            )
            obs = DiagnosticObservation(
                rule_id=RULE_GLOBAL_INTERFACE_INTERRUPTION,
                title="Interface-Wide Transport Interruption",
                severity=SEVERITY_WARNING if incomplete_ue_count > 0 else SEVERITY_INFO,
                description="NG Reset or SCTP transport reset observed on N2 interface.",
                evidence=[f"{e.message_type} observed in frame {e.frame_number}" for e in reset_events],
                related_frames=[e.frame_number for e in reset_events],
            )
            observations.append(obs)

        # Check Paging statistics across all UEs
        paging_procs = [p for ue in ue_contexts for p in ue.procedures if p.name == PROC_PAGING]
        if paging_procs:
            total_pages = len(paging_procs)
            unanswered_pages = sum(1 for p in paging_procs if p.status == ProcedureStatus.FAILED)
            answered_pages = total_pages - unanswered_pages

            latencies = [
                p.end_time - p.start_time
                for p in paging_procs
                if p.status == ProcedureStatus.COMPLETED and p.end_time and p.start_time
            ]
            avg_latency_str = f"{sum(latencies)/len(latencies):.3f}s" if latencies else "N/A"

            total_retries = sum(
                sum(1 for e in p.events if e.message_type == PROC_PAGING) - 1 for p in paging_procs
            )

            evidence = [
                f"Total Paging Requests: {total_pages}",
                f"Answered: {answered_pages}",
                f"Unanswered: {unanswered_pages}",
                f"Average Paging Latency: {avg_latency_str}",
                f"Paging Retransmissions: {total_retries}",
            ]

            failure_rate = (unanswered_pages / total_pages) if total_pages > 0 else 0
            severity = SEVERITY_WARNING if failure_rate > 0.1 else SEVERITY_INFO

            obs = DiagnosticObservation(
                rule_id=RULE_GLOBAL_PAGING_STATS,
                title="Global Paging Statistics",
                severity=severity,
                description=f"Summary of N2 paging procedure execution (Failure Rate: {failure_rate*100:.1f}%).",
                evidence=evidence,
                related_frames=[e.frame_number for p in paging_procs for e in p.events],
            )
            observations.append(obs)

        # Process per-UE diagnostic rules
        for ue in ue_contexts:
            self._evaluate_ue_rules(ue)

        return observations

    def _evaluate_ue_rules(self, ue: UEContext) -> None:
        """Evaluates per-UE diagnostic observations and appends findings to ue.observations."""

        def _is_genuine_auth_failure(p: Procedure) -> bool:
            if p.name != PROC_AUTHENTICATION or p.status != ProcedureStatus.FAILED:
                return False
            # If the failure_cause is a known-benign NAS cause, don't count it.
            if p.failure_cause and is_benign_nas_cause(p.failure_cause):
                return False
            return True

        auth_failed = any(_is_genuine_auth_failure(p) for p in ue.procedures)
        sec_failed = any(p.name == PROC_SECURITY_MODE and p.status == ProcedureStatus.FAILED for p in ue.procedures)
        reg_failed = any(p.name == PROC_REGISTRATION and p.status == ProcedureStatus.FAILED for p in ue.procedures)
        ctx_released = any(p.name == PROC_UE_CONTEXT_RELEASE for p in ue.procedures)

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

        # Rule: Service Request rejected by AMF
        service_failed = any(p.name == PROC_SERVICE_REQUEST and p.status == ProcedureStatus.FAILED for p in ue.procedures)
        if service_failed:
            obs_msg = "Service Request rejected by AMF."
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

        # Rule: Unanswered or problematic paging procedures for this UE
        ue_paging = [p for p in ue.procedures if p.name == PROC_PAGING]
        for p in ue_paging:
            if p.status == ProcedureStatus.FAILED:
                obs_msg = f"Unanswered paging event detected (Request frame {p.events[0].frame_number})."
                if obs_msg not in ue.observations:
                    ue.observations.append(obs_msg)

            # Paging Latency Timing warning
            if p.status == ProcedureStatus.COMPLETED and p.end_time and p.start_time:
                latency = p.end_time - p.start_time
                if latency > 2.0:
                    obs_msg = f"High paging response latency detected: {latency:.3f}s (Request frame {p.events[0].frame_number})."
                    if obs_msg not in ue.observations:
                        ue.observations.append(obs_msg)

            # Paging Retransmission warning
            paging_requests = [e for e in p.events if e.message_type == PROC_PAGING]
            if len(paging_requests) > 1:
                obs_msg = f"Paging retransmissions detected ({len(paging_requests)} attempts for Request frame {p.events[0].frame_number})."
                if obs_msg not in ue.observations:
                    ue.observations.append(obs_msg)

        # Rule: Error Indication detected
        for p in [p for p in ue.procedures if p.name == PROC_ERROR_INDICATION]:
            obs_msg = f"Error Indication detected (cause: {p.failure_cause})."
            if obs_msg not in ue.observations:
                ue.observations.append(obs_msg)

        # Rule: Handover failed/cancelled
        for p in [p for p in ue.procedures if p.name == PROC_HANDOVER]:
            if p.status == ProcedureStatus.FAILED:
                obs_msg = f"Handover failed or cancelled (cause: {p.failure_cause})."
                if obs_msg not in ue.observations:
                    ue.observations.append(obs_msg)

        # Rule: Path Switch failed
        for p in [p for p in ue.procedures if p.name == PROC_PATH_SWITCH]:
            if p.status == ProcedureStatus.FAILED:
                obs_msg = f"Path Switch failed (cause: {p.failure_cause})."
                if obs_msg not in ue.observations:
                    ue.observations.append(obs_msg)

        # Rule: Trace Control failed
        for p in [p for p in ue.procedures if p.name == PROC_TRACE_CONTROL]:
            if p.status == ProcedureStatus.FAILED:
                obs_msg = f"Trace session failed (cause: {p.failure_cause})."
                if obs_msg not in ue.observations:
                    ue.observations.append(obs_msg)

        # Rule: NAS Non-Delivery
        for p in [p for p in ue.procedures if p.name == PROC_NAS_NON_DELIVERY]:
            obs_msg = f"NAS message delivery failure detected (cause: {p.failure_cause})."
            if obs_msg not in ue.observations:
                ue.observations.append(obs_msg)

        # Rule: UE Configuration Update failed
        for p in [p for p in ue.procedures if p.name == PROC_UE_CONFIG_UPDATE]:
            if p.status == ProcedureStatus.FAILED:
                obs_msg = f"UE Configuration Update failed (cause: {p.failure_cause})."
                if obs_msg not in ue.observations:
                    ue.observations.append(obs_msg)

        # Rule: Identity Procedure failed
        for p in [p for p in ue.procedures if p.name == PROC_IDENTITY]:
            if p.status == ProcedureStatus.FAILED:
                obs_msg = f"Identity verification procedure failed (cause: {p.failure_cause})."
                if obs_msg not in ue.observations:
                    ue.observations.append(obs_msg)

        # Rule: NRPPa Transport failed/incomplete
        for p in [p for p in ue.procedures if p.name == PROC_NRPPA_TRANSPORT]:
            if p.status == ProcedureStatus.FAILED:
                obs_msg = f"NRPPa Transport failed (cause: {p.failure_cause})."
                if obs_msg not in ue.observations:
                    ue.observations.append(obs_msg)

        # Rule: Generic timeouts detected
        for p in ue.procedures:
            for obs in p.observations:
                if "Timeout warning" in obs:
                    obs_msg = f"Timeout warning in procedure {p.name}."
                    if obs_msg not in ue.observations:
                        ue.observations.append(obs_msg)

        # Rule: Protocol retransmissions detected
        for p in ue.procedures:
            for obs in p.observations:
                if "Protocol retransmission" in obs:
                    obs_msg = f"Protocol retransmissions observed in {p.name} procedure."
                    if obs_msg not in ue.observations:
                        ue.observations.append(obs_msg)
