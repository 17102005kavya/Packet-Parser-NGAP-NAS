"""
Report Generator for NGAP / NAS Wireshark Diagnostic Analyzer.

Renders detailed, highly formatted terminal reports and structured JSON exports.
"""

import json
from typing import Any, Dict, List
from .models import DiagnosticObservation, DiagnosticReport, ProcedureStatus, UEContext


class ReportGenerator:
    """Renders detailed console text and JSON diagnostic reports from DiagnosticReport objects."""

    def generate_console_report(self, report: DiagnosticReport) -> str:
        """
        Formats a DiagnosticReport instance into a multi-line formatted console text report.

        Args:
            report: The DiagnosticReport object to render.

        Returns:
            Formatted plain-text console report string.
        """
        lines: List[str] = []

        lines.append("================================================================================")
        lines.append("                NGAP / NAS 5G WIRESHARK DIAGNOSTIC ANALYZER REPORT              ")
        lines.append("================================================================================")
        lines.append(f" Capture File          : {report.pcap_file}")
        lines.append(f" Total Frames Analyzed : {report.total_frames_analyzed}")
        lines.append(f" Malformed Skipped     : {report.malformed_frames_skipped}")
        lines.append(f" Total UEs Identified  : {len(report.ue_contexts)}")
        lines.append("================================================================================")
        lines.append("")

        if report.global_observations:
            lines.append("┌──────────────────────────────────────────────────────────────────────────────┐")
            lines.append("│ Interface / Global Network Observations                                      │")
            lines.append("├──────────────────────────────────────────────────────────────────────────────┤")
            for obs in report.global_observations:
                lines.append(f"│  • {obs:<73} │")
            lines.append("└──────────────────────────────────────────────────────────────────────────────┘")
            lines.append("")

        if not report.ue_contexts:
            lines.append("No UE contexts identified in the capture.")
            return "\n".join(lines)

        for ue in report.ue_contexts:
            ran_str = str(ue.ran_ue_ngap_id) if ue.ran_ue_ngap_id is not None else "(not assigned)"
            amf_str = str(ue.amf_ue_ngap_id) if ue.amf_ue_ngap_id is not None else "(not yet assigned)"
            gnb_ip = ue.gnb_ip or "192.168.1.10 (gNB)"
            amf_ip = ue.amf_ip or "192.168.1.50 (AMF)"

            lines.append("====================================================")
            lines.append(f"UE Context Summary ({ue.context_id})")
            lines.append(f"RAN UE NGAP ID : {ran_str:<18} Source Node : gNB ({gnb_ip})")
            lines.append(f"AMF UE NGAP ID : {amf_str:<18} Dest Node   : AMF ({amf_ip})")
            if ue.fiveg_s_tmsi:
                lines.append(f"5G-S-TMSI      : {ue.fiveg_s_tmsi}")
            lines.append("----------------------------------------------------")
            lines.append("Procedures")

            if not ue.procedures:
                lines.append(" None observed")
            else:
                for p in ue.procedures:
                    conf = getattr(p, "confidence", "DIRECT")
                    conf_suffix = " (Inferred)" if conf == "INFERRED" else ""
                    if p.name == "Authentication":
                        if p.status == ProcedureStatus.COMPLETED:
                            lines.append(f" Authentication Successful{conf_suffix}")
                        elif p.status == ProcedureStatus.FAILED:
                            lines.append(" Authentication Failed")
                        else:
                            lines.append(" Authentication Incomplete")
                    elif p.name == "Security Mode":
                        if p.status == ProcedureStatus.COMPLETED:
                            lines.append(f" Security Completed{conf_suffix}")
                        elif p.status == ProcedureStatus.FAILED:
                            lines.append(" Security Failed")
                        else:
                            lines.append(" Security Incomplete")
                    elif p.name == "Service Request":
                        if p.status == ProcedureStatus.COMPLETED:
                            lines.append(f" Service Request Completed{conf_suffix}")
                        elif p.status == ProcedureStatus.FAILED:
                            lines.append(" Service Request Failed")
                        else:
                            lines.append(" Service Request Incomplete")
                    elif "PDU Session" in p.name:
                        if p.status == ProcedureStatus.COMPLETED:
                            lines.append(f" PDU Session Established{conf_suffix}")
                        elif p.status == ProcedureStatus.FAILED:
                            lines.append(" PDU Session Failed")
                        else:
                            lines.append(" PDU Session Incomplete")
                    else:
                        lines.append(f" {p.name} {p.status.value}{conf_suffix}")

            lines.append("----------------------------------------------------")
            lines.append("Explicit Failures")
            if not ue.explicit_failures:
                lines.append(" None")
            else:
                for fail in ue.explicit_failures:
                    cause_str = fail.get("cause", "Unspecified")
                    lines.append(f" {fail['procedure']} (Cause: {cause_str})")

            lines.append("----------------------------------------------------")
            lines.append("Incomplete Procedures")
            if not ue.incomplete_procedures:
                lines.append(" None")
            else:
                for inc in ue.incomplete_procedures:
                    lines.append(f" Last Observed : {inc['last_observed']}")
                    lines.append(f" Expected      : {inc['expected']}")
                    lines.append(" Observation   : Capture ended before procedure")
                    lines.append("                 reached a terminal state.")

            lines.append("----------------------------------------------------")
            lines.append("Diagnostic Observations")
            if not ue.observations:
                lines.append(" None")
            else:
                for obs in ue.observations:
                    lines.append(f" {obs}")
            lines.append("====================================================")
            lines.append("")

        return "\n".join(lines)

    def generate_json_report(self, report: DiagnosticReport) -> str:
        """
        Serializes a DiagnosticReport object to a pretty-printed JSON string.

        Args:
            report: The DiagnosticReport instance to serialize.

        Returns:
            JSON formatted string representation.
        """
        return json.dumps(report.to_dict(), indent=2)
