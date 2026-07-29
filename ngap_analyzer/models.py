"""
Data models for NGAP / NAS Wireshark Diagnostic Analyzer.

Defines the core data structures used throughout the packet parsing, context mapping,
procedure analysis, diagnostic evaluation, and report generation pipeline.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ProcedureStatus(str, Enum):
    """Enumeration of possible procedure execution outcomes."""

    COMPLETED = "Completed"
    FAILED = "Failed"
    INCOMPLETE = "Incomplete"


class Direction(str, Enum):
    """Enumeration of network node signaling flow directions."""

    GNB_TO_AMF = "gNB -> AMF"
    AMF_TO_GNB = "AMF -> gNB"
    UE_TO_AMF = "UE -> AMF"
    AMF_TO_UE = "AMF -> UE"
    UNKNOWN = "Unknown"


@dataclass
class ProtocolEvent:
    """
    Represents a single parsed protocol event extracted from a Wireshark/tshark packet frame.

    Attributes:
        frame_number: Wireshark packet frame index.
        timestamp: Epoch timestamp in seconds.
        timestamp_str: Formatted human-readable timestamp string.
        protocol: Signaling protocol family ("NGAP", "NAS", "SCTP").
        direction: Message transmission direction string (e.g. "gNB -> AMF").
        message_type: Protocol message name or IE title.
        procedure_code: Optional NGAP procedure code string or numeric identifier.
        cause_code: Optional error cause string if present in message.
        ran_ue_ngap_id: Radio Access Network UE NGAP identifier allocated by gNB.
        amf_ue_ngap_id: Core Network UE NGAP identifier allocated by AMF.
        fiveg_s_tmsi: 5G Temporary Mobile Subscriber Identity string.
        pdu_session_id: PDU Session identifier index.
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        src_port: Source transport port.
        dst_port: Destination transport port.
        sctp_stream: SCTP stream identifier.
        raw_fields: Raw dictionary of protocol layer elements.
    """

    frame_number: int
    timestamp: float
    timestamp_str: str
    protocol: str
    direction: str
    message_type: str
    procedure_code: Optional[str] = None
    cause_code: Optional[str] = None
    ran_ue_ngap_id: Optional[int] = None
    amf_ue_ngap_id: Optional[int] = None
    fiveg_s_tmsi: Optional[str] = None
    pdu_session_id: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    sctp_stream: Optional[int] = None
    raw_fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the protocol event instance to a serializable dictionary representation."""
        return {
            "frame_number": self.frame_number,
            "timestamp": self.timestamp_str,
            "protocol": self.protocol,
            "direction": self.direction,
            "message_type": self.message_type,
            "procedure_code": self.procedure_code,
            "cause_code": self.cause_code,
            "ran_ue_ngap_id": self.ran_ue_ngap_id,
            "amf_ue_ngap_id": self.amf_ue_ngap_id,
            "fiveg_s_tmsi": self.fiveg_s_tmsi,
            "pdu_session_id": self.pdu_session_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "sctp_stream": self.sctp_stream,
        }


@dataclass
class Procedure:
    """
    Represents a reconstructed 3GPP signaling procedure spanning one or more protocol events.

    Attributes:
        name: Procedure title (e.g. "Registration", "Authentication", "NG Setup").
        status: Execution status enum (COMPLETED, FAILED, INCOMPLETE).
        start_time: Timestamp of initial request event.
        end_time: Timestamp of terminal response event.
        events: List of constituent ProtocolEvent objects.
        last_observed_msg: Last observed message type in incomplete sequence.
        expected_next_msg: Expected next message type in sequence.
        failure_cause: Reason string for failed procedures.
        confidence: Classification confidence grade ("DIRECT", "INFERRED", "PARTIAL", "UNKNOWN").
        evidence: Textual evidence statements justifying outcome.
        observations: Analytical observations and diagnostic notes.
    """

    name: str
    status: ProcedureStatus
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    events: List[ProtocolEvent] = field(default_factory=list)
    last_observed_msg: Optional[str] = None
    expected_next_msg: Optional[str] = None
    failure_cause: Optional[str] = None
    confidence: str = "DIRECT"
    evidence: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Converts procedure object to a dictionary representation suitable for JSON export."""
        return {
            "name": self.name,
            "status": self.status.value,
            "confidence": self.confidence,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "last_observed_msg": self.last_observed_msg,
            "expected_next_msg": self.expected_next_msg,
            "failure_cause": self.failure_cause,
            "evidence": self.evidence,
            "observations": self.observations,
            "events_frames": [e.frame_number for e in self.events],
        }


@dataclass
class DiagnosticObservation:
    """
    Represents an actionable diagnostic rule evaluation result.

    Attributes:
        rule_id: Unique diagnostic rule identifier string (e.g. "RULE_GLOBAL_01").
        title: Descriptive summary title.
        severity: Severity indicator ("INFO", "WARNING", "ERROR").
        description: Detailed explanation of observation.
        evidence: Supporting textual evidence lines.
        related_frames: List of associated packet frame indices.
    """

    rule_id: str
    title: str
    severity: str
    description: str
    evidence: List[str] = field(default_factory=list)
    related_frames: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Converts diagnostic observation to a dictionary format."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "related_frames": self.related_frames,
        }


@dataclass
class UEContext:
    """
    State container representing a single User Equipment (UE) signaling session context.

    Attributes:
        context_id: System-generated unique identifier string (e.g. "UE_1").
        ran_ue_ngap_id: gNB-assigned RAN UE NGAP ID.
        amf_ue_ngap_id: AMF-assigned AMF UE NGAP ID.
        fiveg_s_tmsi: Temporary mobile subscriber identity.
        gnb_ip: Discovered gNB IP address.
        amf_ip: Discovered AMF IP address.
        events: Chronological sequence of events belonging to this UE context.
        procedures: Reconstructed procedures executed by this UE.
        explicit_failures: Summarized failure records for explicitly failed procedures.
        incomplete_procedures: Summarized records for incomplete procedures.
        observations: Higher-level diagnostic statements attached to this UE context.
    """

    context_id: str
    ran_ue_ngap_id: Optional[int] = None
    amf_ue_ngap_id: Optional[int] = None
    fiveg_s_tmsi: Optional[str] = None
    gnb_ip: Optional[str] = None
    amf_ip: Optional[str] = None
    events: List[ProtocolEvent] = field(default_factory=list)
    procedures: List[Procedure] = field(default_factory=list)
    explicit_failures: List[Dict[str, Any]] = field(default_factory=list)
    incomplete_procedures: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)

    def update_ids(
        self,
        ran_id: Optional[int] = None,
        amf_id: Optional[int] = None,
        tmsi: Optional[str] = None,
    ) -> None:
        """Updates the identifiers associated with this UE context if non-None values are provided."""
        if ran_id is not None:
            self.ran_ue_ngap_id = ran_id
        if amf_id is not None:
            self.amf_ue_ngap_id = amf_id
        if tmsi is not None:
            self.fiveg_s_tmsi = tmsi

    def to_dict(self) -> Dict[str, Any]:
        """Converts UE context into a complete structured dictionary, including event status mapping and timeline."""
        event_status_map: Dict[int, str] = {}
        for p in self.procedures:
            for pe in p.events:
                if event_status_map.get(pe.frame_number) != ProcedureStatus.FAILED:
                    event_status_map[pe.frame_number] = p.status.value

        timeline_dicts: List[Dict[str, Any]] = []
        for e in self.events:
            d = e.to_dict()
            d["procedure_status"] = event_status_map.get(e.frame_number)
            timeline_dicts.append(d)

        return {
            "context_id": self.context_id,
            "ran_ue_ngap_id": self.ran_ue_ngap_id,
            "amf_ue_ngap_id": self.amf_ue_ngap_id if self.amf_ue_ngap_id is not None else "(not yet assigned)",
            "fiveg_s_tmsi": self.fiveg_s_tmsi,
            "gnb_ip": self.gnb_ip or "Unknown gNB",
            "amf_ip": self.amf_ip or "Unknown AMF",
            "procedures": [p.to_dict() for p in self.procedures],
            "explicit_failures": self.explicit_failures,
            "incomplete_procedures": self.incomplete_procedures,
            "diagnostic_observations": self.observations,
            "timeline": timeline_dicts,
        }


@dataclass
class DiagnosticReport:
    """
    Top-level output document aggregating PCAP analysis metrics, global observations, and per-UE contexts.

    Attributes:
        pcap_file: File path of the analyzed packet capture.
        total_frames_analyzed: Count of processed frames.
        malformed_frames_skipped: Count of malformed/unparseable frames skipped.
        global_observations: System-wide observation strings.
        ng_setup_procedures: Global NG Setup procedures.
        sctp_events: Global SCTP protocol events.
        ue_contexts: List of UEContext objects analyzed.
        diagnostic_observations: Higher-level DiagnosticObservation objects.
    """

    pcap_file: str
    total_frames_analyzed: int
    malformed_frames_skipped: int
    global_observations: List[str] = field(default_factory=list)
    ng_setup_procedures: List[Procedure] = field(default_factory=list)
    sctp_events: List[ProtocolEvent] = field(default_factory=list)
    ue_contexts: List[UEContext] = field(default_factory=list)
    diagnostic_observations: List[DiagnosticObservation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the entire diagnostic report into a nested dictionary structure."""
        return {
            "pcap_file": self.pcap_file,
            "total_frames_analyzed": self.total_frames_analyzed,
            "malformed_frames_skipped": self.malformed_frames_skipped,
            "global_observations": self.global_observations,
            "ng_setup_procedures": [p.to_dict() for p in self.ng_setup_procedures],
            "sctp_events": [e.to_dict() for e in self.sctp_events],
            "ue_contexts": [ue.to_dict() for ue in self.ue_contexts],
            "diagnostic_observations": [obs.to_dict() for obs in self.diagnostic_observations],
        }
