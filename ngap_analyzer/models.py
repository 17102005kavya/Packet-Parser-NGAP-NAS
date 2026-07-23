"""
Data models for NGAP / NAS Wireshark Diagnostic Analyzer.
Specifies Event Model, UE Context Model, Procedure Model, and Diagnostic Report structures.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class ProcedureStatus(str, Enum):
    COMPLETED = "Completed"
    FAILED = "Failed"
    INCOMPLETE = "Incomplete"


class Direction(str, Enum):
    GNB_TO_AMF = "gNB -> AMF"
    AMF_TO_GNB = "AMF -> gNB"
    UE_TO_AMF = "UE -> AMF"
    AMF_TO_UE = "AMF -> UE"
    UNKNOWN = "Unknown"


@dataclass
class ProtocolEvent:
    frame_number: int
    timestamp: float
    timestamp_str: str
    protocol: str  # "NGAP", "NAS", "SCTP"
    direction: str  # Direction value or str
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
            "sctp_stream": self.sctp_stream
        }


@dataclass
class Procedure:
    name: str
    status: ProcedureStatus
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    events: List[ProtocolEvent] = field(default_factory=list)
    last_observed_msg: Optional[str] = None
    expected_next_msg: Optional[str] = None
    failure_cause: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "last_observed_msg": self.last_observed_msg,
            "expected_next_msg": self.expected_next_msg,
            "failure_cause": self.failure_cause,
            "evidence": self.evidence,
            "observations": self.observations,
            "events_frames": [e.frame_number for e in self.events]
        }


@dataclass
class DiagnosticObservation:
    rule_id: str
    title: str
    severity: str  # "INFO", "WARNING", "ERROR"
    description: str
    evidence: List[str] = field(default_factory=list)
    related_frames: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "related_frames": self.related_frames
        }


@dataclass
class UEContext:
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

    def update_ids(self, ran_id: Optional[int] = None, amf_id: Optional[int] = None, tmsi: Optional[str] = None):
        if ran_id is not None:
            self.ran_ue_ngap_id = ran_id
        if amf_id is not None:
            self.amf_ue_ngap_id = amf_id
        if tmsi is not None:
            self.fiveg_s_tmsi = tmsi

    def to_dict(self) -> Dict[str, Any]:
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
            "timeline": [e.to_dict() for e in self.events]
        }


@dataclass
class DiagnosticReport:
    pcap_file: str
    total_frames_analyzed: int
    malformed_frames_skipped: int
    global_observations: List[str] = field(default_factory=list)
    ng_setup_procedures: List[Procedure] = field(default_factory=list)
    sctp_events: List[ProtocolEvent] = field(default_factory=list)
    ue_contexts: List[UEContext] = field(default_factory=list)
    diagnostic_observations: List[DiagnosticObservation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pcap_file": self.pcap_file,
            "total_frames_analyzed": self.total_frames_analyzed,
            "malformed_frames_skipped": self.malformed_frames_skipped,
            "global_observations": self.global_observations,
            "ng_setup_procedures": [p.to_dict() for p in self.ng_setup_procedures],
            "sctp_events": [e.to_dict() for e in self.sctp_events],
            "ue_contexts": [ue.to_dict() for ue in self.ue_contexts],
            "diagnostic_observations": [obs.to_dict() for obs in self.diagnostic_observations]
        }
