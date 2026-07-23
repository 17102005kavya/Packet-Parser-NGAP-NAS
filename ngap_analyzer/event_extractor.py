"""
Event Extractor module for NGAP / NAS Wireshark Diagnostic Analyzer.
Converts parsed packet dictionaries into structured ProtocolEvent data models.
"""

from typing import Dict, Any, Optional
from .models import ProtocolEvent


class EventExtractor:
    """
    Transforms parsed raw fields into ProtocolEvent instances.
    """

    def extract_event(self, parsed_packet: Dict[str, Any]) -> Optional[ProtocolEvent]:
        if not parsed_packet:
            return None

        return ProtocolEvent(
            frame_number=parsed_packet.get("frame_number", 0),
            timestamp=parsed_packet.get("timestamp", 0.0),
            timestamp_str=parsed_packet.get("timestamp_str", ""),
            protocol=parsed_packet.get("protocol", "Unknown"),
            direction=parsed_packet.get("direction", "Unknown"),
            message_type=parsed_packet.get("message_type", "Unknown"),
            procedure_code=parsed_packet.get("procedure_code"),
            cause_code=parsed_packet.get("cause_code"),
            ran_ue_ngap_id=parsed_packet.get("ran_ue_ngap_id"),
            amf_ue_ngap_id=parsed_packet.get("amf_ue_ngap_id"),
            fiveg_s_tmsi=parsed_packet.get("fiveg_s_tmsi"),
            pdu_session_id=parsed_packet.get("pdu_session_id"),
            src_ip=parsed_packet.get("src_ip"),
            dst_ip=parsed_packet.get("dst_ip"),
            src_port=parsed_packet.get("src_port"),
            dst_port=parsed_packet.get("dst_port"),
            sctp_stream=parsed_packet.get("sctp_stream"),
            raw_fields=parsed_packet.get("raw_layers", {})
        )
