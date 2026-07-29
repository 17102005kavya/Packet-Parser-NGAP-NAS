"""
UE Context Manager for NGAP / NAS Wireshark Diagnostic Analyzer.

Maintains UE contexts, maps RAN UE NGAP ID and AMF UE NGAP ID transitions,
and builds chronological timelines per UE.
"""

from typing import Dict, List, Optional
from .models import ProtocolEvent, UEContext

DIRECTION_GNB_TO_AMF: str = "gNB -> AMF"
DIRECTION_AMF_TO_GNB: str = "AMF -> gNB"


class UEContextManager:
    """
    Tracks and correlates per-UE signalling events.
    Handles ID pair transitions (RAN UE NGAP ID <-> AMF UE NGAP ID).
    """

    def __init__(self) -> None:
        """Initializes empty maps and lists for tracking UE signaling contexts."""
        self.ue_contexts: List[UEContext] = []
        self.ran_id_map: Dict[int, UEContext] = {}
        self.amf_id_map: Dict[int, UEContext] = {}
        self.tmsi_map: Dict[str, UEContext] = {}
        self.global_events: List[ProtocolEvent] = []

    def process_event(self, event: ProtocolEvent) -> Optional[UEContext]:
        """
        Correlates event to an existing UEContext or creates a new UEContext.
        If event is non-UE specific (e.g., NG Setup, SCTP), stores in global_events.

        Args:
            event: The parsed ProtocolEvent to process.

        Returns:
            Matched or newly created UEContext, or None for global interface events.
        """
        ran_id = event.ran_ue_ngap_id
        amf_id = event.amf_ue_ngap_id
        tmsi = event.fiveg_s_tmsi

        # Global events with no UE IDs
        if ran_id is None and amf_id is None and tmsi is None:
            self.global_events.append(event)
            return None

        # Find existing context by any of the IDs
        context: Optional[UEContext] = None

        if ran_id is not None and ran_id in self.ran_id_map:
            context = self.ran_id_map[ran_id]
        elif amf_id is not None and amf_id in self.amf_id_map:
            context = self.amf_id_map[amf_id]
        elif tmsi is not None and tmsi in self.tmsi_map:
            context = self.tmsi_map[tmsi]

        # If no matching context, check if we can merge or create a new one
        if context is None:
            context_id = f"UE_{len(self.ue_contexts) + 1}"
            context = UEContext(
                context_id=context_id,
                ran_ue_ngap_id=ran_id,
                amf_ue_ngap_id=amf_id,
                fiveg_s_tmsi=tmsi,
            )
            self.ue_contexts.append(context)

        # Update maps with new IDs if present
        if ran_id is not None:
            context.ran_ue_ngap_id = ran_id
            self.ran_id_map[ran_id] = context

        if amf_id is not None:
            context.amf_ue_ngap_id = amf_id
            self.amf_id_map[amf_id] = context

        if tmsi is not None:
            context.fiveg_s_tmsi = tmsi
            self.tmsi_map[tmsi] = context

        # Infer gNB IP and AMF IP from event direction
        if event.src_ip and event.dst_ip:
            if DIRECTION_GNB_TO_AMF in event.direction:
                context.gnb_ip = event.src_ip
                context.amf_ip = event.dst_ip
            elif DIRECTION_AMF_TO_GNB in event.direction:
                context.amf_ip = event.src_ip
                context.gnb_ip = event.dst_ip

        # Add event to UE context timeline
        context.events.append(event)
        return context

    def get_all_contexts(self) -> List[UEContext]:
        """Returns the list of all tracked UEContext instances."""
        return self.ue_contexts

    def get_global_events(self) -> List[ProtocolEvent]:
        """Returns the list of all tracked global interface events."""
        return self.global_events
