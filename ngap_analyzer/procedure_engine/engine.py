"""
Procedure Analysis Engine.
Orchestrates individual procedure analyzers across global events and UE contexts.
"""

from typing import List, Tuple
from ..models import ProtocolEvent, UEContext, Procedure
from .registration_analyzer import RegistrationAnalyzer
from .authentication_analyzer import AuthenticationAnalyzer
from .security_analyzer import SecurityAnalyzer
from .service_request_analyzer import ServiceRequestAnalyzer
from .pdu_session_analyzer import PDUSessionAnalyzer
from .ng_setup_analyzer import NGSetupAnalyzer
from .ue_context_analyzer import UEContextAnalyzer
from .transport_analyzer import TransportAnalyzer
from .paging_analyzer import PagingAnalyzer
from .unclassified_collector import UnclassifiedEventCollector
from .nas_non_delivery_analyzer import NASNonDeliveryAnalyzer
from .identity_procedure_analyzer import IdentityProcedureAnalyzer
from .config_update_analyzer import ConfigUpdateAnalyzer
from .error_indication_analyzer import ErrorIndicationAnalyzer
from .handover_analyzer import HandoverAnalyzer
from .path_switch_analyzer import PathSwitchAnalyzer
from .ran_status_transfer_analyzer import RANStatusTransferAnalyzer
from .trace_analyzer import TraceAnalyzer


class ProcedureAnalysisEngine:
    """
    Coordinates procedure reconstruction per UE context and at the global interface level.
    """

    def __init__(self):
        self.registration_analyzer = RegistrationAnalyzer()
        self.auth_analyzer = AuthenticationAnalyzer()
        self.security_analyzer = SecurityAnalyzer()
        self.service_request_analyzer = ServiceRequestAnalyzer()
        self.pdu_analyzer = PDUSessionAnalyzer()
        self.ng_setup_analyzer = NGSetupAnalyzer()
        self.ue_context_analyzer = UEContextAnalyzer()
        self.transport_analyzer = TransportAnalyzer()
        self.paging_analyzer = PagingAnalyzer()
        self.unclassified_collector = UnclassifiedEventCollector()
        self.nas_non_delivery_analyzer = NASNonDeliveryAnalyzer()
        self.identity_procedure_analyzer = IdentityProcedureAnalyzer()
        self.config_update_analyzer = ConfigUpdateAnalyzer()
        self.error_indication_analyzer = ErrorIndicationAnalyzer()
        self.handover_analyzer = HandoverAnalyzer()
        self.path_switch_analyzer = PathSwitchAnalyzer()
        self.ran_status_transfer_analyzer = RANStatusTransferAnalyzer()
        self.trace_analyzer = TraceAnalyzer()

    def process(self, ue_contexts: List[UEContext], global_events: List[ProtocolEvent]) -> List[Procedure]:
        """
        Analyzes all UE contexts and global events.
        Populates context.procedures, context.explicit_failures, and context.incomplete_procedures.
        Returns global interface procedures (e.g. NG Setup, Transport events).
        """
        # Process global procedures
        ng_setup_procs = self.ng_setup_analyzer.analyze(global_events)
        transport_procs = self.transport_analyzer.analyze(global_events)
        global_unclassified = self.unclassified_collector.analyze(global_events)
        global_config_procs = self.config_update_analyzer.analyze(global_events)
        global_error_procs = self.error_indication_analyzer.analyze(global_events)
        global_procs = ng_setup_procs + transport_procs + global_unclassified + global_config_procs + global_error_procs

        # Process per-UE procedures
        for ue in ue_contexts:
            ue.procedures = []
            ue.explicit_failures = []
            ue.incomplete_procedures = []

            reg_procs = self.registration_analyzer.analyze(ue.events)
            auth_procs = self.auth_analyzer.analyze(ue.events)
            sec_procs = self.security_analyzer.analyze(ue.events)
            service_procs = self.service_request_analyzer.analyze(ue.events)
            pdu_procs = self.pdu_analyzer.analyze(ue.events)
            ctx_procs = self.ue_context_analyzer.analyze(ue.events)
            paging_procs = self.paging_analyzer.analyze(ue.events)
            nas_non_deliv_procs = self.nas_non_delivery_analyzer.analyze(ue.events)
            identity_procs = self.identity_procedure_analyzer.analyze(ue.events)
            ue_config_procs = self.config_update_analyzer.analyze(ue.events)
            error_ind_procs = self.error_indication_analyzer.analyze(ue.events)
            ho_procs = self.handover_analyzer.analyze(ue.events)
            ps_procs = self.path_switch_analyzer.analyze(ue.events)
            status_xfer_procs = self.ran_status_transfer_analyzer.analyze(ue.events)
            trace_procs = self.trace_analyzer.analyze(ue.events)
            ue_unclassified = self.unclassified_collector.analyze(ue.events)

            all_ue_procs = (
                reg_procs + auth_procs + sec_procs + service_procs + pdu_procs + ctx_procs + paging_procs +
                nas_non_deliv_procs + identity_procs + ue_config_procs + error_ind_procs + ho_procs +
                ps_procs + status_xfer_procs + trace_procs + ue_unclassified
            )
            ue.procedures = all_ue_procs

            # Populate explicit failures and incomplete summaries
            for p in all_ue_procs:
                if p.status == p.status.FAILED:
                    failure_entry = {
                        "procedure": p.name,
                        "cause": p.failure_cause or "Unspecified Failure",
                        "evidence": p.evidence,
                        "frames": [e.frame_number for e in p.events]
                    }
                    ue.explicit_failures.append(failure_entry)
                elif p.status == p.status.INCOMPLETE:
                    inc_entry = {
                        "procedure": p.name,
                        "last_observed": p.last_observed_msg or "Unknown",
                        "expected": p.expected_next_msg or "Unknown",
                        "evidence": p.evidence,
                        "frames": [e.frame_number for e in p.events]
                    }
                    ue.incomplete_procedures.append(inc_entry)

        return global_procs
