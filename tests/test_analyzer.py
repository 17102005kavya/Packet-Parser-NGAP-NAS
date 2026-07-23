"""
Unit and Integration Tests for NGAP / NAS Wireshark Diagnostic Analyzer.
Tests event extraction, UE ID correlation, procedure state machines,
diagnostic rules, and console/JSON report rendering.
"""

import json
import os
import tempfile
import unittest

from ngap_analyzer.models import ProtocolEvent, UEContext, ProcedureStatus
from ngap_analyzer.packet_parser import PacketParser
from ngap_analyzer.event_extractor import EventExtractor
from ngap_analyzer.ue_context_manager import UEContextManager
from ngap_analyzer.procedure_engine.engine import ProcedureAnalysisEngine
from ngap_analyzer.diagnostic_engine import DiagnosticEngine
from ngap_analyzer.report_generator import ReportGenerator
from ngap_analyzer.cli import run_analyzer
from ngap_analyzer.procedure_engine.pdu_session_analyzer import PDUSessionAnalyzer


class TestNGAPAnalyzer(unittest.TestCase):

    def setUp(self):
        self.parser = PacketParser()
        self.extractor = EventExtractor()
        self.ctx_manager = UEContextManager()
        self.proc_engine = ProcedureAnalysisEngine()
        self.diag_engine = DiagnosticEngine()
        self.reporter = ReportGenerator()

    def test_tshark_wrapped_field_values_are_resolved(self):
        """Regression test for tshark JSON field values wrapped as lists of objects."""
        ngap_layer = {
            "ngap.procedureCode": [{"raw": "14"}],
            "ngap.AMF_UE_NGAP_ID": [{"raw": "302"}],
            "ngap.radioNetwork": [{"raw": "21"}],
            "ngap.nas": [{"raw": "1"}],
        }

        self.assertEqual(self.parser._extract_int(ngap_layer, ["ngap.procedureCode"]), 14)
        self.assertEqual(self.parser._extract_int(ngap_layer, ["ngap.AMF_UE_NGAP_ID"]), 302)
        self.assertEqual(self.parser._extract_str(ngap_layer, ["ngap.radioNetwork"]), "21")
        self.assertEqual(self.parser._extract_str(ngap_layer, ["ngap.nas"]), "1")

    def test_successful_ue_flow(self):
        """Tests Section 18.1 Successful UE flow reconstruction."""
        packets = [
            # Initial UE Message + Reg Request (RAN ID: 15)
            {
                "frame": {"frame.number": ["1"], "frame.time_epoch": ["100.0"], "frame.time": "100.0"},
                "ngap": {"ngap.procedureCode": ["14"], "ngap.RAN_UE_NGAP_ID": ["15"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Registration request"]}
            },
            # Downlink NAS Transport + Auth Request (RAN ID: 15, AMF ID: 302)
            {
                "frame": {"frame.number": ["2"], "frame.time_epoch": ["100.1"], "frame.time": "100.1"},
                "ngap": {"ngap.procedureCode": ["15"], "ngap.RAN_UE_NGAP_ID": ["15"], "ngap.AMF_UE_NGAP_ID": ["302"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Authentication request"]}
            },
            # Uplink NAS Transport + Auth Response (AMF ID: 302)
            {
                "frame": {"frame.number": ["3"], "frame.time_epoch": ["100.2"], "frame.time": "100.2"},
                "ngap": {"ngap.procedureCode": ["16"], "ngap.RAN_UE_NGAP_ID": ["15"], "ngap.AMF_UE_NGAP_ID": ["302"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Authentication response"]}
            },
            # Security Mode Command (AMF ID: 302)
            {
                "frame": {"frame.number": ["4"], "frame.time_epoch": ["100.3"], "frame.time": "100.3"},
                "ngap": {"ngap.procedureCode": ["15"], "ngap.RAN_UE_NGAP_ID": ["15"], "ngap.AMF_UE_NGAP_ID": ["302"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Security mode command"]}
            },
            # Security Mode Complete (AMF ID: 302)
            {
                "frame": {"frame.number": ["5"], "frame.time_epoch": ["100.4"], "frame.time": "100.4"},
                "ngap": {"ngap.procedureCode": ["16"], "ngap.RAN_UE_NGAP_ID": ["15"], "ngap.AMF_UE_NGAP_ID": ["302"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Security mode complete"]}
            },
            # Registration Accept (AMF ID: 302)
            {
                "frame": {"frame.number": ["6"], "frame.time_epoch": ["100.5"], "frame.time": "100.5"},
                "ngap": {"ngap.procedureCode": ["15"], "ngap.RAN_UE_NGAP_ID": ["15"], "ngap.AMF_UE_NGAP_ID": ["302"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Registration accept"]}
            },
            # PDU Session Establishment Request (AMF ID: 302)
            {
                "frame": {"frame.number": ["7"], "frame.time_epoch": ["100.6"], "frame.time": "100.6"},
                "ngap": {"ngap.procedureCode": ["16"], "ngap.RAN_UE_NGAP_ID": ["15"], "ngap.AMF_UE_NGAP_ID": ["302"]},
                "nas-5gs": {"nas_5gs.sm.message_type": ["PDU session establishment request"]}
            },
            # PDU Session Establishment Accept (AMF ID: 302)
            {
                "frame": {"frame.number": ["8"], "frame.time_epoch": ["100.7"], "frame.time": "100.7"},
                "ngap": {"ngap.procedureCode": ["15"], "ngap.RAN_UE_NGAP_ID": ["15"], "ngap.AMF_UE_NGAP_ID": ["302"]},
                "nas-5gs": {"nas_5gs.sm.message_type": ["PDU session establishment accept"]}
            }
        ]

        for pkt in packets:
            parsed = self.parser.parse_packet(pkt)
            event = self.extractor.extract_event(parsed)
            self.ctx_manager.process_event(event)

        ues = self.ctx_manager.get_all_contexts()
        self.assertEqual(len(ues), 1)
        ue = ues[0]
        self.assertEqual(ue.ran_ue_ngap_id, 15)
        self.assertEqual(ue.amf_ue_ngap_id, 302)

        global_procs = self.proc_engine.process(ues, self.ctx_manager.get_global_events())
        self.diag_engine.evaluate(ues, global_procs, self.ctx_manager.get_global_events())

        # Verify completed procedures
        proc_names = [p.name for p in ue.procedures if p.status == ProcedureStatus.COMPLETED]
        self.assertIn("Registration", proc_names)
        self.assertIn("Authentication", proc_names)
        self.assertIn("Security Mode", proc_names)

        # Verify no explicit failures
        self.assertEqual(len(ue.explicit_failures), 0)

        # Verify console report content
        report_text = self.reporter.generate_console_report(
            self._make_report(ues, global_procs)
        )
        self.assertIn("RAN UE NGAP ID : 15", report_text)
        self.assertIn("AMF UE NGAP ID : 302", report_text)
        self.assertIn("Registration Completed", report_text)
        self.assertIn("Authentication Successful", report_text)
        self.assertIn("Security Completed", report_text)
        self.assertIn("No protocol anomalies detected.", report_text)

    def test_explicit_auth_failure_flow(self):
        """Tests Section 18.2 Explicit Auth Failure flow reconstruction."""
        packets = [
            # Initial UE Message (RAN ID: 22)
            {
                "frame": {"frame.number": ["10"], "frame.time_epoch": ["200.0"], "frame.time": "200.0"},
                "ngap": {"ngap.procedureCode": ["14"], "ngap.RAN_UE_NGAP_ID": ["22"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Registration request"]}
            },
            # Auth Request (RAN ID: 22, AMF ID: 318)
            {
                "frame": {"frame.number": ["11"], "frame.time_epoch": ["200.1"], "frame.time": "200.1"},
                "ngap": {"ngap.procedureCode": ["15"], "ngap.RAN_UE_NGAP_ID": ["22"], "ngap.AMF_UE_NGAP_ID": ["318"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Authentication request"]}
            },
            # Auth Failure (MAC failure)
            {
                "frame": {"frame.number": ["12"], "frame.time_epoch": ["200.2"], "frame.time": "200.2"},
                "ngap": {"ngap.procedureCode": ["16"], "ngap.RAN_UE_NGAP_ID": ["22"], "ngap.AMF_UE_NGAP_ID": ["318"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Authentication failure"], "nas_5gs.mm.5gmm_cause": ["MAC failure"]}
            },
            # Registration Reject
            {
                "frame": {"frame.number": ["13"], "frame.time_epoch": ["200.3"], "frame.time": "200.3"},
                "ngap": {"ngap.procedureCode": ["15"], "ngap.RAN_UE_NGAP_ID": ["22"], "ngap.AMF_UE_NGAP_ID": ["318"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Registration reject"], "nas_5gs.mm.5gmm_cause": ["Authentication failure"]}
            }
        ]

        for pkt in packets:
            parsed = self.parser.parse_packet(pkt)
            event = self.extractor.extract_event(parsed)
            self.ctx_manager.process_event(event)

        ues = self.ctx_manager.get_all_contexts()
        self.assertEqual(len(ues), 1)
        ue = ues[0]

        global_procs = self.proc_engine.process(ues, self.ctx_manager.get_global_events())
        self.diag_engine.evaluate(ues, global_procs, self.ctx_manager.get_global_events())

        self.assertTrue(len(ue.explicit_failures) >= 2)
        report_text = self.reporter.generate_console_report(
            self._make_report(ues, global_procs)
        )
        self.assertIn("RAN UE NGAP ID : 22", report_text)
        self.assertIn("AMF UE NGAP ID : 318", report_text)
        self.assertIn("Authentication Failure", report_text)
        self.assertIn("Authentication Failure caused Registration termination.", report_text)

    def test_incomplete_procedure_flow(self):
        """Tests Section 18.3 Incomplete procedure flow reconstruction."""
        packets = [
            # Initial UE Message (RAN ID: 40, no AMF ID)
            {
                "frame": {"frame.number": ["30"], "frame.time_epoch": ["300.0"], "frame.time": "300.0"},
                "ngap": {"ngap.procedureCode": ["14"], "ngap.RAN_UE_NGAP_ID": ["40"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Registration request"]}
            }
        ]

        for pkt in packets:
            parsed = self.parser.parse_packet(pkt)
            event = self.extractor.extract_event(parsed)
            self.ctx_manager.process_event(event)

        ues = self.ctx_manager.get_all_contexts()
        ue = ues[0]

        global_procs = self.proc_engine.process(ues, self.ctx_manager.get_global_events())
        self.diag_engine.evaluate(ues, global_procs, self.ctx_manager.get_global_events())

        self.assertEqual(len(ue.incomplete_procedures), 1)
        report_text = self.reporter.generate_console_report(
            self._make_report(ues, global_procs)
        )
        self.assertIn("RAN UE NGAP ID : 40", report_text)
        self.assertIn("AMF UE NGAP ID : (not yet assigned)", report_text)
        self.assertIn("Registration Incomplete", report_text)
        self.assertIn("Insufficient evidence to classify outcome.", report_text)

    def test_json_file_execution(self):
        """Tests end-to-end execution reading a JSON capture file."""
        test_packets = [
            {
                "frame": {"frame.number": ["1"], "frame.time_epoch": ["100.0"], "frame.time": "100.0"},
                "ngap": {"ngap.procedureCode": ["14"], "ngap.RAN_UE_NGAP_ID": ["15"]},
                "nas-5gs": {"nas_5gs.mm.message_type": ["Registration request"]}
            }
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(test_packets, f)
            temp_path = f.name

        try:
            report_out = run_analyzer(temp_path, output_json=True)
            report_dict = json.loads(report_out)
            self.assertEqual(report_dict["total_frames_analyzed"], 1)
            self.assertEqual(len(report_dict["ue_contexts"]), 1)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def _make_report(self, ues, global_procs):
        from ngap_analyzer.models import DiagnosticReport
        return DiagnosticReport(
            pcap_file="test_capture.pcap",
            total_frames_analyzed=10,
            malformed_frames_skipped=0,
            ng_setup_procedures=global_procs,
            ue_contexts=ues
        )



class TestAuditFixes(unittest.TestCase):
    """
    Regression tests for all findings from the failure-classification audit.
    """

    def setUp(self):
        self.auth_analyzer = __import__(
            "ngap_analyzer.procedure_engine.authentication_analyzer",
            fromlist=["AuthenticationAnalyzer"]
        ).AuthenticationAnalyzer()
        self.transport_analyzer = __import__(
            "ngap_analyzer.procedure_engine.transport_analyzer",
            fromlist=["TransportAnalyzer"]
        ).TransportAnalyzer()
        self.registration_analyzer = __import__(
            "ngap_analyzer.procedure_engine.registration_analyzer",
            fromlist=["RegistrationAnalyzer"]
        ).RegistrationAnalyzer()
        self.unclassified = __import__(
            "ngap_analyzer.procedure_engine.unclassified_collector",
            fromlist=["UnclassifiedEventCollector"]
        ).UnclassifiedEventCollector()
        self.pdu_session_analyzer = PDUSessionAnalyzer()

    def _make_event(self, msg, cause=None, frame=1, ts=100.0):
        return ProtocolEvent(
            frame_number=frame, timestamp=ts, timestamp_str=str(ts),
            protocol="NAS", direction="gNB -> AMF",
            message_type=msg, cause_code=cause,
        )

    # ------------------------------------------------------------------
    # Finding 1: Authentication Failure with synch-failure = COMPLETED
    # ------------------------------------------------------------------
    def test_pdu_session_release_cause_is_classified_from_3gpp_names(self):
        """Benign NGAP CauseRadioNetwork values should be treated as normal releases."""
        events = [
            ProtocolEvent(
                frame_number=1,
                timestamp=100.0,
                timestamp_str="100.0",
                protocol="NGAP",
                direction="gNB -> AMF",
                message_type="PDU Session Resource Release Command",
                cause_code="NGAP cause (radioNetwork): release-due-to-ngran-generated-reason (3)",
                pdu_session_id=5,
            ),
            ProtocolEvent(
                frame_number=2,
                timestamp=100.1,
                timestamp_str="100.1",
                protocol="NGAP",
                direction="AMF -> gNB",
                message_type="PDU Session Resource Release Response",
                cause_code=None,
                pdu_session_id=5,
            ),
        ]
        procs = self.pdu_session_analyzer.analyze(events)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.COMPLETED)

    def test_auth_synch_failure_is_incomplete_mid_resync(self):
        """Synch failure with no retry = INCOMPLETE (capture ended mid-resync).

        The old code closed the procedure as COMPLETED on the Failure event itself.
        The spec-correct behaviour (TS 24.501 §5.4.1.3.4) is that synch failure
        is NOT a resolved outcome — auth has not succeeded.  Without the retry
        Auth Request the procedure must stay open as INCOMPLETE.
        """
        events = [
            self._make_event("Authentication Request", frame=1),
            self._make_event("Authentication Failure",
                             cause="5GMM/5GSM cause: 21", frame=2),
        ]
        procs = self.auth_analyzer.analyze(events)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.INCOMPLETE,
                         "synch failure with no retry should be INCOMPLETE, not COMPLETED")
        obs = " ".join(procs[0].observations)
        self.assertIn("resync", obs.lower())

    def test_auth_synch_failure_full_resync_is_completed(self):
        """Full 4-step resync (Case A): ONE procedure, status=COMPLETED."""
        events = [
            self._make_event("Authentication Request", frame=1),
            self._make_event("Authentication Failure",
                             cause="5GMM/5GSM cause: 21", frame=2),
            self._make_event("Authentication Request", frame=3),
            self._make_event("Authentication Response", frame=4),
        ]
        procs = self.auth_analyzer.analyze(events)
        self.assertEqual(len(procs), 1, "resync must stay as ONE procedure, not split into two")
        self.assertEqual(procs[0].status, ProcedureStatus.COMPLETED)
        self.assertEqual(len(procs[0].events), 4, "all 4 events must belong to the same procedure")

    def test_auth_synch_failure_text_form_is_incomplete_mid_resync(self):
        """Text-form synch failure cause with no retry = INCOMPLETE."""
        events = [
            self._make_event("Authentication Request", frame=1),
            self._make_event("Authentication Failure",
                             cause="5GMM/5GSM cause: synch failure", frame=2),
        ]
        procs = self.auth_analyzer.analyze(events)
        self.assertEqual(procs[0].status, ProcedureStatus.INCOMPLETE)

    def test_auth_mac_failure_remains_failed(self):
        """MAC failure must still be classified as FAILED."""
        events = [
            self._make_event("Authentication Request", frame=1),
            self._make_event("Authentication Failure",
                             cause="5GMM/5GSM cause: MAC failure", frame=2),
        ]
        procs = self.auth_analyzer.analyze(events)
        self.assertEqual(procs[0].status, ProcedureStatus.FAILED)

    def test_auth_reject_is_always_failed(self):
        """Authentication Reject (AMF→UE) must always be FAILED."""
        events = [
            self._make_event("Authentication Request", frame=1),
            self._make_event("Authentication Reject", frame=2),
        ]
        procs = self.auth_analyzer.analyze(events)
        self.assertEqual(procs[0].status, ProcedureStatus.FAILED)

    def test_auth_no_cause_failure_is_failed(self):
        """Authentication Failure with no cause must be FAILED (not synch)."""
        events = [
            self._make_event("Authentication Request", frame=1),
            self._make_event("Authentication Failure", cause=None, frame=2),
        ]
        procs = self.auth_analyzer.analyze(events)
        self.assertEqual(procs[0].status, ProcedureStatus.FAILED)

    # ------------------------------------------------------------------
    # Finding 3: Transport event classification
    # ------------------------------------------------------------------
    def test_sctp_abort_is_failed(self):
        events = [self._make_event("SCTP Abort", frame=1)]
        procs = self.transport_analyzer.analyze(events)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.FAILED)

    def test_sctp_shutdown_is_completed_not_failed(self):
        events = [self._make_event("SCTP Shutdown", frame=1)]
        procs = self.transport_analyzer.analyze(events)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.COMPLETED,
                         "SCTP Shutdown is graceful teardown, not a failure")

    def test_sctp_init_is_completed_not_failed(self):
        events = [self._make_event("SCTP Init", frame=1)]
        procs = self.transport_analyzer.analyze(events)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.COMPLETED,
                         "SCTP Init is normal startup, not a failure")

    def test_ng_reset_pair_is_completed(self):
        """NG Reset + Acknowledge must be paired into a single COMPLETED procedure."""
        events = [
            self._make_event("NG Reset", frame=1),
            self._make_event("NG Reset Acknowledge", frame=2),
        ]
        procs = self.transport_analyzer.analyze(events)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.COMPLETED)
        self.assertEqual(len(procs[0].events), 2)

    def test_ng_reset_without_ack_is_incomplete(self):
        """NG Reset without Acknowledge must be INCOMPLETE, not FAILED."""
        events = [self._make_event("NG Reset", frame=1)]
        procs = self.transport_analyzer.analyze(events)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.INCOMPLETE,
                         "NG Reset alone should be INCOMPLETE, not FAILED")

    # ------------------------------------------------------------------
    # Finding 4 + 5: Registration case + Registration Complete
    # ------------------------------------------------------------------
    def test_registration_request_capitalised_matches(self):
        """Parser now emits 'Registration Request' (capital R) — analyzer must match."""
        events = [
            self._make_event("Registration Request", frame=1),
            self._make_event("Registration Accept", frame=2),
        ]
        procs = self.registration_analyzer.analyze(events)
        completed = [p for p in procs if p.status == ProcedureStatus.COMPLETED]
        self.assertEqual(len(completed), 1, "Registration should be COMPLETED")

    def test_registration_full_three_step_handshake(self):
        """Registration Request -> Accept -> Complete should yield a single COMPLETED proc."""
        events = [
            self._make_event("Registration Request", frame=1),
            self._make_event("Registration Accept", frame=2),
            self._make_event("Registration Complete", frame=3),
        ]
        procs = self.registration_analyzer.analyze(events)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.COMPLETED)
        obs = " ".join(procs[0].observations)
        self.assertIn("full handshake", obs.lower())

    def test_registration_accept_without_complete_still_completed(self):
        """Accept without Complete must still be COMPLETED (mobility/periodic regs)."""
        events = [
            self._make_event("Registration Request", frame=1),
            self._make_event("Registration Accept", frame=2),
        ]
        procs = self.registration_analyzer.analyze(events)
        self.assertEqual(procs[0].status, ProcedureStatus.COMPLETED)

    # ------------------------------------------------------------------
    # Finding 8: Unknown Signalling is surfaced, not swallowed
    # ------------------------------------------------------------------
    def test_unknown_signalling_is_surfaced(self):
        """Unknown Signalling events must produce a procedure record, not be discarded."""
        events = [
            self._make_event("Unknown Signalling", frame=5),
            self._make_event("Unknown Signalling", frame=6),
        ]
        procs = self.unclassified.analyze(events)
        self.assertEqual(len(procs), 1)
        self.assertIn("2", procs[0].observations[0])  # "2 message(s)"

    def test_no_unknown_signalling_returns_empty(self):
        """No Unknown Signalling events -> empty list returned."""
        events = [self._make_event("Registration Request", frame=1)]
        procs = self.unclassified.analyze(events)
        self.assertEqual(procs, [])

    # ------------------------------------------------------------------
    # NAS cause classifier unit tests (Finding 7)
    # ------------------------------------------------------------------
    def test_nas_classifier_synch_numeric(self):
        from ngap_analyzer.procedure_engine.nas_cause_classifier import is_synch_failure
        self.assertTrue(is_synch_failure("5GMM/5GSM cause: 21"))

    def test_nas_classifier_synch_text(self):
        from ngap_analyzer.procedure_engine.nas_cause_classifier import is_synch_failure
        self.assertTrue(is_synch_failure("5GMM/5GSM cause: synch failure"))

    def test_nas_classifier_synch_hex(self):
        from ngap_analyzer.procedure_engine.nas_cause_classifier import is_synch_failure
        self.assertTrue(is_synch_failure("5GMM/5GSM cause: 0x15"))

    def test_nas_classifier_mac_failure_not_benign(self):
        from ngap_analyzer.procedure_engine.nas_cause_classifier import is_synch_failure
        self.assertFalse(is_synch_failure("5GMM/5GSM cause: MAC failure"))

    def test_nas_classifier_none_not_benign(self):
        from ngap_analyzer.procedure_engine.nas_cause_classifier import is_synch_failure
        self.assertFalse(is_synch_failure(None))


class TestExtendedSuite(unittest.TestCase):
    """
    Extended Test Suite covering Modules A-E, Registration Analyzer, and Structural/Cross-Module tests.
    """

    def setUp(self):
        self.parser = PacketParser()
        self.extractor = EventExtractor()
        self.ctx_manager = UEContextManager()
        self.proc_engine = ProcedureAnalysisEngine()

    def test_parser_numeric_pdu_type_zero(self):
        """PARSER-5: Numeric pdu_type '0' mapped to initiatingMessage."""
        pkt = {
            "frame": {"frame.number": ["1"], "frame.time_epoch": ["100.0"], "frame.time": "100.0"},
            "ngap": {
                "ngap.procedureCode": ["21"],
                "ngap.pdu_type": ["0"],
                "ngap.elementaryProcedure": ["ngSetup"]
            }
        }
        parsed = self.parser.parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["message_type"], "NG Setup Request")

    def test_parser_adversarial_substring_order(self):
        """PARSER-6: Adversarial substring order — unsuccessfulOutcome must win over successfulOutcome."""
        pkt = {
            "frame": {"frame.number": ["1"], "frame.time_epoch": ["100.0"], "frame.time": "100.0"},
            "ngap": {
                "ngap.procedureCode": ["21"],
                "ngap.message_type": ["unsuccessfulOutcome successfulOutcome"],
                "ngap.elementaryProcedure": ["ngSetup"]
            }
        }
        parsed = self.parser.parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["message_type"], "NG Setup Failure")

    def test_parser_unrecognized_pdu_type(self):
        """PARSER-7: Unrecognized/out-of-range pdu_type ('3' or 'unknown') handled gracefully."""
        pkt = {
            "frame": {"frame.number": ["1"], "frame.time_epoch": ["100.0"], "frame.time": "100.0"},
            "ngap": {
                "ngap.procedureCode": ["9999"],
                "ngap.pdu_type": ["3"]
            }
        }
        parsed = self.parser.parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["message_type"], "Unknown Signalling")

    def test_parser_truncated_and_missing_fields(self):
        """PARSER-4 / STRUCT-4: Truncated IEs and missing mandatory fields handling."""
        pkt_empty = {}
        self.assertIsNone(self.parser.parse_packet(pkt_empty))

        pkt_truncated = {
            "frame": {"frame.number": ["1"]},
            "ngap": {}
        }
        self.assertIsNone(self.parser.parse_packet(pkt_truncated))

    def test_auth_double_resync(self):
        """AUTH-6: Double-resync test stays INCOMPLETE across multiple synch failures."""
        import trace_auth_cases
        trace_auth_cases.test_auth_6_double_resync()

    def test_auth_mid_second_procedure_timeout(self):
        """AUTH-7: Mid-second-procedure timeout preserves evidence of 2nd Auth Request."""
        import trace_auth_cases
        trace_auth_cases.test_auth_7_mid_second_procedure_timeout()

    def test_pdu_out_of_order_setup_unsuccessful(self):
        """PDU-5: NGAP Setup Unsuccessful arrives before NAS Accept."""
        import trace_pdu_cases
        trace_pdu_cases.test_pdu_5_out_of_order_setup_unsuccessful()

    def test_pdu_id_reuse(self):
        """PDU-6: Reused pdu_id does not bleed state across sessions."""
        import trace_pdu_cases
        trace_pdu_cases.test_pdu_6_pdu_id_reuse()

    def test_pdu_late_ngap_failure_with_abnormal_release(self):
        """PDU-7: Combined late NGAP failure with abnormal release."""
        import trace_pdu_cases
        trace_pdu_cases.test_pdu_7_late_ngap_failure_with_abnormal_release()

    def test_ngs_retry_exhaustion(self):
        """NGS-6: 4 repeated NG Setup failures with TimeToWait triggers terminal FAILED state."""
        import verify_ng_setup
        verify_ng_setup.test_ngs_6_retry_exhaustion()

    def test_ngs_timetowait_expires_no_retry(self):
        """NGS-7: TimeToWait expires with no retry received stays INCOMPLETE."""
        import verify_ng_setup
        verify_ng_setup.test_ngs_7_timetowait_expires_no_retry()

    def test_ngs_fresh_request_during_open_retry_window(self):
        """NGS-8: Fresh NG Setup Request during retry window supersedes old attempt."""
        import verify_ng_setup
        verify_ng_setup.test_ngs_8_fresh_request_during_open_retry_window()

    def test_sec_command_retransmission(self):
        """SEC-3: Security Mode Command retransmission is appended to same procedure."""
        analyzer = __import__("ngap_analyzer.procedure_engine.security_analyzer", fromlist=["SecurityAnalyzer"]).SecurityAnalyzer()
        evt1 = ProtocolEvent(frame_number=1, timestamp=100.0, timestamp_str="100.0", protocol="NAS", direction="AMF -> gNB", message_type="Security Mode Command")
        evt2 = ProtocolEvent(frame_number=2, timestamp=100.5, timestamp_str="100.5", protocol="NAS", direction="AMF -> gNB", message_type="Security Mode Command")
        evt2.is_retransmission = True
        evt3 = ProtocolEvent(frame_number=3, timestamp=100.6, timestamp_str="100.6", protocol="NAS", direction="gNB -> AMF", message_type="Security Mode Complete")
        procs = analyzer.analyze([evt1, evt2, evt3])
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.COMPLETED)
        self.assertEqual(len(procs[0].events), 3)

    def test_sec_reject_then_retry(self):
        """SEC-4: Security Mode Reject followed by new Security Mode Command."""
        analyzer = __import__("ngap_analyzer.procedure_engine.security_analyzer", fromlist=["SecurityAnalyzer"]).SecurityAnalyzer()
        evt1 = ProtocolEvent(frame_number=1, timestamp=100.0, timestamp_str="100.0", protocol="NAS", direction="AMF -> gNB", message_type="Security Mode Command")
        evt2 = ProtocolEvent(frame_number=2, timestamp=100.1, timestamp_str="100.1", protocol="NAS", direction="gNB -> AMF", message_type="Security Mode Reject", cause_code="5GMM cause: 24")
        evt3 = ProtocolEvent(frame_number=3, timestamp=100.5, timestamp_str="100.5", protocol="NAS", direction="AMF -> gNB", message_type="Security Mode Command")
        evt4 = ProtocolEvent(frame_number=4, timestamp=100.6, timestamp_str="100.6", protocol="NAS", direction="gNB -> AMF", message_type="Security Mode Complete")
        procs = analyzer.analyze([evt1, evt2, evt3, evt4])
        self.assertEqual(len(procs), 2)
        self.assertEqual(procs[0].status, ProcedureStatus.FAILED)
        self.assertEqual(procs[1].status, ProcedureStatus.COMPLETED)

    def test_trn_sctp_abort_by_cause_chunk(self):
        """TRN-3: SCTP Abort classified by specific cause chunk."""
        analyzer = __import__("ngap_analyzer.procedure_engine.transport_analyzer", fromlist=["TransportAnalyzer"]).TransportAnalyzer()
        evt1 = ProtocolEvent(frame_number=1, timestamp=100.0, timestamp_str="100.0", protocol="SCTP", direction="gNB <-> AMF", message_type="SCTP Abort", cause_code="User Initiated Abort")
        evt2 = ProtocolEvent(frame_number=2, timestamp=101.0, timestamp_str="101.0", protocol="SCTP", direction="gNB <-> AMF", message_type="SCTP Abort", cause_code="Protocol Violation")
        procs = analyzer.analyze([evt1, evt2])
        self.assertEqual(len(procs), 2)
        self.assertEqual(procs[0].status, ProcedureStatus.FAILED)
        self.assertEqual(procs[0].failure_cause, "User Initiated Abort")
        self.assertEqual(procs[1].status, ProcedureStatus.FAILED)
        self.assertEqual(procs[1].failure_cause, "Protocol Violation")

    def test_trn_sctp_abort_mid_flight_procedure(self):
        """TRN-4 / CROSS-1: SCTP Abort mid-flight during higher-layer procedure marks procedure FAILED."""
        reg_analyzer = __import__("ngap_analyzer.procedure_engine.registration_analyzer", fromlist=["RegistrationAnalyzer"]).RegistrationAnalyzer()
        evt1 = ProtocolEvent(frame_number=1, timestamp=100.0, timestamp_str="100.0", protocol="NAS", direction="gNB -> AMF", message_type="Registration Request")
        evt2 = ProtocolEvent(frame_number=2, timestamp=100.1, timestamp_str="100.1", protocol="SCTP", direction="gNB <-> AMF", message_type="SCTP Abort", cause_code="User Initiated Abort")
        procs = reg_analyzer.analyze([evt1, evt2])
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.FAILED)
        self.assertEqual(procs[0].failure_cause, "User Initiated Abort")

    def test_reg_duplicate_starter_request(self):
        """REG-1: Duplicate starter Registration Request flushes old as INCOMPLETE (superseded)."""
        import trace_registration_cases
        trace_registration_cases.test_reg_1_duplicate_starter_request()

    def test_reg_successful_full_handshake(self):
        """REG-2: Successful Registration with optional Registration Complete step."""
        import trace_registration_cases
        trace_registration_cases.test_reg_2_successful_registration_with_complete()

    def test_reg_successful_periodic_update(self):
        """REG-3: Successful Registration without Registration Complete step."""
        import trace_registration_cases
        trace_registration_cases.test_reg_3_successful_registration_without_complete()

    def test_reg_reject_with_5gmm_cause(self):
        """REG-4: Registration Reject with 5GMM cause."""
        import trace_registration_cases
        trace_registration_cases.test_reg_4_registration_reject()

    def test_reg_superseded_mid_flight(self):
        """REG-5: Registration superseded mid-flight by new Request."""
        import trace_registration_cases
        trace_registration_cases.test_reg_5_registration_superseded_mid_flight()

    def test_struct_cross_module_ng_setup_racing_pdu(self):
        """STRUCT-3: Interleaving test — NG Setup retry racing PDU session establishment."""
        global_events = [
            ProtocolEvent(frame_number=1, timestamp=100.0, timestamp_str="100.0", protocol="NGAP", direction="gNB -> AMF", message_type="NG Setup Request"),
            ProtocolEvent(frame_number=2, timestamp=100.1, timestamp_str="100.1", protocol="NGAP", direction="AMF -> gNB", message_type="NG Setup Failure", cause_code="NGAP cause (misc): unspecified (6) timeToWait: v5s"),
        ]
        ue_events = [
            ProtocolEvent(frame_number=3, timestamp=101.0, timestamp_str="101.0", protocol="NAS", direction="gNB -> AMF", message_type="PDU Session Establishment Request", pdu_session_id=1),
            ProtocolEvent(frame_number=4, timestamp=101.1, timestamp_str="101.1", protocol="NAS", direction="AMF -> gNB", message_type="PDU Session Establishment Accept", pdu_session_id=1),
        ]
        global_events.append(ProtocolEvent(frame_number=5, timestamp=105.2, timestamp_str="105.2", protocol="NGAP", direction="gNB -> AMF", message_type="NG Setup Request"))
        global_events.append(ProtocolEvent(frame_number=6, timestamp=105.3, timestamp_str="105.3", protocol="NGAP", direction="AMF -> gNB", message_type="NG Setup Response"))

        ng_procs = self.proc_engine.ng_setup_analyzer.analyze(global_events)
        pdu_procs = self.proc_engine.pdu_analyzer.analyze(ue_events)

        self.assertEqual(len(ng_procs), 1)
        self.assertEqual(ng_procs[0].status, ProcedureStatus.COMPLETED)
        self.assertEqual(len(pdu_procs), 1)
        self.assertEqual(pdu_procs[0].status, ProcedureStatus.COMPLETED)

    def test_struct_out_of_order_frames(self):
        """STRUCT-1: Out-of-order frame arrival handling."""
        events = [
            ProtocolEvent(frame_number=2, timestamp=100.1, timestamp_str="100.1", protocol="NAS", direction="AMF -> gNB", message_type="Registration Accept"),
            ProtocolEvent(frame_number=1, timestamp=100.0, timestamp_str="100.0", protocol="NAS", direction="gNB -> AMF", message_type="Registration Request"),
        ]
        # When sorted by frame_number or timestamp:
        sorted_events = sorted(events, key=lambda e: e.frame_number)
        procs = self.proc_engine.registration_analyzer.analyze(sorted_events)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].status, ProcedureStatus.COMPLETED)

    def test_struct_duplicate_frame_numbers(self):
        """STRUCT-2: Duplicate frame numbers in input packet stream."""
        events = [
            ProtocolEvent(frame_number=1, timestamp=100.0, timestamp_str="100.0", protocol="NAS", direction="gNB -> AMF", message_type="Registration Request"),
            ProtocolEvent(frame_number=1, timestamp=100.0, timestamp_str="100.0", protocol="NAS", direction="gNB -> AMF", message_type="Registration Request"),
            ProtocolEvent(frame_number=2, timestamp=100.1, timestamp_str="100.1", protocol="NAS", direction="AMF -> gNB", message_type="Registration Accept"),
        ]
        procs = self.proc_engine.registration_analyzer.analyze(events)
        self.assertEqual(len(procs), 2)
        self.assertEqual(procs[0].status, ProcedureStatus.INCOMPLETE)
        self.assertEqual(procs[1].status, ProcedureStatus.COMPLETED)


if __name__ == "__main__":
    unittest.main()

