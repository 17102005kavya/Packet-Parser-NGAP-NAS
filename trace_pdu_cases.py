"""
Trace verification script for PDU Session Analyzer (Module C).
Tests PDU session establishment, release, out-of-order failures, pdu_id reuse, and abnormal releases.
"""

from ngap_analyzer.models import ProtocolEvent, ProcedureStatus
from ngap_analyzer.procedure_engine.pdu_session_analyzer import PDUSessionAnalyzer


def make_event(msg_type, pdu_id=1, cause=None, frame=1, ts=100.0):
    return ProtocolEvent(
        frame_number=frame,
        timestamp=ts,
        timestamp_str=str(ts),
        protocol="NGAP" if "Resource" in msg_type else "NAS",
        direction="gNB -> AMF" if "Request" in msg_type or "Response" in msg_type else "AMF -> gNB",
        message_type=msg_type,
        cause_code=cause,
        pdu_session_id=pdu_id,
    )


def test_pdu_1_successful_establishment():
    analyzer = PDUSessionAnalyzer()
    events = [
        make_event("PDU Session Establishment Request", pdu_id=1, frame=1, ts=100.0),
        make_event("PDU Session Establishment Accept", pdu_id=1, frame=2, ts=100.1),
        make_event("PDU Session Resource Setup Request", pdu_id=1, frame=3, ts=100.2),
        make_event("PDU Session Resource Setup Response", pdu_id=1, frame=4, ts=100.3),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 2
    assert all(p.status == ProcedureStatus.COMPLETED for p in procs)


def test_pdu_2_late_ngap_failure():
    analyzer = PDUSessionAnalyzer()
    events = [
        make_event("PDU Session Establishment Request", pdu_id=1, frame=1, ts=100.0),
        make_event("PDU Session Establishment Accept", pdu_id=1, frame=2, ts=100.1),
        make_event("PDU Session Resource Setup Request", pdu_id=1, frame=3, ts=100.2),
        make_event("PDU Session Resource Setup Unsuccessful", pdu_id=1, cause="NGAP cause (radioNetwork): radio-resources-not-available (22)", frame=4, ts=100.3),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 2
    nas_proc = [p for p in procs if "NAS" in p.name][0]
    ngap_proc = [p for p in procs if "NGAP" in p.name][0]
    assert nas_proc.status == ProcedureStatus.COMPLETED
    assert ngap_proc.status == ProcedureStatus.FAILED
    assert "radio-resources-not-available" in ngap_proc.failure_cause


def test_pdu_3_normal_release():
    analyzer = PDUSessionAnalyzer()
    events = [
        make_event("PDU Session Resource Release Command", pdu_id=1, cause="NGAP cause (radioNetwork): release-due-to-ngran-generated-reason (3)", frame=1, ts=100.0),
        make_event("PDU Session Resource Release Response", pdu_id=1, frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.COMPLETED


def test_pdu_4_abnormal_release():
    analyzer = PDUSessionAnalyzer()
    events = [
        make_event("PDU Session Resource Release Command", pdu_id=1, cause="NGAP cause (radioNetwork): radio-connection-with-ue-lost (21)", frame=1, ts=100.0),
        make_event("PDU Session Resource Release Response", pdu_id=1, frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.FAILED


def test_pdu_5_out_of_order_setup_unsuccessful():
    """
    PDU-5 / PDU-E: Out-of-order variant of PDU-B
    NGAP Resource Setup Unsuccessful arrives before NAS Establishment Accept is processed.
    Assert failure is correctly attached to right pdu_id and not dropped or misfiled.
    """
    analyzer = PDUSessionAnalyzer()
    events = [
        make_event("PDU Session Establishment Request", pdu_id=2, frame=1, ts=100.0),
        make_event("PDU Session Resource Setup Request", pdu_id=2, frame=2, ts=100.1),
        make_event("PDU Session Resource Setup Unsuccessful", pdu_id=2, cause="NGAP cause (radioNetwork): radio-resources-not-available (22)", frame=3, ts=100.2),
        make_event("PDU Session Establishment Accept", pdu_id=2, frame=4, ts=100.3),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 2
    ngap_proc = [p for p in procs if "NGAP" in p.name][0]
    nas_proc = [p for p in procs if "NAS" in p.name][0]
    assert ngap_proc.status == ProcedureStatus.FAILED
    assert nas_proc.status == ProcedureStatus.COMPLETED


def test_pdu_6_pdu_id_reuse():
    """
    PDU-6 / PDU-F: pdu_id-reuse test
    pdu_id=5 released, then a new session later reuses pdu_id=5.
    Assert composite tracking keys don't bleed state from old session into new session.
    """
    analyzer = PDUSessionAnalyzer()
    events = [
        # Session 1
        make_event("PDU Session Establishment Request", pdu_id=5, frame=1, ts=100.0),
        make_event("PDU Session Establishment Accept", pdu_id=5, frame=2, ts=100.1),
        make_event("PDU Session Resource Release Command", pdu_id=5, cause="NGAP cause (radioNetwork): normal-release (0)", frame=3, ts=100.2),
        make_event("PDU Session Resource Release Response", pdu_id=5, frame=4, ts=100.3),
        # Session 2 reusing pdu_id=5
        make_event("PDU Session Establishment Request", pdu_id=5, frame=5, ts=105.0),
        make_event("PDU Session Establishment Accept", pdu_id=5, frame=6, ts=105.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 3
    # 2 NAS procedures, 1 Release procedure
    nas_procs = [p for p in procs if "NAS" in p.name]
    assert len(nas_procs) == 2
    assert all(p.status == ProcedureStatus.COMPLETED for p in nas_procs)


def test_pdu_7_late_ngap_failure_with_abnormal_release():
    """
    PDU-7 / PDU-G: Combined PDU-B + PDU-E (late NGAP failure with abnormal release)
    A release arrives for a pdu_id that failed NGAP setup.
    Assert graceful handling with no crashes and sensible statuses.
    """
    analyzer = PDUSessionAnalyzer()
    events = [
        make_event("PDU Session Establishment Request", pdu_id=3, frame=1, ts=100.0),
        make_event("PDU Session Establishment Accept", pdu_id=3, frame=2, ts=100.1),
        make_event("PDU Session Resource Setup Request", pdu_id=3, frame=3, ts=100.2),
        make_event("PDU Session Resource Setup Unsuccessful", pdu_id=3, cause="NGAP cause (radioNetwork): radio-resources-not-available (22)", frame=4, ts=100.3),
        make_event("PDU Session Resource Release Command", pdu_id=3, cause="NGAP cause (radioNetwork): radio-connection-with-ue-lost (21)", frame=5, ts=100.4),
        make_event("PDU Session Resource Release Response", pdu_id=3, frame=6, ts=100.5),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 3
    ngap_proc = [p for p in procs if "NGAP" in p.name][0]
    rel_proc = [p for p in procs if "Release" in p.name][0]
    assert ngap_proc.status == ProcedureStatus.FAILED
    assert rel_proc.status == ProcedureStatus.FAILED


def run_all_tests():
    test_pdu_1_successful_establishment()
    test_pdu_2_late_ngap_failure()
    test_pdu_3_normal_release()
    test_pdu_4_abnormal_release()
    test_pdu_5_out_of_order_setup_unsuccessful()
    test_pdu_6_pdu_id_reuse()
    test_pdu_7_late_ngap_failure_with_abnormal_release()
    print("All trace_pdu_cases tests passed successfully!")


if __name__ == "__main__":
    run_all_tests()
