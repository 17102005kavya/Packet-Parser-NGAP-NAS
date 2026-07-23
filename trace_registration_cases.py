"""
Trace verification script for Registration Analyzer (Missing Component).
Tests Registration procedure state machine, duplicate starter requests, full handshakes, periodic updates, and failures.
"""

from ngap_analyzer.models import ProtocolEvent, ProcedureStatus
from ngap_analyzer.procedure_engine.registration_analyzer import RegistrationAnalyzer


def make_event(msg_type, cause=None, frame=1, ts=100.0):
    return ProtocolEvent(
        frame_number=frame,
        timestamp=ts,
        timestamp_str=str(ts),
        protocol="NAS",
        direction="gNB -> AMF" if "Request" in msg_type or "Complete" in msg_type else "AMF -> gNB",
        message_type=msg_type,
        cause_code=cause,
    )


def test_reg_1_duplicate_starter_request():
    """
    REG-1: Duplicate starter Registration Request arrives before first completes.
    Assert no silent overwrite: first flushed as INCOMPLETE (superseded), second handled.
    """
    analyzer = RegistrationAnalyzer()
    events = [
        make_event("Registration Request", frame=1, ts=100.0),
        make_event("Registration Request", frame=2, ts=100.5),
        make_event("Registration Accept", frame=3, ts=100.6),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 2
    assert procs[0].status == ProcedureStatus.INCOMPLETE
    assert "superseded" in " ".join(procs[0].observations).lower()
    assert procs[1].status == ProcedureStatus.COMPLETED


def test_reg_2_successful_registration_with_complete():
    """
    REG-2: Successful Registration with optional Registration Complete step present.
    Assert 1 COMPLETED procedure with full 3-step handshake observation.
    """
    analyzer = RegistrationAnalyzer()
    events = [
        make_event("Registration Request", frame=1, ts=100.0),
        make_event("Registration Accept", frame=2, ts=100.1),
        make_event("Registration Complete", frame=3, ts=100.2),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.COMPLETED
    assert "full handshake" in " ".join(procs[0].observations).lower()


def test_reg_3_successful_registration_without_complete():
    """
    REG-3: Successful Registration with Registration Complete step absent.
    Assert 1 COMPLETED procedure (normal for mobility / periodic registration updates).
    """
    analyzer = RegistrationAnalyzer()
    events = [
        make_event("Registration Request", frame=1, ts=100.0),
        make_event("Registration Accept", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.COMPLETED


def test_reg_4_registration_reject():
    """
    REG-4: Registration Reject with specific 5GMM cause.
    Assert 1 FAILED procedure with failure_cause set to cause.
    """
    analyzer = RegistrationAnalyzer()
    events = [
        make_event("Registration Request", frame=1, ts=100.0),
        make_event("Registration Reject", cause="5GMM/5GSM cause: Illegal UE (3)", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.FAILED
    assert "Illegal UE" in procs[0].failure_cause


def test_reg_5_registration_superseded_mid_flight():
    """
    REG-5: Registration superseded by new Request mid-flight.
    Request 1 -> Request 2 -> Accept 2.
    Assert Procedure 1 is INCOMPLETE and Procedure 2 is COMPLETED.
    """
    analyzer = RegistrationAnalyzer()
    events = [
        make_event("Registration Request", frame=1, ts=100.0),
        make_event("Registration Request", frame=2, ts=101.0),
        make_event("Registration Accept", frame=3, ts=101.1),
        make_event("Registration Complete", frame=4, ts=101.2),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 2
    assert procs[0].status == ProcedureStatus.INCOMPLETE
    assert procs[1].status == ProcedureStatus.COMPLETED


def run_all_tests():
    test_reg_1_duplicate_starter_request()
    test_reg_2_successful_registration_with_complete()
    test_reg_3_successful_registration_without_complete()
    test_reg_4_registration_reject()
    test_reg_5_registration_superseded_mid_flight()
    print("All trace_registration_cases tests passed successfully!")


if __name__ == "__main__":
    run_all_tests()
