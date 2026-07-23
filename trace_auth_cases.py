"""
Trace verification script for Authentication Analyzer (Module B).
Tests authentication procedure state machines and edge cases.
"""

from ngap_analyzer.models import ProtocolEvent, ProcedureStatus
from ngap_analyzer.procedure_engine.authentication_analyzer import AuthenticationAnalyzer


def make_event(msg_type, cause=None, frame=1, ts=100.0):
    return ProtocolEvent(
        frame_number=frame,
        timestamp=ts,
        timestamp_str=str(ts),
        protocol="NAS",
        direction="gNB -> AMF" if "Response" in msg_type or "Failure" in msg_type else "AMF -> gNB",
        message_type=msg_type,
        cause_code=cause,
    )


def test_auth_1_successful_handshake():
    analyzer = AuthenticationAnalyzer()
    events = [
        make_event("Authentication Request", frame=1, ts=100.0),
        make_event("Authentication Response", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1, f"Expected 1 procedure, got {len(procs)}"
    assert procs[0].status == ProcedureStatus.COMPLETED
    assert len(procs[0].events) == 2


def test_auth_2_explicit_mac_failure():
    analyzer = AuthenticationAnalyzer()
    events = [
        make_event("Authentication Request", frame=1, ts=100.0),
        make_event("Authentication Failure", cause="5GMM/5GSM cause: MAC failure", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.FAILED
    assert procs[0].failure_cause == "5GMM/5GSM cause: MAC failure"


def test_auth_3_synch_failure_no_retry():
    analyzer = AuthenticationAnalyzer()
    events = [
        make_event("Authentication Request", frame=1, ts=100.0),
        make_event("Authentication Failure", cause="5GMM/5GSM cause: 21", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.INCOMPLETE
    assert "resync" in " ".join(procs[0].observations).lower()


def test_auth_4_full_resync_cycle():
    analyzer = AuthenticationAnalyzer()
    events = [
        make_event("Authentication Request", frame=1, ts=100.0),
        make_event("Authentication Failure", cause="5GMM/5GSM cause: 21", frame=2, ts=100.1),
        make_event("Authentication Request", frame=3, ts=100.2),
        make_event("Authentication Response", frame=4, ts=100.3),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.COMPLETED
    assert len(procs[0].events) == 4


def test_auth_5_auth_reject():
    analyzer = AuthenticationAnalyzer()
    events = [
        make_event("Authentication Request", frame=1, ts=100.0),
        make_event("Authentication Reject", cause="5GMM/5GSM cause: Illegal UE", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.FAILED
    assert procs[0].failure_cause == "5GMM/5GSM cause: Illegal UE"


def test_auth_6_double_resync():
    """
    AUTH-6 / AUTH-F: Double resync test
    Auth Req -> Auth Fail(#21) -> Auth Req -> Auth Fail(#21)
    Assert procedure stays INCOMPLETE (awaiting retry) across multiple resync attempts.
    """
    analyzer = AuthenticationAnalyzer()
    events = [
        make_event("Authentication Request", frame=1, ts=100.0),
        make_event("Authentication Failure", cause="5GMM/5GSM cause: 21", frame=2, ts=100.1),
        make_event("Authentication Request", frame=3, ts=100.2),
        make_event("Authentication Failure", cause="5GMM/5GSM cause: 21", frame=4, ts=100.3),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.INCOMPLETE
    assert len(procs[0].events) == 4
    obs = " ".join(procs[0].observations)
    assert "resync" in obs.lower()


def test_auth_7_mid_second_procedure_timeout():
    """
    AUTH-7 / AUTH-G: Mid-second-procedure timeout case
    Auth Req -> Auth Fail(#21) -> Auth Req -> (unrelated traffic / capture end)
    Assert procedure is handled as INCOMPLETE with evidence pointing to frame of 2nd Auth Request.
    """
    analyzer = AuthenticationAnalyzer()
    events = [
        make_event("Authentication Request", frame=1, ts=100.0),
        make_event("Authentication Failure", cause="5GMM/5GSM cause: 21", frame=2, ts=100.1),
        make_event("Authentication Request", frame=3, ts=100.2),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.INCOMPLETE
    assert procs[0].last_observed_msg == "Authentication Request"
    evidence_str = " ".join(procs[0].evidence)
    assert "frame 3" in evidence_str or "frame 3" in str(procs[0].events[-1].frame_number)


def run_all_tests():
    test_auth_1_successful_handshake()
    test_auth_2_explicit_mac_failure()
    test_auth_3_synch_failure_no_retry()
    test_auth_4_full_resync_cycle()
    test_auth_5_auth_reject()
    test_auth_6_double_resync()
    test_auth_7_mid_second_procedure_timeout()
    print("All trace_auth_cases tests passed successfully!")


if __name__ == "__main__":
    run_all_tests()
