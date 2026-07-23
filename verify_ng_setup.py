"""
Trace verification script for NG Setup Analyzer (Module D).
Tests NG Setup procedure state machine, TimeToWait handling, retry exhaustion, and supersede logic.
"""

from ngap_analyzer.models import ProtocolEvent, ProcedureStatus
from ngap_analyzer.procedure_engine.ng_setup_analyzer import NGSetupAnalyzer


def make_event(msg_type, cause=None, frame=1, ts=100.0, is_fresh=False):
    event = ProtocolEvent(
        frame_number=frame,
        timestamp=ts,
        timestamp_str=str(ts),
        protocol="NGAP",
        direction="gNB -> AMF" if "Request" in msg_type else "AMF -> gNB",
        message_type=msg_type,
        cause_code=cause,
    )
    if is_fresh:
        event.is_fresh = True
    return event


def test_ngs_1_successful_setup():
    analyzer = NGSetupAnalyzer()
    events = [
        make_event("NG Setup Request", frame=1, ts=100.0),
        make_event("NG Setup Response", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.COMPLETED


def test_ngs_2_hard_failure():
    analyzer = NGSetupAnalyzer()
    events = [
        make_event("NG Setup Request", frame=1, ts=100.0),
        make_event("NG Setup Failure", cause="NGAP cause (radioNetwork): unknown-plmn (0)", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.FAILED


def test_ngs_3_retryable_failure_and_success():
    analyzer = NGSetupAnalyzer()
    events = [
        make_event("NG Setup Request", frame=1, ts=100.0),
        make_event("NG Setup Failure", cause="NGAP cause (misc): unspecified (6) timeToWait: v5s", frame=2, ts=100.1),
        make_event("NG Setup Request", frame=3, ts=105.2),
        make_event("NG Setup Response", frame=4, ts=105.3),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.COMPLETED
    assert len(procs[0].events) == 4


def test_ngs_4_retryable_failure_capture_ended():
    analyzer = NGSetupAnalyzer()
    events = [
        make_event("NG Setup Request", frame=1, ts=100.0),
        make_event("NG Setup Failure", cause="NGAP cause (misc): unspecified (6) timeToWait: v5s", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.INCOMPLETE
    assert "timeToWait" in str(procs[0].evidence) or "timeToWait" in " ".join(procs[0].observations).lower()


def test_ngs_5_superseded_request():
    analyzer = NGSetupAnalyzer()
    events = [
        make_event("NG Setup Request", frame=1, ts=100.0),
        make_event("NG Setup Request", frame=2, ts=100.5),
        make_event("NG Setup Response", frame=3, ts=100.6),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 2
    assert procs[0].status == ProcedureStatus.INCOMPLETE
    assert procs[1].status == ProcedureStatus.COMPLETED


def test_ngs_6_retry_exhaustion():
    """
    NGS-6: Retry exhaustion test
    Request -> Failure+TTW -> Request -> Failure+TTW -> Request -> Failure+TTW -> Request -> Failure+TTW
    Assert terminal state FAILED after 3 retries (4 failures total).
    """
    analyzer = NGSetupAnalyzer()
    events = []
    frame = 1
    ts = 100.0
    # 4 attempts (1 initial + 3 retries) all ending in Failure with TimeToWait
    for i in range(4):
        events.append(make_event("NG Setup Request", frame=frame, ts=ts))
        frame += 1
        ts += 0.1
        events.append(make_event("NG Setup Failure", cause="NGAP cause (misc): unspecified (6) timeToWait: v5s", frame=frame, ts=ts))
        frame += 1
        ts += 5.0

    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.FAILED
    assert "retry limit" in procs[0].failure_cause.lower() or "exhausted" in procs[0].failure_cause.lower()


def test_ngs_7_timetowait_expires_no_retry():
    """
    NGS-7: TimeToWait expires with no retry ever received
    Request -> Failure+TTW -> (capture continues / ends)
    Assert procedure remains INCOMPLETE with observation noting TTW without retry.
    """
    analyzer = NGSetupAnalyzer()
    events = [
        make_event("NG Setup Request", frame=1, ts=100.0),
        make_event("NG Setup Failure", cause="NGAP cause (misc): unspecified (6) timeToWait: v10s", frame=2, ts=100.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 1
    assert procs[0].status == ProcedureStatus.INCOMPLETE
    obs = " ".join(procs[0].observations)
    assert "awaiting gNB retry" in obs or "no retry Request seen" in obs


def test_ngs_8_fresh_request_during_open_retry_window():
    """
    NGS-8: Fresh NG Setup Request arrives during open retry window (Failure+TTW pending).
    Assert old attempt is correctly closed out as INCOMPLETE (superseded) rather than left dangling.
    """
    analyzer = NGSetupAnalyzer()
    events = [
        make_event("NG Setup Request", frame=1, ts=100.0),
        make_event("NG Setup Failure", cause="NGAP cause (misc): unspecified (6) timeToWait: v5s", frame=2, ts=100.1),
        make_event("NG Setup Request", frame=3, ts=102.0, is_fresh=True),
        make_event("NG Setup Response", frame=4, ts=102.1),
    ]
    procs = analyzer.analyze(events)
    assert len(procs) == 2
    assert procs[0].status == ProcedureStatus.INCOMPLETE
    assert "superseded" in " ".join(procs[0].observations).lower()
    assert procs[1].status == ProcedureStatus.COMPLETED


def run_all_tests():
    test_ngs_1_successful_setup()
    test_ngs_2_hard_failure()
    test_ngs_3_retryable_failure_and_success()
    test_ngs_4_retryable_failure_capture_ended()
    test_ngs_5_superseded_request()
    test_ngs_6_retry_exhaustion()
    test_ngs_7_timetowait_expires_no_retry()
    test_ngs_8_fresh_request_during_open_retry_window()
    print("All verify_ng_setup tests passed successfully!")


if __name__ == "__main__":
    run_all_tests()
