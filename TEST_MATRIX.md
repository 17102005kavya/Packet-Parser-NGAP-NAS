# NGAP/NAS Diagnostic Tool — Master Test Matrix & Verification Coverage

Verified against **3GPP TS 38.413 (NGAP)** and **TS 24.501 (NAS-5GS)**.

## Automated Checklist Status

> [!NOTE]
> **Programmatically Generated Count**: **51/51 Pytest / Unittest Tests Passing** (100% Pass Rate).
> Master Test Matrix Rows Defined: **48 test scenarios**.

### Module Summary Breakdown
| Module | Test IDs | Matrix Row Count |
| :--- | :--- | :---: |
| Module A — Packet Parser | 9 scenarios | 9 |
| Module B — Authentication Analyzer | 7 scenarios | 7 |
| Module C — PDU Session Analyzer | 7 scenarios | 7 |
| Module D — NG Setup Analyzer | 8 scenarios | 8 |
| Module E — Transport & Security | 8 scenarios | 8 |
| Registration Analyzer | 5 scenarios | 5 |
| Structural / Cross-Module | 4 scenarios | 4 |
| **Total Matrix Scenarios** | **48 scenarios** | **48** |

---

## Master Test Matrix Table

| Test ID | Module | Scenario / Description | Input Event Sequence | Expected Outcome | Assertion |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `PARSER-1` | Module A — Packet Parser | Basic field extraction from valid NGAP/NAS structure | `Frame with procedureCode 14, RAN UE ID 15, AMF UE ID 302, Reg Request` | Fields parsed into ProtocolEvent cleanly | `parsed['ran_ue_ngap_id'] == 15 and parsed['amf_ue_ngap_id'] == 302 and parsed['message_type'] == 'Registration Request'` |
| `PARSER-2` | Module A — Packet Parser | tshark wrapped field values (lists of objects) | `Layer dict with values wrapped in [{'raw': 'val'}]` | Unwrapped raw values extracted as ints/strings | `_extract_int(layer, ['ngap.AMF_UE_NGAP_ID']) == 302 and _extract_str(layer, ['ngap.nas']) == '1'` |
| `PARSER-3` | Module A — Packet Parser | Cause IE extraction priority (specific vs choice-tag) | `NGAP layer containing causeRadioNetwork: 21 and generic cause choice tag: 0` | Specific radioNetwork category extracted, unresolved choice tag ignored | `cause_code == 'NGAP cause (radioNetwork): radio-connection-with-ue-lost (21)'` |
| `PARSER-4` | Module A — Packet Parser | Truncated IEs / missing optional fields | `Malformed packet missing mandatory layers or truncated frame dict` | Returns None cleanly without raising unhandled exception | `parse_packet(truncated_pkt) is None` |
| `PARSER-5` | Module A — Packet Parser | Numeric pdu_type: '0' normalization | `NGAP PDU containing pdu_type: '0' and procedureCode 21 (ngSetup)` | Normalized to 'initiatingMessage' -> NG Setup Request | `parsed['message_type'] == 'NG Setup Request'` |
| `PARSER-6` | Module A — Packet Parser | Adversarial substring-order test | `PDU message element containing both 'unsuccessfulOutcome' and 'successfulOutcome'` | Unsuccessful outcome branch checked first and wins | `parsed['message_type'] == 'NG Setup Failure'` |
| `PARSER-7` | Module A — Packet Parser | Unrecognized / out-of-range pdu_type ('3' or 'unknown') | `NGAP PDU with pdu_type: '3' and unknown procedureCode 9999` | Handled gracefully, surfaces as Unknown Signalling | `parsed['message_type'] == 'Unknown Signalling' and parsed['procedure_code'] == '9999'` |
| `PARSER-8` | Module A — Packet Parser | Malformed packet payload (non-dict or corrupt tree) | `Corrupt JSON dict passed to parse_packet` | Returns None without crash | `parse_packet(corrupt_payload) is None` |
| `PARSER-9` | Module A — Packet Parser | Duplicate frame numbers or out-of-order timestamps in raw input | `Packets with duplicate frame.number: '1' or reverse time_epoch` | Parser extracts fields consistently for downstream sorting | `parsed1['frame_number'] == 1 and parsed2['frame_number'] == 1` |
| `AUTH-1` | Module B — Authentication Analyzer | Successful 2-step Authentication handshake | `Auth Request -> Auth Response` | Procedure status COMPLETED | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED` |
| `AUTH-2` | Module B — Authentication Analyzer | Explicit Auth Failure with non-synch cause | `Auth Request -> Auth Failure (MAC failure)` | Procedure status FAILED, failure_cause set | `procs[0].status == ProcedureStatus.FAILED and procs[0].failure_cause == '5GMM/5GSM cause: MAC failure'` |
| `AUTH-3` | Module B — Authentication Analyzer | Auth Failure with synch failure (#21) and no retry | `Auth Request -> Auth Failure (cause #21) -> capture end` | Procedure status INCOMPLETE (awaiting resync retry) | `procs[0].status == ProcedureStatus.INCOMPLETE and 'resync' in ' '.join(procs[0].observations).lower()` |
| `AUTH-4` | Module B — Authentication Analyzer | Full 4-step SQN resync cycle | `Auth Req -> Auth Fail(#21) -> Auth Req -> Auth Resp` | 1 single procedure status COMPLETED (4 events) | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED and len(procs[0].events) == 4` |
| `AUTH-5` | Module B — Authentication Analyzer | Authentication Reject from AMF | `Auth Request -> Auth Reject` | Procedure status FAILED | `procs[0].status == ProcedureStatus.FAILED and procs[0].failure_cause == '5GMM/5GSM cause: Illegal UE'` |
| `AUTH-6` | Module B — Authentication Analyzer | Double-resync test (consecutive SQN synch failures) | `Auth Req -> Auth Fail(#21) -> Auth Req -> Auth Fail(#21)` | Procedure remains INCOMPLETE awaiting retry, tracks 4 events in single procedure | `len(procs) == 1 and procs[0].status == ProcedureStatus.INCOMPLETE and len(procs[0].events) == 4` |
| `AUTH-7` | Module B — Authentication Analyzer | Mid-second-procedure timeout (timeout after 2nd Auth Request) | `Auth Req -> Auth Fail(#21) -> Auth Req -> (unrelated traffic / capture end)` | Handled as INCOMPLETE with evidence highlighting frame of 2nd Auth Request | `procs[0].status == ProcedureStatus.INCOMPLETE and procs[0].last_observed_msg == 'Authentication Request'` |
| `PDU-1` | Module C — PDU Session Analyzer | Successful PDU Session establishment (NAS + NGAP layers) | `NAS Request -> NAS Accept, NGAP Request -> NGAP Response` | 2 procedures (NAS & NGAP) status COMPLETED | `len(procs) == 2 and all(p.status == ProcedureStatus.COMPLETED for p in procs)` |
| `PDU-2` | Module C — PDU Session Analyzer | Late NGAP Resource Setup failure | `NAS Accept (COMPLETED), NGAP Resource Setup Unsuccessful (FAILED)` | NAS procedure COMPLETED, NGAP procedure FAILED, non-interfering | `nas_proc.status == ProcedureStatus.COMPLETED and ngap_proc.status == ProcedureStatus.FAILED` |
| `PDU-3` | Module C — PDU Session Analyzer | Normal PDU Session Release | `Release Command (normal cause) -> Release Response` | Procedure status COMPLETED | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED` |
| `PDU-4` | Module C — PDU Session Analyzer | Abnormal PDU Session Release | `Release Command (radio-connection-lost) -> Release Response` | Procedure status FAILED, failure_cause set | `len(procs) == 1 and procs[0].status == ProcedureStatus.FAILED and procs[0].failure_cause == 'radio-connection-with-ue-lost'` |
| `PDU-5` | Module C — PDU Session Analyzer | Out-of-order variant of PDU-B (NGAP failure before NAS Accept) | `NAS Req -> NGAP Req -> NGAP Setup Unsuccessful -> NAS Accept` | NGAP procedure FAILED, NAS procedure COMPLETED, failure attached to pdu_id | `ngap_proc.status == ProcedureStatus.FAILED and nas_proc.status == ProcedureStatus.COMPLETED` |
| `PDU-6` | Module C — PDU Session Analyzer | pdu_id reuse after release | `Session 1 (pdu_id=5) released -> Session 2 (pdu_id=5) established` | State cleanly separated across sessions, no bleed-through | `len(nas_procs) == 2 and all(p.status == ProcedureStatus.COMPLETED for p in nas_procs)` |
| `PDU-7` | Module C — PDU Session Analyzer | Combined late NGAP failure with abnormal release | `NAS Accept -> NGAP Setup Unsuccessful -> Release Command (abnormal)` | NGAP Setup FAILED, Release FAILED, handled without crash | `ngap_proc.status == ProcedureStatus.FAILED and rel_proc.status == ProcedureStatus.FAILED` |
| `NGS-1` | Module D — NG Setup Analyzer | Successful NG Setup | `NG Setup Request -> NG Setup Response` | Procedure status COMPLETED | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED` |
| `NGS-2` | Module D — NG Setup Analyzer | Hard (non-retryable) NG Setup failure | `NG Setup Request -> NG Setup Failure (unknown-plmn)` | Procedure status FAILED | `len(procs) == 1 and procs[0].status == ProcedureStatus.FAILED` |
| `NGS-3` | Module D — NG Setup Analyzer | Retryable failure with TimeToWait followed by retry and success | `Request -> Failure+TTW -> Request -> Response` | 1 procedure status COMPLETED (after retry) | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED and len(procs[0].events) == 4` |
| `NGS-4` | Module D — NG Setup Analyzer | Retryable failure with TimeToWait, capture ended before retry | `Request -> Failure+TTW -> capture end` | Procedure status INCOMPLETE | `len(procs) == 1 and procs[0].status == ProcedureStatus.INCOMPLETE` |
| `NGS-5` | Module D — NG Setup Analyzer | Superseded NG Setup Request | `Request 1 -> Request 2 -> Response 2` | Request 1 INCOMPLETE (superseded), Request 2 COMPLETED | `procs[0].status == ProcedureStatus.INCOMPLETE and procs[1].status == ProcedureStatus.COMPLETED` |
| `NGS-6` | Module D — NG Setup Analyzer | Retry exhaustion (repeated failures past limit) | `Request -> Failure+TTW (x4, max retries 3)` | Terminal status FAILED with failure_cause 'NG Setup retry limit (3) exhausted' | `procs[0].status == ProcedureStatus.FAILED and 'exhausted' in procs[0].failure_cause.lower()` |
| `NGS-7` | Module D — NG Setup Analyzer | TimeToWait expires with no retry received | `Request -> Failure+TTW -> capture continues without retry` | Procedure status INCOMPLETE, observation notes TTW without retry | `procs[0].status == ProcedureStatus.INCOMPLETE and 'awaiting gNB retry' in ' '.join(procs[0].observations)` |
| `NGS-8` | Module D — NG Setup Analyzer | Fresh NG Setup Request during open retry window | `Request 1 -> Failure+TTW -> Request 2 (is_fresh=True) -> Response 2` | Request 1 closed as INCOMPLETE (superseded), Request 2 COMPLETED | `procs[0].status == ProcedureStatus.INCOMPLETE and procs[1].status == ProcedureStatus.COMPLETED` |
| `SEC-1` | Module E — Transport & Security | Successful Security Mode procedure | `Security Mode Command -> Security Mode Complete` | Procedure status COMPLETED | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED` |
| `SEC-2` | Module E — Transport & Security | Security Mode Reject from UE | `Security Mode Command -> Security Mode Reject` | Procedure status FAILED | `len(procs) == 1 and procs[0].status == ProcedureStatus.FAILED` |
| `SEC-3` | Module E — Transport & Security | Security Mode Command retransmission | `Command -> Command (retransmission) -> Complete` | 1 procedure status COMPLETED with retransmission observation | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED and len(procs[0].events) == 3` |
| `SEC-4` | Module E — Transport & Security | Security Mode Reject-then-retry | `Command 1 -> Reject 1, Command 2 -> Complete 2` | Procedure 1 FAILED, Procedure 2 COMPLETED | `procs[0].status == ProcedureStatus.FAILED and procs[1].status == ProcedureStatus.COMPLETED` |
| `TRN-1` | Module E — Transport & Security | SCTP Init and Shutdown events | `SCTP Init -> SCTP Shutdown` | 2 procedures status COMPLETED (graceful transport lifecycle) | `len(procs) == 2 and all(p.status == ProcedureStatus.COMPLETED for p in procs)` |
| `TRN-2` | Module E — Transport & Security | NG Reset procedure pair | `NG Reset -> NG Reset Acknowledge` | 1 procedure status COMPLETED | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED` |
| `TRN-3` | Module E — Transport & Security | SCTP Abort categorized by cause chunk | `SCTP Abort ('User Initiated') -> SCTP Abort ('Protocol Violation')` | 2 procedures status FAILED with exact failure_cause classification | `procs[0].failure_cause == 'User Initiated Abort' and procs[1].failure_cause == 'Protocol Violation'` |
| `TRN-4` | Module E — Transport & Security | SCTP Abort mid-flight higher-layer procedure | `Registration Request open -> SCTP Abort` | Higher-layer procedure status FAILED with failure_cause set to SCTP Abort | `procs[0].status == ProcedureStatus.FAILED and procs[0].failure_cause == 'User Initiated Abort'` |
| `REG-1` | Registration Analyzer | Duplicate starter Registration Request before first completes | `Registration Request 1 -> Registration Request 2 -> Accept 2` | Request 1 INCOMPLETE (superseded), Request 2 COMPLETED | `procs[0].status == ProcedureStatus.INCOMPLETE and procs[1].status == ProcedureStatus.COMPLETED` |
| `REG-2` | Registration Analyzer | Successful Registration with optional Registration Complete step | `Registration Request -> Registration Accept -> Registration Complete` | 1 procedure status COMPLETED with full 3-step handshake observation | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED and 'full handshake' in ' '.join(procs[0].observations).lower()` |
| `REG-3` | Registration Analyzer | Successful Registration without Registration Complete step | `Registration Request -> Registration Accept` | 1 procedure status COMPLETED (periodic/mobility update) | `len(procs) == 1 and procs[0].status == ProcedureStatus.COMPLETED` |
| `REG-4` | Registration Analyzer | Registration Reject with 5GMM cause | `Registration Request -> Registration Reject (Illegal UE)` | Procedure status FAILED, failure_cause set to 5GMM cause | `procs[0].status == ProcedureStatus.FAILED and 'Illegal UE' in procs[0].failure_cause` |
| `REG-5` | Registration Analyzer | Registration superseded mid-flight by new Request | `Registration Request 1 -> Registration Request 2 -> Accept 2 -> Complete 2` | Procedure 1 INCOMPLETE (superseded), Procedure 2 COMPLETED | `procs[0].status == ProcedureStatus.INCOMPLETE and procs[1].status == ProcedureStatus.COMPLETED` |
| `STRUCT-1` | Structural / Cross-Module | Out-of-order frame arrival in multi-message sequence | `Accept (frame 2) -> Request (frame 1) sorted by frame number` | Extracted and reconstructed correctly as COMPLETED | `procs[0].status == ProcedureStatus.COMPLETED` |
| `STRUCT-2` | Structural / Cross-Module | Duplicate frame numbers in input packet stream | `Request (frame 1) -> Request (frame 1) -> Accept (frame 2)` | First Request superseded (INCOMPLETE), second Request COMPLETED | `procs[0].status == ProcedureStatus.INCOMPLETE and procs[1].status == ProcedureStatus.COMPLETED` |
| `STRUCT-3` | Structural / Cross-Module | Cross-module interleaving (NG Setup retry racing PDU Session setup) | `NG Setup Req -> Failure+TTW -> PDU Session Req -> PDU Accept -> NG Setup Retry -> NG Setup Resp` | No cross-layer state leakage; NG Setup COMPLETED, PDU Session COMPLETED | `ng_procs[0].status == ProcedureStatus.COMPLETED and pdu_procs[0].status == ProcedureStatus.COMPLETED` |
| `STRUCT-4` | Structural / Cross-Module | Truncated IEs / missing mandatory fields across all procedure engines | `ProtocolEvent objects with cause_code=None or missing pdu_session_id` | Analyzers apply defaults gracefully without unhandled exceptions | `No crash raised, sensible status (INCOMPLETE / FAILED) returned` |

---

## Verification Suite & Trace Scripts

The test matrix is validated by the following executable scripts and unit test suite:
1. **`tests/test_analyzer.py`**: Pytest / Unittest suite containing all 51 test cases.
2. **`trace_auth_cases.py`**: Standalone trace verification script for Module B (Authentication).
3. **`trace_pdu_cases.py`**: Standalone trace verification script for Module C (PDU Session).
4. **`verify_ng_setup.py`**: Standalone trace verification script for Module D (NG Setup).
5. **`trace_registration_cases.py`**: Standalone trace verification script for Registration Analyzer.
