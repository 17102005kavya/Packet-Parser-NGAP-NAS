# 5G NGAP/NAS Packet Parser & Diagnostic Suite
## System Architecture & Developer Reference Guide

---

## 1. Executive Summary & Purpose

The **5G NGAP/NAS Packet Parser** is a specialized control plane analysis tool designed to ingest raw Wireshark packet captures (`.pcap` / `.pcapng` / `.json`), parse 3GPP TS 38.413 (NGAP) and TS 24.501 (5GS NAS) signaling traces, reconstruct end-to-end subscriber procedure state machines, and automatically detect protocol anomalies, timeouts, and network failures.

Unlike static PCAP viewers that operate on isolated packets, this application maintains **stateful subscriber contexts** across transient identifiers (`5G-S-TMSI`, `RAN-UE-NGAP-ID`, `AMF-UE-NGAP-ID`) and evaluates sequence timing, procedure latencies, and protocol violations.

---

## 2. High-Level System Architecture

The pipeline consists of six decoupled architectural layers:

```
[Raw Capture Input (.pcap / .json)]
                 │
                 ▼
[Packet Ingestion & Parsing Layer (tshark wrapper & ASN.1 tree decoder)]
                 │
                 ▼
[UE Context Correlation Engine (RAN-UE-ID / AMF-UE-ID / 5G-S-TMSI mapping)]
                 │
                 ▼
[Procedure Reconstruction Engine (15+ 3GPP TS 38.413 / TS 24.501 State Engines)]
                 │
                 ▼
[Diagnostic & Anomaly Framework (Timeout, Retransmission, Cause Classifier)]
                 │
                 ▼
[Presentation & API Layer (CLI / Standalone HTML / REST Web GUI Dashboard)]
```

### Module Overview

```
Packet Parser/
├── main.py                          # CLI / Server entry point & orchestration
├── server.py                        # Embedded HTTP REST server & Web GUI backend
├── ngap_analyzer/
│   ├── models.py                    # Domain models (ProtocolEvent, UEContext, Procedure)
│   ├── packet_reader.py             # tshark execution wrapper & JSON stream reader
│   ├── packet_parser.py             # ASN.1 / tshark JSON tree parser & dynamic decoder
│   ├── ue_context_manager.py        # Subscriber identifier correlation & timeline builder
│   ├── diagnostic_engine.py         # Multi-procedure anomaly detection & rule engine
│   ├── html_report_generator.py     # Standalone HTML report generator with embedded GUI
│   └── procedure_engine/
│       ├── engine.py                # Procedure orchestrator
│       ├── registration_analyzer.py # TS 24.501 Registration procedure state engine
│       ├── authentication_analyzer.py# TS 38.413 / 24.501 Auth procedure state engine
│       ├── security_analyzer.py     # Security Mode Command/Complete state engine
│       ├── service_request_analyzer.# Service Request & Service Accept/Reject engine
│       ├── pdu_session_analyzer.py  # PDU Session Setup/Modify/Release state engine
│       ├── ue_context_analyzer.py   # Initial Context Setup & Context Release engine
│       ├── paging_analyzer.py       # TS 38.413 Paging & UE response timing engine
│       ├── handover_analyzer.py     # N2 Handover state machine lifecycle engine
│       ├── path_switch_analyzer.py  # Path Switch Request/Ack/Failure engine
│       ├── config_update_analyzer.py# AMF, RAN, & UE Configuration Update engine
│       ├── identity_procedure_analyzer.py # Identity Request/Response state engine
│       ├── nas_non_delivery_analyzer.py   # NAS Non-Delivery & Reroute Request engine
│       ├── error_indication_analyzer.py   # Error Indication & trigger correlation engine
│       ├── nrppa_transport_analyzer.py    # UE & Non-UE Associated NRPPa transport engine
│       ├── trace_analyzer.py        # Trace Control & Cell Traffic Trace engine
│       ├── timeout_detector.py      # Configurable threshold timeout detector
│       ├── retransmission_detector.py # Duplicate capture vs. retransmission classifier
│       └── unclassified_collector.py# Fallback unclassified event tracker
└── web/                             # Web GUI frontend SPA (Vanilla JS + Glassmorphism CSS)
```

---

## 3. Core Subsystems & Technical Details

### A. Packet Ingestion & Dynamic Parsing Layer (`packet_reader.py`, `packet_parser.py`)
- **Tshark Integration**: Executes `tshark -T json -2 -R "ngap || nas_5gs"` to extract deep protocol field trees.
- **Dynamic Tree Traversal**: Uses `_find_key_recursive()` and `_discover_procedure_name_from_tree()` to dynamically discover procedure names directly from `NGAP_PDU_tree` ASN.1 elements without relying exclusively on hardcoded lookup tables.
- **ASN.1 / PDU Type Normalization**: Resolves numeric PDU choices (`0 = initiatingMessage`, `1 = successfulOutcome`, `2 = unsuccessfulOutcome`) and handles Wireshark schema variations across different versions.

### B. UE Context Correlation Engine (`ue_context_manager.py`)
Subscribers transition across temporary IDs during connection establishment. The `UEContextManager` maintains three concurrent mapping tables:
1. `ran_id_map`: Maps `RAN_UE_NGAP_ID` $\rightarrow$ `UEContext`
2. `amf_id_map`: Maps `AMF_UE_NGAP_ID` $\rightarrow$ `UEContext`
3. `tmsi_map`: Maps `5G-S-TMSI` $\rightarrow$ `UEContext`

When a packet arrives (e.g., a `Paging` command carrying only `5G-S-TMSI`, followed by an `Initial UE Message` allocating a `RAN_UE_NGAP_ID`), the manager dynamically links all three IDs to a single unified `UEContext` timeline.

### C. Procedure State Engines (`procedure_engine/`)
Procedure reconstruction follows 3GPP TS 38.413 and TS 24.501 specifications:
- **Registration**: Tracks `Registration Request` $\rightarrow$ `Registration Accept` $\rightarrow$ `Registration Complete` (or `Registration Reject`). Handles optional 2-step updates where `Registration Complete` is omitted.
- **PDU Session Management**: Tracks multi-session PDU setup, modification, and release.
- **Handovers & Path Switch**: Tracks N2 Handover lifecycle (`Handover Required` $\rightarrow$ `Request` $\rightarrow$ `Ack` $\rightarrow$ `Command` $\rightarrow$ `Notify`), measures phase latencies, and tracks cancellations.
- **Paging**: Tracks `Paging` commands, calculates latency to the subsequent `Initial UE Message` / `Service Request`, and flags unanswered pages.

### D. Generic Timeout Framework (`timeout_detector.py`)
Applies configurable per-procedure timeout thresholds (e.g., Registration: 6s, Handover: 10s, Auth: 4s). Scans incomplete procedures against the capture's latest timestamp to flag unresponded requests and infer probable root causes (e.g., radio link failure, packet loss).

### E. Retransmission vs. Duplicate Capture Classifier (`retransmission_detector.py`)
Analyzes chronological deltas ($\Delta t$) between consecutive identical messages:
$$\text{Classification} = \begin{cases} \text{Duplicate Capture (Double-logging)}, & \Delta t < 50\text{ ms} \\ \text{Legitimate Protocol Retransmission}, & \Delta t \ge 50\text{ ms} \end{cases}$$

### F. Diagnostic Engine (`diagnostic_engine.py`)
Applies rule-based anomaly evaluation to generate observations for:
- Benign releases vs. explicit failures (e.g., ignoring normal handover releases like `ims-voice-eps-fallback-or-rat-fallback-triggered`).
- Authentication or Security Mode rejects causing registration termination.
- Unanswered paging, high latency warnings, and protocol error indications.

---

## 4. Execution & API Modes

1. **CLI Mode**:
   ```bash
   python main.py --pcap capture.pcap --json report.json --html report.html
   ```
2. **Web GUI Dashboard**:
   ```bash
   python main.py --gui --port 8080
   ```
3. **Docker Containerization**:
   ```bash
   docker-compose up -d --build
   ```

---

## 5. Verification & Testing Standards

The repository contains a 76-test suite in `tests/test_analyzer.py` executing full regression testing across procedure state machines, timeout logic, retransmissions, and diagnostic outputs.
