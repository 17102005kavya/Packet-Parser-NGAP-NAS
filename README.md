# NGAP / NAS Wireshark Diagnostic Analyzer

A PCAP-based tool for parsing 5G NGAP and NAS signalling, detecting protocol failures, reconstructing procedure state machines, and reporting UE context state.

---

## Executive Overview

Diagnosing 5G Core signalling issues on the N2 interface between gNB and AMF often involves manually searching through Wireshark frames, correlating `RAN UE NGAP ID` and `AMF UE NGAP ID`, and determining procedure outcomes by hand.

This tool automates 5G N2 diagnostic triage:
1. Decodes NGAP and embedded NAS-5GS signalling using Wireshark `tshark` / `PyShark`.
2. Correlates events into per-UE contexts, dynamically mapping `RAN UE NGAP ID` and `AMF UE NGAP ID` pairs.
3. Reconstructs multi-message signalling procedures (NG Setup, Registration, Authentication, Security Mode, PDU Session Establishment, Context Setup/Release, SCTP lifecycle).
4. Distinguishes **Confirmed Protocol Failures** (with explicit cause codes) from **Incomplete Procedures** (truncated captures).
5. Applies a **Rule-Based Diagnostic Engine** to produce explainable, traceable diagnostic observations.

---

## System Architecture

```
+------------------+     +-------------------+     +----------------------+
| PCAP/PCAPNG File | --> | PyShark / tshark  | --> |    Packet Parser     |
+------------------+     +-------------------+     +----------------------+
                                                               |
                                                               v
+------------------+     +-------------------+     +----------------------+
|  Final Report    | <-- | Diagnostic Engine | <-- | UE Context Manager   |
|  Console / JSON  |     +-------------------+     | & Procedure Engine   |
+------------------+                               +----------------------+
```

### Modular Pipeline
- **`packet_reader.py`**: Loads capture files via `tshark` JSON output or `PyShark`.
- **`packet_parser.py`**: Extracts procedure codes, cause codes, IDs, and NAS payloads.
- **`event_extractor.py`**: Normalizes raw layer structures into `ProtocolEvent` dataclasses.
- **`ue_context_manager.py`**: Manages `UEContext` instances and maps RAN <-> AMF ID pairing.
- **`procedure_engine/`**: Reconstructs procedure state machines (`Registration`, `Authentication`, `Security Mode`, `PDU Session`, `NG Setup`, `UE Context Setup/Release`, `Transport`).
- **`diagnostic_engine.py`**: Evaluates cross-procedure diagnostic rules.
- **`report_generator.py`**: Formats console summary text and structured JSON export.

---

## Prerequisites & Installation

### 1. Requirements
- **Python**: Version 3.8 or higher.
- **Wireshark / tshark**: Installed on system and added to system PATH (`tshark -v`).

#### Installing `tshark`
- **Windows**: Install Wireshark from [wireshark.org](https://www.wireshark.org/) and ensure *tshark* is included in your system PATH (e.g., `C:\Program Files\Wireshark`).
- **Linux (Ubuntu/Debian)**: `sudo apt-get update && sudo apt-get install -y tshark wireshark`
- **macOS**: `brew install wireshark`

### 2. Python Dependencies
Install required Python packages:
```bash
pip install -r requirements.txt
```

---

## Usage Guide

### Launch Web GUI Dashboard
Launch an interactive, glassmorphism dark-mode web dashboard in your browser:
```bash
python main.py --gui
# or specify custom port
python main.py --gui --port 8080
```
Open `http://localhost:8080` in your web browser to drag & drop `.pcap` / `.json` files, view live metrics, filter UE contexts, and inspect 5G signalling sequence diagrams.

### Basic Invocation (CLI)
Analyze a `.pcap` or `.pcapng` capture file and render a per-UE diagnostic summary:
```bash
python main.py -f path/to/capture.pcap
```

### Save Report to File
```bash
python main.py -f path/to/capture.pcap -o report.txt
```

### Export Machine-Readable JSON
```bash
python main.py -f path/to/capture.pcap --json -o report.json
```

### Force PyShark Decoder Mode
```bash
python main.py -f path/to/capture.pcap --pyshark
```

### Enable Verbose Debug Logging
```bash
python main.py -f path/to/capture.pcap -v
```

---

## Sample Console Output

```text
====================================================
      NGAP / NAS DIAGNOSTIC ANALYZER REPORT         
====================================================
Capture File          : sample_capture.pcap
Total Frames Analyzed : 42
Malformed Skipped     : 0
Total UEs Identified  : 1

====================================================
UE Context Summary
RAN UE NGAP ID : 22
AMF UE NGAP ID : 318
----------------------------------------------------
Procedures
 Registration Failed
 Authentication Failed
----------------------------------------------------
Explicit Failures
 Authentication Failure (5GMM/5GSM cause: MAC failure)
 Registration Reject (5GMM/5GSM cause: Authentication failure)
----------------------------------------------------
Incomplete Procedures
 None
----------------------------------------------------
Diagnostic Observations
 Authentication Failure caused Registration termination.
====================================================
```

---

## Deployment & Automation Plan

### 1. Standalone / CLI Deployment
Copy the package folder to any workstation with Python 3 and Wireshark installed:
```bash
python -m unittest discover -s tests
```

### 2. CI/CD & Automated PCAP Triage Pipeline
Integrate PCAP triage into test pipelines or network log aggregators:

```bash
# Process a folder of PCAP captures and generate JSON reports
for file in captures/*.pcap; do
    python main.py -f "$file" --json -o "${file%.pcap}_report.json"
done
```

### 3. Docker Deployment Containerization
Create a `Dockerfile` for standardized server/cloud deployment:

```dockerfile
FROM python:3.11-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "main.py"]
```

Build and run container:
```bash
docker build -t ngap-analyzer .
docker run --rm -v $(pwd)/captures:/data ngap-analyzer -f /data/capture.pcap --json -o /data/report.json
```

---

## Running Unit Tests

To run the automated unit test suite:
```bash
python -m unittest discover -s tests
```

---

## Troubleshooting

1. **`tshark executable is not found in system PATH`**
   - Ensure Wireshark is installed and `tshark` is added to your PATH environment variable.
   - Verify by running `tshark --version` in your terminal.

2. **Decryption of Ciphered NAS Signalling**
   - NAS messages exchanged after `Security Mode Complete` may be ciphered. `tshark` decodes message headers, presence, and timing. For full deciphering of encrypted NAS payloads, pass keylogs to `tshark` or Wireshark preferences.
