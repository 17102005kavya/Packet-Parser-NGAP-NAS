"""
Web GUI Server for NGAP / NAS Wireshark Diagnostic Analyzer.
Provides a local HTTP server with API endpoints for file uploads, analysis, and sample data.
"""

import json
import logging
import os
import re
import sys
import tempfile
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from ngap_analyzer.cli import run_analyzer
from ngap_analyzer.models import DiagnosticReport

logger = logging.getLogger(__name__)

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


class AnalyzerHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/sample":
            self.send_sample_data()
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/analyze":
            self.handle_analyze_upload()
        else:
            self.send_error(404, "Endpoint not found")

    def send_sample_data(self):
        sample_path = os.path.join(os.path.dirname(__file__), "tests", "test_sample.json")
        if not os.path.exists(sample_path):
            # Create inline sample JSON if not present
            sample_data = self._generate_sample_report()
            self._send_json(sample_data)
            return

        try:
            report_out = run_analyzer(sample_path, output_json=True)
            self._send_json(json.loads(report_out))
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

    def handle_analyze_upload(self):
        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", 0))

        if content_length == 0:
            self._send_json({"error": "No file content uploaded"}, status=400)
            return

        body = self.rfile.read(content_length)

        # Handle multipart/form-data or raw binary/json
        filename = "uploaded_capture.pcap"
        file_bytes = body

        if "boundary=" in content_type:
            boundary = content_type.split("boundary=")[1].encode()
            parts = body.split(b"--" + boundary)
            for part in parts:
                if b'filename="' in part:
                    header, content = part.split(b"\r\n\r\n", 1)
                    file_bytes = content.rsplit(b"\r\n", 1)[0]
                    # Extract filename if possible
                    fn_match = re.search(r'filename="([^"]+)"', header.decode("utf-8", "ignore"))
                    if fn_match:
                        filename = fn_match.group(1)
                    break

        suffix = ".json" if filename.endswith(".json") else ".pcap"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_file.write(file_bytes)
            temp_path = temp_file.name

        try:
            report_json_str = run_analyzer(temp_path, output_json=True)
            report_dict = json.loads(report_json_str)
            report_dict["pcap_file"] = filename
            self._send_json(report_dict)
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            self._send_json({"error": str(e)}, status=500)
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _generate_sample_report(self):
        return {
            "pcap_file": "5g_n2_sample_capture.pcap",
            "total_frames_analyzed": 48,
            "malformed_frames_skipped": 0,
            "global_observations": [
                "NG Setup completed successfully on gNB-01.",
                "SCTP association active (Port 38412)."
            ],
            "ng_setup_procedures": [
                {
                    "name": "NG Setup",
                    "status": "Completed",
                    "start_time": 100.0,
                    "end_time": 100.05,
                    "last_observed_msg": "NG Setup Response",
                    "expected_next_msg": None,
                    "failure_cause": None,
                    "evidence": ["NG Setup Response frame 2"],
                    "observations": ["NG Setup completed successfully."],
                    "events_frames": [1, 2]
                }
            ],
            "sctp_events": [],
            "ue_contexts": [
                {
                    "context_id": "UE_1",
                    "ran_ue_ngap_id": 15,
                    "amf_ue_ngap_id": 302,
                    "fiveg_s_tmsi": "24601-01-0000000015",
                    "gnb_ip": "192.168.1.10",
                    "amf_ip": "192.168.1.50",
                    "procedures": [
                        {"name": "Registration", "status": "Completed", "last_observed_msg": "Registration Accept", "expected_next_msg": None, "failure_cause": None, "evidence": [], "observations": ["Registration completed successfully."], "events_frames": [3, 4, 5, 6, 7]},
                        {"name": "Authentication", "status": "Completed", "last_observed_msg": "Authentication Response", "expected_next_msg": None, "failure_cause": None, "evidence": [], "observations": ["Authentication Successful"], "events_frames": [4, 5]},
                        {"name": "Security Mode", "status": "Completed", "last_observed_msg": "Security Mode Complete", "expected_next_msg": None, "failure_cause": None, "evidence": [], "observations": ["Security Completed"], "events_frames": [6, 7]},
                        {"name": "PDU Session Establishment (ID: 1)", "status": "Completed", "last_observed_msg": "PDU Session Establishment Accept", "expected_next_msg": None, "failure_cause": None, "evidence": [], "observations": ["PDU Session Established"], "events_frames": [8, 9]}
                    ],
                    "explicit_failures": [],
                    "incomplete_procedures": [],
                    "diagnostic_observations": [
                        "NG Setup completed successfully.",
                        "Identifier continuity maintained.",
                        "No protocol anomalies detected."
                    ],
                    "timeline": [
                        {"frame_number": 3, "timestamp": "100.100", "protocol": "NGAP", "direction": "gNB -> AMF", "message_type": "Initial UE Message", "procedure_code": "14", "cause_code": None, "ran_ue_ngap_id": 15, "amf_ue_ngap_id": None, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.50", "src_port": 38412, "dst_port": 38412, "sctp_stream": 1},
                        {"frame_number": 4, "timestamp": "100.120", "protocol": "NAS", "direction": "AMF -> gNB", "message_type": "Authentication Request", "procedure_code": "15", "cause_code": None, "ran_ue_ngap_id": 15, "amf_ue_ngap_id": 302, "src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "src_port": 38412, "dst_port": 38412, "sctp_stream": 1},
                        {"frame_number": 5, "timestamp": "100.150", "protocol": "NAS", "direction": "gNB -> AMF", "message_type": "Authentication Response", "procedure_code": "16", "cause_code": None, "ran_ue_ngap_id": 15, "amf_ue_ngap_id": 302, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.50", "src_port": 38412, "dst_port": 38412, "sctp_stream": 1},
                        {"frame_number": 6, "timestamp": "100.180", "protocol": "NAS", "direction": "AMF -> gNB", "message_type": "Security Mode Command", "procedure_code": "15", "cause_code": None, "ran_ue_ngap_id": 15, "amf_ue_ngap_id": 302, "src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "src_port": 38412, "dst_port": 38412, "sctp_stream": 1},
                        {"frame_number": 7, "timestamp": "100.210", "protocol": "NAS", "direction": "gNB -> AMF", "message_type": "Security Mode Complete", "procedure_code": "16", "cause_code": None, "ran_ue_ngap_id": 15, "amf_ue_ngap_id": 302, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.50", "src_port": 38412, "dst_port": 38412, "sctp_stream": 1},
                        {"frame_number": 8, "timestamp": "100.250", "protocol": "NAS", "direction": "AMF -> gNB", "message_type": "Registration Accept", "procedure_code": "15", "cause_code": None, "ran_ue_ngap_id": 15, "amf_ue_ngap_id": 302, "src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "src_port": 38412, "dst_port": 38412, "sctp_stream": 1}
                    ]
                },
                {
                    "context_id": "UE_2",
                    "ran_ue_ngap_id": 22,
                    "amf_ue_ngap_id": 318,
                    "fiveg_s_tmsi": None,
                    "gnb_ip": "192.168.1.10",
                    "amf_ip": "192.168.1.50",
                    "procedures": [
                        {"name": "Registration", "status": "Failed", "last_observed_msg": "Registration Reject", "expected_next_msg": None, "failure_cause": "5GMM cause: 3 (Illegal UE)", "evidence": ["Registration Reject in frame 14"], "observations": ["Registration Failed: 5GMM cause: 3 (Illegal UE)"], "events_frames": [10, 11, 12, 14]},
                        {"name": "Authentication", "status": "Failed", "last_observed_msg": "Authentication Failure", "expected_next_msg": None, "failure_cause": "MAC failure", "evidence": ["Authentication Failure in frame 12"], "observations": ["Authentication Failed: MAC failure"], "events_frames": [11, 12]}
                    ],
                    "explicit_failures": [
                        {"procedure": "Authentication Failure", "cause": "MAC failure", "evidence": ["Authentication Failure in frame 12"], "frames": [12]},
                        {"procedure": "Registration Reject", "cause": "Authentication failure (MAC failure)", "evidence": ["Registration Reject in frame 14"], "frames": [14]}
                    ],
                    "incomplete_procedures": [],
                    "diagnostic_observations": [
                        "Authentication Failure caused Registration termination."
                    ],
                    "timeline": [
                        {"frame_number": 10, "timestamp": "200.000", "protocol": "NGAP", "direction": "gNB -> AMF", "message_type": "Initial UE Message", "procedure_code": "14", "cause_code": None, "ran_ue_ngap_id": 22, "amf_ue_ngap_id": None, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.50", "src_port": 38412, "dst_port": 38412, "sctp_stream": 2},
                        {"frame_number": 11, "timestamp": "200.050", "protocol": "NAS", "direction": "AMF -> gNB", "message_type": "Authentication Request", "procedure_code": "15", "cause_code": None, "ran_ue_ngap_id": 22, "amf_ue_ngap_id": 318, "src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "src_port": 38412, "dst_port": 38412, "sctp_stream": 2},
                        {"frame_number": 12, "timestamp": "200.100", "protocol": "NAS", "direction": "gNB -> AMF", "message_type": "Authentication Failure", "procedure_code": "16", "cause_code": "5GMM/5GSM cause: MAC failure", "ran_ue_ngap_id": 22, "amf_ue_ngap_id": 318, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.50", "src_port": 38412, "dst_port": 38412, "sctp_stream": 2},
                        {"frame_number": 14, "timestamp": "200.200", "protocol": "NAS", "direction": "AMF -> gNB", "message_type": "Registration Reject", "procedure_code": "15", "cause_code": "5GMM/5GSM cause: Authentication failure", "ran_ue_ngap_id": 22, "amf_ue_ngap_id": 318, "src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "src_port": 38412, "dst_port": 38412, "sctp_stream": 2}
                    ]
                },
                {
                    "context_id": "UE_3",
                    "ran_ue_ngap_id": 40,
                    "amf_ue_ngap_id": "(not yet assigned)",
                    "fiveg_s_tmsi": None,
                    "gnb_ip": "192.168.1.10",
                    "amf_ip": "192.168.1.50",
                    "procedures": [
                        {"name": "Registration", "status": "Incomplete", "last_observed_msg": "Initial UE Message", "expected_next_msg": "Registration Accept / Reject", "failure_cause": None, "evidence": ["Capture ended after frame 30"], "observations": ["Registration procedure incomplete."], "events_frames": [30]}
                    ],
                    "explicit_failures": [],
                    "incomplete_procedures": [
                        {"procedure": "Registration", "last_observed": "Initial UE Message", "expected": "Registration Accept / Reject", "evidence": ["Capture ended before response"], "frames": [30]}
                    ],
                    "diagnostic_observations": [
                        "Insufficient evidence to classify outcome."
                    ],
                    "timeline": [
                        {"frame_number": 30, "timestamp": "300.000", "protocol": "NGAP", "direction": "gNB -> AMF", "message_type": "Initial UE Message", "procedure_code": "14", "cause_code": None, "ran_ue_ngap_id": 40, "amf_ue_ngap_id": None, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.50", "src_port": 38412, "dst_port": 38412, "sctp_stream": 3}
                    ]
                }
            ],
            "diagnostic_observations": [
                {
                    "rule_id": "RULE_UE_01",
                    "title": "Authentication Failure Impact",
                    "severity": "ERROR",
                    "description": "Authentication failure triggered Registration termination.",
                    "evidence": ["MAC failure frame 12"],
                    "related_frames": [12, 14]
                }
            ]
        }


def start_server(port: int = 8080, open_browser: bool = True):
    server_address = ("", port)
    httpd = HTTPServer(server_address, AnalyzerHTTPRequestHandler)
    url = f"http://localhost:{port}"
    print(f"\n====================================================")
    print(f"[+] NGAP / NAS Web GUI Server Running at:")
    print(f"    --> {url}")
    print(f"====================================================\n")

    if open_browser:
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Web GUI Server.")
        httpd.server_close()


if __name__ == "__main__":
    start_server()
