"""
Command-Line Interface for NGAP / NAS Wireshark Diagnostic Analyzer.
"""

import argparse
import logging
import sys
from typing import Optional, List

from .packet_reader import PacketReader
from .packet_parser import PacketParser
from .event_extractor import EventExtractor
from .ue_context_manager import UEContextManager
from .procedure_engine.engine import ProcedureAnalysisEngine
from .diagnostic_engine import DiagnosticEngine
from .report_generator import ReportGenerator
from .html_report_generator import HTMLReportGenerator
from .models import DiagnosticReport


def run_analyzer(
    file_path: str,
    use_pyshark: bool = False,
    output_json: bool = False,
    output_html: bool = False,
    output_path: Optional[str] = None
) -> str:
    """
    Executes the full NGAP/NAS analysis pipeline on file_path and returns the formatted report string.
    """
    reader = PacketReader(use_pyshark=use_pyshark)
    parser = PacketParser()
    extractor = EventExtractor()
    ctx_manager = UEContextManager()
    proc_engine = ProcedureAnalysisEngine()
    diag_engine = DiagnosticEngine()
    reporter = ReportGenerator()
    html_reporter = HTMLReportGenerator()

    total_frames = 0
    malformed_count = 0

    for raw_pkt in reader.read_packets(file_path):
        total_frames += 1
        parsed = parser.parse_packet(raw_pkt)
        if not parsed:
            malformed_count += 1
            continue

        event = extractor.extract_event(parsed)
        if not event:
            malformed_count += 1
            continue

        ctx_manager.process_event(event)

    ue_contexts = ctx_manager.get_all_contexts()
    global_events = ctx_manager.get_global_events()

    global_procs = proc_engine.process(ue_contexts, global_events)
    diag_observations = diag_engine.evaluate(ue_contexts, global_procs, global_events)

    report = DiagnosticReport(
        pcap_file=file_path,
        total_frames_analyzed=total_frames,
        malformed_frames_skipped=malformed_count,
        ng_setup_procedures=[p for p in global_procs if p.name == "NG Setup"],
        sctp_events=[e for e in global_events if "SCTP" in e.protocol or "SCTP" in e.message_type],
        ue_contexts=ue_contexts,
        diagnostic_observations=diag_observations
    )

    if output_html:
        formatted_output = html_reporter.generate_html_report(report)
    elif output_json:
        formatted_output = reporter.generate_json_report(report)
    else:
        formatted_output = reporter.generate_console_report(report)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(formatted_output)

    return formatted_output


def main(args_list: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(
        description="NGAP / NAS Wireshark Diagnostic Analyzer - Parse 5G Core captures, reconstruct procedures, and diagnose failures."
    )
    parser.add_argument(
        "-f", "--file", help="Path to PCAP/PCAPNG or exported tshark JSON capture file."
    )
    parser.add_argument(
        "-g", "--gui", action="store_true", help="Launch interactive Web GUI dashboard."
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Port for Web GUI server (default: 8080)."
    )
    parser.add_argument(
        "-o", "--output", help="Optional output file path to write results."
    )
    parser.add_argument(
        "--json", action="store_true", help="Export report as structured JSON."
    )
    parser.add_argument(
        "--html", action="store_true", help="Export report as interactive standalone HTML dashboard."
    )
    parser.add_argument(
        "--pyshark", action="store_true", help="Force using PyShark decoder instead of tshark JSON subprocess."
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose debug logging."
    )

    args = parser.parse_args(args_list)

    if args.gui:
        import os
        from server import start_server
        start_server(port=args.port)
        return

    if not args.file:
        parser.error("The --file / -f argument is required unless running in --gui mode.")

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    try:
        report_text = run_analyzer(
            file_path=args.file,
            use_pyshark=args.pyshark,
            output_json=args.json,
            output_html=args.html,
            output_path=args.output
        )
        if args.output:
            print(f"[+] Diagnostic report successfully written to: {args.output}")
        else:
            print(report_text)
    except Exception as e:
        print(f"Error executing analysis: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
