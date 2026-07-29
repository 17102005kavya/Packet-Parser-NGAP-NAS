"""
Command-Line Interface for NGAP / NAS Wireshark Diagnostic Analyzer.

Provides CLI entry points for parsing 5G Core packet captures, executing diagnostic
evaluations, exporting JSON/HTML reports, or launching the web GUI dashboard.
"""

import argparse
import logging
import os
import sys
from typing import List, Optional

from .diagnostic_engine import DiagnosticEngine
from .event_extractor import EventExtractor
from .html_report_generator import HTMLReportGenerator
from .models import DiagnosticReport
from .packet_parser import PacketParser
from .packet_reader import PacketReader
from .procedure_engine.engine import ProcedureAnalysisEngine
from .report_generator import ReportGenerator
from .ue_context_manager import UEContextManager

DEFAULT_WEB_PORT: int = 8080
PROCEDURE_NG_SETUP: str = "NG Setup"
PROTOCOL_SCTP: str = "SCTP"


def run_analyzer(
    file_path: str,
    use_pyshark: bool = False,
    output_json: bool = False,
    output_html: bool = False,
    output_path: Optional[str] = None,
) -> str:
    """
    Executes the full NGAP/NAS analysis pipeline on file_path and returns the formatted report string.

    Args:
        file_path: Path to input PCAP/PCAPNG or pre-parsed JSON capture file.
        use_pyshark: Whether to force PyShark engine instead of tshark JSON.
        output_json: Whether to format output as structured JSON.
        output_html: Whether to format output as standalone HTML dashboard.
        output_path: Optional output file path to write results.

    Returns:
        Formatted report string (Console text, JSON, or HTML).
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
        ng_setup_procedures=[p for p in global_procs if p.name == PROCEDURE_NG_SETUP],
        sctp_events=[
            e for e in global_events if PROTOCOL_SCTP in e.protocol or PROTOCOL_SCTP in e.message_type
        ],
        ue_contexts=ue_contexts,
        diagnostic_observations=diag_observations,
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


def main(args_list: Optional[List[str]] = None) -> None:
    """
    Main entry point for command-line execution.

    Args:
        args_list: Optional list of argument strings for testing programmatic invocation.
    """
    parser = argparse.ArgumentParser(
        description=(
            "NGAP / NAS Wireshark Diagnostic Analyzer - "
            "Parse 5G Core captures, reconstruct procedures, and diagnose failures."
        )
    )
    parser.add_argument(
        "-f", "--file", help="Path to PCAP/PCAPNG or exported tshark JSON capture file."
    )
    parser.add_argument(
        "-g", "--gui", action="store_true", help="Launch interactive Web GUI dashboard."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_WEB_PORT,
        help=f"Port for Web GUI server (default: {DEFAULT_WEB_PORT}).",
    )
    parser.add_argument(
        "-o", "--output", help="Optional output file path to write results."
    )
    parser.add_argument(
        "--json", action="store_true", help="Export report as structured JSON."
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Export report as interactive standalone HTML dashboard.",
    )
    parser.add_argument(
        "--pyshark",
        action="store_true",
        help="Force using PyShark decoder instead of tshark JSON subprocess.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose debug logging."
    )

    args = parser.parse_args(args_list)

    if args.gui:
        from server import start_server

        start_server(port=args.port)
        return

    if not args.file:
        parser.error("The --file / -f argument is required unless running in --gui mode.")

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    try:
        report_text = run_analyzer(
            file_path=args.file,
            use_pyshark=args.pyshark,
            output_json=args.json,
            output_html=args.html,
            output_path=args.output,
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
