"""
Packet Reader module for NGAP / NAS Wireshark Diagnostic Analyzer.

Supports reading packet captures via tshark JSON subprocess output, PyShark FileCapture,
or direct loading of pre-parsed synthetic packet structures for testing and analysis.
"""

import json
import logging
import shutil
import subprocess
from typing import Any, Dict, Generator, Optional

logger = logging.getLogger(__name__)

TSHARK_DISPLAY_FILTER: str = "ngap || nas-5gs || sctp"


class PacketReader:
    """
    Reads packets from PCAP/PCAPNG files via tshark JSON output, PyShark,
    or pre-loaded packet dictionaries.
    """

    def __init__(self, use_pyshark: bool = False) -> None:
        """
        Initializes PacketReader.

        Args:
            use_pyshark: If True, uses PyShark binding instead of tshark JSON subprocess.
        """
        self.use_pyshark = use_pyshark
        self.malformed_count = 0

    @staticmethod
    def is_tshark_available() -> bool:
        """Checks if the tshark binary is accessible in system executable PATH."""
        return shutil.which("tshark") is not None

    def read_packets(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        """
        Reads packet structures from file_path.

        Yields normalized packet dictionary representations containing frame metadata and decoded layers.

        Args:
            file_path: Path to capture file (.pcap, .pcapng, or exported .json).
        """
        self.malformed_count = 0

        # If file_path is a JSON file (e.g. synthetic test capture or exported tshark json)
        if file_path.endswith(".json"):
            yield from self._read_from_json_file(file_path)
            return

        if self.use_pyshark:
            try:
                yield from self._read_with_pyshark(file_path)
                return
            except Exception as e:
                logger.warning(f"PyShark parsing failed ({e}), falling back to tshark JSON process reader.")

        if self.is_tshark_available():
            yield from self._read_with_tshark_json(file_path)
        else:
            raise RuntimeError(
                "tshark executable is not found in system PATH. "
                "Please install Wireshark/tshark or provide a pre-parsed JSON file."
            )

    def _read_from_json_file(self, json_path: str) -> Generator[Dict[str, Any], None, None]:
        """Reads packet structures directly from a JSON capture export file."""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                for packet in data:
                    yield packet
            elif isinstance(data, dict):
                yield data

    def _read_with_tshark_json(self, pcap_path: str) -> Generator[Dict[str, Any], None, None]:
        """Invokes tshark CLI subprocess to decode pcap file to JSON structures."""
        cmd = [
            "tshark",
            "-r", pcap_path,
            "-T", "json",
            "-Y", TSHARK_DISPLAY_FILTER,
        ]
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            stdout, stderr = process.communicate()
            if process.returncode != 0 and not stdout:
                logger.error(f"tshark error: {stderr}")
                return

            if stdout.strip():
                packets = json.loads(stdout)
                for pkt in packets:
                    yield pkt
        except Exception as e:
            logger.error(f"Error executing tshark process: {e}")
            raise

    def _read_with_pyshark(self, pcap_path: str) -> Generator[Dict[str, Any], None, None]:
        """Reads packet frames using PyShark library bindings."""
        import pyshark  # type: ignore

        capture = pyshark.FileCapture(
            pcap_path,
            display_filter=TSHARK_DISPLAY_FILTER,
            keep_packets=False,
        )
        for pkt in capture:
            try:
                pkt_dict = self._pyshark_pkt_to_dict(pkt)
                yield pkt_dict
            except Exception as e:
                self.malformed_count += 1
                logger.debug(f"Skipping malformed pyshark packet: {e}")
        capture.close()

    def _pyshark_pkt_to_dict(self, pkt: Any) -> Dict[str, Any]:
        """Translates PyShark packet object properties into normalized dictionary structure."""
        layers = {}
        for layer in pkt.layers:
            layer_name = layer.layer_name.lower()
            layer_dict = {}
            for field in layer.field_names:
                try:
                    layer_dict[field] = getattr(layer, field)
                except Exception:
                    pass
            layers[layer_name] = layer_dict

        frame_num = int(pkt.number)
        time_epoch = float(pkt.sniff_timestamp) if hasattr(pkt, "sniff_timestamp") else 0.0
        time_str = str(pkt.sniff_time) if hasattr(pkt, "sniff_time") else ""

        return {
            "_source": {
                "layers": {
                    "frame": {
                        "frame.number": [str(frame_num)],
                        "frame.time_epoch": [str(time_epoch)],
                        "frame.time": [time_str],
                    },
                    **layers,
                }
            }
        }
