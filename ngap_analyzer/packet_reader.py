"""
Packet Reader module for NGAP / NAS Wireshark Diagnostic Analyzer.
Supports PyShark FileCapture, tshark -T json subprocess output parsing,
and synthetic packet loading for standalone execution/testing.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Dict, Any, Generator, List, Optional

logger = logging.getLogger(__name__)


class PacketReader:
    """
    Reads packets from PCAP/PCAPNG files via tshark JSON output, PyShark,
    or pre-loaded packet dictionaries.
    """

    def __init__(self, use_pyshark: bool = False):
        self.use_pyshark = use_pyshark
        self.malformed_count = 0

    @staticmethod
    def is_tshark_available() -> bool:
        return shutil.which("tshark") is not None

    def read_packets(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        """
        Reads packet structures from file_path.
        Yields normalized packet dictionary representations containing frame metadata and decoded layers.
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
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                for packet in data:
                    yield packet
            elif isinstance(data, dict):
                yield data

    def _read_with_tshark_json(self, pcap_path: str) -> Generator[Dict[str, Any], None, None]:
        cmd = [
            "tshark",
            "-r", pcap_path,
            "-T", "json",
            "-Y", "ngap || nas-5gs || sctp"
        ]
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
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
        import pyshark  # type: ignore

        capture = pyshark.FileCapture(
            pcap_path,
            display_filter="ngap || nas-5gs || sctp",
            keep_packets=False
        )
        for pkt in capture:
            try:
                pkt_dict = self._pyshark_pkt_to_dict(pkt)
                yield pkt_dict
            except Exception as e:
                self.malformed_count += 1
                logger.debug(f"Skipping malformed pyshark packet: {e}")
        capture.close()

    def _pyshark_pkt_to_dict(self, pkt) -> Dict[str, Any]:
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
        time_epoch = float(pkt.sniff_timestamp) if hasattr(pkt, 'sniff_timestamp') else 0.0
        time_str = str(pkt.sniff_time) if hasattr(pkt, 'sniff_time') else ""

        return {
            "_source": {
                "layers": {
                    "frame": {
                        "frame.number": [str(frame_num)],
                        "frame.time_epoch": [str(time_epoch)],
                        "frame.time": [time_str]
                    },
                    **layers
                }
            }
        }
