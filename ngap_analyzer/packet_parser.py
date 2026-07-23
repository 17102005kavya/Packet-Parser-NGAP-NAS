"""
Packet Parser for NGAP / NAS Wireshark Diagnostic Analyzer.
Extracts raw fields from Wireshark/tshark packet structures.
"""

import logging
import re
import json
from typing import Dict, Any, Optional, Tuple, List

logger = logging.getLogger(__name__)


class PacketParser:
    """
    Parses low-level tshark JSON layer structures and normalizes NGAP, NAS, and SCTP fields.
    """
    NGAP_PROCEDURES = {
        4: "downlinkNASTransport",
        9: "errorIndication",
        14: "initialContextSetup",
        15: "initialUEMessage",
        21: "ngSetup",
        20: "ngReset",
        28: "pduSessionResourceRelease",
        29: "pduSessionResourceSetup",
        41: "uEContextRelease",
        42: "uEContextReleaseRequest",
        46: "uplinkNASTransport",
    }

    def parse_packet(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parses a raw packet dictionary into a normalized dictionary of extracted fields.
        Returns None if packet is malformed or not relevant.
        """
        try:
            layers = self._get_layers(packet)
            if not layers:
                return None

            frame_layer = layers.get("frame", {})
            frame_number = self._extract_int(frame_layer, ["frame.number", "number"]) or 0
            time_epoch = self._extract_float(frame_layer, ["frame.time_epoch", "time_epoch"]) or 0.0
            time_str = self._extract_str(frame_layer, ["frame.time", "time"]) or str(time_epoch)

            # Check for SCTP, NGAP, NAS-5GS layers
            sctp_layer = layers.get("sctp")
            ngap_layer = layers.get("ngap")
            nas_layer = layers.get("nas-5gs") or layers.get("nas_5gs") or layers.get("gsm_a.dtap")

            if not ngap_layer and not sctp_layer and not nas_layer:
                return None

            protocol = "NGAP" if ngap_layer else ("NAS" if nas_layer else "SCTP")

            # Extract IDs
            ran_ue_ngap_id = self._extract_ue_id(ngap_layer, ["ngap.RAN_UE_NGAP_ID", "ngap.ran_ue_ngap_id", "ran_ue_ngap_id"])
            amf_ue_ngap_id = self._extract_ue_id(ngap_layer, ["ngap.AMF_UE_NGAP_ID", "ngap.amf_ue_ngap_id", "amf_ue_ngap_id"])
            tmsi = self._extract_tmsi(ngap_layer, nas_layer)

            # Extract Message Type & Procedure Code
            message_type, procedure_code = self._extract_message_type(ngap_layer, nas_layer, sctp_layer)
            if not message_type:
                return None

            # Extract Direction
            direction = self._determine_direction(ngap_layer, nas_layer, sctp_layer, message_type)

            # Extract Cause Codes
            cause_code = self._extract_cause(ngap_layer, nas_layer)

            # Extract PDU Session ID
            pdu_session_id = self._extract_int(
                ngap_layer, ["ngap.PDUSessionID", "ngap.pdu_session_id"]
            ) or self._extract_int(
                nas_layer, ["nas_5gs.sm.pdu_session_id", "pdu_session_id"]
            )

            # Extract IP & Transport Endpoints
            ip_layer = layers.get("ip") or layers.get("ipv6") or {}
            src_ip = self._extract_str(ip_layer, ["ip.src", "ipv6.src", "src"])
            dst_ip = self._extract_str(ip_layer, ["ip.dst", "ipv6.dst", "dst"])

            src_port = self._extract_int(sctp_layer, ["sctp.srcport", "srcport"])
            dst_port = self._extract_int(sctp_layer, ["sctp.dstport", "dstport"])
            sctp_stream = self._extract_int(sctp_layer, ["sctp.stream", "stream"])

            return {
                "frame_number": frame_number,
                "timestamp": time_epoch,
                "timestamp_str": time_str,
                "protocol": protocol,
                "direction": direction,
                "message_type": message_type,
                "procedure_code": str(procedure_code) if procedure_code is not None else None,
                "cause_code": cause_code,
                "ran_ue_ngap_id": ran_ue_ngap_id,
                "amf_ue_ngap_id": amf_ue_ngap_id,
                "fiveg_s_tmsi": tmsi,
                "pdu_session_id": pdu_session_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "sctp_stream": sctp_stream,
                "raw_layers": layers
            }
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None

    def _get_layers(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        if "_source" in packet and "layers" in packet["_source"]:
            return packet["_source"]["layers"]
        if "layers" in packet:
            return packet["layers"]
        return packet

    def _unwrap_value(self, value: Any) -> Any:
        if isinstance(value, list):
            for item in value:
                unwrapped = self._unwrap_value(item)
                if unwrapped is not None:
                    return unwrapped
            return None

        if isinstance(value, dict):
            for key in ("raw", "value", "showname", "text", "name"):
                if key in value:
                    return self._unwrap_value(value[key])

            if len(value) == 1:
                return self._unwrap_value(next(iter(value.values())))

        return value

    def _search_single_key(self, layer, target_key):
        target_key = target_key.lower()

        if layer is None:
            return None

        if isinstance(layer, dict):
            for k, v in layer.items():
                k_lower = k.lower()

                if (
                    k_lower == target_key
                    or k_lower.endswith("." + target_key)
                    or k_lower.split(".")[-1] == target_key
                ):
                    return self._unwrap_value(v)

                result = self._search_single_key(v, target_key)
                if result is not None:
                    return result

        elif isinstance(layer, list):
            for item in layer:
                result = self._search_single_key(item, target_key)
                if result is not None:
                    return result

        return None

    def _extract_val(self, layer: Optional[Dict[str, Any]], keys: List[str]) -> Any:
        """
        Tries each key in `keys`, IN ORDER, and returns the first match.
        This makes the order of the `keys` list a genuine priority list:
        the first key that matches anywhere in the tree wins, even if a
        later key in the list would have matched something higher up in
        the tree. This matters for fields like NGAP's Cause IE, where a
        generic/ambiguous key (e.g. the outer CHOICE tag "ngap.cause")
        can otherwise shadow a more specific, meaningful key
        (e.g. "ngap.causeRadioNetwork") purely because of tree position.
        """
        if not layer:
            return None

        for key in keys:
            val = self._search_single_key(layer, key.lower())
            if val is not None:
                return val

        return None

    def _extract_str(self, layer: Optional[Dict[str, Any]], keys: List[str]) -> Optional[str]:
        val = self._extract_val(layer, keys)
        if val is not None:
            return str(val)
        return None

    def _extract_int(self, layer: Optional[Dict[str, Any]], keys: List[str]) -> Optional[int]:
        val = self._extract_val(layer, keys)
        if val is not None:
            try:
                if isinstance(val, str) and val.startswith("0x"):
                    return int(val, 16)
                return int(val)
            except ValueError:
                pass
        return None

    def _extract_float(self, layer: Optional[Dict[str, Any]], keys: List[str]) -> Optional[float]:
        val = self._extract_val(layer, keys)
        if val is not None:
            try:
                return float(val)
            except ValueError:
                pass
        return None

    def _extract_ue_id(self, layer: Optional[Dict[str, Any]], keys: List[str]) -> Optional[int]:
        val = self._extract_int(layer, keys)
        return val

    def _extract_tmsi(self, ngap_layer: Optional[Dict[str, Any]], nas_layer: Optional[Dict[str, Any]]) -> Optional[str]:
        tmsi = self._extract_str(ngap_layer, ["ngap.fiveg_s_tmsi", "ngap.5g_s_tmsi", "fiveg_s_tmsi"])
        if not tmsi and nas_layer:
            tmsi = self._extract_str(nas_layer, ["nas_5gs.mm.5g_s_tmsi", "nas_5gs.5g_s_tmsi", "5g_s_tmsi"])
        return tmsi

    def _extract_message_type(
        self,
        ngap_layer: Optional[Dict[str, Any]],
        nas_layer: Optional[Dict[str, Any]],
        sctp_layer: Optional[Dict[str, Any]]
     ) -> Tuple[Optional[str], Optional[int]]:
        procedure_code = self._extract_int(ngap_layer, ["ngap.procedureCode", "procedureCode"])

        # Check NAS Message Type first if present
        nas_msg_type = self._extract_str(nas_layer, [
            "nas_5gs.mm.message_type", "nas_5gs.sm.message_type", "nas_5gs.message_type", "message_type"
        ])

        if nas_msg_type:
            mapped_nas = self._normalize_nas_msg(nas_msg_type)
            if mapped_nas:
                return mapped_nas, procedure_code

        # Next check NGAP Message Type
        ngap_msg_type = self._extract_str(ngap_layer, [
            "ngap.ngap_message_element", "ngap.procedureCode_element", "ngap.message_type"
        ])

        # If ngap layer contains elementary procedure name
        if ngap_layer:
            pdu_type = self._extract_str(
                ngap_layer,
                ["ngap.NGAP_PDU", "ngap.pdu_type", "pdu"]
            )

            # --- Bug fix: normalise numeric pdu_type values ---
            # Older tshark versions (≤ ~3.2) emit the NGAP PDU choice as an
            # integer rather than the symbolic name.  Map them here so all
            # downstream comparisons can use exact string equality.
            #
            # Per TS 38.413 ASN.1:  NGAP-PDU ::= CHOICE {
            #     initiatingMessage   InitiatingMessage,    -- choice index 0
            #     successfulOutcome   SuccessfulOutcome,    -- choice index 1
            #     unsuccessfulOutcome UnsuccessfulOutcome,  -- choice index 2
            # }
            _NUMERIC_PDU_TYPE = {
                "0": "initiatingMessage",
                "1": "successfulOutcome",
                "2": "unsuccessfulOutcome",
            }
            if pdu_type in _NUMERIC_PDU_TYPE:
                pdu_type = _NUMERIC_PDU_TYPE[pdu_type]

            elem_proc = self._extract_str(
                ngap_layer,
                ["ngap.elementaryProcedure", "elementaryProcedure"]
            )

            # If tshark didn't expose elementaryProcedure, infer it from procedureCode
            if not elem_proc and procedure_code is not None:
                elem_proc = self.NGAP_PROCEDURES.get(procedure_code)

            # --- NOTE on substring check order (Bug fix) ---
            # "successfulOutcome" is a strict substring of "unsuccessfulOutcome".
            # Every if-elif below therefore checks "unsuccessfulOutcome" FIRST so
            # that an unsuccessful frame is never misclassified as a success.
            # The preferred path is the exact-match on pdu_type (no ambiguity);
            # the str(ngap_layer) substring check is a fallback for tshark builds
            # that do not emit a separate pdu_type field at all.

            if elem_proc == "initialUEMessage":
                return "Initial UE Message", procedure_code

            elif elem_proc == "ngSetup":
                if pdu_type == "unsuccessfulOutcome" or "unsuccessfulOutcome" in str(ngap_layer):
                    return "NG Setup Failure", procedure_code
                elif pdu_type == "successfulOutcome" or "successfulOutcome" in str(ngap_layer):
                    return "NG Setup Response", procedure_code
                return "NG Setup Request", procedure_code

            elif elem_proc == "downlinkNASTransport":
                return "Downlink NAS Transport", procedure_code

            elif elem_proc == "uplinkNASTransport":
                return "Uplink NAS Transport", procedure_code

            elif elem_proc == "pduSessionResourceSetup":
                if pdu_type == "unsuccessfulOutcome" or "unsuccessfulOutcome" in str(ngap_layer):
                    return "PDU Session Resource Setup Unsuccessful", procedure_code
                elif pdu_type == "successfulOutcome" or "successfulOutcome" in str(ngap_layer):
                    return "PDU Session Resource Setup Response", procedure_code
                return "PDU Session Resource Setup Request", procedure_code

            elif elem_proc == "pduSessionResourceRelease":
                if pdu_type == "successfulOutcome" or "successfulOutcome" in str(ngap_layer):
                    return "PDU Session Resource Release Response", procedure_code
                return "PDU Session Resource Release Command", procedure_code

            elif elem_proc == "initialContextSetup":
                if pdu_type == "unsuccessfulOutcome" or "unsuccessfulOutcome" in str(ngap_layer):
                    return "Initial Context Setup Failure", procedure_code
                elif pdu_type == "successfulOutcome" or "successfulOutcome" in str(ngap_layer):
                    return "Initial Context Setup Response", procedure_code
                return "Initial Context Setup Request", procedure_code

            elif elem_proc == "uEContextRelease":
                if pdu_type == "successfulOutcome" or "successfulOutcome" in str(ngap_layer):
                    return "UE Context Release Complete", procedure_code
                elif pdu_type == "initiatingMessage" or "initiatingMessage" in str(ngap_layer):
                    return "UE Context Release Command", procedure_code
                return "UE Context Release Request", procedure_code

            elif elem_proc == "uEContextReleaseRequest":
                return "UE Context Release Request", procedure_code

            elif elem_proc == "errorIndication":
                return "Error Indication", procedure_code

            elif elem_proc == "ngReset":
                if pdu_type == "successfulOutcome" or "successfulOutcome" in str(ngap_layer):
                    return "NG Reset Acknowledge", procedure_code
                return "NG Reset", procedure_code


        # Check SCTP layer
        if sctp_layer:
            chunk_type = self._extract_str(sctp_layer, ["sctp.chunk_type", "chunk_type"])
            if chunk_type:
                if "SHUTDOWN" in chunk_type.upper():
                    return "SCTP Shutdown", None
                elif "ABORT" in chunk_type.upper():
                    return "SCTP Abort", None
                elif "INIT" in chunk_type.upper():
                    return "SCTP Init", None

        return ngap_msg_type or "Unknown Signalling", procedure_code

    def _normalize_nas_msg(self, msg_str: str) -> Optional[str]:
        msg_lower = str(msg_str).lower()
        if "registration request" in msg_lower or msg_lower in ["0x41", "65"]:
            return "Registration Request"
        if "registration accept" in msg_lower or msg_lower in ["0x42", "66"]:
            return "Registration Accept"
        if "registration complete" in msg_lower or msg_lower in ["0x43", "67"]:
            return "Registration Complete"
        if "registration reject" in msg_lower or msg_lower in ["0x44", "68"]:
            return "Registration Reject"
        if "service request" in msg_lower or msg_lower in ["0x4c", "76"]:
            return "Service Request"
        if "service reject" in msg_lower or msg_lower in ["0x4d", "77"]:
            return "Service Reject"
        if "authentication request" in msg_lower or msg_lower in ["0x56", "86"]:
            return "Authentication Request"
        if "authentication response" in msg_lower or msg_lower in ["0x57", "87"]:
            return "Authentication Response"
        if "authentication failure" in msg_lower or msg_lower in ["0x59", "89"]:
            return "Authentication Failure"
        if "authentication reject" in msg_lower or msg_lower in ["0x58", "88"]:
            return "Authentication Reject"
        if "de-registration request" in msg_lower or msg_lower in ["0x5b", "91"]:
            return "De-registration Request"
        if "de-registration accept" in msg_lower or msg_lower in ["0x5c", "92"]:
            return "De-registration Accept"
        if "security mode command" in msg_lower or msg_lower in ["0x5d", "93"]:
            return "Security Mode Command"
        if "security mode complete" in msg_lower or msg_lower in ["0x5e", "94"]:
            return "Security Mode Complete"
        if "security mode reject" in msg_lower or msg_lower in ["0x5f", "95"]:
            return "Security Mode Reject"
        if "pdu session establishment request" in msg_lower or msg_lower in ["0xc1", "193"]:
            return "PDU Session Establishment Request"
        if "pdu session establishment accept" in msg_lower or msg_lower in ["0xc2", "194"]:
            return "PDU Session Establishment Accept"
        if "pdu session establishment reject" in msg_lower or msg_lower in ["0xc3", "195"]:
            return "PDU Session Establishment Reject"
        return msg_str

    def _determine_direction(
        self,
        ngap_layer: Optional[Dict[str, Any]],
        nas_layer: Optional[Dict[str, Any]],
        sctp_layer: Optional[Dict[str, Any]],
        msg_type: str
    ) -> str:
        msg_lower = msg_type.lower()

        # Check explicit messages
        gnb_to_amf_msgs = [
            "initial ue message", "uplink nas transport", "ng setup request",
            "registration request", "authentication response", "authentication failure",
            "security mode complete", "security mode reject", "pdu session establishment request",
            "ue context release request"
        ]
        amf_to_gnb_msgs = [
            "downlink nas transport", "ng setup response", "ng setup failure",
            "initial context setup request", "ue context release command",
            "registration accept", "registration reject", "authentication request",
            "authentication reject", "security mode command",
            "pdu session establishment accept", "pdu session establishment reject"
        ]

        for m in gnb_to_amf_msgs:
            if m in msg_lower:
                return "gNB -> AMF"

        for m in amf_to_gnb_msgs:
            if m in msg_lower:
                return "AMF -> gNB"

        return "gNB <-> AMF"

    def _extract_cause(self, ngap_layer: Optional[Dict[str, Any]], nas_layer: Optional[Dict[str, Any]]) -> Optional[str]:
        """
        Extracts the NGAP/NAS release/failure cause.

        Important: NGAP's `Cause` IE is an ASN.1 CHOICE:

            Cause ::= CHOICE {
                radioNetwork    CauseRadioNetwork,
                transport       CauseTransport,
                nas             CauseNas,
                protocol        CauseProtocol,
                misc            CauseMisc,
                ...
            }

        Wireshark's dissector typically exposes a generic/ambiguous
        choice-tag field (often surfaced as a bare "ngap.cause" key) in
        addition to the specific per-category field (e.g.
        "ngap.causeRadioNetwork"). The choice tag is just an index
        (0=radioNetwork, 1=transport, 2=nas, 3=protocol, 4=misc) - NOT
        the actual reason - so it must never be treated as the cause
        value itself. We therefore search the specific category fields
        FIRST, and only fall back to the generic tag (clearly labeled
        as unresolved) if nothing more specific is found.

        NOTE: even the category-specific field may come through as a
        raw enumerated integer rather than decoded text, depending on
        your tshark version/dissector output. If you see something
        like "NGAP causeRadioNetwork: 21" instead of a name like
        "user-inactivity", that's a separate issue (tshark not
        emitting the human-readable enum name) - validate against a
        real `tshark -T json` sample for that field before assuming
        this extraction is still wrong.
        """
        # Check NAS cause first
        nas_cause = self._extract_str(nas_layer, [
            "nas_5gs.mm.5gmm_cause", "nas_5gs.sm.5gsm_cause", "nas_5gs.5gmm_cause", "5gmm_cause"
        ])
        if nas_cause:
            return f"5GMM/5GSM cause: {nas_cause}"

        # Check specific NGAP cause categories BEFORE the generic/ambiguous
        # choice-tag key. Field names follow the ASN.1 CHOICE identifiers
        # directly (confirmed against real tshark JSON output nested under
        # "ngap.Cause_tree" - NOT "ngap.causeRadioNetwork" etc. as might be
        # assumed):
        #   Cause ::= CHOICE { radioNetwork, transport, nas, protocol, misc, ... }
        # The matched value is the raw enum index within that category's
        # enumeration (equivalent to the sibling "per.enum_index" field).
        category_keys = [
            ("radioNetwork", ["ngap.CauseRadioNetwork", "ngap.causeRadioNetwork", "ngap.radioNetwork"]),
            ("transport", ["ngap.CauseTransport", "ngap.causeTransport", "ngap.transport"]),
            ("nas", ["ngap.CauseNas", "ngap.causeNas", "ngap.nas"]),
            ("protocol", ["ngap.CauseProtocol", "ngap.causeProtocol", "ngap.protocol"]),
            ("misc", ["ngap.CauseMisc", "ngap.causeMisc", "ngap.misc"]),
        ]
        for category, keys in category_keys:
            val = self._extract_str(ngap_layer, keys)
            if val is not None:
                label = self._lookup_cause_name(category, val)
                if label:
                    return f"NGAP cause ({category}): {label} ({val})"
                return f"NGAP cause ({category}): index {val} (unmapped - validate against 3GPP TS 38.413)"

        # Fall back to the generic choice-tag field. This is ambiguous -
        # it may only tell us which category was chosen (as a 0-4 index),
        # not the actual reason - so label it clearly as unresolved
        # rather than presenting it as a real cause.
        generic_val = self._extract_str(ngap_layer, ["ngap.cause"])
        if generic_val is not None:
            return f"NGAP cause (unresolved choice tag): {generic_val}"

        return None

    # PROVISIONAL cause-name lookup tables. Only CauseNas is filled in -
    # it's a small (4-value), well-documented enum per 3GPP TS 38.413:
    #   CauseNas ::= ENUMERATED { normal-release, authentication-failure,
    #                             deregister, unspecified, ... }
    # CauseRadioNetwork/CauseTransport/CauseProtocol/CauseMisc have many
    # more values each and have NOT been validated against real capture
    # data yet - deliberately left unmapped so they show as "unmapped"
    # rather than a guessed name. Fill these in once cross-checked against
    # known-cause packets (e.g. compare against an independently-detected
    # Authentication Failure or Security Mode Reject in the same trace).
    
    _CAUSE_NAME_TABLES = {
        "nas": {
            "0": "normal-release",
            "1": "authentication-failure",
            "2": "deregister",
            "3": "unspecified",
        },
        "radioNetwork": {
        "0": "unspecified",
        "1": "txnrelocoverall-expiry",
        "2": "successful-handover",
        "3": "release-due-to-ngran-generated-reason",
        "4": "release-due-to-5gc-generated-reason",
        "5": "handover-cancelled",
        "6": "partial-handover",
        "7": "ho-failure-in-target-5GC-ngran-node-or-target-system",
        "8": "ho-target-not-allowed",
        "9": "tngrelocoverall-expiry",
        "10": "tngrelocprep-expiry",
        "11": "cell-not-available",
        "12": "unknown-targetID",
        "13": "no-radio-resources-available-in-target-cell",
        "14": "unknown-local-UE-NGAP-ID",
        "15": "inconsistent-remote-UE-NGAP-ID",
        "16": "handover-desirable-for-radio-reason",
        "17": "time-critical-handover",
        "18": "resource-optimisation-handover",
        "19": "reduce-load-in-serving-cell",
        "20": "user-inactivity",
        "21": "radio-connection-with-ue-lost",
        "22": "radio-resources-not-available",
        "23": "invalid-qos-combination",
        "24": "failure-in-radio-interface-procedure",
        "25": "interaction-with-other-procedure",
        "26": "unknown-PDU-session-ID",
        "27": "unknown-qos-flow-ID",
        "28": "multiple-PDU-session-ID-instances",
        "29": "multiple-qos-flow-ID-instances",
        "30": "encryption-and-or-integrity-protection-algorithms-not-supported",
        "31": "ng-intra-system-handover-triggered",
        "32": "ng-inter-system-handover-triggered",
        "33": "xn-handover-triggered",
        "34": "not-supported-5QI-value",
        "35": "ue-context-transfer",
        "36": "ims-voice-eps-fallback-or-rat-fallback-triggered",
        "37": "up-integrity-protection-not-possible",
        "38": "up-confidentiality-protection-not-possible",
        "39": "slice-not-supported",
        "40": "ue-in-rrc-inactive-state-not-reachable",
        "41": "redirection",
        "42": "resources-not-available-for-the-slice",
        "43": "ue-max-integrity-protected-data-rate-reason",
        "44": "release-due-to-cn-detected-mobility",

        # Extension values (verify against your NGAP version if encountered)
        "45": "n26-interface-not-available",
        "46": "release-due-to-pre-emption",
        "47": "multiple-location-reporting-reference-ID-instances",
        "48": "rsn-not-available-for-the-up",
        "49": "npn-access-denied",
        "50": "cag-only-access-denied",
        "51": "insufficient-ue-capabilities",
        "52": "redcap-ue-not-supported",
        "53": "unknown-MBS-Session-ID",
        "54": "indicated-MBS-session-area-information-not-served-by-the-gNB",
        "55": "inconsistent-slice-info-for-the-session",
        "56": "misaligned-association-for-multicast-unicast",
        "57": "eredcap-ue-not-supported",
        "58": "two-rx-xr-ue-not-supported",
        "59": "aerial-ue-flight-information-reporting-initiation-failure",
        "60": "unknown-RAN-AIoT-Device-NGAP-ID",
        "61": "requested-AIoT-service-area-information-not-served-by-the-gNB",
        "62": "unknown-AIoT-session",
        "63": "aiot-device-not-reachable",
        "64": "multiple-AIoT-session-ID-instances",
    }
    }

    def _lookup_cause_name(self, category: str, raw_index: str) -> Optional[str]:
        table = self._CAUSE_NAME_TABLES.get(category)
        if not table:
            return None
        return table.get(str(raw_index))