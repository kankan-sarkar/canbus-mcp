"""Stage 5: transport protocol reassembly & UDS diagnostic session analyzer.

extract_uds_diagnostic_transcript, reassemble_j1939_multipacket.
"""
from __future__ import annotations

from pathlib import Path

import can

from can_mcp.engines.dbc_engine import _parse_int_literal
from can_mcp.engines.trace_engine import _resolve_trace_path, filter_and_export_trace, iter_trace_messages
from can_mcp.models.errors import CanMcpError
from can_mcp.utils import guardrail

# ---- ISO 14229 (UDS) service & negative-response-code tables --------------

UDS_SERVICES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x27: "SecurityAccess",
    0x2E: "WriteDataByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x3E: "TesterPresent",
    0x85: "ControlDTCSetting",
}

NRC_NAMES = {
    0x10: "GeneralReject",
    0x11: "ServiceNotSupported",
    0x12: "SubFunctionNotSupported",
    0x13: "IncorrectMessageLengthOrInvalidFormat",
    0x14: "ResponseTooLong",
    0x21: "BusyRepeatRequest",
    0x22: "ConditionsNotCorrect",
    0x24: "RequestSequenceError",
    0x31: "RequestOutOfRange",
    0x33: "SecurityAccessDenied",
    0x35: "InvalidKey",
    0x36: "ExceededNumberOfAttempts",
    0x37: "RequiredTimeDelayNotExpired",
    0x70: "UploadDownloadNotAccepted",
    0x71: "TransferDataSuspended",
    0x72: "GeneralProgrammingFailure",
    0x73: "WrongBlockSequenceCounter",
    0x78: "RequestCorrectlyReceived-ResponsePending",
    0x7E: "SubFunctionNotSupportedInActiveSession",
    0x7F: "ServiceNotSupportedInActiveSession",
}

DEFAULT_FUNCTIONAL_REQUEST_ID = 0x7DF
DEFAULT_PHYSICAL_REQUEST_IDS = {DEFAULT_FUNCTIONAL_REQUEST_ID, *range(0x7E0, 0x7E8)}
DEFAULT_PHYSICAL_RESPONSE_IDS = set(range(0x7E8, 0x7F0))


def _resolve_diagnostic_ids(request_id: str | None, response_id: str | None) -> tuple[set[int], set[int]]:
    if request_id is not None or response_id is not None:
        if request_id is None or response_id is None:
            raise CanMcpError(
                "INCOMPLETE_DIAGNOSTIC_IDS", "Both request_id and response_id must be given together.",
                "Pass both custom IDs, or neither to use the standard 0x7DF/0x7E0-0x7EF defaults.",
            )
        req = _parse_int_literal(str(request_id))
        resp = _parse_int_literal(str(response_id))
        if req is None or resp is None:
            raise CanMcpError("INVALID_DIAGNOSTIC_ID", f"Could not parse request_id/response_id ('{request_id}', '{response_id}').",
                               "Use decimal integers or '0x...' hex strings.")
        return {req}, {resp}
    return set(DEFAULT_PHYSICAL_REQUEST_IDS), set(DEFAULT_PHYSICAL_RESPONSE_IDS)


# ---- ISO 15765-2 (ISO-TP) state machine ------------------------------------

class _IsoTpSession:
    """Per-arbitration-ID ISO-TP reassembly state (SF/FF/FC/CF), for both
    8-byte classical CAN and up to 64-byte CAN FD payloads.
    """

    def __init__(self, arbitration_id: int):
        self.arbitration_id = arbitration_id
        self.active = False
        self.buffer = bytearray()
        self.expected_length = 0
        self.expected_sn = 1
        self.start_timestamp: float | None = None

    def _reset(self) -> None:
        self.active = False
        self.buffer = bytearray()
        self.expected_length = 0
        self.expected_sn = 1
        self.start_timestamp = None

    def feed(self, msg: can.Message) -> dict | None:
        data = msg.data
        if not data:
            return None
        pci_type = data[0] >> 4

        if pci_type == 0x0:  # Single Frame
            length = data[0] & 0x0F
            if length == 0 and len(data) > 1:  # CAN FD SF escape sequence
                length = data[1]
                payload = bytes(data[2:2 + length])
            else:
                payload = bytes(data[1:1 + length])
            self._reset()
            return {"event": "COMPLETE", "payload": payload, "timestamp": msg.timestamp}

        if pci_type == 0x1:  # First Frame
            length = ((data[0] & 0x0F) << 8) | data[1]
            offset = 2
            if length == 0 and len(data) >= 6:  # CAN FD FF escape sequence (32-bit length)
                length = int.from_bytes(data[2:6], "big")
                offset = 6
            self.buffer = bytearray(data[offset:])
            self.expected_length = length
            self.expected_sn = 1
            self.active = True
            self.start_timestamp = msg.timestamp
            return {"event": "FIRST_FRAME", "timestamp": msg.timestamp, "total_length": length}

        if pci_type == 0x2:  # Consecutive Frame
            sn = data[0] & 0x0F
            if not self.active:
                return {"event": "UNEXPECTED_CONSECUTIVE_FRAME", "timestamp": msg.timestamp}
            if sn != self.expected_sn:
                error = {
                    "event": "ISOTP_SEQUENCE_ERROR", "timestamp": msg.timestamp,
                    "expected_sn": self.expected_sn, "got_sn": sn,
                }
                self._reset()
                return error
            self.buffer.extend(data[1:])
            self.expected_sn = (self.expected_sn + 1) % 16
            if len(self.buffer) >= self.expected_length:
                payload = bytes(self.buffer[:self.expected_length])
                start_ts = self.start_timestamp
                self._reset()
                return {"event": "COMPLETE", "payload": payload, "timestamp": msg.timestamp, "start_timestamp": start_ts}
            return {"event": "CONSECUTIVE_FRAME", "timestamp": msg.timestamp, "sn": sn}

        if pci_type == 0x3:  # Flow Control
            return {
                "event": "FLOW_CONTROL", "timestamp": msg.timestamp,
                "flow_status": data[0] & 0x0F,
                "block_size": data[1] if len(data) > 1 else 0,
                "st_min": data[2] if len(data) > 2 else 0,
            }

        return {"event": "UNKNOWN_PCI", "timestamp": msg.timestamp}


def _decode_uds_payload(payload: bytes, timestamp: float, direction: str) -> dict:
    raw_hex = payload.hex().upper()
    if not payload:
        return {"timestamp": timestamp, "direction": direction, "raw": raw_hex, "type": "EMPTY"}

    sid = payload[0]
    if sid == 0x7F and len(payload) >= 3:
        original_sid, nrc = payload[1], payload[2]
        return {
            "timestamp": timestamp, "direction": direction, "raw": raw_hex, "type": "NEGATIVE_RESPONSE",
            "service": UDS_SERVICES.get(original_sid, hex(original_sid)), "service_id": hex(original_sid),
            "sub_function": hex(payload[3]) if len(payload) > 3 else None,
            "nrc": hex(nrc), "nrc_name": NRC_NAMES.get(nrc, "Unknown"),
        }
    if sid in UDS_SERVICES:
        return {
            "timestamp": timestamp, "direction": direction, "raw": raw_hex, "type": "REQUEST",
            "service": UDS_SERVICES[sid], "service_id": hex(sid),
            "sub_function": hex(payload[1]) if len(payload) > 1 else None,
            "data": payload[2:].hex().upper() if len(payload) > 2 else "",
        }
    if (sid - 0x40) in UDS_SERVICES:
        base_sid = sid - 0x40
        return {
            "timestamp": timestamp, "direction": direction, "raw": raw_hex, "type": "POSITIVE_RESPONSE",
            "service": UDS_SERVICES[base_sid], "service_id": hex(base_sid),
            "data": payload[1:].hex().upper(),
        }
    return {"timestamp": timestamp, "direction": direction, "raw": raw_hex, "type": "UNKNOWN", "service_id": hex(sid)}


def _detect_security_lockout(transcript: list[dict]) -> list[dict]:
    """Every SecurityAccess negative response is a failed attempt; the
    ordered list of these *is* the lockout sequence the gate asks for.
    """
    return [
        {"event": "SECURITY_ACCESS_FAILURE", "timestamp": entry["timestamp"], "nrc_name": entry["nrc_name"]}
        for entry in transcript
        if entry.get("type") == "NEGATIVE_RESPONSE" and entry.get("service") == "SecurityAccess"
    ]


def extract_uds_diagnostic_transcript(
    log_path: str,
    request_id: str | None = None,
    response_id: str | None = None,
    export_filtered_log_path: str | None = None,
    max_chars: int | None = None,
) -> dict:
    path = _resolve_trace_path(log_path)
    request_ids, response_ids = _resolve_diagnostic_ids(request_id, response_id)
    diagnostic_ids = request_ids | response_ids

    sessions: dict[int, _IsoTpSession] = {}
    transcript: list[dict] = []
    isotp_events: list[dict] = []

    for msg in iter_trace_messages(path):
        if msg.is_error_frame or msg.arbitration_id not in diagnostic_ids:
            continue
        direction = "REQUEST" if msg.arbitration_id in request_ids else "RESPONSE"
        session = sessions.setdefault(msg.arbitration_id, _IsoTpSession(msg.arbitration_id))
        result = session.feed(msg)
        if result is None:
            continue
        if result["event"] == "COMPLETE":
            transcript.append(_decode_uds_payload(result["payload"], result["timestamp"], direction))
        elif result["event"] == "ISOTP_SEQUENCE_ERROR":
            isotp_events.append({**result, "arbitration_id_hex": hex(msg.arbitration_id), "direction": direction})
        elif result["event"] in ("FIRST_FRAME", "FLOW_CONTROL", "CONSECUTIVE_FRAME", "UNEXPECTED_CONSECUTIVE_FRAME", "UNKNOWN_PCI"):
            isotp_events.append({**result, "arbitration_id_hex": hex(msg.arbitration_id), "direction": direction})

    security_events = _detect_security_lockout(transcript)

    exported_log_path = None
    if export_filtered_log_path:
        include_ids = [hex(i) for i in diagnostic_ids]
        filter_and_export_trace(log_path, export_filtered_log_path, include_ids=include_ids)
        exported_log_path = export_filtered_log_path

    def build(prefix_transcript: list) -> dict:
        return {
            "log_path": log_path,
            "request_ids": sorted(hex(i) for i in request_ids),
            "response_ids": sorted(hex(i) for i in response_ids),
            "transcript": prefix_transcript,
            "isotp_events": isotp_events,
            "security_lockout_detected": any(e["nrc_name"] == "ExceededNumberOfAttempts" for e in security_events),
            "security_events": security_events,
            "exported_log_path": exported_log_path,
        }

    if max_chars is None:
        return build(transcript)
    return guardrail.fit_rows_to_char_budget(build, transcript, max_chars)


# ---- J1939-21 transport protocol (BAM / CMDT) reassembly -------------------

PGN_TP_CM = 0xEC
PGN_TP_DT = 0xEB
TP_CM_BAM_CONTROL_BYTE = 0x20
TP_CM_RTS_CONTROL_BYTE = 0x10


def reassemble_j1939_multipacket(log_path: str) -> dict:
    path = _resolve_trace_path(log_path)
    sessions: dict[int, dict] = {}
    completed: list[dict] = []

    for msg in iter_trace_messages(path):
        if msg.is_error_frame or not msg.is_extended_id or not msg.data:
            continue
        pf = (msg.arbitration_id >> 16) & 0xFF
        source_address = msg.arbitration_id & 0xFF

        if pf == PGN_TP_CM and len(msg.data) >= 8:
            control = msg.data[0]
            if control in (TP_CM_BAM_CONTROL_BYTE, TP_CM_RTS_CONTROL_BYTE):
                total_size = int.from_bytes(msg.data[1:3], "little")
                total_packets = msg.data[3]
                pgn = int.from_bytes(msg.data[5:8], "little")
                sessions[source_address] = {
                    "mode": "BAM" if control == TP_CM_BAM_CONTROL_BYTE else "CMDT",
                    "total_size": total_size, "total_packets": total_packets, "pgn": pgn,
                    "buffer": bytearray(total_size), "received": set(), "start_timestamp": msg.timestamp,
                }
            continue

        if pf == PGN_TP_DT and len(msg.data) >= 2:
            session = sessions.get(source_address)
            if session is None:
                continue
            sn = msg.data[0]
            offset = (sn - 1) * 7
            chunk = msg.data[1:8]
            take = max(0, min(len(chunk), session["total_size"] - offset))
            if take > 0:
                session["buffer"][offset:offset + take] = chunk[:take]
            session["received"].add(sn)
            if len(session["received"]) >= session["total_packets"]:
                completed.append({
                    "source_address": source_address, "source_address_hex": hex(source_address),
                    "mode": session["mode"], "pgn": session["pgn"], "pgn_hex": hex(session["pgn"]),
                    "total_size": session["total_size"],
                    "payload_hex": bytes(session["buffer"]).hex().upper(),
                    "start_timestamp": session["start_timestamp"], "end_timestamp": msg.timestamp,
                    "packet_count": session["total_packets"],
                })
                del sessions[source_address]

    incomplete = [
        {
            "source_address_hex": hex(sa), "pgn_hex": hex(s["pgn"]),
            "received_packets": len(s["received"]), "expected_packets": s["total_packets"],
        }
        for sa, s in sessions.items()
    ]

    return {
        "log_path": log_path,
        "reassembled_messages": completed,
        "incomplete_sessions": incomplete,
    }
