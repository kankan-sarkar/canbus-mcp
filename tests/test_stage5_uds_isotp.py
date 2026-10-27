"""Stage 5 Test & Validation Gate (REQUIREMENTS.md section 4, Stage 5.2)."""
from __future__ import annotations

import pytest

from can_mcp.engines import protocol_engine
from tests.fixtures import generator


@pytest.fixture()
def scratch_path():
    paths = []

    def _make(name: str):
        path = generator.FIXTURES_DIR / name
        paths.append(path)
        return path

    yield _make
    for path in paths:
        if path.exists():
            path.unlink()


class TestGate5_1_IsoTpReassembly:
    """Gate 5.1: Feed a synthetic .asc trace containing a 64-byte
    ReadDataByIdentifier (0x22 F1 90) VIN/calibration read split across 1
    First Frame, 1 Flow Control, and 9 Consecutive Frames. Verify complete
    payload reassembly.
    """

    def test_full_64_byte_payload_is_reassembled(self, scratch_path):
        path = scratch_path("isotp_long_read.asc")
        _, expected_payload = generator.generate_isotp_long_read_trace(path)

        result = protocol_engine.extract_uds_diagnostic_transcript(str(path))

        responses = [e for e in result["transcript"] if e["direction"] == "RESPONSE"]
        assert len(responses) == 1
        response = responses[0]
        assert response["type"] == "POSITIVE_RESPONSE"
        assert response["service"] == "ReadDataByIdentifier"
        assert response["raw"] == expected_payload.hex().upper()
        assert len(expected_payload) == 64

    def test_flow_control_and_nine_consecutive_frames_observed(self, scratch_path):
        path = scratch_path("isotp_long_read2.asc")
        generator.generate_isotp_long_read_trace(path)

        result = protocol_engine.extract_uds_diagnostic_transcript(str(path))
        events = result["isotp_events"]

        assert sum(1 for e in events if e["event"] == "FIRST_FRAME") == 1
        assert sum(1 for e in events if e["event"] == "FLOW_CONTROL") == 1
        # 9 Consecutive Frames were sent; the 9th completes the message (and
        # is reported via the transcript's COMPLETE payload, not as its own
        # CONSECUTIVE_FRAME event), so 8 show up here.
        assert sum(1 for e in events if e["event"] == "CONSECUTIVE_FRAME") == 8
        assert sum(1 for e in events if e["event"] == "ISOTP_SEQUENCE_ERROR") == 0

    def test_initial_request_is_decoded(self, scratch_path):
        path = scratch_path("isotp_long_read3.asc")
        generator.generate_isotp_long_read_trace(path)

        result = protocol_engine.extract_uds_diagnostic_transcript(str(path))
        requests = [e for e in result["transcript"] if e["direction"] == "REQUEST"]
        assert len(requests) == 1
        assert requests[0]["service"] == "ReadDataByIdentifier"
        assert requests[0]["raw"] == "22F190"


class TestGate5_2_SecurityAccessAndNrc:
    """Gate 5.2: Feed a trace simulating a failed 0x27 Security Access
    handshake (seed -> bad key -> InvalidKey -> ExceededNumberOfAttempts).
    Verify the transcript flags the exact security lockout sequence.
    """

    def test_security_lockout_detected(self, scratch_path):
        path = scratch_path("security_access_failure.blf")
        generator.generate_security_access_failure_trace(path)

        result = protocol_engine.extract_uds_diagnostic_transcript(str(path))
        assert result["security_lockout_detected"] is True

    def test_exact_failure_sequence_order_and_codes(self, scratch_path):
        path = scratch_path("security_access_failure2.blf")
        generator.generate_security_access_failure_trace(path)

        result = protocol_engine.extract_uds_diagnostic_transcript(str(path))
        events = result["security_events"]
        assert [e["nrc_name"] for e in events] == ["InvalidKey", "ExceededNumberOfAttempts"]
        assert events[0]["timestamp"] < events[1]["timestamp"]

    def test_full_transcript_matches_handshake_steps(self, scratch_path):
        path = scratch_path("security_access_failure3.blf")
        generator.generate_security_access_failure_trace(path)

        result = protocol_engine.extract_uds_diagnostic_transcript(str(path))
        transcript = result["transcript"]
        assert [e["type"] for e in transcript] == [
            "REQUEST", "POSITIVE_RESPONSE", "REQUEST", "NEGATIVE_RESPONSE", "NEGATIVE_RESPONSE",
        ]
        assert all(e["service"] == "SecurityAccess" for e in transcript)
        assert transcript[3]["nrc_name"] == "InvalidKey"
        assert transcript[4]["nrc_name"] == "ExceededNumberOfAttempts"


class TestGate5_3_IsoTpSequenceFault:
    """Gate 5.3: Inject a dropped Consecutive Frame (SN jumping from 2 to 4)
    and verify the engine reports an ISOTP_SEQUENCE_ERROR at the exact
    timestamp.
    """

    def test_sequence_error_reported_at_exact_timestamp(self, scratch_path):
        path = scratch_path("isotp_sequence_error.blf")
        _, expected_error_timestamp = generator.generate_isotp_sequence_error_trace(path)

        result = protocol_engine.extract_uds_diagnostic_transcript(str(path))
        sequence_errors = [e for e in result["isotp_events"] if e["event"] == "ISOTP_SEQUENCE_ERROR"]

        assert len(sequence_errors) == 1
        error = sequence_errors[0]
        assert error["timestamp"] == pytest.approx(expected_error_timestamp, abs=1e-6)
        assert error["expected_sn"] == 3
        assert error["got_sn"] == 4

    def test_no_complete_message_after_dropped_frame(self, scratch_path):
        path = scratch_path("isotp_sequence_error2.blf")
        generator.generate_isotp_sequence_error_trace(path)

        result = protocol_engine.extract_uds_diagnostic_transcript(str(path))
        assert result["transcript"] == []


class TestJ1939MultipacketReassembly:
    """Supplementary coverage for reassemble_j1939_multipacket (BAM)."""

    def test_bam_payload_reassembled_exactly(self, scratch_path):
        path = scratch_path("j1939_bam.blf")
        payload = b"HELLO-FROM-ECU1"
        _, expected_payload = generator.generate_j1939_bam_trace(path, payload=payload)

        result = protocol_engine.reassemble_j1939_multipacket(str(path))
        assert len(result["reassembled_messages"]) == 1
        message = result["reassembled_messages"][0]
        assert bytes.fromhex(message["payload_hex"]) == expected_payload
        assert message["mode"] == "BAM"
        assert message["pgn_hex"] == hex(generator.J1939_BAM_PGN)
        assert message["source_address_hex"] == hex(generator.J1939_BAM_SOURCE_ADDRESS)
        assert result["incomplete_sessions"] == []
