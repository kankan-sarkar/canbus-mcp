"""Stage 1 Test & Validation Gate (REQUIREMENTS.md section 4, Stage 1.2)."""
from __future__ import annotations

import cantools
import pytest

from can_mcp.engines import dbc_engine
from can_mcp.utils import bitmath
from tests.fixtures import generator


@pytest.fixture(scope="module")
def sample_powertrain_path():
    """Deterministically (re)generated into tests/fixtures/, inside the
    workspace sandbox, on every run."""
    return generator.generate_sample_powertrain()


@pytest.fixture(scope="module")
def overlap_injected_path():
    return generator.generate_overlap_injected()


class TestGate1_1_FixtureGenerator:
    """Gate 1.1: Fixture generator creates a valid sample_powertrain.dbc
    containing Intel, Motorola, signed, unsigned, and multiplexed signals.
    """

    def test_fixture_file_is_written_and_parses_cleanly(self, sample_powertrain_path):
        assert sample_powertrain_path.exists()
        db = cantools.database.load_file(str(sample_powertrain_path), strict=True)
        assert len(db.messages) == 3

    def test_fixture_contains_intel_and_motorola_signals(self, sample_powertrain_path):
        db = cantools.database.load_file(str(sample_powertrain_path))
        byte_orders = {s.byte_order for m in db.messages for s in m.signals}
        assert byte_orders == {"little_endian", "big_endian"}

    def test_fixture_contains_signed_and_unsigned_signals(self, sample_powertrain_path):
        db = cantools.database.load_file(str(sample_powertrain_path))
        signedness = {s.is_signed for m in db.messages for s in m.signals}
        assert signedness == {True, False}

    def test_fixture_contains_multiplexed_signals(self, sample_powertrain_path):
        db = cantools.database.load_file(str(sample_powertrain_path))
        transmission = db.get_message_by_name("TransmissionStatus")
        muxer = next(s for s in transmission.signals if s.name == "GearSelector_Mux")
        branches = [s for s in transmission.signals if s.multiplexer_ids]
        assert muxer.is_multiplexer is True
        assert len(branches) == 2
        assert {tuple(b.multiplexer_ids) for b in branches} == {(0,), (1,)}

    def test_inspect_database_summary_matches_fixture(self, sample_powertrain_path):
        summary = dbc_engine.inspect_database_summary(str(sample_powertrain_path))
        assert summary["protocol_type"] == "CAN"
        assert summary["baudrate"] == generator.SAMPLE_BAUDRATE
        assert summary["ecu_count"] == 4
        assert summary["message_count"] == 3
        assert summary["signal_count"] == 7
        assert set(summary["nodes"]) == {"ECU_Engine", "ECU_TCU", "ECU_ABS", "Gateway"}


class TestGate1_2_SearchDatabase:
    """Gate 1.2: search_database accurately locates signals by unit
    (e.g. "rpm", "degC") and hex ID ("0x120").
    """

    def test_search_by_unit_rpm(self, sample_powertrain_path):
        result = dbc_engine.search_database(str(sample_powertrain_path), "rpm")
        signal_names = {m["signal"] for m in result["matches"] if m["category"] == "unit"}
        assert "EngineSpeed" in signal_names

    def test_search_by_unit_degc(self, sample_powertrain_path):
        result = dbc_engine.search_database(str(sample_powertrain_path), "degC")
        signal_names = {m["signal"] for m in result["matches"] if m["category"] == "unit"}
        assert "CoolantTemp" in signal_names

    def test_search_by_hex_id(self, sample_powertrain_path):
        result = dbc_engine.search_database(str(sample_powertrain_path), "0x120")
        id_matches = [m for m in result["matches"] if m["category"] == "id"]
        assert any(m["message"] == "TransmissionStatus" for m in id_matches)
        assert any(m["value"] == "0x120" for m in id_matches)

    def test_search_restricted_to_search_type(self, sample_powertrain_path):
        result = dbc_engine.search_database(str(sample_powertrain_path), "rpm", search_type="unit")
        assert all(m["category"] == "unit" for m in result["matches"])

    def test_search_by_signal_name_substring_is_case_insensitive(self, sample_powertrain_path):
        result = dbc_engine.search_database(str(sample_powertrain_path), "enginespeed")
        assert any(m["signal"] == "EngineSpeed" for m in result["matches"])

    def test_search_respects_max_results(self, sample_powertrain_path):
        result = dbc_engine.search_database(str(sample_powertrain_path), "e", max_results=2)
        assert len(result["matches"]) <= 2


class TestGate1_3_VisualizeFrameLayout:
    """Gate 1.3: visualize_frame_layout accurately maps a 12-bit Motorola
    signal spanning across byte boundaries without off-by-one bit errors.
    """

    def test_wheel_speed_fl_bit_positions_match_hand_derivation(self, sample_powertrain_path):
        db = cantools.database.load_file(str(sample_powertrain_path))
        message = db.get_message_by_name("WheelSpeeds")
        signal = next(s for s in message.signals if s.name == "WheelSpeedFL")
        assert signal.byte_order == "big_endian"
        assert signal.length == 12
        positions = bitmath.signal_bit_positions(signal)
        assert positions == list(range(16, 28))

    def test_wheel_speed_fl_round_trips_through_cantools_encode_decode(self, sample_powertrain_path):
        db = cantools.database.load_file(str(sample_powertrain_path))
        message = db.get_message_by_name("WheelSpeeds")
        raw = message.encode({"WheelSpeedFL": 0.0, "SteeringTorque": 0})
        # 0xABC (12-bit) split across byte2 (full) and the upper nibble of byte3.
        raw = bytearray(raw)
        raw[2] = 0xAB
        raw[3] = (raw[3] & 0x0F) | 0xC0
        decoded = message.decode(bytes(raw))
        assert decoded["WheelSpeedFL"] == pytest.approx(0xABC * 0.1)

    def test_ascii_grid_marks_byte2_fully_and_byte3_upper_nibble_only(self, sample_powertrain_path):
        result = dbc_engine.visualize_frame_layout(str(sample_powertrain_path), "WheelSpeeds")
        lines = {line.split(":", 1)[0]: line for line in result["ascii_grid"].splitlines() if line.startswith("byte")}
        byte2_cells = lines["byte2"].split(":", 1)[1].split()
        byte3_cells = lines["byte3"].split(":", 1)[1].split()
        assert all(cell.strip() not in ("", ".") for cell in byte2_cells)
        assert all(cell.strip() not in ("", ".") for cell in byte3_cells[:4])
        assert all(cell.strip() == "." for cell in byte3_cells[4:])

    def test_free_bit_spans_reported_for_unused_bytes(self, sample_powertrain_path):
        result = dbc_engine.visualize_frame_layout(str(sample_powertrain_path), "WheelSpeeds")
        assert any("byte0" in span for span in result["free_bit_spans"])

    def test_resolves_message_by_hex_id_too(self, sample_powertrain_path):
        result = dbc_engine.visualize_frame_layout(str(sample_powertrain_path), "0x140")
        assert result["message_name"] == "WheelSpeeds"


class TestGate1_4_ValidateDatabaseIntegrity:
    """Gate 1.4: validate_database_integrity detects an intentionally
    injected 2-bit overlap between two Intel signals and returns the exact
    colliding bit indices.
    """

    def test_valid_fixture_reports_no_issues(self, sample_powertrain_path):
        report = dbc_engine.validate_database_integrity(str(sample_powertrain_path))
        assert report["is_valid"] is True
        assert report["issue_count"] == 0

    def test_overlap_fixture_is_detected(self, overlap_injected_path):
        report = dbc_engine.validate_database_integrity(str(overlap_injected_path))
        assert report["is_valid"] is False
        overlap_issues = [i for i in report["issues"] if i["check"] == "bit_overlap"]
        assert len(overlap_issues) == 1

    def test_overlap_colliding_bits_are_exact(self, overlap_injected_path):
        report = dbc_engine.validate_database_integrity(str(overlap_injected_path))
        overlap_issue = next(i for i in report["issues"] if i["check"] == "bit_overlap")
        details = overlap_issue["details"]
        assert {details["signal_a"], details["signal_b"]} == {"SignalA", "SignalB"}
        # SignalA occupies LSB bits [10..17], SignalB occupies [16..23] -> 2-bit overlap at 16,17.
        colliding_labels = set(details["colliding_byte_bit_labels"])
        assert colliding_labels == {"byte2.bit0", "byte2.bit1"}
        assert len(details["colliding_bits"]) == 2

    def test_mutually_exclusive_mux_branches_are_not_flagged_as_overlap(self, sample_powertrain_path):
        report = dbc_engine.validate_database_integrity(str(sample_powertrain_path))
        transmission_issues = [i for i in report["issues"] if i["message_name"] == "TransmissionStatus"]
        assert transmission_issues == []
