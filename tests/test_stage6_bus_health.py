"""Stage 6 Test & Validation Gate (REQUIREMENTS.md section 4, Stage 6.2)."""
from __future__ import annotations

import pytest

from can_mcp.engines import health_engine
from tests.fixtures import generator


@pytest.fixture(scope="module")
def bus_health_dbc_path():
    return generator.generate_bus_health_dbc()


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


class TestGate6_1_JitterAndMissingFrame:
    """Gate 6.1: Inject a 250ms dropout into a cyclic 10ms message (0x100)
    in a test trace; verify analyze_bus_health_and_faults flags the exact
    timestamp window and reports 25 missed cycles.
    """

    def test_missing_frame_event_reports_25_missed_cycles(self, scratch_path, bus_health_dbc_path):
        path = scratch_path("cyclic_dropout.blf")
        _, last_before, gap_timestamp = generator.generate_cyclic_dropout_trace(path)

        result = health_engine.analyze_bus_health_and_faults(str(path), str(bus_health_dbc_path))
        events = result["missing_frame_events"]

        assert len(events) == 1
        event = events[0]
        assert event["frame_id_hex"] == hex(generator.CYCLIC_FRAME_ID)
        assert event["name"] == "CyclicMsg100"
        assert event["missed_cycles"] == 25

    def test_exact_timestamp_window_reported(self, scratch_path, bus_health_dbc_path):
        path = scratch_path("cyclic_dropout2.blf")
        _, last_before, gap_timestamp = generator.generate_cyclic_dropout_trace(path)

        result = health_engine.analyze_bus_health_and_faults(str(path), str(bus_health_dbc_path))
        event = result["missing_frame_events"][0]

        assert event["window_start"] == pytest.approx(last_before, abs=1e-6)
        assert event["window_end"] == pytest.approx(gap_timestamp, abs=1e-6)

    def test_no_false_positives_on_clean_cyclic_trace(self, scratch_path, bus_health_dbc_path):
        path = scratch_path("cyclic_clean.blf")
        generator.generate_cyclic_dropout_trace(path, dropout_extra_ms=0.0)

        result = health_engine.analyze_bus_health_and_faults(str(path), str(bus_health_dbc_path))
        assert result["missing_frame_events"] == []


class TestGate6_2_ErrorStormAndBusOff:
    """Gate 6.2: Inject a burst of 128 Error Frames followed by a 500ms
    cessation of transmissions from ECU Node A; verify the tool diagnoses a
    likely Node Bus-Off transition and outputs termination/baudrate
    troubleshooting steps.
    """

    def test_error_storm_detected(self, scratch_path, bus_health_dbc_path):
        path = scratch_path("error_storm_busoff.blf")
        generator.generate_error_storm_busoff_trace(path)

        result = health_engine.analyze_bus_health_and_faults(str(path), str(bus_health_dbc_path))
        assert len(result["error_storms"]) == 1
        assert result["error_storms"][0]["error_count"] == 128
        assert result["error_frame_count"] == 128

    def test_bus_off_candidate_identifies_node_a(self, scratch_path, bus_health_dbc_path):
        path = scratch_path("error_storm_busoff2.blf")
        generator.generate_error_storm_busoff_trace(path)

        result = health_engine.analyze_bus_health_and_faults(str(path), str(bus_health_dbc_path))
        candidates = result["bus_off_candidates"]
        assert len(candidates) >= 1
        node_a_candidate = next(c for c in candidates if c["frame_id_hex"] == hex(generator.NODE_A_FRAME_ID))
        assert node_a_candidate["name"] == "NodeAStatus"
        assert node_a_candidate["sender"] == "ECU_A"
        assert node_a_candidate["silence_ms"] >= 400

    def test_advisory_mentions_termination_and_baudrate(self, scratch_path, bus_health_dbc_path):
        path = scratch_path("error_storm_busoff3.blf")
        generator.generate_error_storm_busoff_trace(path)

        result = health_engine.analyze_bus_health_and_faults(str(path), str(bus_health_dbc_path))
        advisory_text = " ".join(result["advisories"]).lower()
        assert "bus-off" in advisory_text or "bus off" in advisory_text
        assert "termination" in advisory_text
        assert "baudrate" in advisory_text


class TestGate6_3_HeuristicReverseEngineering:
    """Gate 6.3: Generate a raw trace with no DBC containing an 8-byte
    frame with: Byte 0-1 = smooth sine wave (16-bit), Byte 6 (lower nibble)
    = 0..15 rolling counter, Byte 7 = XOR checksum. Verify
    reverse_engineer_unknown_frames correctly classifies all three
    bitfields with >90% confidence.
    """

    @pytest.fixture()
    def unknown_signal_path(self, scratch_path):
        path = scratch_path("unknown_signals.blf")
        generator.generate_unknown_signal_trace(path)
        return path

    def test_sine_wave_bytes_classified_as_continuous_signal(self, unknown_signal_path):
        result = health_engine.reverse_engineer_unknown_frames(str(unknown_signal_path))
        fields = result["frames"][0]["fields"]
        sine_field = next(f for f in fields if f["byte_range"] == [0, 1])
        assert sine_field["classification"] == "CONTINUOUS_PHYSICAL_SIGNAL"
        assert sine_field["confidence"] > 0.90

    def test_byte6_classified_as_alive_counter(self, unknown_signal_path):
        result = health_engine.reverse_engineer_unknown_frames(str(unknown_signal_path))
        fields = result["frames"][0]["fields"]
        counter_field = next(f for f in fields if 6 in f["byte_range"])
        assert counter_field["classification"] == "ALIVE_COUNTER"
        assert counter_field["confidence"] > 0.90

    def test_byte7_classified_as_checksum_candidate(self, unknown_signal_path):
        result = health_engine.reverse_engineer_unknown_frames(str(unknown_signal_path))
        fields = result["frames"][0]["fields"]
        checksum_field = next(f for f in fields if f["byte_range"] == [7, 7])
        assert checksum_field["classification"] == "CHECKSUM_CANDIDATE"
        assert checksum_field["confidence"] > 0.90

    def test_constant_padding_bytes_classified_as_constant(self, unknown_signal_path):
        result = health_engine.reverse_engineer_unknown_frames(str(unknown_signal_path))
        fields = result["frames"][0]["fields"]
        for byte_index in (2, 3, 4, 5):
            field = next(f for f in fields if f["byte_range"] == [byte_index, byte_index])
            assert field["classification"] == "CONSTANT_MASK"

    def test_draft_dbc_text_is_valid_dbc(self, unknown_signal_path):
        import cantools
        result = health_engine.reverse_engineer_unknown_frames(str(unknown_signal_path))
        draft_text = result["frames"][0]["draft_dbc_text"]
        db = cantools.database.load_string(draft_text, database_format="dbc")
        assert len(db.messages) == 1
        assert db.messages[0].frame_id == 0x555

    def test_target_frame_id_restricts_analysis(self, unknown_signal_path):
        result = health_engine.reverse_engineer_unknown_frames(str(unknown_signal_path), target_frame_id="0x555")
        assert result["analyzed_frame_count"] == 1
        result_other = health_engine.reverse_engineer_unknown_frames(str(unknown_signal_path), target_frame_id="0x999")
        assert result_other["analyzed_frame_count"] == 0


class TestExtendedIdRegression:
    """Regression for a crash found testing against real extended-ID/J1939
    traces: _build_draft_dbc() built a cantools Message without
    is_extended_frame=True, so cantools rejected any arbitration ID above
    11 bits — making a whole-file scan-all-frames call unusable on any
    real-world extended-ID trace.
    """

    def test_extended_id_frame_does_not_crash_and_is_tagged_extended(self, scratch_path):
        import cantools
        path = scratch_path("extended_id_unknown.blf")
        extended_id = 0x18FF1234
        generator.generate_unknown_signal_trace(path, frame_id=extended_id, frame_count=200)

        result = health_engine.reverse_engineer_unknown_frames(str(path), target_frame_id=hex(extended_id))
        assert result["analyzed_frame_count"] == 1
        draft_db = cantools.database.load_string(result["frames"][0]["draft_dbc_text"], database_format="dbc")
        assert draft_db.messages[0].frame_id == extended_id
        assert draft_db.messages[0].is_extended_frame is True

    def test_scan_all_mode_does_not_crash_on_extended_ids(self, scratch_path):
        path = scratch_path("extended_id_scan_all.blf")
        generator.generate_unknown_signal_trace(path, frame_id=0x18FF1234, frame_count=200)
        result = health_engine.reverse_engineer_unknown_frames(str(path))
        assert "error" not in result
        assert result["analyzed_frame_count"] == 1


class TestMultiChannelBusHealthRegression:
    """Regression for a correctness bug found testing against real
    multi-channel logs: analyze_bus_health_and_faults summed bus-load bits
    and per-ID timestamps across ALL channels before comparing to one
    nominal_baudrate, producing a false ">80% bus load" advisory on a file
    that was really 3 separate physical buses merged into one.
    """

    def test_bus_load_reported_independently_per_channel(self, scratch_path):
        path = scratch_path("multi_channel_bus_health.blf")
        generator.generate_multi_channel_collision_trace(path, frame_count_per_channel=200, cycle_a_s=0.001, cycle_b_s=0.1)

        result = health_engine.analyze_bus_health_and_faults(str(path), nominal_baudrate=500_000)
        assert set(result["channels"]) == {"0", "1"}
        assert "0" in result["bus_load_by_channel"]
        assert "1" in result["bus_load_by_channel"]
        # Channel 0 is busy (1kHz), channel 1 is quiet (10Hz): they must be
        # reported independently, not as one merged (and therefore wrong) figure.
        assert result["bus_load_by_channel"]["0"]["peak_load_percent"] > result["bus_load_by_channel"]["1"]["peak_load_percent"]

    def test_missing_frame_and_bus_off_events_tagged_with_channel(self, scratch_path):
        path = scratch_path("multi_channel_bus_health2.blf")
        generator.generate_multi_channel_collision_trace(path)
        db_path = generator.generate_bus_health_dbc(scratch_path("multi_channel_bus_health2.dbc"))
        result = health_engine.analyze_bus_health_and_faults(str(path), str(db_path))
        for event in result["missing_frame_events"]:
            assert "channel" in event
        for candidate in result["bus_off_candidates"]:
            assert "channel" in candidate
