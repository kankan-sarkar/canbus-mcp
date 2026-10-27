"""Stage 4 Test & Validation Gate (REQUIREMENTS.md section 4, Stage 4.2)."""
from __future__ import annotations

import json

import can as python_can
import cantools
import pytest

from can_mcp.engines import trace_engine
from tests.fixtures import generator

FRAME_COUNT = 5000


@pytest.fixture(scope="module")
def dbc_path():
    return generator.generate_vehicle_trace_dbc()


@pytest.fixture(scope="module")
def base_trace_path(dbc_path):
    path = generator.FIXTURES_DIR / "_stage4_base_trace.blf"
    generator.generate_synthetic_trace(path, frame_count=FRAME_COUNT)
    yield path
    path.unlink(missing_ok=True)


@pytest.fixture()
def scratch_path():
    paths = []

    def _make(name: str):
        path = generator.FIXTURES_DIR / name
        paths.append(path)
        return path

    yield _make
    for path in paths:
        for extra in (path, path.with_name(path.stem + ".tmp" + path.suffix), path.with_name(path.name + ".bak")):
            if extra.exists():
                extra.unlink()


@pytest.fixture(scope="module")
def original_messages(base_trace_path):
    return list(python_can.LogReader(str(base_trace_path), relative_timestamp=False))


@pytest.fixture(scope="module")
def ground_truth(base_trace_path, dbc_path):
    db = cantools.database.load_file(str(dbc_path))
    matching, non_matching = set(), set()
    for msg in python_can.LogReader(str(base_trace_path), relative_timestamp=False):
        decoded = db.decode_message(msg.arbitration_id, msg.data)
        bucket = matching if decoded["VehicleSpeed"] > 100.0 else non_matching
        bucket.add(round(msg.timestamp, 6))
    return matching, non_matching


class TestGate4_1_MultiFormatIO:
    """Gate 4.1: Programmatically generate a 5,000-frame synthetic trace in
    .blf, convert it via filter_and_export_trace to .asc, .trc, and .csv,
    and verify identical frame counts, arbitration IDs, timestamps, and
    payloads across all formats.
    """

    def test_base_trace_has_expected_frame_count(self, original_messages):
        assert len(original_messages) == FRAME_COUNT

    @pytest.mark.parametrize("target_ext", ["asc", "trc", "csv"])
    def test_format_conversion_preserves_frames_exactly(self, base_trace_path, original_messages, scratch_path, target_ext):
        out_path = scratch_path(f"_stage4_converted.{target_ext}")
        result = trace_engine.filter_and_export_trace(str(base_trace_path), str(out_path))
        assert result["success"] is True
        assert result["matched_frame_count"] == FRAME_COUNT

        converted = list(python_can.LogReader(str(out_path), relative_timestamp=False))
        assert len(converted) == len(original_messages)
        for original, converted_msg in zip(original_messages, converted):
            assert converted_msg.arbitration_id == original.arbitration_id
            assert converted_msg.timestamp == pytest.approx(original.timestamp, abs=1e-6)
            assert converted_msg.data == original.data

    def test_parquet_round_trip_preserves_frames(self, base_trace_path, original_messages, scratch_path):
        parquet_path = scratch_path("_stage4_converted.parquet")
        back_path = scratch_path("_stage4_converted_back.blf")

        trace_engine.filter_and_export_trace(str(base_trace_path), str(parquet_path))
        trace_engine.filter_and_export_trace(str(parquet_path), str(back_path))

        roundtripped = list(python_can.LogReader(str(back_path), relative_timestamp=False))
        assert len(roundtripped) == len(original_messages)
        for original, rt in zip(original_messages, roundtripped):
            assert rt.arbitration_id == original.arbitration_id
            assert rt.timestamp == pytest.approx(original.timestamp, abs=1e-6)
            assert rt.data == original.data


class TestGate4_2_SignalExpressionFilter:
    """Gate 4.2: Filter the 5,000-frame .blf trace with
    signal_condition="VehicleSpeed > 100.0", write to high_speed_only.blf,
    and verify only frames matching the physical decoded condition are
    present.
    """

    def test_output_contains_exactly_the_matching_frames(self, base_trace_path, dbc_path, ground_truth, scratch_path):
        matching, _ = ground_truth
        out_path = scratch_path("high_speed_only.blf")

        result = trace_engine.filter_and_export_trace(
            str(base_trace_path), str(out_path), dbc_path=str(dbc_path), signal_condition="VehicleSpeed > 100.0",
        )
        assert result["success"] is True
        assert result["matched_frame_count"] == len(matching)

        output_timestamps = {
            round(m.timestamp, 6) for m in python_can.LogReader(str(out_path), relative_timestamp=False)
        }
        assert output_timestamps == matching

    def test_no_output_frame_violates_the_condition(self, base_trace_path, dbc_path, scratch_path):
        db = cantools.database.load_file(str(dbc_path))
        out_path = scratch_path("high_speed_only2.blf")
        trace_engine.filter_and_export_trace(
            str(base_trace_path), str(out_path), dbc_path=str(dbc_path), signal_condition="VehicleSpeed > 100.0",
        )
        for msg in python_can.LogReader(str(out_path), relative_timestamp=False):
            decoded = db.decode_message(msg.arbitration_id, msg.data)
            assert decoded["VehicleSpeed"] > 100.0

    def test_compound_condition(self, base_trace_path, dbc_path, scratch_path):
        db = cantools.database.load_file(str(dbc_path))
        out_path = scratch_path("mid_range.blf")
        result = trace_engine.filter_and_export_trace(
            str(base_trace_path), str(out_path), dbc_path=str(dbc_path),
            signal_condition="VehicleSpeed > 50.0 and VehicleSpeed < 150.0",
        )
        assert result["matched_frame_count"] > 0
        for msg in python_can.LogReader(str(out_path), relative_timestamp=False):
            decoded = db.decode_message(msg.arbitration_id, msg.data)
            assert 50.0 < decoded["VehicleSpeed"] < 150.0

    def test_unsafe_expression_is_rejected(self, base_trace_path, dbc_path, scratch_path):
        from can_mcp.models.errors import CanMcpError
        out_path = scratch_path("unsafe.blf")
        with pytest.raises(CanMcpError) as excinfo:
            trace_engine.filter_and_export_trace(
                str(base_trace_path), str(out_path), dbc_path=str(dbc_path),
                signal_condition="__import__('os').system('echo pwned')",
            )
        assert excinfo.value.error_code == "INVALID_SIGNAL_CONDITION"
        assert not out_path.exists()


class TestGate4_3_TokenGuardrail:
    """Gate 4.3: Ensure summarize_trace_log and query_decoded_signals never
    return payloads exceeding a configurable character ceiling (default
    16,000 chars).
    """

    DEFAULT_CEILING = 16_000

    def test_summarize_trace_log_under_default_ceiling(self, base_trace_path, dbc_path):
        result = trace_engine.summarize_trace_log(str(base_trace_path), str(dbc_path))
        assert len(json.dumps(result)) <= self.DEFAULT_CEILING

    def test_summarize_trace_log_respects_many_distinct_ids(self, scratch_path):
        path = scratch_path("_stage4_many_ids.blf")
        logger = python_can.Logger(filename=str(path))
        try:
            for i in range(2000):
                logger.on_message_received(python_can.Message(
                    timestamp=1_700_000_000.0 + i * 0.001, arbitration_id=1 + i,
                    is_extended_id=False, data=bytes([i % 256] * 8), channel=0,
                ))
        finally:
            logger.stop()

        result = trace_engine.summarize_trace_log(str(path))
        text = json.dumps(result)
        assert len(text) <= self.DEFAULT_CEILING
        assert result["distinct_id_count"] == 2000
        assert result["truncated"] is True
        assert result["omitted_count"] == 2000 - len(result["per_id_summary"])

    def test_summarize_trace_log_respects_custom_ceiling(self, base_trace_path):
        small_ceiling = 500
        result = trace_engine.summarize_trace_log(str(base_trace_path), max_chars=small_ceiling)
        assert len(json.dumps(result)) <= small_ceiling

    def test_query_decoded_signals_summary_under_default_ceiling(self, base_trace_path, dbc_path):
        result = trace_engine.query_decoded_signals(
            str(base_trace_path), str(dbc_path), ["VehicleSpeed", "EngineRPM"], max_rows=5000,
        )
        assert len(json.dumps(result)) <= self.DEFAULT_CEILING

    def test_query_decoded_signals_raw_respects_max_rows_and_ceiling(self, base_trace_path, dbc_path):
        result = trace_engine.query_decoded_signals(
            str(base_trace_path), str(dbc_path), ["VehicleSpeed"], aggregation="raw", max_rows=20,
        )
        assert len(result["rows"]) <= 20
        assert len(json.dumps(result)) <= self.DEFAULT_CEILING

    def test_query_decoded_signals_summary_still_reports_full_stats(self, base_trace_path, dbc_path):
        result = trace_engine.query_decoded_signals(str(base_trace_path), str(dbc_path), ["VehicleSpeed"])
        stats = result["signals"]["VehicleSpeed"]
        assert stats["count"] == FRAME_COUNT
        assert stats["min"] == pytest.approx(0.0, abs=0.2)
        assert stats["max"] == pytest.approx(250.0, abs=0.2)


class TestMultiChannelIdCollisionRegression:
    """Regression for a bug found testing against real multi-channel logs:
    the same arbitration ID reused on two independent physical CAN channels
    was merged into one timeline, producing negative/doubled delta-t.
    summarize_trace_log must key its per-ID stats by (channel, id).
    """

    @pytest.fixture()
    def collision_trace_path(self, scratch_path):
        path = scratch_path("multi_channel_collision.blf")
        generator.generate_multi_channel_collision_trace(path)
        return path

    def test_same_id_on_different_channels_reported_separately(self, collision_trace_path):
        result = trace_engine.summarize_trace_log(str(collision_trace_path))
        rows = [r for r in result["per_id_summary"] if r["frame_id_hex"] == hex(0x301)]
        assert len(rows) == 2
        assert {r["channel"] for r in rows} == {"0", "1"}

    def test_no_negative_or_implausible_delta_t(self, collision_trace_path):
        result = trace_engine.summarize_trace_log(str(collision_trace_path))
        for row in result["per_id_summary"]:
            if row["min_dt_ms"] is not None:
                assert row["min_dt_ms"] >= 0
            if row["max_dt_ms"] is not None:
                assert row["max_dt_ms"] < result["duration_seconds"] * 1000

    def test_each_channel_reports_its_own_correct_cadence(self, collision_trace_path):
        result = trace_engine.summarize_trace_log(str(collision_trace_path))
        rows_by_channel = {r["channel"]: r for r in result["per_id_summary"] if r["frame_id_hex"] == hex(0x301)}
        assert rows_by_channel["0"]["mean_dt_ms"] == pytest.approx(100.0, abs=1.0)
        assert rows_by_channel["1"]["mean_dt_ms"] == pytest.approx(40.0, abs=1.0)
