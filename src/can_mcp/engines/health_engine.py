"""Stage 6: bus health diagnostics & unknown-signal reverse-engineering.

analyze_bus_health_and_faults, reverse_engineer_unknown_frames.
"""
from __future__ import annotations

import math
import re
from collections import defaultdict

import cantools.database.can as can
from cantools.database.conversion import BaseConversion

from can_mcp.config import MAX_RESPONSE_CHARS
from can_mcp.engines.dbc_engine import _parse_int_literal, load_database
from can_mcp.engines.trace_engine import _channel_key, _resolve_trace_path, iter_trace_messages
from can_mcp.models.errors import CanMcpError
from can_mcp.utils import guardrail

# --------------------------------------------------------------------------
# analyze_bus_health_and_faults
# --------------------------------------------------------------------------

BUS_LOAD_WINDOW_SECONDS = 0.1
BUS_LOAD_HIGH_THRESHOLD_PERCENT = 80.0
BIT_STUFFING_OVERHEAD = 1.15
MISSING_FRAME_RATIO = 2.5
BABBLING_RATIO = 0.5
ERROR_BURST_GAP_SECONDS = 0.02
ERROR_STORM_MIN_COUNT = 20
BUS_OFF_MIN_SILENCE_SECONDS = 0.08
COUNTER_NAME_PATTERN = re.compile(r"counter|alive|sqc", re.IGNORECASE)


def _frame_bit_count(is_extended: bool, dlc: int) -> float:
    """Approximate on-wire bit count for a classical CAN frame (SOF, ID,
    control, CRC, ACK, EOF, IFS), before bit-stuffing overhead.
    """
    overhead = 67 if is_extended else 47
    return overhead + 8 * dlc


def _group_error_bursts(error_timestamps: list[float]) -> list[list[float]]:
    bursts: list[list[float]] = []
    for ts in error_timestamps:
        if bursts and ts - bursts[-1][-1] <= ERROR_BURST_GAP_SECONDS:
            bursts[-1].append(ts)
        else:
            bursts.append([ts])
    return bursts


def _find_silence_after(timestamps: list[float], after: float) -> tuple[float | None, float | None]:
    """Return (last_ts_before, first_ts_after) straddling `after`."""
    last_before, first_after = None, None
    for ts in timestamps:
        if ts <= after:
            last_before = ts
        elif first_after is None:
            first_after = ts
            break
    return last_before, first_after


def analyze_bus_health_and_faults(
    log_path: str,
    dbc_path: str | None = None,
    nominal_baudrate: int = 500_000,
    fd_data_baudrate: int = 2_000_000,
    max_chars: int = MAX_RESPONSE_CHARS,
) -> dict:
    path = _resolve_trace_path(log_path)
    db = load_database(dbc_path) if dbc_path else None

    cycle_time_ms_by_id: dict[int, int] = {}
    name_by_id: dict[int, str] = {}
    sender_by_id: dict[int, str] = {}
    counter_signals: list[tuple] = []  # (message, signal)
    if db is not None:
        for message in db.messages:
            name_by_id[message.frame_id] = message.name
            if message.senders:
                sender_by_id[message.frame_id] = message.senders[0]
            if message.cycle_time:
                cycle_time_ms_by_id[message.frame_id] = message.cycle_time
            for signal in message.signals:
                if COUNTER_NAME_PATTERN.search(signal.name):
                    counter_signals.append((message, signal))

    timestamps_by_channel: dict[str, dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))
    window_bits_by_channel: dict[str, dict[int, float]] = defaultdict(lambda: defaultdict(float))
    error_timestamps: list[float] = []
    total_frames = 0
    error_frame_count = 0
    start_ts: float | None = None
    end_ts: float | None = None

    for msg in iter_trace_messages(path):
        total_frames += 1
        if start_ts is None:
            start_ts = msg.timestamp
        end_ts = msg.timestamp
        if msg.is_error_frame:
            error_frame_count += 1
            error_timestamps.append(msg.timestamp)
            continue
        channel = _channel_key(msg)
        window_idx = int((msg.timestamp - start_ts) // BUS_LOAD_WINDOW_SECONDS)
        window_bits_by_channel[channel][window_idx] += _frame_bit_count(bool(msg.is_extended_id), msg.dlc or 0) * BIT_STUFFING_OVERHEAD
        timestamps_by_channel[channel][msg.arbitration_id].append(msg.timestamp)

    duration = (end_ts - start_ts) if (start_ts is not None and end_ts is not None) else 0.0

    # ---- bus load, per channel (each channel is its own physical bus) --
    window_capacity_bits = nominal_baudrate * BUS_LOAD_WINDOW_SECONDS
    high_load_windows = []
    bus_load_by_channel = {}
    peak_load_percent = 0.0
    for channel, windows in window_bits_by_channel.items():
        channel_peak = 0.0
        channel_high_count = 0
        for window_idx, bits in sorted(windows.items()):
            load_percent = (bits / window_capacity_bits) * 100.0 if window_capacity_bits else 0.0
            channel_peak = max(channel_peak, load_percent)
            if load_percent >= BUS_LOAD_HIGH_THRESHOLD_PERCENT:
                channel_high_count += 1
                high_load_windows.append({
                    "channel": channel,
                    "window_start": round(start_ts + window_idx * BUS_LOAD_WINDOW_SECONDS, 6),
                    "window_end": round(start_ts + (window_idx + 1) * BUS_LOAD_WINDOW_SECONDS, 6),
                    "load_percent": round(load_percent, 2),
                })
        bus_load_by_channel[channel] = {"peak_load_percent": round(channel_peak, 2), "high_load_window_count": channel_high_count}
        peak_load_percent = max(peak_load_percent, channel_peak)

    # ---- cycle-time jitter: missing frames & babbling nodes -----------
    missing_frame_events = []
    babbling_nodes = []
    for channel, timestamps_by_id in timestamps_by_channel.items():
        for frame_id, cycle_ms in cycle_time_ms_by_id.items():
            ts_list = timestamps_by_id.get(frame_id, [])
            if len(ts_list) < 2:
                continue
            babble_count = 0
            for prev, cur in zip(ts_list, ts_list[1:]):
                delta_ms = (cur - prev) * 1000.0
                if delta_ms > MISSING_FRAME_RATIO * cycle_ms:
                    missing_frame_events.append({
                        "channel": channel, "frame_id_hex": hex(frame_id), "name": name_by_id.get(frame_id),
                        "window_start": round(prev, 6), "window_end": round(cur, 6),
                        "delta_ms": round(delta_ms, 3), "cycle_time_ms": cycle_ms,
                        "missed_cycles": max(0, round(delta_ms / cycle_ms) - 1),
                    })
                elif delta_ms < BABBLING_RATIO * cycle_ms:
                    babble_count += 1
            if babble_count >= max(3, len(ts_list) // 4):
                babbling_nodes.append({
                    "channel": channel, "frame_id_hex": hex(frame_id), "name": name_by_id.get(frame_id),
                    "cycle_time_ms": cycle_ms, "fast_frame_count": babble_count,
                })

    # ---- error storms & bus-off candidates -----------------------------
    error_storms = [
        {"start_timestamp": round(burst[0], 6), "end_timestamp": round(burst[-1], 6), "error_count": len(burst)}
        for burst in _group_error_bursts(error_timestamps)
        if len(burst) >= ERROR_STORM_MIN_COUNT
    ]

    bus_off_candidates = []
    for storm in error_storms:
        for channel, timestamps_by_id in timestamps_by_channel.items():
            for frame_id, ts_list in timestamps_by_id.items():
                last_before, first_after = _find_silence_after(ts_list, storm["end_timestamp"])
                if last_before is None or first_after is None:
                    continue
                silence = first_after - last_before
                if silence >= BUS_OFF_MIN_SILENCE_SECONDS:
                    bus_off_candidates.append({
                        "channel": channel, "frame_id_hex": hex(frame_id), "name": name_by_id.get(frame_id),
                        "sender": sender_by_id.get(frame_id),
                        "silence_start": round(last_before, 6), "silence_end": round(first_after, 6),
                        "silence_ms": round(silence * 1000.0, 3),
                        "correlated_error_storm": {"start_timestamp": storm["start_timestamp"], "end_timestamp": storm["end_timestamp"]},
                    })

    # ---- alive-counter faults (requires DBC) ---------------------------
    counter_faults = []
    if db is not None and counter_signals:
        for message, signal in counter_signals:
            has_any_timestamps = any(message.frame_id in by_id for by_id in timestamps_by_channel.values())
            if not has_any_timestamps:
                continue
            modulus = 2 ** signal.length
            prev_raw_by_channel: dict[str, int | None] = defaultdict(lambda: None)
            freeze_run_by_channel: dict[str, int] = defaultdict(int)
            for msg in iter_trace_messages(path):
                if msg.arbitration_id != message.frame_id or msg.is_error_frame:
                    continue
                channel = _channel_key(msg)
                try:
                    raw = message.decode(msg.data, decode_choices=False)[signal.name]
                except Exception:  # noqa: BLE001
                    continue
                raw = int(raw)
                prev_raw = prev_raw_by_channel[channel]
                if prev_raw is not None:
                    if raw == prev_raw:
                        freeze_run_by_channel[channel] += 1
                        if freeze_run_by_channel[channel] == 3:
                            counter_faults.append({
                                "channel": channel, "message": message.name, "signal": signal.name, "fault": "FREEZE",
                                "timestamp": msg.timestamp, "value": raw,
                            })
                    else:
                        freeze_run_by_channel[channel] = 0
                        expected = (prev_raw + 1) % modulus
                        if raw != expected:
                            counter_faults.append({
                                "channel": channel, "message": message.name, "signal": signal.name, "fault": "SKIP",
                                "timestamp": msg.timestamp, "expected": expected, "got": raw,
                            })
                prev_raw_by_channel[channel] = raw

    advisories = []
    for candidate in bus_off_candidates:
        label = f"{candidate.get('name') or candidate['frame_id_hex']} (channel {candidate['channel']})"
        advisories.append(
            f"Error storm ({candidate['correlated_error_storm']['start_timestamp']}s-"
            f"{candidate['correlated_error_storm']['end_timestamp']}s) followed by a "
            f"{candidate['silence_ms']:.0f} ms silence on {label} indicates a likely Bus-Off transition. "
            "Check 120-Ohm termination resistors at both bus ends and verify baudrate/bit-timing "
            "configuration matches across all nodes."
        )
    for event in missing_frame_events:
        label = f"{event.get('name') or event['frame_id_hex']} (channel {event['channel']})"
        advisories.append(
            f"{label} missed {event['missed_cycles']} cycle(s) between {event['window_start']}s and "
            f"{event['window_end']}s (Δt={event['delta_ms']}ms vs {event['cycle_time_ms']}ms expected); "
            "investigate a transmitting-node reset, scheduling overrun, or bus contention."
        )
    for node in babbling_nodes:
        label = f"{node.get('name') or node['frame_id_hex']} (channel {node['channel']})"
        advisories.append(f"{label} is transmitting far faster than its configured cycle time (babbling node); "
                           "check for a stuck task, misconfigured timer, or duplicate transmitter.")
    for channel, load in bus_load_by_channel.items():
        if load["high_load_window_count"] > 0:
            advisories.append(f"Channel {channel}: {load['high_load_window_count']} window(s) exceeded "
                               f"{BUS_LOAD_HIGH_THRESHOLD_PERCENT:.0f}% bus load (peak {load['peak_load_percent']}%); "
                               "consider raising baudrate or redistributing message priorities/cycle times on that bus.")
    for fault in counter_faults:
        if fault["fault"] == "FREEZE":
            advisories.append(f"{fault['message']}.{fault['signal']} alive counter froze at {fault['value']} "
                               f"around t={fault['timestamp']}s; the transmitting node may be hung.")
        else:
            advisories.append(f"{fault['message']}.{fault['signal']} alive counter skipped (expected "
                               f"{fault['expected']}, got {fault['got']}) at t={fault['timestamp']}s.")

    def build(prefix_missing: list) -> dict:
        return {
            "log_path": log_path,
            "duration_seconds": round(duration, 6),
            "total_frame_count": total_frames,
            "error_frame_count": error_frame_count,
            "nominal_baudrate": nominal_baudrate,
            "fd_data_baudrate": fd_data_baudrate,
            "channels": sorted(bus_load_by_channel),
            "peak_bus_load_percent": round(peak_load_percent, 2),
            "bus_load_by_channel": bus_load_by_channel,
            "high_load_windows": high_load_windows[:50],
            "error_storms": error_storms,
            "bus_off_candidates": bus_off_candidates,
            "missing_frame_events": prefix_missing,
            "babbling_nodes": babbling_nodes,
            "counter_faults": counter_faults[:50],
            "advisories": advisories,
        }

    return guardrail.fit_rows_to_char_budget(build, missing_frame_events, max_chars)


# --------------------------------------------------------------------------
# reverse_engineer_unknown_frames
# --------------------------------------------------------------------------

MIN_SAMPLES_FOR_ANALYSIS = 20
CONSTANT_CONFIDENCE = 1.0
COUNTER_MATCH_RATIO_THRESHOLD = 0.85
CHECKSUM_ENTROPY_THRESHOLD_BITS = 6.5
CHECKSUM_CORRELATION_THRESHOLD = 0.85
CONTINUOUS_MAX_NORMALIZED_DERIVATIVE = 0.15
DISCRETE_MAX_DISTINCT_VALUES = 6
DISCRETE_MAX_TOGGLE_RATIO = 0.3


def _shannon_entropy_bits(values: list[int], bit_width: int) -> float:
    if not values:
        return 0.0
    counts: dict[int, int] = defaultdict(int)
    for v in values:
        counts[v] += 1
    total = len(values)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return min(entropy, bit_width)


def _nibble_counter_match_ratio(values: list[int], modulus: int) -> float:
    if len(values) < 2:
        return 0.0
    matches = sum(1 for a, b in zip(values, values[1:]) if b == (a + 1) % modulus)
    return matches / (len(values) - 1)


def _classify_byte_field(byte_index: int, byte_values: list[int], other_bytes: list[list[int]]) -> dict | None:
    distinct = set(byte_values)
    if len(distinct) == 1:
        return {"byte_range": [byte_index, byte_index], "bit_length": 8, "classification": "CONSTANT_MASK",
                "confidence": CONSTANT_CONFIDENCE, "value": byte_values[0]}

    counter_ratio_8 = _nibble_counter_match_ratio(byte_values, 256)
    if counter_ratio_8 >= COUNTER_MATCH_RATIO_THRESHOLD:
        return {"byte_range": [byte_index, byte_index], "bit_length": 8, "classification": "ALIVE_COUNTER",
                "confidence": round(counter_ratio_8, 3)}

    entropy = _shannon_entropy_bits(byte_values, 8)
    if entropy >= CHECKSUM_ENTROPY_THRESHOLD_BITS and other_bytes:
        changes_with_others = 0
        total_pairs = 0
        for i in range(1, len(byte_values)):
            other_changed = any(other[i] != other[i - 1] for other in other_bytes)
            if other_changed:
                total_pairs += 1
                if byte_values[i] != byte_values[i - 1]:
                    changes_with_others += 1
        correlation = (changes_with_others / total_pairs) if total_pairs else 0.0
        if correlation >= CHECKSUM_CORRELATION_THRESHOLD:
            return {"byte_range": [byte_index, byte_index], "bit_length": 8, "classification": "CHECKSUM_CANDIDATE",
                    "confidence": round(min(correlation, entropy / 8.0 + 0.2), 3), "entropy_bits": round(entropy, 3)}

    if len(distinct) <= DISCRETE_MAX_DISTINCT_VALUES:
        toggles = sum(1 for a, b in zip(byte_values, byte_values[1:]) if a != b)
        toggle_ratio = toggles / max(1, len(byte_values) - 1)
        if toggle_ratio <= DISCRETE_MAX_TOGGLE_RATIO:
            return {"byte_range": [byte_index, byte_index], "bit_length": 8, "classification": "DISCRETE_STATUS_FLAG",
                    "confidence": round(1.0 - toggle_ratio, 3), "distinct_values": sorted(distinct)}

    return None


def _classify_nibble_field(byte_index: int, high: bool, nibble_values: list[int]) -> dict | None:
    distinct = set(nibble_values)
    label_suffix = "high_nibble" if high else "low_nibble"
    if len(distinct) == 1:
        return {"byte_range": [byte_index, byte_index], "bit_length": 4, "field": label_suffix,
                "classification": "CONSTANT_MASK", "confidence": CONSTANT_CONFIDENCE, "value": nibble_values[0]}
    ratio = _nibble_counter_match_ratio(nibble_values, 16)
    if ratio >= COUNTER_MATCH_RATIO_THRESHOLD:
        return {"byte_range": [byte_index, byte_index], "bit_length": 4, "field": label_suffix,
                "classification": "ALIVE_COUNTER", "confidence": round(ratio, 3)}
    return None


def _classify_16bit_span(byte_index: int, lo_values: list[int], hi_values: list[int]) -> dict | None:
    combined = [lo | (hi << 8) for lo, hi in zip(lo_values, hi_values)]
    if len(set(combined)) == 1:
        return None  # constant, already handled at byte level
    diffs = [b - a for a, b in zip(combined, combined[1:])]
    if not diffs:
        return None
    mean_abs_diff = sum(abs(d) for d in diffs) / len(diffs)
    value_range = max(combined) - min(combined) or 1
    normalized = mean_abs_diff / value_range
    counter_ratio = _nibble_counter_match_ratio(combined, 65536)
    if normalized <= CONTINUOUS_MAX_NORMALIZED_DERIVATIVE and counter_ratio < COUNTER_MATCH_RATIO_THRESHOLD:
        # Quadratic falloff: genuinely smooth signals (normalized << threshold)
        # stay near full confidence; only signals approaching the threshold
        # itself get pulled down toward 0.5.
        ratio = normalized / CONTINUOUS_MAX_NORMALIZED_DERIVATIVE
        confidence = max(0.0, 1.0 - 0.5 * ratio ** 2)
        return {"byte_range": [byte_index, byte_index + 1], "bit_length": 16,
                "classification": "CONTINUOUS_PHYSICAL_SIGNAL", "confidence": round(min(confidence, 0.99), 3),
                "normalized_derivative": round(normalized, 4)}
    return None


def _build_draft_dbc(frame_id: int, dlc: int, fields: list[dict]) -> str:
    signals = []
    for idx, field in enumerate(fields):
        start_byte = field["byte_range"][0]
        length = field["bit_length"]
        start_bit = start_byte * 8 + (4 if field.get("field") == "high_nibble" else 0)
        name = f"Unknown_{field['classification']}_{idx}_B{field['byte_range'][0]}"
        signals.append(can.Signal(
            name=name, start=start_bit, length=length, byte_order="little_endian", is_signed=False,
            conversion=BaseConversion.factory(scale=1, offset=0), comment=field["classification"],
        ))
    message = can.Message(
        frame_id=frame_id, name=f"Unknown_0x{frame_id:X}", length=dlc, signals=signals,
        is_extended_frame=frame_id > 0x7FF, strict=False,
    )
    database = can.Database(messages=[message], strict=False)
    return database.as_dbc_string()


def reverse_engineer_unknown_frames(
    log_path: str,
    dbc_path: str | None = None,
    target_frame_id: str | None = None,
) -> dict:
    path = _resolve_trace_path(log_path)
    db = load_database(dbc_path) if dbc_path else None
    known_ids = {m.frame_id for m in db.messages} if db is not None else set()

    target_id = None
    if target_frame_id is not None:
        target_id = _parse_int_literal(str(target_frame_id))
        if target_id is None:
            raise CanMcpError("INVALID_FRAME_ID", f"'{target_frame_id}' is not a valid hex/decimal frame ID.",
                               "Use a decimal integer or a '0x...' hex string.")

    # Keyed by (channel, frame_id): the same arbitration ID is routinely
    # reused across independent physical buses in multi-channel logs, each
    # carrying a different payload layout — merging them would corrupt the
    # byte-statistics heuristics below (confirmed against real traces).
    frames_by_channel_id: dict[tuple, list[bytes]] = defaultdict(list)
    for msg in iter_trace_messages(path):
        if msg.is_error_frame or not msg.data:
            continue
        if target_id is not None and msg.arbitration_id != target_id:
            continue
        if target_id is None and msg.arbitration_id in known_ids:
            continue
        frames_by_channel_id[(_channel_key(msg), msg.arbitration_id)].append(bytes(msg.data))

    results = []
    for (channel, frame_id), payloads in frames_by_channel_id.items():
        if len(payloads) < MIN_SAMPLES_FOR_ANALYSIS:
            continue
        dlc = max(len(p) for p in payloads)
        payloads = [p for p in payloads if len(p) == dlc]
        if len(payloads) < MIN_SAMPLES_FOR_ANALYSIS:
            continue

        byte_columns = [[p[i] for p in payloads] for i in range(dlc)]
        claimed_bytes: set[int] = set()
        fields: list[dict] = []

        # Byte-level patterns (constant/counter/checksum/discrete) are far
        # more specific than "looks smooth", so they're resolved first and
        # never get stolen by a 16-bit continuous-signal span.
        byte_classifications: dict[int, dict] = {}
        for i in range(dlc):
            classification = _classify_byte_field(i, byte_columns[i], [byte_columns[j] for j in range(dlc) if j != i])
            if classification:
                byte_classifications[i] = classification
                fields.append(classification)
                claimed_bytes.add(i)

        i = 0
        while i < dlc - 1:
            if i in claimed_bytes or (i + 1) in claimed_bytes:
                i += 1
                continue
            span = _classify_16bit_span(i, byte_columns[i], byte_columns[i + 1])
            if span:
                fields.append(span)
                claimed_bytes.update({i, i + 1})
                i += 2
            else:
                i += 1

        for i in range(dlc):
            if i in claimed_bytes:
                continue
            low = [v & 0x0F for v in byte_columns[i]]
            high = [(v >> 4) & 0x0F for v in byte_columns[i]]
            low_field = _classify_nibble_field(i, False, low)
            high_field = _classify_nibble_field(i, True, high)
            if low_field:
                fields.append(low_field)
            if high_field:
                fields.append(high_field)

        results.append({
            "channel": channel, "frame_id_hex": hex(frame_id), "sample_count": len(payloads), "dlc": dlc,
            "fields": sorted(fields, key=lambda f: f["byte_range"][0]),
            "draft_dbc_text": _build_draft_dbc(frame_id, dlc, fields),
        })

    return {
        "log_path": log_path,
        "analyzed_frame_count": len(results),
        "frames": results,
    }
