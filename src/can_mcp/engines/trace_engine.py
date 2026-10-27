"""Stage 4: streaming multi-format trace ingestion, filtering & export.

summarize_trace_log, query_decoded_signals, filter_and_export_trace.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import can
import polars as pl

from can_mcp.config import MAX_RESPONSE_CHARS, resolve_workspace_path
from can_mcp.engines.dbc_engine import _parse_int_literal, load_database
from can_mcp.models.errors import CanMcpError
from can_mcp.models.schemas import ExportResult
from can_mcp.utils import guardrail, safe_eval, transactions

NATIVE_CAN_FORMATS = {".asc", ".blf", ".trc", ".log", ".csv"}
PARQUET_EXT = ".parquet"
SUPPORTED_TRACE_EXTENSIONS = NATIVE_CAN_FORMATS | {PARQUET_EXT}


def _resolve_trace_path(path_str: str, must_exist: bool = True) -> Path:
    path = resolve_workspace_path(path_str)
    if path.suffix.lower() not in SUPPORTED_TRACE_EXTENSIONS:
        raise CanMcpError(
            "UNSUPPORTED_TRACE_FORMAT", f"'{path.suffix}' is not a supported trace format.",
            f"Use one of: {', '.join(sorted(SUPPORTED_TRACE_EXTENSIONS))}.",
        )
    if must_exist and not path.exists():
        raise CanMcpError("FILE_NOT_FOUND", f"Trace file not found at '{path_str}'.",
                           "Check the path is correct and relative to the workspace root.")
    return path


def _message_to_parquet_row(msg: can.Message) -> dict:
    return {
        "timestamp": msg.timestamp,
        "arbitration_id": msg.arbitration_id,
        "is_extended_id": bool(msg.is_extended_id),
        "is_error_frame": bool(msg.is_error_frame),
        "is_remote_frame": bool(msg.is_remote_frame),
        "channel": msg.channel if isinstance(msg.channel, int) else None,
        "dlc": msg.dlc,
        "data_hex": (msg.data or b"").hex(),
    }


def _parquet_row_to_message(row: dict) -> can.Message:
    data_hex = row.get("data_hex") or ""
    return can.Message(
        timestamp=row["timestamp"], arbitration_id=row["arbitration_id"],
        is_extended_id=bool(row.get("is_extended_id", False)), is_error_frame=bool(row.get("is_error_frame", False)),
        is_remote_frame=bool(row.get("is_remote_frame", False)), channel=row.get("channel"),
        dlc=row.get("dlc"), data=bytes.fromhex(data_hex) if data_hex else b"",
    )


def iter_trace_messages(path: Path):
    """Stream every frame in `path`, one at a time, regardless of format.

    `relative_timestamp=False` is passed unconditionally: every native
    python-can reader except ASCReader ignores it, and ASC's own default of
    relative-to-start timestamps would otherwise make cross-format timestamp
    comparisons meaningless (ASC is the only format that stores time
    relative to a "Begin Triggerblock" header instead of absolute epoch).
    """
    if path.suffix.lower() == PARQUET_EXT:
        for row in pl.read_parquet(path).iter_rows(named=True):
            yield _parquet_row_to_message(row)
        return
    yield from can.LogReader(str(path), relative_timestamp=False)


def _channel_key(msg: can.Message) -> str:
    """Normalize python-can's `channel` (int, str, or None) to a stable,
    JSON-friendly dict key. The same arbitration ID is routinely reused
    across independent physical CAN buses in multi-channel logs (confirmed
    against real multi-channel traces), each with its own cadence and
    payload layout, so per-ID structures below must key on (channel, id),
    never on id alone — merging across channels silently produces negative
    or doubled delta-t statistics.
    """
    return str(msg.channel) if msg.channel is not None else "default"


def _resolve_arbitration_id(token: str) -> int:
    value = _parse_int_literal(str(token))
    if value is None:
        raise CanMcpError("INVALID_ARBITRATION_ID", f"'{token}' is not a valid hex/decimal arbitration ID.",
                           "Use a decimal integer or a '0x...' hex string.")
    return value


# ---- summarize_trace_log ----------------------------------------------------

class _IdAccumulator:
    __slots__ = ("count", "last_ts", "sum_dt_ms", "min_dt_ms", "max_dt_ms", "dt_count", "dlc_values", "byte_histogram", "error_count")

    def __init__(self):
        self.count = 0
        self.last_ts = None
        self.sum_dt_ms = 0.0
        self.min_dt_ms = None
        self.max_dt_ms = None
        self.dt_count = 0
        self.dlc_values: set[int] = set()
        self.byte_histogram = [0] * 256
        self.error_count = 0

    def add(self, msg: can.Message) -> None:
        self.count += 1
        if msg.is_error_frame:
            self.error_count += 1
        else:
            self.dlc_values.add(msg.dlc or 0)
            for byte in msg.data or b"":
                self.byte_histogram[byte] += 1
        if self.last_ts is not None:
            dt_ms = (msg.timestamp - self.last_ts) * 1000.0
            self.sum_dt_ms += dt_ms
            self.dt_count += 1
            self.min_dt_ms = dt_ms if self.min_dt_ms is None else min(self.min_dt_ms, dt_ms)
            self.max_dt_ms = dt_ms if self.max_dt_ms is None else max(self.max_dt_ms, dt_ms)
        self.last_ts = msg.timestamp

    @property
    def mean_dt_ms(self) -> float | None:
        return (self.sum_dt_ms / self.dt_count) if self.dt_count else None

    @property
    def entropy_bits(self) -> float | None:
        total = sum(self.byte_histogram)
        if total == 0:
            return None
        entropy = 0.0
        for freq in self.byte_histogram:
            if freq:
                p = freq / total
                entropy -= p * math.log2(p)
        return entropy


def summarize_trace_log(log_path: str, dbc_path: str | None = None, max_chars: int = MAX_RESPONSE_CHARS) -> dict:
    path = _resolve_trace_path(log_path)
    db = load_database(dbc_path) if dbc_path else None

    accumulators: dict[tuple, _IdAccumulator] = {}
    channels: set = set()
    total_frames = 0
    error_frames = 0
    start_ts: float | None = None
    end_ts: float | None = None

    for msg in iter_trace_messages(path):
        total_frames += 1
        if msg.is_error_frame:
            error_frames += 1
        if msg.channel is not None:
            channels.add(msg.channel)
        if start_ts is None:
            start_ts = msg.timestamp
        end_ts = msg.timestamp
        key = (_channel_key(msg), msg.arbitration_id)
        accumulators.setdefault(key, _IdAccumulator()).add(msg)

    duration = (end_ts - start_ts) if (start_ts is not None and end_ts is not None) else 0.0

    rows = []
    for (channel, frame_id), acc in sorted(accumulators.items(), key=lambda kv: -kv[1].count):
        name = None
        if db is not None:
            try:
                name = db.get_message_by_frame_id(frame_id).name
            except KeyError:
                name = None
        dlc_values = sorted(acc.dlc_values)
        rows.append({
            "channel": channel,
            "frame_id_hex": hex(frame_id),
            "name": name,
            "count": acc.count,
            "error_count": acc.error_count,
            "mean_dt_ms": round(acc.mean_dt_ms, 3) if acc.mean_dt_ms is not None else None,
            "min_dt_ms": round(acc.min_dt_ms, 3) if acc.min_dt_ms is not None else None,
            "max_dt_ms": round(acc.max_dt_ms, 3) if acc.max_dt_ms is not None else None,
            "dlc": dlc_values[0] if len(dlc_values) == 1 else dlc_values,
            "payload_entropy_bits": round(acc.entropy_bits, 3) if acc.entropy_bits is not None else None,
        })

    def build(prefix_rows: list) -> dict:
        return {
            "log_path": log_path,
            "duration_seconds": round(duration, 6),
            "start_timestamp": start_ts,
            "end_timestamp": end_ts,
            "total_frame_count": total_frames,
            "error_frame_count": error_frames,
            "channels": sorted(channels, key=str),
            "distinct_id_count": len(accumulators),
            "per_id_summary": prefix_rows,
        }

    return guardrail.fit_rows_to_char_budget(build, rows, max_chars)


# ---- query_decoded_signals --------------------------------------------------

class _WelfordStats:
    __slots__ = ("count", "mean", "_m2", "min", "max", "first", "last")

    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self._m2 = 0.0
        self.min: float | None = None
        self.max: float | None = None
        self.first: float | None = None
        self.last: float | None = None

    def add(self, value: float) -> None:
        self.count += 1
        if self.first is None:
            self.first = value
        self.last = value
        self.min = value if self.min is None else min(self.min, value)
        self.max = value if self.max is None else max(self.max, value)
        delta = value - self.mean
        self.mean += delta / self.count
        self._m2 += delta * (value - self.mean)

    @property
    def std(self) -> float | None:
        return math.sqrt(self._m2 / self.count) if self.count >= 2 else None


class _StreamDownsampler:
    """Bounded-memory, single-pass, roughly time-even decimation: the
    buffer is halved (keeping every other point) whenever it fills past
    2x the target size, so it stays O(cap) for an arbitrarily long stream.
    """

    def __init__(self, cap: int):
        self.cap = max(1, cap)
        self._buffer: list = []

    def add(self, point) -> None:
        self._buffer.append(point)
        if len(self._buffer) >= self.cap * 2:
            self._buffer = self._buffer[::2]

    def result(self) -> list:
        return self._buffer[: self.cap]


def _to_numeric(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_jsonable(value):
    numeric = _to_numeric(value)
    return round(numeric, 6) if numeric is not None else str(value)


def _build_signal_frame_index(db, signal_names: list[str]) -> dict[str, object]:
    signal_to_message = {}
    for message in db.messages:
        for signal in message.signals:
            if signal.name in signal_names and signal.name not in signal_to_message:
                signal_to_message[signal.name] = message
    missing = [name for name in signal_names if name not in signal_to_message]
    if missing:
        raise CanMcpError(
            "SIGNAL_NOT_FOUND", f"Signal(s) not found in DBC: {missing}",
            "Use search_database to locate the correct signal name(s).",
        )
    return signal_to_message


def _in_time_range(timestamp: float, start_time: float | None, end_time: float | None) -> bool:
    if start_time is not None and timestamp < start_time:
        return False
    if end_time is not None and timestamp > end_time:
        return False
    return True


def query_decoded_signals(
    log_path: str,
    dbc_path: str,
    signal_names: list[str],
    start_time: float | None = None,
    end_time: float | None = None,
    max_rows: int = 100,
    aggregation: str = "summary",
    max_chars: int = MAX_RESPONSE_CHARS,
) -> dict:
    path = _resolve_trace_path(log_path)
    db = load_database(dbc_path)
    signal_to_message = _build_signal_frame_index(db, signal_names)
    relevant_frame_ids = {m.frame_id for m in signal_to_message.values()}

    if aggregation != "summary":
        rows = []
        for msg in iter_trace_messages(path):
            if msg.is_error_frame or msg.arbitration_id not in relevant_frame_ids:
                continue
            if not _in_time_range(msg.timestamp, start_time, end_time):
                continue
            try:
                decoded = db.decode_message(msg.arbitration_id, msg.data)
            except Exception:  # noqa: BLE001 - skip frames that fail to decode
                continue
            row = {"timestamp": msg.timestamp}
            matched = False
            for name in signal_names:
                if name in decoded:
                    row[name] = _to_jsonable(decoded[name])
                    matched = True
            if matched:
                rows.append(row)
            if len(rows) >= max_rows:
                break

        def build_raw(prefix: list) -> dict:
            return {"log_path": log_path, "signal_names": signal_names, "aggregation": aggregation, "rows": prefix}

        return guardrail.fit_rows_to_char_budget(build_raw, rows, max_chars)

    stats = {name: _WelfordStats() for name in signal_names}
    downsamplers = {name: _StreamDownsampler(max_rows) for name in signal_names}
    anomalies: dict[str, list] = {name: [] for name in signal_names}

    for msg in iter_trace_messages(path):
        if msg.is_error_frame or msg.arbitration_id not in relevant_frame_ids:
            continue
        if not _in_time_range(msg.timestamp, start_time, end_time):
            continue
        try:
            decoded = db.decode_message(msg.arbitration_id, msg.data)
        except Exception:  # noqa: BLE001 - skip frames that fail to decode
            continue
        for name in signal_names:
            if name not in decoded:
                continue
            value = _to_numeric(decoded[name])
            if value is None:
                continue
            st = stats[name]
            std = st.std
            if std and abs(value - st.mean) > 3 * std:
                anomalies[name].append({"t": msg.timestamp, "v": value, "z": round((value - st.mean) / std, 2)})
                anomalies[name] = sorted(anomalies[name], key=lambda a: -abs(a["z"]))[:20]
            st.add(value)
            downsamplers[name].add({"t": msg.timestamp, "v": value})

    def render(series_cap: int, anomaly_cap: int) -> dict:
        return {
            "log_path": log_path,
            "signal_names": signal_names,
            "aggregation": "summary",
            "signals": {
                name: {
                    "count": stats[name].count,
                    "min": stats[name].min,
                    "max": stats[name].max,
                    "mean": round(stats[name].mean, 6) if stats[name].count else None,
                    "std": round(stats[name].std, 6) if stats[name].std is not None else None,
                    "first": stats[name].first,
                    "last": stats[name].last,
                    "series": downsamplers[name].result()[:series_cap],
                    "anomalies": anomalies[name][:anomaly_cap],
                }
                for name in signal_names
            },
        }

    payload = render(max_rows, 20)
    for series_cap, anomaly_cap in ((max_rows, 10), (max(1, max_rows // 2), 5), (10, 0), (1, 0)):
        if len(json.dumps(payload)) <= max_chars:
            break
        payload = render(series_cap, anomaly_cap)
    payload["truncated"] = any(
        stats[name].count > len(payload["signals"][name]["series"]) for name in signal_names
    )
    return payload


# ---- filter_and_export_trace ------------------------------------------------

def _matches_id_filters(arbitration_id: int, include_ids: set[int] | None, exclude_ids: set[int] | None) -> bool:
    if include_ids is not None and arbitration_id not in include_ids:
        return False
    if exclude_ids is not None and arbitration_id in exclude_ids:
        return False
    return True


def _write_native_format(path: Path, messages) -> int:
    writer = can.Logger(filename=str(path))
    count = 0
    try:
        for msg in messages:
            writer.on_message_received(msg)
            count += 1
    finally:
        writer.stop()
    return count


def _write_parquet(path: Path, messages) -> int:
    rows = [_message_to_parquet_row(msg) for msg in messages]
    pl.DataFrame(rows).write_parquet(path)
    return len(rows)


def filter_and_export_trace(
    input_log_path: str,
    output_path: str,
    dbc_path: str | None = None,
    include_ids: list[str] | None = None,
    exclude_ids: list[str] | None = None,
    time_range: tuple[float, float] | None = None,
    signal_condition: str | None = None,
    dry_run: bool = False,
) -> dict:
    in_path = _resolve_trace_path(input_log_path)
    out_path = _resolve_trace_path(output_path, must_exist=False)

    include_set = {_resolve_arbitration_id(i) for i in include_ids} if include_ids else None
    exclude_set = {_resolve_arbitration_id(i) for i in exclude_ids} if exclude_ids else None

    condition_tree = None
    db = None
    if signal_condition:
        if not dbc_path:
            raise CanMcpError("DBC_REQUIRED_FOR_CONDITION", "signal_condition requires dbc_path to be set.",
                               "Pass dbc_path, or drop signal_condition.")
        db = load_database(dbc_path)
        try:
            condition_tree = safe_eval.compile_condition(signal_condition)
        except (SyntaxError, safe_eval.UnsafeExpressionError) as exc:
            raise CanMcpError("INVALID_SIGNAL_CONDITION", str(exc),
                               "Use a simple comparison/boolean expression over decoded signal names, e.g. 'VehicleSpeed > 100.0'.") from exc
    elif dbc_path:
        db = load_database(dbc_path)

    def matching_messages():
        for msg in iter_trace_messages(in_path):
            if not _matches_id_filters(msg.arbitration_id, include_set, exclude_set):
                continue
            if time_range is not None and not _in_time_range(msg.timestamp, time_range[0], time_range[1]):
                continue
            if condition_tree is not None:
                if msg.is_error_frame:
                    continue
                try:
                    decoded = db.decode_message(msg.arbitration_id, msg.data)
                except Exception:  # noqa: BLE001 - frame doesn't belong to a known message
                    continue
                try:
                    if not safe_eval.evaluate_condition(condition_tree, decoded):
                        continue
                except KeyError:
                    continue
            yield msg

    if dry_run:
        matched_count = sum(1 for _ in matching_messages())
        result = ExportResult(
            success=True, dry_run=True, input_path=input_log_path, output_path=output_path,
            matched_frame_count=matched_count,
            message=f"Dry run: {matched_count} frame(s) would be written to '{output_path}'.",
        )
        return result.model_dump()

    # Keep the real extension on the tmp file: can.Logger dispatches its
    # writer purely by suffix, so a ".tmp" suffix would break format detection.
    tmp_path = out_path.with_name(out_path.stem + ".tmp" + out_path.suffix)
    try:
        if out_path.suffix.lower() == PARQUET_EXT:
            count = _write_parquet(tmp_path, matching_messages())
        else:
            count = _write_native_format(tmp_path, matching_messages())
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        raise CanMcpError("EXPORT_FAILED", f"Could not write '{output_path}': {exc}",
                           "Check the output format is one of .blf/.asc/.trc/.log/.csv/.parquet.") from exc

    backup = transactions.commit_file_atomically(tmp_path, out_path)

    result = ExportResult(
        success=True, dry_run=False, input_path=input_log_path, output_path=output_path,
        matched_frame_count=count, backup_path=str(backup) if backup else None,
        message=f"Wrote {count} matching frame(s) to '{output_path}'.",
    )
    return result.model_dump()
