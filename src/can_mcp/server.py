"""FastMCP entry point & tool registration."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from can_mcp.engines import dbc_engine, health_engine, protocol_engine, trace_engine
from can_mcp.models.errors import response_dict_from_exception

mcp = FastMCP("can-engineering-mcp")


def _safe_call(func, *args, **kwargs) -> dict:
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - tool boundary must never raise
        return response_dict_from_exception(exc)


@mcp.tool()
def inspect_database_summary(dbc_path: str) -> dict:
    """Protocol type, baudrate, ECU/message/signal counts, and node matrix."""
    return _safe_call(dbc_engine.inspect_database_summary, dbc_path)


@mcp.tool()
def search_database(dbc_path: str, query: str, search_type: str = "all", max_results: int = 25) -> dict:
    """Case-insensitive fuzzy/substring search across messages, signals, IDs, units, comments, and value tables."""
    return _safe_call(dbc_engine.search_database, dbc_path, query, search_type, max_results)


@mcp.tool()
def visualize_frame_layout(dbc_path: str, frame_id_or_name: str) -> dict:
    """ASCII bit/byte grid showing exact Intel/Motorola signal occupancy for one frame."""
    return _safe_call(dbc_engine.visualize_frame_layout, dbc_path, frame_id_or_name)


@mcp.tool()
def validate_database_integrity(dbc_path: str) -> dict:
    """Detect bit overlaps, DLC violations, invalid DLC sizes, duplicate names, and bad min/max/scale."""
    return _safe_call(dbc_engine.validate_database_integrity, dbc_path)


@mcp.tool()
def manage_ecu_node(dbc_path: str, action: str, node_name: str, comment: str = "", new_name: str | None = None, dry_run: bool = False) -> dict:
    """Add, rename, or delete an ECU node (BU_), updating sender/receiver references."""
    return _safe_call(dbc_engine.manage_ecu_node, dbc_path, action, node_name, comment, new_name, dry_run)


@mcp.tool()
def upsert_dbc_message(
    dbc_path: str, frame_id: int, name: str, dlc: int, sender: str,
    is_extended: bool = False, is_fd: bool = False, cycle_time_ms: int | None = None,
    comment: str = "", dry_run: bool = False,
) -> dict:
    """Create or update a CAN/CAN FD frame, writing GenMsgCycleTime and VFrameFormat attributes."""
    return _safe_call(
        dbc_engine.upsert_dbc_message, dbc_path, frame_id, name, dlc, sender,
        is_extended, is_fd, cycle_time_ms, comment, dry_run,
    )


@mcp.tool()
def delete_dbc_message(dbc_path: str, frame_id_or_name: str, dry_run: bool = False) -> dict:
    """Remove a frame cleanly from the database."""
    return _safe_call(dbc_engine.delete_dbc_message, dbc_path, frame_id_or_name, dry_run)


@mcp.tool()
def add_or_update_signal(
    dbc_path: str, message_id_or_name: str, signal_name: str, length: int,
    start_bit: int | None = None, auto_pack: bool = False, byte_order: str = "little_endian",
    is_signed: bool = False, scale: float = 1.0, offset: float = 0.0,
    min_val: float | None = None, max_val: float | None = None, unit: str = "",
    receivers: list[str] | None = None, mux_is_switch: bool = False, mux_value: int | None = None,
    value_table: dict[int, str] | None = None, dry_run: bool = False,
) -> dict:
    """Create or update a signal; auto_pack=True finds the first free bit block. Rejects bit-overlapping writes."""
    return _safe_call(
        dbc_engine.add_or_update_signal, dbc_path, message_id_or_name, signal_name, length,
        start_bit, auto_pack, byte_order, is_signed, scale, offset, min_val, max_val, unit,
        receivers, mux_is_switch, mux_value, value_table, dry_run,
    )


@mcp.tool()
def delete_dbc_signal(dbc_path: str, message_id_or_name: str, signal_name: str, dry_run: bool = False) -> dict:
    """Delete a signal and its associated value table/attribute entries."""
    return _safe_call(dbc_engine.delete_dbc_signal, dbc_path, message_id_or_name, signal_name, dry_run)


@mcp.tool()
def generate_database_from_template(
    output_path: str, template_type: str, baudrate: int = 500_000,
    node_names: list[str] | None = None, dry_run: bool = False,
) -> dict:
    """Generate a clean-room baseline, J1939, CANopen CiA301, or UDS/ISO-TP skeleton .dbc from scratch."""
    return _safe_call(dbc_engine.generate_database_from_template, output_path, template_type, baudrate, node_names, dry_run)


@mcp.tool()
def convert_database_format(input_path: str, output_path: str, target_format: str | None = None, dry_run: bool = False) -> dict:
    """Convert between .dbc/.dbf/.arxml/.kcd/.sym/.xlsx (via canmatrix) and report any attribute loss."""
    return _safe_call(dbc_engine.convert_database_format, input_path, output_path, target_format, dry_run)


@mcp.tool()
def diff_databases(db_path_a: str, db_path_b: str) -> dict:
    """Structured engineering changelog between two databases of any supported format: added/removed messages and signals, bit shifts, scaling/offset changes, and cycle-time changes."""
    return _safe_call(dbc_engine.diff_databases, db_path_a, db_path_b)


@mcp.tool()
def summarize_trace_log(log_path: str, dbc_path: str | None = None) -> dict:
    """Stream a .asc/.blf/.trc/.log/.csv/.parquet trace and return duration, frame/error counts, channels, and a per-arbitration-ID summary table (count, Δt stats, DLC, payload entropy)."""
    return _safe_call(trace_engine.summarize_trace_log, log_path, dbc_path)


@mcp.tool()
def query_decoded_signals(
    log_path: str, dbc_path: str, signal_names: list[str],
    start_time: float | None = None, end_time: float | None = None,
    max_rows: int = 100, aggregation: str = "summary",
) -> dict:
    """Decode requested signals across a trace; aggregation='summary' returns min/max/mean/std/anomalies plus a downsampled time series, otherwise up to max_rows raw decoded rows."""
    return _safe_call(trace_engine.query_decoded_signals, log_path, dbc_path, signal_names, start_time, end_time, max_rows, aggregation)


@mcp.tool()
def filter_and_export_trace(
    input_log_path: str, output_path: str, dbc_path: str | None = None,
    include_ids: list[str] | None = None, exclude_ids: list[str] | None = None,
    time_range: tuple[float, float] | None = None, signal_condition: str | None = None,
    dry_run: bool = False,
) -> dict:
    """Stream-filter a trace by arbitration ID, time range, and/or a decoded signal_condition expression, writing matches to .blf/.asc/.trc/.log/.csv/.parquet."""
    return _safe_call(
        trace_engine.filter_and_export_trace, input_log_path, output_path, dbc_path,
        include_ids, exclude_ids, time_range, signal_condition, dry_run,
    )


@mcp.tool()
def extract_uds_diagnostic_transcript(
    log_path: str, request_id: str | None = None, response_id: str | None = None,
    export_filtered_log_path: str | None = None,
) -> dict:
    """Reassemble ISO-TP (SF/FF/FC/CF) diagnostic sessions and decode UDS requests/responses, NRCs, and security-access lockouts."""
    return _safe_call(
        protocol_engine.extract_uds_diagnostic_transcript, log_path, request_id, response_id, export_filtered_log_path,
    )


@mcp.tool()
def reassemble_j1939_multipacket(log_path: str) -> dict:
    """Reassemble J1939 BAM/CMDT transport-protocol sessions (PGN 0xEC00/0xEB00) into complete multi-byte PGN payloads."""
    return _safe_call(protocol_engine.reassemble_j1939_multipacket, log_path)


@mcp.tool()
def analyze_bus_health_and_faults(
    log_path: str, dbc_path: str | None = None,
    nominal_baudrate: int = 500_000, fd_data_baudrate: int = 2_000_000,
) -> dict:
    """Diagnose bus load/microbursts, error storms & Bus-Off transitions, cycle-time jitter/missing-frame/babbling-node faults, and alive-counter skips/freezes, with root-cause advisories."""
    return _safe_call(health_engine.analyze_bus_health_and_faults, log_path, dbc_path, nominal_baudrate, fd_data_baudrate)


@mcp.tool()
def reverse_engineer_unknown_frames(log_path: str, dbc_path: str | None = None, target_frame_id: str | None = None) -> dict:
    """Classify undocumented payload bitfields (constant masks, alive counters, checksum candidates, continuous physical signals, discrete flags) and emit a draft candidate DBC."""
    return _safe_call(health_engine.reverse_engineer_unknown_frames, log_path, dbc_path, target_frame_id)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
