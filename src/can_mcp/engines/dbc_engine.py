"""Stage 1: read-only DBC inspection tools.
Stage 2: atomic DBC authoring, auto-packing & mutation engine.
Stage 3: protocol template generator & cross-format database converter.

Stage 1: inspect_database_summary, search_database, visualize_frame_layout,
validate_database_integrity.
Stage 2: manage_ecu_node, upsert_dbc_message, delete_dbc_message,
add_or_update_signal, delete_dbc_signal.
Stage 3: generate_database_from_template, convert_database_format,
diff_databases.
"""
from __future__ import annotations

import difflib
import re
from collections import OrderedDict
from pathlib import Path

import canmatrix.formats
import cantools
import cantools.database.can as can
import cantools.database.errors as cantools_errors
from cantools.database.can.formats.dbc import DbcSpecifics
from cantools.database.can.formats.dbc.dbc_attribute import DbcAttribute
from cantools.database.can.formats.dbc.dbc_attribute_definition import DbcAttributeDefinition
from cantools.database.can.formats.dbc.dbc_writer import (
    ATTRIBUTE_DEFINITION_GENMSGCYCLETIME,
    ATTRIBUTE_DEFINITION_GENSIGSTARTVALUE,
)
from cantools.database.conversion import BaseConversion

from can_mcp.config import resolve_workspace_path
from can_mcp.models.errors import CanMcpError
from can_mcp.models.schemas import (
    ConversionResult,
    DatabaseSummary,
    DiffReport,
    FrameLayoutResult,
    IntegrityIssue,
    IntegrityReport,
    MutationResult,
    SearchMatch,
    SearchResults,
)
from can_mcp.utils import bitmath, transactions


def _parse_int_literal(text: str) -> int | None:
    text = text.strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


_VECTOR_INDEPENDENT_SIG_MSG_BO = re.compile(r"^BO_\s+(\d+)\s+VECTOR__INDEPENDENT_SIG_MSG\s*:", re.MULTILINE)


def _strip_independent_sig_msg_val_entries(text: str) -> str:
    """cantools intentionally skips loading the Vector-generated
    VECTOR__INDEPENDENT_SIG_MSG container message (holds signals not
    assigned to any real frame — a common, legitimate Vector DBC export
    artifact) but never strips that frame's VAL_ entries first, so its own
    post-load "unused VAL_ entries" sanity check then raises unconditionally
    (independent of strict=True/False) — a confirmed upstream cantools gap,
    not a strict-mode issue. Since cantools never constructs that message
    either way, its VAL_ entries are already unusable; pre-stripping them
    here lets the rest of the file load normally.
    """
    for match in _VECTOR_INDEPENDENT_SIG_MSG_BO.finditer(text):
        frame_id = match.group(1)
        text = re.sub(rf"^VAL_\s+{frame_id}\s+.*;\s*\n?", "", text, flags=re.MULTILINE)
    return text


def load_database(dbc_path: str) -> cantools.database.can.Database:
    """Load a DBC file, sandboxed to the workspace root.

    Loaded with strict=False so tools like validate_database_integrity can
    inspect and report structural problems instead of cantools raising on
    load before the tool gets a chance to run.
    """
    path: Path = resolve_workspace_path(dbc_path)
    if not path.exists():
        raise CanMcpError(
            error_code="FILE_NOT_FOUND",
            reason=f"DBC file not found at '{dbc_path}'.",
            suggested_fix="Check the path is correct and relative to the workspace root.",
        )
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        text = _strip_independent_sig_msg_val_entries(text)
        return cantools.database.load_string(text, database_format="dbc", strict=False)
    except cantools_errors.Error as exc:
        raise CanMcpError(
            error_code="DBC_PARSE_ERROR",
            reason=str(exc),
            suggested_fix="Verify the file is a well-formed DBC document.",
        ) from exc


def resolve_message(db: cantools.database.can.Database, frame_id_or_name: str):
    as_int = _parse_int_literal(str(frame_id_or_name))
    if as_int is not None:
        try:
            return db.get_message_by_frame_id(as_int)
        except KeyError:
            pass
    try:
        return db.get_message_by_name(str(frame_id_or_name))
    except KeyError as exc:
        raise CanMcpError(
            error_code="MESSAGE_NOT_FOUND",
            reason=f"No message matching '{frame_id_or_name}' (checked both frame ID and name).",
            suggested_fix="Use search_database to locate the correct message name or arbitration ID.",
        ) from exc


def inspect_database_summary(dbc_path: str) -> dict:
    db = load_database(dbc_path)
    protocol_type = "CAN FD" if any(m.is_fd for m in db.messages) else "CAN"
    baudrate = None
    if db.dbc is not None and "BusSpeed" in db.dbc.attributes:
        baudrate = db.dbc.attributes["BusSpeed"].value

    node_message_matrix = {
        node.name: [m.name for m in db.messages if node.name in (m.senders or [])]
        for node in db.nodes
    }

    summary = DatabaseSummary(
        protocol_type=protocol_type,
        baudrate=baudrate,
        ecu_count=len(db.nodes),
        message_count=len(db.messages),
        signal_count=sum(len(m.signals) for m in db.messages),
        nodes=[node.name for node in db.nodes],
        node_message_matrix=node_message_matrix,
    )
    return summary.model_dump()


def _iter_signals(db):
    for message in db.messages:
        for signal in message.signals:
            yield message, signal


def search_database(
    dbc_path: str,
    query: str,
    search_type: str = "all",
    max_results: int = 25,
) -> dict:
    db = load_database(dbc_path)
    query_lower = query.strip().lower()
    query_int = _parse_int_literal(query)
    matches: list[SearchMatch] = []

    want = lambda cat: search_type in ("all", cat)  # noqa: E731

    if want("message"):
        for message in db.messages:
            if query_lower in message.name.lower():
                matches.append(SearchMatch(category="message", message=message.name, signal=None, field="name", value=message.name))

    if want("id"):
        for message in db.messages:
            if query_int is not None and message.frame_id == query_int:
                matches.append(SearchMatch(category="id", message=message.name, signal=None, field="frame_id", value=hex(message.frame_id)))
            elif query_lower in hex(message.frame_id) or query_lower in str(message.frame_id):
                matches.append(SearchMatch(category="id", message=message.name, signal=None, field="frame_id", value=hex(message.frame_id)))

    if want("signal"):
        for message, signal in _iter_signals(db):
            if query_lower in signal.name.lower():
                matches.append(SearchMatch(category="signal", message=message.name, signal=signal.name, field="name", value=signal.name))

    if want("unit"):
        for message, signal in _iter_signals(db):
            if signal.unit and query_lower in signal.unit.lower():
                matches.append(SearchMatch(category="unit", message=message.name, signal=signal.name, field="unit", value=signal.unit))

    if want("comment"):
        for message in db.messages:
            if message.comment and query_lower in str(message.comment).lower():
                matches.append(SearchMatch(category="comment", message=message.name, signal=None, field="comment", value=str(message.comment)))
        for message, signal in _iter_signals(db):
            if signal.comment and query_lower in str(signal.comment).lower():
                matches.append(SearchMatch(category="comment", message=message.name, signal=signal.name, field="comment", value=str(signal.comment)))

    if want("value_table"):
        for message, signal in _iter_signals(db):
            if not signal.choices:
                continue
            for raw_value, label in signal.choices.items():
                if query_lower in str(label).lower():
                    matches.append(SearchMatch(
                        category="value_table", message=message.name, signal=signal.name,
                        field="value_table", value=f"{raw_value}={label}",
                    ))

    # Fuzzy fallback on names only, when nothing matched via substring.
    if not matches and want("message"):
        close = difflib.get_close_matches(query_lower, [m.name.lower() for m in db.messages], n=max_results, cutoff=0.6)
        for message in db.messages:
            if message.name.lower() in close:
                matches.append(SearchMatch(category="message", message=message.name, signal=None, field="name", value=message.name))
    if not matches and want("signal"):
        close = difflib.get_close_matches(query_lower, [s.name.lower() for _, s in _iter_signals(db)], n=max_results, cutoff=0.6)
        for message, signal in _iter_signals(db):
            if signal.name.lower() in close:
                matches.append(SearchMatch(category="signal", message=message.name, signal=signal.name, field="name", value=signal.name))

    results = SearchResults(
        query=query,
        search_type=search_type,
        total_matches=len(matches),
        matches=matches[:max_results],
    )
    return results.model_dump()


def visualize_frame_layout(dbc_path: str, frame_id_or_name: str) -> dict:
    db = load_database(dbc_path)
    message = resolve_message(db, frame_id_or_name)

    cells = bitmath.build_bit_grid(message)
    free_spans = []
    span_start = None
    for cell in cells:
        if cell.occupant is None and span_start is None:
            span_start = cell.network_index
        elif cell.occupant is not None and span_start is not None:
            free_spans.append(_format_span(span_start, cell.network_index - 1))
            span_start = None
    if span_start is not None:
        free_spans.append(_format_span(span_start, cells[-1].network_index))

    result = FrameLayoutResult(
        message_name=message.name,
        frame_id=message.frame_id,
        frame_id_hex=hex(message.frame_id),
        dlc=message.length,
        ascii_grid=bitmath.render_ascii_grid(message),
        free_bit_spans=free_spans,
    )
    return result.model_dump()


def _format_span(start_p: int, end_p: int) -> str:
    start_byte, start_bit = bitmath.network_bit_to_byte_bit(start_p)
    end_byte, end_bit = bitmath.network_bit_to_byte_bit(end_p)
    return f"byte{start_byte}.bit{start_bit}-byte{end_byte}.bit{end_bit}"


def validate_database_integrity(dbc_path: str) -> dict:
    db = load_database(dbc_path)
    issues: list[IntegrityIssue] = []

    message_names_seen: dict[str, int] = {}
    for message in db.messages:
        message_names_seen[message.name] = message_names_seen.get(message.name, 0) + 1

        for overlap in bitmath.find_bit_overlaps(message):
            issues.append(IntegrityIssue(
                check="bit_overlap", severity="error", message_name=message.name, signal_name=None,
                details={
                    "signal_a": overlap.signal_a,
                    "signal_b": overlap.signal_b,
                    "colliding_bits": overlap.colliding_bits,
                    "colliding_byte_bit_labels": overlap.colliding_byte_bit_labels,
                },
            ))

        for signal_name in bitmath.signals_exceeding_dlc(message):
            issues.append(IntegrityIssue(
                check="dlc_boundary_exceeded", severity="error", message_name=message.name, signal_name=signal_name,
                details={"dlc_bits": message.length * 8},
            ))

        expected_dlc_set = bitmath.VALID_FD_DLCS if message.is_fd else bitmath.VALID_CLASSIC_DLCS
        if message.length not in expected_dlc_set:
            issues.append(IntegrityIssue(
                check="invalid_dlc", severity="error", message_name=message.name, signal_name=None,
                details={"dlc": message.length, "is_fd": message.is_fd},
            ))

        signal_names_seen: dict[str, int] = {}
        for signal in message.signals:
            signal_names_seen[signal.name] = signal_names_seen.get(signal.name, 0) + 1
            if signal.minimum is not None and signal.maximum is not None and signal.minimum > signal.maximum:
                issues.append(IntegrityIssue(
                    check="invalid_min_max", severity="error", message_name=message.name, signal_name=signal.name,
                    details={"minimum": signal.minimum, "maximum": signal.maximum},
                ))
            if signal.scale == 0:
                issues.append(IntegrityIssue(
                    check="invalid_scale", severity="error", message_name=message.name, signal_name=signal.name,
                    details={"scale": signal.scale},
                ))
        for name, count in signal_names_seen.items():
            if count > 1:
                issues.append(IntegrityIssue(
                    check="duplicate_signal_name", severity="error", message_name=message.name, signal_name=name,
                    details={"occurrences": count},
                ))

    for name, count in message_names_seen.items():
        if count > 1:
            issues.append(IntegrityIssue(
                check="duplicate_message_name", severity="error", message_name=name, signal_name=None,
                details={"occurrences": count},
            ))

    report = IntegrityReport(is_valid=len(issues) == 0, issue_count=len(issues), issues=issues)
    return report.model_dump()


# --------------------------------------------------------------------------
# Stage 2: atomic DBC authoring, auto-packing & mutation engine
# --------------------------------------------------------------------------

def _load_or_create_database(dbc_path: str) -> tuple[can.Database, Path]:
    path = resolve_workspace_path(dbc_path)
    if path.exists():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            text = _strip_independent_sig_msg_val_entries(text)
            db = cantools.database.load_string(text, database_format="dbc", strict=False)
        except cantools_errors.Error as exc:
            raise CanMcpError(
                error_code="DBC_PARSE_ERROR", reason=str(exc),
                suggested_fix="Verify the file is a well-formed DBC document.",
            ) from exc
    else:
        db = can.Database(messages=[], nodes=[], strict=False)
    return db, path


def _ensure_vframeformat_definition(db: can.Database) -> None:
    """cantools only auto-registers the VFrameFormat BA_DEF_ when a bus is
    marked CAN FD; register it ourselves so GenMsgCycleTime's sibling
    attribute gets written for every message, FD or not. Once this
    definition exists, cantools derives the per-message BA_ value itself
    from message.is_fd / message.is_extended_frame on dump.
    """
    if db.dbc is None:
        db.dbc = DbcSpecifics()
    db.dbc.attribute_definitions.setdefault(
        "VFrameFormat",
        DbcAttributeDefinition(name="VFrameFormat", default_value=0, kind="BO_", type_name="INT", minimum=0, maximum=15),
    )


def _clone_message(message: can.Message, **overrides) -> can.Message:
    kwargs = dict(
        frame_id=message.frame_id,
        name=message.name,
        length=message.length,
        signals=message.signals,
        senders=list(message.senders) if message.senders else [],
        comment=message.comment,
        cycle_time=message.cycle_time,
        is_extended_frame=message.is_extended_frame,
        is_fd=message.is_fd,
        dbc_specifics=message.dbc,
        strict=False,
    )
    kwargs.update(overrides)
    return can.Message(**kwargs)


def _clone_signal(signal: can.Signal, **overrides) -> can.Signal:
    kwargs = dict(
        name=signal.name,
        start=signal.start,
        length=signal.length,
        byte_order=signal.byte_order,
        is_signed=signal.is_signed,
        conversion=signal.conversion,
        minimum=signal.minimum,
        maximum=signal.maximum,
        unit=signal.unit,
        comment=signal.comment,
        receivers=list(signal.receivers) if signal.receivers else [],
        is_multiplexer=signal.is_multiplexer,
        multiplexer_ids=signal.multiplexer_ids,
        multiplexer_signal=signal.multiplexer_signal,
        spn=signal.spn,
    )
    kwargs.update(overrides)
    return can.Signal(**kwargs)


def _commit_database(db: can.Database, path: Path, dry_run: bool) -> str | None:
    """Dump `db` to DBC text and, unless dry_run, atomically write it (with a
    .bak of the prior contents) to `path`. Returns the backup path as a str,
    or None (no backup was made / dry_run).
    """
    db.refresh()
    text = db.as_dbc_string()
    if dry_run:
        return None
    backup = transactions.write_text_atomically(text, path)
    return str(backup) if backup else None


def _conflict_error(error_code: str, reason: str, suggested_fix: str, message: can.Message) -> CanMcpError:
    return CanMcpError(
        error_code=error_code, reason=reason, suggested_fix=suggested_fix,
        extra={"conflict_layout": bitmath.render_ascii_grid(message)},
    )


# ---- manage_ecu_node ------------------------------------------------------

def manage_ecu_node(
    dbc_path: str,
    action: str,
    node_name: str,
    comment: str = "",
    new_name: str | None = None,
    dry_run: bool = False,
) -> dict:
    db, path = _load_or_create_database(dbc_path)
    existing_names = {n.name for n in db.nodes}

    if action == "add":
        if node_name in existing_names:
            raise CanMcpError("NODE_ALREADY_EXISTS", f"ECU node '{node_name}' already exists.",
                               "Use action='rename' or pick a different node_name.")
        new_nodes = [*db.nodes, can.Node(name=node_name, comment=comment or None)]
        rebuilt = can.Database(messages=db.messages, nodes=new_nodes, buses=db.buses, dbc_specifics=db.dbc, strict=False)

    elif action == "rename":
        if node_name not in existing_names:
            raise CanMcpError("NODE_NOT_FOUND", f"ECU node '{node_name}' does not exist.",
                               "Use action='add' to create it first.")
        if not new_name:
            raise CanMcpError("NEW_NAME_REQUIRED", "Renaming a node requires `new_name`.",
                               "Pass new_name='TargetNodeName'.")
        if new_name in existing_names:
            raise CanMcpError("NODE_ALREADY_EXISTS", f"ECU node '{new_name}' already exists.",
                               "Pick a different new_name.")
        new_nodes = [can.Node(name=new_name, comment=n.comment) if n.name == node_name else n for n in db.nodes]
        new_messages = []
        for message in db.messages:
            senders = [new_name if s == node_name else s for s in (message.senders or [])]
            signals = [
                _clone_signal(sig, receivers=[new_name if r == node_name else r for r in (sig.receivers or [])])
                if node_name in (sig.receivers or []) else sig
                for sig in message.signals
            ]
            if senders != list(message.senders or []) or any(s is not o for s, o in zip(signals, message.signals)):
                new_messages.append(_clone_message(message, senders=senders, signals=signals))
            else:
                new_messages.append(message)
        rebuilt = can.Database(messages=new_messages, nodes=new_nodes, buses=db.buses, dbc_specifics=db.dbc, strict=False)

    elif action == "delete":
        if node_name not in existing_names:
            raise CanMcpError("NODE_NOT_FOUND", f"ECU node '{node_name}' does not exist.",
                               "Check inspect_database_summary for the current node list.")
        new_nodes = [n for n in db.nodes if n.name != node_name]
        new_messages = []
        for message in db.messages:
            senders = [s for s in (message.senders or []) if s != node_name]
            signals = [
                _clone_signal(sig, receivers=[r for r in (sig.receivers or []) if r != node_name])
                if node_name in (sig.receivers or []) else sig
                for sig in message.signals
            ]
            if senders != list(message.senders or []) or any(s is not o for s, o in zip(signals, message.signals)):
                new_messages.append(_clone_message(message, senders=senders, signals=signals))
            else:
                new_messages.append(message)
        rebuilt = can.Database(messages=new_messages, nodes=new_nodes, buses=db.buses, dbc_specifics=db.dbc, strict=False)

    else:
        raise CanMcpError("INVALID_ACTION", f"Unknown action '{action}'.",
                           "Use one of: add, rename, delete.")

    backup = _commit_database(rebuilt, path, dry_run)
    result = MutationResult(
        success=True, dry_run=dry_run, backup_path=backup,
        message=f"Node '{node_name}' {action} succeeded.",
        details={"nodes": [n.name for n in rebuilt.nodes]},
    )
    return result.model_dump()


# ---- upsert_dbc_message ----------------------------------------------------

def upsert_dbc_message(
    dbc_path: str,
    frame_id: int,
    name: str,
    dlc: int,
    sender: str,
    is_extended: bool = False,
    is_fd: bool = False,
    cycle_time_ms: int | None = None,
    comment: str = "",
    dry_run: bool = False,
) -> dict:
    db, path = _load_or_create_database(dbc_path)

    if db.nodes and sender not in {n.name for n in db.nodes}:
        raise CanMcpError("SENDER_NODE_NOT_FOUND", f"Sender node '{sender}' does not exist.",
                           "Call manage_ecu_node(action='add', node_name=...) first.")

    existing = next((m for m in db.messages if m.frame_id == frame_id), None)
    other_name_collision = any(m.name == name and m is not existing for m in db.messages)
    if other_name_collision:
        raise CanMcpError("MESSAGE_NAME_CONFLICT", f"A different message already uses the name '{name}'.",
                           "Choose a unique message name.")

    if existing is not None:
        updated = _clone_message(
            existing, name=name, length=dlc, senders=[sender], comment=comment or existing.comment,
            cycle_time=cycle_time_ms, is_extended_frame=is_extended, is_fd=is_fd,
        )
        overflow = bitmath.signals_exceeding_dlc(updated)
        if overflow:
            raise _conflict_error(
                "DLC_TOO_SMALL_FOR_EXISTING_SIGNALS",
                f"Shrinking '{name}' to DLC={dlc} would push signal(s) {overflow} past the frame boundary.",
                "Delete or re-pack those signals before shrinking the DLC.",
                updated,
            )
        new_messages = [updated if m is existing else m for m in db.messages]
        verb = "updated"
    else:
        new_message = can.Message(
            frame_id=frame_id, name=name, length=dlc, signals=[], senders=[sender],
            comment=comment or None, cycle_time=cycle_time_ms,
            is_extended_frame=is_extended, is_fd=is_fd, strict=False,
        )
        new_messages = [*db.messages, new_message]
        verb = "created"

    rebuilt = can.Database(messages=new_messages, nodes=db.nodes, buses=db.buses, dbc_specifics=db.dbc, strict=False)
    _ensure_vframeformat_definition(rebuilt)

    backup = _commit_database(rebuilt, path, dry_run)
    result = MutationResult(
        success=True, dry_run=dry_run, backup_path=backup,
        message=f"Message '{name}' (0x{frame_id:X}) {verb}.",
        details={"frame_id": frame_id, "name": name, "dlc": dlc},
    )
    return result.model_dump()


# ---- delete_dbc_message -----------------------------------------------------

def delete_dbc_message(dbc_path: str, frame_id_or_name: str, dry_run: bool = False) -> dict:
    db, path = _load_or_create_database(dbc_path)
    message = resolve_message(db, frame_id_or_name)

    new_messages = [m for m in db.messages if m is not message]
    rebuilt = can.Database(messages=new_messages, nodes=db.nodes, buses=db.buses, dbc_specifics=db.dbc, strict=False)

    backup = _commit_database(rebuilt, path, dry_run)
    result = MutationResult(
        success=True, dry_run=dry_run, backup_path=backup,
        message=f"Message '{message.name}' (0x{message.frame_id:X}) deleted.",
        details={"frame_id": message.frame_id, "name": message.name},
    )
    return result.model_dump()


# ---- add_or_update_signal ---------------------------------------------------

def add_or_update_signal(
    dbc_path: str,
    message_id_or_name: str,
    signal_name: str,
    length: int,
    start_bit: int | None = None,
    auto_pack: bool = False,
    byte_order: str = "little_endian",
    is_signed: bool = False,
    scale: float = 1.0,
    offset: float = 0.0,
    min_val: float | None = None,
    max_val: float | None = None,
    unit: str = "",
    receivers: list[str] | None = None,
    mux_is_switch: bool = False,
    mux_value: int | None = None,
    value_table: dict[int, str] | None = None,
    dry_run: bool = False,
) -> dict:
    db, path = _load_or_create_database(dbc_path)
    message = resolve_message(db, message_id_or_name)

    existing_signal = next((s for s in message.signals if s.name == signal_name), None)
    other_signals = [s for s in message.signals if s is not existing_signal]

    if mux_is_switch:
        is_multiplexer, multiplexer_ids, multiplexer_signal = True, None, None
    elif mux_value is not None:
        switch = next((s for s in other_signals if s.is_multiplexer), None)
        if switch is None:
            raise CanMcpError(
                "NO_MULTIPLEXER_SWITCH", f"Message '{message.name}' has no multiplexer switch signal yet.",
                "Add the switch signal first with mux_is_switch=True.",
            )
        is_multiplexer, multiplexer_ids, multiplexer_signal = False, [mux_value], switch.name
    else:
        is_multiplexer, multiplexer_ids, multiplexer_signal = False, None, None

    if start_bit is None:
        if not auto_pack:
            raise CanMcpError("START_BIT_REQUIRED", "start_bit must be given unless auto_pack=True.",
                               "Pass an explicit start_bit, or set auto_pack=True.")
        resolved_start = bitmath.find_free_bit_block(message, length, byte_order, exclude_signal_name=signal_name)
        if resolved_start is None:
            raise _conflict_error(
                "NO_FREE_BIT_BLOCK",
                f"No contiguous {length}-bit free block for byte_order='{byte_order}' in '{message.name}'.",
                "Free up space by deleting/shrinking another signal, or widen the message DLC.",
                message,
            )
    else:
        resolved_start = start_bit

    choices = OrderedDict({int(k): v for k, v in value_table.items()}) if value_table else None
    candidate = can.Signal(
        name=signal_name, start=resolved_start, length=length, byte_order=byte_order, is_signed=is_signed,
        conversion=BaseConversion.factory(scale=scale, offset=offset, choices=choices),
        minimum=min_val, maximum=max_val, unit=unit or None, receivers=list(receivers) if receivers else [],
        is_multiplexer=is_multiplexer, multiplexer_ids=multiplexer_ids, multiplexer_signal=multiplexer_signal,
    )

    candidate_signals = [*other_signals, candidate]
    probe_message = _clone_message(message, signals=candidate_signals)

    overlaps = bitmath.find_bit_overlaps(probe_message)
    if overlaps:
        raise _conflict_error(
            "SIGNAL_BIT_OVERLAP",
            f"Signal '{signal_name}' at start={resolved_start} ({byte_order}) collides with "
            + ", ".join(f"{o.signal_a}<->{o.signal_b}" for o in overlaps),
            "Choose a different start_bit, delete the conflicting signal, or use auto_pack=True.",
            probe_message,
        )
    overflow = bitmath.signals_exceeding_dlc(probe_message)
    if overflow:
        raise _conflict_error(
            "SIGNAL_EXCEEDS_DLC",
            f"Signal(s) {overflow} exceed the {probe_message.length * 8}-bit frame boundary of '{message.name}'.",
            "Reduce the signal length/start_bit, or widen the message DLC first.",
            probe_message,
        )

    new_messages = [probe_message if m is message else m for m in db.messages]
    rebuilt = can.Database(messages=new_messages, nodes=db.nodes, buses=db.buses, dbc_specifics=db.dbc, strict=False)

    backup = _commit_database(rebuilt, path, dry_run)
    verb = "updated" if existing_signal is not None else "added"
    result = MutationResult(
        success=True, dry_run=dry_run, backup_path=backup,
        message=f"Signal '{signal_name}' {verb} in '{message.name}' at start_bit={resolved_start}.",
        details={"start_bit": resolved_start, "byte_order": byte_order, "length": length},
    )
    return result.model_dump()


# ---- delete_dbc_signal -------------------------------------------------------

def delete_dbc_signal(dbc_path: str, message_id_or_name: str, signal_name: str, dry_run: bool = False) -> dict:
    db, path = _load_or_create_database(dbc_path)
    message = resolve_message(db, message_id_or_name)

    target = next((s for s in message.signals if s.name == signal_name), None)
    if target is None:
        raise CanMcpError("SIGNAL_NOT_FOUND", f"Signal '{signal_name}' not found in '{message.name}'.",
                           "Use visualize_frame_layout to see the current signal list.")

    if target.is_multiplexer:
        dependents = [s.name for s in message.signals if s.multiplexer_signal == target.name]
        if dependents:
            raise CanMcpError(
                "MUX_SWITCH_IN_USE",
                f"'{signal_name}' is the multiplexer switch for {dependents}; cannot delete it while they exist.",
                "Delete the dependent multiplexed branch signals first.",
            )

    remaining = [s for s in message.signals if s is not target]
    updated = _clone_message(message, signals=remaining)
    new_messages = [updated if m is message else m for m in db.messages]
    rebuilt = can.Database(messages=new_messages, nodes=db.nodes, buses=db.buses, dbc_specifics=db.dbc, strict=False)

    backup = _commit_database(rebuilt, path, dry_run)
    result = MutationResult(
        success=True, dry_run=dry_run, backup_path=backup,
        message=f"Signal '{signal_name}' deleted from '{message.name}'.",
        details={"message": message.name, "signal": signal_name},
    )
    return result.model_dump()


# --------------------------------------------------------------------------
# Stage 3: protocol template generator & cross-format database converter
# --------------------------------------------------------------------------

def _set_global_int_attribute(db: can.Database, name: str, value: int, minimum: int = 0, maximum: int = 10_000_000, default: int = 0) -> None:
    if db.dbc is None:
        db.dbc = DbcSpecifics()
    definition = DbcAttributeDefinition(name=name, default_value=default, kind=None, type_name="INT", minimum=minimum, maximum=maximum)
    db.dbc.attribute_definitions[name] = definition
    db.dbc.attributes[name] = DbcAttribute(value=value, definition=definition)


def _set_global_string_attribute(db: can.Database, name: str, value: str, default: str) -> None:
    if db.dbc is None:
        db.dbc = DbcSpecifics()
    definition = DbcAttributeDefinition(name=name, default_value=default, kind=None, type_name="STRING")
    db.dbc.attribute_definitions[name] = definition
    db.dbc.attributes[name] = DbcAttribute(value=value, definition=definition)


# ---- generate_database_from_template: raw_can / can_fd --------------------

def _build_raw_can_template(baudrate: int, node_names: list[str], is_fd: bool) -> can.Database:
    db = can.Database(messages=[], nodes=[can.Node(name=n) for n in node_names], strict=True)
    _set_global_int_attribute(db, "BusSpeed", baudrate, maximum=10_000_000, default=500_000)
    _set_global_string_attribute(db, "BusType", "CAN FD" if is_fd else "CAN", default="CAN")
    # Pre-register the standard mutation-engine attributes even though no
    # message/signal uses them yet, per REQUIREMENTS.md 3.1.
    db.dbc.attribute_definitions.setdefault("GenMsgCycleTime", ATTRIBUTE_DEFINITION_GENMSGCYCLETIME)
    db.dbc.attribute_definitions.setdefault("GenSigStartValue", ATTRIBUTE_DEFINITION_GENSIGSTARTVALUE)
    return db


# ---- generate_database_from_template: j1939_skeleton -----------------------

def _j1939_id(priority: int, pf: int, ps: int, sa: int) -> int:
    return (priority << 26) | (pf << 16) | (ps << 8) | sa


def _build_j1939_skeleton_template(baudrate: int, node_names: list[str]) -> can.Database:
    nodes = node_names or ["J1939_ECU1"]
    sender = nodes[0]
    messages = []

    for idx, node in enumerate(nodes):
        sa = idx
        messages.append(can.Message(
            frame_id=_j1939_id(6, 0xEE, 0xFF, sa), name=f"AddressClaimed_{node}", length=8,
            signals=[can.Signal(name="ECUNameField", start=0, length=64, byte_order="little_endian", is_signed=False)],
            senders=[node], is_extended_frame=True, protocol="j1939", strict=True,
        ))
        messages.append(can.Message(
            frame_id=_j1939_id(6, 0xFE, 0xCA, sa), name=f"DM1_ActiveDTCs_{node}", length=8,
            signals=[
                can.Signal(name="LampStatus", start=0, length=16, byte_order="little_endian", is_signed=False),
                can.Signal(name="SPN", start=16, length=19, byte_order="little_endian", is_signed=False),
                can.Signal(name="FMI", start=35, length=5, byte_order="little_endian", is_signed=False),
                can.Signal(name="OccurrenceCount", start=40, length=7, byte_order="little_endian", is_signed=False),
                can.Signal(name="ConversionMethod", start=47, length=1, byte_order="little_endian", is_signed=False),
            ],
            senders=[node], is_extended_frame=True, protocol="j1939", strict=True,
        ))

    messages.append(can.Message(
        frame_id=_j1939_id(6, 0xEA, 0xFF, 0xFE), name="RequestPGN", length=8,
        signals=[can.Signal(name="RequestedPGN", start=0, length=24, byte_order="little_endian", is_signed=False)],
        senders=[sender], is_extended_frame=True, protocol="j1939", strict=True,
    ))
    messages.append(can.Message(
        frame_id=_j1939_id(7, 0xEC, 0xFF, 0xFE), name="TP_CM_BAM", length=8,
        signals=[
            can.Signal(name="ControlByte", start=0, length=8, byte_order="little_endian", is_signed=False),
            can.Signal(name="TotalMessageSize", start=8, length=16, byte_order="little_endian", is_signed=False),
            can.Signal(name="TotalPackets", start=24, length=8, byte_order="little_endian", is_signed=False),
            can.Signal(name="Reserved", start=32, length=8, byte_order="little_endian", is_signed=False),
            can.Signal(name="ParameterGroupNumber", start=40, length=24, byte_order="little_endian", is_signed=False),
        ],
        senders=[sender], is_extended_frame=True, protocol="j1939", strict=True,
    ))
    messages.append(can.Message(
        frame_id=_j1939_id(7, 0xEB, 0xFF, 0xFE), name="TP_DT", length=8,
        signals=[
            can.Signal(name="SequenceNumber", start=0, length=8, byte_order="little_endian", is_signed=False),
            can.Signal(name="PacketData", start=8, length=56, byte_order="little_endian", is_signed=False),
        ],
        senders=[sender], is_extended_frame=True, protocol="j1939", strict=True,
    ))

    db = can.Database(messages=messages, nodes=[can.Node(name=n) for n in nodes], strict=True)
    _ensure_vframeformat_definition(db)
    _set_global_int_attribute(db, "BusSpeed", baudrate, maximum=10_000_000, default=500_000)
    return db


# ---- generate_database_from_template: canopen_cia301 -----------------------

_CIA301_HEARTBEAT_STATES = OrderedDict({0: "Boot-up", 4: "Stopped", 5: "Operational", 127: "Pre-operational"})


def _build_canopen_cia301_template(baudrate: int, node_names: list[str]) -> can.Database:
    nodes = node_names or ["Node1"]
    messages = [
        can.Message(
            frame_id=0x000, name="NMT", length=2, senders=[nodes[0]], strict=True,
            signals=[
                can.Signal(name="CommandSpecifier", start=0, length=8, byte_order="little_endian", is_signed=False),
                can.Signal(name="TargetNodeId", start=8, length=8, byte_order="little_endian", is_signed=False),
            ],
        ),
        can.Message(frame_id=0x080, name="SYNC", length=0, signals=[], senders=[nodes[0]], strict=True),
    ]

    for idx, node in enumerate(nodes, start=1):
        node_id = idx
        messages.append(can.Message(
            frame_id=0x080 + node_id, name=f"EMCY_{node}", length=8, senders=[node], strict=True,
            signals=[
                can.Signal(name="EmergencyErrorCode", start=0, length=16, byte_order="little_endian", is_signed=False),
                can.Signal(name="ErrorRegister", start=16, length=8, byte_order="little_endian", is_signed=False),
                can.Signal(name="ManufacturerSpecificErrorField", start=24, length=40, byte_order="little_endian", is_signed=False),
            ],
        ))
        for pdo_num, base in enumerate([0x180, 0x280, 0x380, 0x480], start=1):
            messages.append(can.Message(frame_id=base + node_id, name=f"TPDO{pdo_num}_{node}", length=8, signals=[], senders=[node], strict=True))
        for pdo_num, base in enumerate([0x200, 0x300, 0x400, 0x500], start=1):
            messages.append(can.Message(frame_id=base + node_id, name=f"RPDO{pdo_num}_{node}", length=8, signals=[], senders=[node], strict=True))
        for prefix, base in (("TSDO", 0x580), ("RSDO", 0x600)):
            messages.append(can.Message(
                frame_id=base + node_id, name=f"{prefix}_{node}", length=8, senders=[node], strict=True,
                signals=[
                    can.Signal(name="CommandSpecifier", start=0, length=8, byte_order="little_endian", is_signed=False),
                    can.Signal(name="Index", start=8, length=16, byte_order="little_endian", is_signed=False),
                    can.Signal(name="SubIndex", start=24, length=8, byte_order="little_endian", is_signed=False),
                    can.Signal(name="Data", start=32, length=32, byte_order="little_endian", is_signed=False),
                ],
            ))
        messages.append(can.Message(
            frame_id=0x700 + node_id, name=f"Heartbeat_{node}", length=1, senders=[node], strict=True,
            signals=[can.Signal(
                name="NMTState", start=0, length=8, byte_order="little_endian", is_signed=False,
                conversion=BaseConversion.factory(scale=1, offset=0, choices=OrderedDict(_CIA301_HEARTBEAT_STATES)),
            )],
        ))

    db = can.Database(messages=messages, nodes=[can.Node(name=n) for n in nodes], strict=True)
    _set_global_int_attribute(db, "BusSpeed", baudrate, maximum=10_000_000, default=500_000)
    return db


# ---- generate_database_from_template: uds_iso15765 -------------------------

def _build_uds_iso15765_template(baudrate: int, node_names: list[str]) -> can.Database:
    nodes = node_names or ["ECU_Diag"]
    tester = nodes[0]
    messages = [can.Message(frame_id=0x7DF, name="UDS_FunctionalRequest", length=8, signals=[], senders=[tester], strict=True)]
    for i in range(8):
        responder = nodes[i % len(nodes)]
        messages.append(can.Message(frame_id=0x7E0 + i, name=f"UDS_PhysicalRequest_{i}", length=8, signals=[], senders=[tester], strict=True))
        messages.append(can.Message(frame_id=0x7E8 + i, name=f"UDS_PhysicalResponse_{i}", length=8, signals=[], senders=[responder], strict=True))

    db = can.Database(messages=messages, nodes=[can.Node(name=n) for n in nodes], strict=True)
    _set_global_int_attribute(db, "BusSpeed", baudrate, maximum=10_000_000, default=500_000)
    return db


_TEMPLATE_BUILDERS = {
    "raw_can": lambda baudrate, nodes: _build_raw_can_template(baudrate, nodes, is_fd=False),
    "can_fd": lambda baudrate, nodes: _build_raw_can_template(baudrate, nodes, is_fd=True),
    "j1939_skeleton": _build_j1939_skeleton_template,
    "canopen_cia301": _build_canopen_cia301_template,
    "uds_iso15765": _build_uds_iso15765_template,
}


def generate_database_from_template(
    output_path: str,
    template_type: str,
    baudrate: int = 500_000,
    node_names: list[str] | None = None,
    dry_run: bool = False,
) -> dict:
    path = resolve_workspace_path(output_path)
    if path.suffix.lower() != ".dbc":
        raise CanMcpError(
            "INVALID_OUTPUT_FORMAT", f"output_path '{output_path}' must end in .dbc.",
            "Generate the .dbc template first, then use convert_database_format to export other formats.",
        )

    builder = _TEMPLATE_BUILDERS.get(template_type)
    if builder is None:
        raise CanMcpError(
            "UNKNOWN_TEMPLATE_TYPE", f"Unknown template_type '{template_type}'.",
            f"Use one of: {', '.join(sorted(_TEMPLATE_BUILDERS))}.",
        )

    try:
        db = builder(baudrate, list(node_names) if node_names else [])
    except cantools_errors.Error as exc:
        raise CanMcpError("TEMPLATE_GENERATION_FAILED", str(exc), "This is a template-generator bug; please report it.") from exc

    backup = _commit_database(db, path, dry_run)
    result = MutationResult(
        success=True, dry_run=dry_run, backup_path=backup,
        message=f"Generated '{template_type}' template with {len(db.messages)} message(s) and {len(db.nodes)} node(s).",
        details={"template_type": template_type, "message_count": len(db.messages), "node_count": len(db.nodes)},
    )
    return result.model_dump()


# ---- convert_database_format ------------------------------------------------

def _infer_canmatrix_format(path: Path) -> str | None:
    ext = path.suffix.lower().lstrip(".")
    for fmt, mapped_ext in canmatrix.formats.extensionMapping.items():
        if mapped_ext == ext:
            return fmt
    return None


def _require_format_capability(fmt: str | None, capability: str, role: str) -> str:
    if fmt is None or fmt not in canmatrix.formats.supportedFormats:
        raise CanMcpError(
            "UNSUPPORTED_FORMAT", f"Could not determine a supported {role} format.",
            f"Supported formats: {', '.join(sorted(canmatrix.formats.supportedFormats))}.",
        )
    if capability not in canmatrix.formats.supportedFormats[fmt]:
        raise CanMcpError(
            "UNSUPPORTED_FORMAT_DIRECTION",
            f"canmatrix cannot {capability} the '{fmt}' format in this installation.",
            "Pick a different target_format, or check that the optional parser dependency is installed.",
        )
    return fmt


# canmatrix's dbf writer unconditionally injects a message-scope
# "GenMsgCycleTime" INT attribute definition without its default value
# (dbf.py has the default-writing line for PARAM_MSG commented out), which
# then crashes canmatrix's own dbf *reader*. This patches any such
# default-less INT/HEX line back into a parseable one after the fact.
_DBF_PARAM_MSG_MISSING_DEFAULT = re.compile(r'^".*?",(?:INT|HEX),-?\d+(?:\.\d+)?,-?\d+(?:\.\d+)?$')


def _patch_dbf_missing_param_msg_defaults(path: Path) -> None:
    text = path.read_text(encoding="iso-8859-1")
    lines = text.splitlines()
    in_param_msg = False
    patched = []
    for line in lines:
        stripped = line.strip()
        if stripped == "[START_PARAM_MSG]":
            in_param_msg = True
        elif stripped == "[END_PARAM_MSG]":
            in_param_msg = False
        elif in_param_msg and _DBF_PARAM_MSG_MISSING_DEFAULT.match(stripped):
            line = line.rstrip() + ",0"
        patched.append(line)
    path.write_text("\n".join(patched) + "\n", encoding="iso-8859-1")


def _verify_conversion(source_matrices: dict, output_path: Path, target_format: str) -> tuple[str | None, list[str]]:
    """Returns (critical_error, attribute_loss). `critical_error` is set
    only when the written output can't be read back at all (e.g. a format
    writer/reader round-trip bug) — that's a hard conversion failure, not
    mere attribute loss, and callers must not report success=True for it.
    """
    losses: list[str] = []
    try:
        reloaded = canmatrix.formats.loadp(str(output_path), import_type=target_format)
    except Exception as exc:  # noqa: BLE001 - verification must never crash the whole conversion
        return f"Could not reload the converted {target_format} file to verify it: {exc}", losses
    if not reloaded:
        return f"Converted {target_format} file reloaded as empty or unreadable.", losses

    for key, src_matrix in source_matrices.items():
        dst_matrix = reloaded.get(key)
        if dst_matrix is None:
            losses.append(f"Bus '{key or '<default>'}' is missing entirely after conversion.")
            continue
        src_frames = {f.name: f for f in src_matrix.frames}
        dst_frames = {f.name: f for f in dst_matrix.frames}
        for name in sorted(src_frames.keys() - dst_frames.keys()):
            losses.append(f"Message '{name}' was lost converting to {target_format}.")
        for name in sorted(src_frames.keys() & dst_frames.keys()):
            src_f, dst_f = src_frames[name], dst_frames[name]
            src_sig_names = {s.name for s in src_f.signals}
            dst_sig_names = {s.name for s in dst_f.signals}
            for sig_name in sorted(src_sig_names - dst_sig_names):
                losses.append(f"Signal '{name}.{sig_name}' was lost converting to {target_format}.")
            for attr in sorted(set(src_f.attributes) - set(dst_f.attributes)):
                losses.append(f"Attribute '{attr}' on message '{name}' was lost converting to {target_format}.")
        for attr in sorted(set(src_matrix.frame_defines) - set(dst_matrix.frame_defines)):
            losses.append(f"Message-level attribute definition '{attr}' is not representable in {target_format}.")
        for attr in sorted(set(src_matrix.global_defines) - set(dst_matrix.global_defines)):
            losses.append(f"Database-level attribute definition '{attr}' is not representable in {target_format}.")
    return None, losses


def convert_database_format(
    input_path: str,
    output_path: str,
    target_format: str | None = None,
    dry_run: bool = False,
) -> dict:
    in_path = resolve_workspace_path(input_path)
    if not in_path.exists():
        raise CanMcpError("FILE_NOT_FOUND", f"Input file not found at '{input_path}'.",
                           "Check the path is correct and relative to the workspace root.")
    out_path = resolve_workspace_path(output_path)

    source_format = _require_format_capability(_infer_canmatrix_format(in_path), "load", "source")
    target_format = _require_format_capability(target_format or _infer_canmatrix_format(out_path), "dump", "target")

    try:
        matrices = canmatrix.formats.loadp(str(in_path), import_type=source_format)
    except Exception as exc:
        raise CanMcpError("SOURCE_LOAD_FAILED", f"Could not parse '{input_path}' as {source_format}: {exc}",
                           "Verify the input file is well-formed, or check validate_database_integrity first.") from exc
    if not matrices:
        raise CanMcpError("SOURCE_LOAD_FAILED", f"'{input_path}' loaded as empty.", "Verify the input file is not corrupt.")

    message_count = sum(len(m.frames) for m in matrices.values())

    if dry_run:
        result = ConversionResult(
            success=True, dry_run=True, backup_path=None, source_format=source_format, target_format=target_format,
            message_count=message_count, attribute_loss=[],
            message=f"Dry run: would convert '{input_path}' ({source_format}) -> '{output_path}' ({target_format}).",
        )
        return result.model_dump()

    tmp_path = out_path.with_name(out_path.name + ".tmp")
    try:
        canmatrix.formats.dumpp(matrices, str(tmp_path), export_type=target_format)
        if target_format == "dbf":
            _patch_dbf_missing_param_msg_defaults(tmp_path)
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        raise CanMcpError("CONVERSION_FAILED", f"Could not write {target_format} output: {exc}",
                           "Check that all required optional dependencies for this format are installed.") from exc

    critical_error, attribute_loss = _verify_conversion(matrices, tmp_path, target_format)
    if critical_error is not None:
        tmp_path.unlink(missing_ok=True)
        raise CanMcpError(
            "CONVERSION_UNREADABLE", critical_error,
            f"The {target_format} writer produced a file its own reader rejects (a known limitation of "
            "some canmatrix format backends with certain inputs, e.g. extended 29-bit IDs on non-J1939 "
            "protocols for .dbf). Try a different target_format.",
        )
    backup = transactions.commit_file_atomically(tmp_path, out_path)

    result = ConversionResult(
        success=True, dry_run=False, backup_path=str(backup) if backup else None,
        source_format=source_format, target_format=target_format, message_count=message_count,
        attribute_loss=attribute_loss,
        message=f"Converted '{input_path}' ({source_format}) -> '{output_path}' ({target_format}).",
    )
    return result.model_dump()


# ---- diff_databases ---------------------------------------------------------

def _load_canmatrix_single(path: Path):
    fmt = _require_format_capability(_infer_canmatrix_format(path), "load", "diff input")
    matrices = canmatrix.formats.loadp(str(path), import_type=fmt)
    if not matrices:
        raise CanMcpError("SOURCE_LOAD_FAILED", f"'{path}' loaded as empty.", "Verify the input file is not corrupt.")
    return next(iter(matrices.values()))


def diff_databases(db_path_a: str, db_path_b: str) -> dict:
    path_a = resolve_workspace_path(db_path_a)
    path_b = resolve_workspace_path(db_path_b)
    for label, p, original in (("A", path_a, db_path_a), ("B", path_b, db_path_b)):
        if not p.exists():
            raise CanMcpError("FILE_NOT_FOUND", f"Database {label} not found at '{original}'.",
                               "Check the path is correct and relative to the workspace root.")

    matrix_a = _load_canmatrix_single(path_a)
    matrix_b = _load_canmatrix_single(path_b)

    frames_a = {f.name: f for f in matrix_a.frames}
    frames_b = {f.name: f for f in matrix_b.frames}

    added_messages = sorted(frames_b.keys() - frames_a.keys())
    removed_messages = sorted(frames_a.keys() - frames_b.keys())
    added_signals, removed_signals = [], []
    bit_shift_changes, scaling_changes, cycle_time_changes = [], [], []

    for name in sorted(frames_a.keys() & frames_b.keys()):
        frame_a, frame_b = frames_a[name], frames_b[name]
        sig_a = {s.name: s for s in frame_a.signals}
        sig_b = {s.name: s for s in frame_b.signals}

        for sig_name in sorted(sig_b.keys() - sig_a.keys()):
            added_signals.append({"message": name, "signal": sig_name})
        for sig_name in sorted(sig_a.keys() - sig_b.keys()):
            removed_signals.append({"message": name, "signal": sig_name})

        for sig_name in sorted(sig_a.keys() & sig_b.keys()):
            signal_a, signal_b = sig_a[sig_name], sig_b[sig_name]
            if signal_a.start_bit != signal_b.start_bit:
                bit_shift_changes.append({
                    "message": name, "signal": sig_name,
                    "old_start_bit": signal_a.start_bit, "new_start_bit": signal_b.start_bit,
                    "shift_bits": signal_b.start_bit - signal_a.start_bit,
                })
            if float(signal_a.factor) != float(signal_b.factor) or float(signal_a.offset) != float(signal_b.offset):
                scaling_changes.append({
                    "message": name, "signal": sig_name,
                    "old_scale": float(signal_a.factor), "new_scale": float(signal_b.factor),
                    "old_offset": float(signal_a.offset), "new_offset": float(signal_b.offset),
                })

        if frame_a.cycle_time != frame_b.cycle_time:
            cycle_time_changes.append({
                "message": name, "old_cycle_time_ms": frame_a.cycle_time, "new_cycle_time_ms": frame_b.cycle_time,
            })

    report = DiffReport(
        added_messages=added_messages, removed_messages=removed_messages,
        added_signals=added_signals, removed_signals=removed_signals,
        bit_shift_changes=bit_shift_changes, scaling_changes=scaling_changes,
        cycle_time_changes=cycle_time_changes,
    )
    return report.model_dump()
