"""Pydantic schemas for Stage 1 tool inputs/outputs."""
from __future__ import annotations

from pydantic import BaseModel


class DatabaseSummary(BaseModel):
    protocol_type: str  # "CAN" or "CAN FD"
    baudrate: int | None
    ecu_count: int
    message_count: int
    signal_count: int
    nodes: list[str]
    node_message_matrix: dict[str, list[str]]


class SearchMatch(BaseModel):
    category: str  # message | signal | id | unit | comment | value_table
    message: str | None
    signal: str | None
    field: str
    value: str


class SearchResults(BaseModel):
    query: str
    search_type: str
    total_matches: int
    matches: list[SearchMatch]


class FrameLayoutResult(BaseModel):
    message_name: str
    frame_id: int
    frame_id_hex: str
    dlc: int
    ascii_grid: str
    free_bit_spans: list[str]


class IntegrityIssue(BaseModel):
    check: str
    severity: str  # "error" | "warning"
    message_name: str | None
    signal_name: str | None
    details: dict


class IntegrityReport(BaseModel):
    is_valid: bool
    issue_count: int
    issues: list[IntegrityIssue]


class MutationResult(BaseModel):
    success: bool
    dry_run: bool
    backup_path: str | None
    message: str
    details: dict = {}


class ConversionResult(BaseModel):
    success: bool
    dry_run: bool
    backup_path: str | None
    source_format: str
    target_format: str
    message_count: int
    attribute_loss: list[str] = []
    message: str


class DiffReport(BaseModel):
    added_messages: list[str] = []
    removed_messages: list[str] = []
    added_signals: list[dict] = []
    removed_signals: list[dict] = []
    bit_shift_changes: list[dict] = []
    scaling_changes: list[dict] = []
    cycle_time_changes: list[dict] = []


class ExportResult(BaseModel):
    success: bool
    dry_run: bool
    input_path: str
    output_path: str
    matched_frame_count: int
    backup_path: str | None = None
    message: str
