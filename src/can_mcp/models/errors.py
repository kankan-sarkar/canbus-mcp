"""Structured error envelope shared by every MCP tool.

Per REQUIREMENTS.md section 5.1, every tool must catch library exceptions and
return a structured diagnostic (error_code, reason, suggested_fix) instead of
letting a raw traceback reach the LLM.
"""
from __future__ import annotations

from pydantic import BaseModel


class ErrorEnvelope(BaseModel):
    error_code: str
    reason: str
    suggested_fix: str

    def to_dict(self) -> dict:
        return {"error": self.model_dump()}


class CanMcpError(Exception):
    """Internal exception carrying the fields needed to build an ErrorEnvelope.

    `extra` carries tool-specific diagnostic payloads (e.g. the ASCII bit-grid
    conflict map for a signal overlap rejection) that ride alongside the
    envelope but aren't part of its fixed schema.
    """

    def __init__(self, error_code: str, reason: str, suggested_fix: str, extra: dict | None = None):
        super().__init__(reason)
        self.error_code = error_code
        self.reason = reason
        self.suggested_fix = suggested_fix
        self.extra = extra or {}

    def to_envelope(self) -> ErrorEnvelope:
        return ErrorEnvelope(
            error_code=self.error_code,
            reason=self.reason,
            suggested_fix=self.suggested_fix,
        )

    def to_response_dict(self) -> dict:
        return {**self.to_envelope().to_dict(), **self.extra}


def envelope_from_exception(exc: Exception) -> ErrorEnvelope:
    """Map a raw library/stdlib exception onto a structured envelope."""
    if isinstance(exc, CanMcpError):
        return exc.to_envelope()
    if isinstance(exc, FileNotFoundError):
        return ErrorEnvelope(
            error_code="FILE_NOT_FOUND",
            reason=str(exc),
            suggested_fix="Verify the path exists and is relative to the configured workspace root.",
        )
    return ErrorEnvelope(
        error_code="UNEXPECTED_ERROR",
        reason=f"{type(exc).__name__}: {exc}",
        suggested_fix="Check the input parameters; if the problem persists this may be a tool bug.",
    )


def response_dict_from_exception(exc: Exception) -> dict:
    """Full tool-response dict for any exception, including CanMcpError extras."""
    if isinstance(exc, CanMcpError):
        return exc.to_response_dict()
    return envelope_from_exception(exc).to_dict()
