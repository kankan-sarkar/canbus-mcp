"""Token/character guardrail shared by trace tools (Stage 4 Gate 4.3).

Large traces can produce arbitrarily large per-ID or per-signal tables;
these tools must never hand the LLM a payload bigger than a configurable
character ceiling (default 16,000, per REQUIREMENTS.md section 5 NFR3 /
Gate 4.3).
"""
from __future__ import annotations

import json
from collections.abc import Callable

from can_mcp.config import MAX_RESPONSE_CHARS


def fit_rows_to_char_budget(
    build_payload: Callable[[list], dict],
    rows: list,
    max_chars: int = MAX_RESPONSE_CHARS,
) -> dict:
    """Binary-search the largest prefix of `rows` whose JSON-serialized
    `build_payload(prefix)` fits within `max_chars`, tagging the result with
    `truncated`/`omitted_count` when rows had to be dropped.

    The `truncated`/`omitted_count` keys are added inside the size
    measurement itself (not after), so the returned payload's real
    serialized size never overshoots `max_chars` because of their own
    characters.
    """
    def finalize(n: int) -> dict:
        payload = build_payload(rows[:n])
        payload["truncated"] = n < len(rows)
        payload["omitted_count"] = len(rows) - n
        return payload

    if len(json.dumps(finalize(len(rows)))) <= max_chars:
        return finalize(len(rows))

    lo, hi, best_n = 0, len(rows), 0
    while lo <= hi:
        mid = (lo + hi) // 2
        if len(json.dumps(finalize(mid))) <= max_chars:
            best_n = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return finalize(best_n)
