"""Offline decoder for a single Codex CLI turn; NOT a production adapter.

CLI output is host-reported data, not a provider usage attestation. This module
does not dispatch processes, grant source access, or settle the budget ledger.
In particular, a CLI thread ID is never promoted to a provider call ID.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


class CodexCLIOutputError(ValueError):
    """A bounded, non-content-bearing diagnostic code."""


@dataclass(frozen=True)
class CLIReportedUsage:
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    reasoning_output_tokens: int | None


@dataclass(frozen=True)
class DecodedCLITurn:
    host_thread_id: str
    final_text: str
    usage: CLIReportedUsage
    stream_sha256: str
    # Missing cost is unknown, including for subscription-backed execution.
    cost_units: None = None
    provider_call_id: None = None


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CodexCLIOutputError("CLI_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise CodexCLIOutputError("CLI_NON_FINITE_JSON_NUMBER")


def _integer(mapping: dict, key: str) -> int:
    value = mapping.get(key)
    if type(value) is not int or value < 0:
        raise CodexCLIOutputError("CLI_USAGE_INVALID")
    return value


def decode_codex_turn(
    stream: bytes, *, exit_code: int | None,
    max_stream_bytes: int = 1_000_000, max_events: int = 512,
    max_final_bytes: int = 128_000,
) -> DecodedCLITurn:
    """Accept exactly one successful, tool-free JSONL turn.

    Errors deliberately omit stdout/stderr, message text, thread IDs, and usage
    values. Any decoder failure after process launch leaves dispatch certainty
    to the executor; it does NOT prove a pre-send failure or permit a retry.
    Internal CLI reconnect events are rejected even if a final result follows.
    """
    for limit in (max_stream_bytes, max_events, max_final_bytes):
        if type(limit) is not int or limit <= 0:
            raise CodexCLIOutputError("CLI_LIMIT_INVALID")
    if type(stream) is not bytes or len(stream) > max_stream_bytes:
        raise CodexCLIOutputError("CLI_STREAM_LIMIT")
    if type(exit_code) is not int or exit_code != 0:
        raise CodexCLIOutputError("CLI_PROCESS_INCOMPLETE_OR_FAILED")
    try:
        lines = stream.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        raise CodexCLIOutputError("CLI_UTF8_INVALID") from None
    if not lines or len(lines) > max_events:
        raise CodexCLIOutputError("CLI_EVENT_LIMIT")
    state = "new"
    thread_id = ""
    final_text: str | None = None
    usage: CLIReportedUsage | None = None
    items: dict[str, tuple[str, bool]] = {}
    for line in lines:
        try:
            event = json.loads(line, object_pairs_hook=_pairs, parse_constant=_constant)
        except (ValueError, RecursionError):
            raise CodexCLIOutputError("CLI_JSON_INVALID") from None
        if not isinstance(event, dict):
            raise CodexCLIOutputError("CLI_EVENT_INVALID")
        kind = event.get("type")
        if kind in ("error", "turn.failed"):
            raise CodexCLIOutputError("CLI_ERROR_OR_RECONNECT")
        if state == "complete":
            raise CodexCLIOutputError("CLI_EVENT_AFTER_TERMINAL")
        if kind == "thread.started" and state == "new":
            thread_id = event.get("thread_id")
            if not isinstance(thread_id, str) or not thread_id or len(thread_id) > 256:
                raise CodexCLIOutputError("CLI_THREAD_INVALID")
            state = "thread"
        elif kind == "turn.started" and state == "thread":
            state = "turn"
        elif kind in ("item.started", "item.updated", "item.completed") and state == "turn":
            item = event.get("item")
            if not isinstance(item, dict):
                raise CodexCLIOutputError("CLI_ITEM_INVALID")
            item_type, item_id = item.get("type"), item.get("id")
            # A prompt saying 'no tools' is not an enforcement mechanism.
            if item_type not in ("agent_message", "reasoning"):
                raise CodexCLIOutputError("CLI_TOOL_OR_UNSUPPORTED_ITEM")
            if not isinstance(item_id, str) or not item_id or len(item_id) > 256:
                raise CodexCLIOutputError("CLI_ITEM_INVALID")
            previous = items.get(item_id)
            if previous and (previous[0] != item_type or previous[1] or kind == "item.started"):
                raise CodexCLIOutputError("CLI_ITEM_LIFECYCLE_INVALID")
            if kind == "item.updated" and previous is None:
                raise CodexCLIOutputError("CLI_ITEM_LIFECYCLE_INVALID")
            items[item_id] = (item_type, kind == "item.completed")
            if item_type == "agent_message" and kind == "item.completed":
                text = item.get("text")
                if not isinstance(text, str) or not text.strip():
                    raise CodexCLIOutputError("CLI_FINAL_MISSING")
                try:
                    text_size = len(text.encode("utf-8", errors="strict"))
                except UnicodeError:
                    raise CodexCLIOutputError("CLI_UTF8_INVALID") from None
                if text_size > max_final_bytes:
                    raise CodexCLIOutputError("CLI_FINAL_LIMIT")
                if final_text is not None:
                    raise CodexCLIOutputError("CLI_MULTIPLE_FINAL_MESSAGES")
                final_text = text
        elif kind == "turn.completed" and state == "turn":
            raw = event.get("usage")
            if not isinstance(raw, dict):
                raise CodexCLIOutputError("CLI_USAGE_MISSING")
            input_tokens = _integer(raw, "input_tokens")
            cached_tokens = _integer(raw, "cached_input_tokens")
            output_tokens = _integer(raw, "output_tokens")
            reasoning = _integer(raw, "reasoning_output_tokens") if "reasoning_output_tokens" in raw else None
            if cached_tokens > input_tokens:
                raise CodexCLIOutputError("CLI_USAGE_INVALID")
            usage = CLIReportedUsage(input_tokens, cached_tokens, output_tokens, reasoning)
            state = "complete"
        else:
            raise CodexCLIOutputError("CLI_EVENT_ORDER_OR_TYPE_INVALID")
    if state != "complete" or final_text is None or usage is None:
        raise CodexCLIOutputError("CLI_TURN_INCOMPLETE")
    if any(not completed for _, completed in items.values()):
        raise CodexCLIOutputError("CLI_ITEM_INCOMPLETE")
    return DecodedCLITurn(thread_id, final_text, usage, hashlib.sha256(stream).hexdigest())
