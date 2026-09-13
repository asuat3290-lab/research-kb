"""Offline CLI event fixtures, never a real model or provider call."""

import copy
import json
import unittest
from dataclasses import FrozenInstanceError

from research_kb.max_research.runner.codex_cli_codec import (
    CodexCLIOutputError, decode_codex_turn,
)


def events():
    return [
        {"type": "thread.started", "thread_id": "host-thread"},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"id": "a", "type": "agent_message", "text": '{"candidate":true}'}},
        {"type": "turn.completed", "usage": {"input_tokens": 12, "cached_input_tokens": 3, "output_tokens": 4}},
    ]


def stream(values):
    return ("\n".join(json.dumps(v) for v in values) + "\n").encode()


class CodexCLICodecTests(unittest.TestCase):
    def reject(self, values, code=None):
        with self.assertRaises(CodexCLIOutputError) as found:
            decode_codex_turn(stream(values), exit_code=0)
        if code:
            self.assertEqual(str(found.exception), code)

    def test_success_preserves_host_reported_usage_not_cost_authority(self):
        result = decode_codex_turn(stream(events()), exit_code=0)
        self.assertEqual(result.host_thread_id, "host-thread")
        self.assertEqual(result.usage.input_tokens, 12)
        self.assertEqual(result.usage.cached_input_tokens, 3)
        self.assertIsNone(result.usage.reasoning_output_tokens)
        self.assertIsNone(result.provider_call_id)
        self.assertIsNone(result.cost_units)
        self.assertEqual(len(result.stream_sha256), 64)
        with self.assertRaises(FrozenInstanceError):
            result.final_text = "changed"

    def test_missing_usage_rejected_not_defaulted(self):
        value = events()
        value[-1].pop("usage")
        self.reject(value, "CLI_USAGE_MISSING")

    def test_invalid_usage_fields(self):
        for field in ("input_tokens", "cached_input_tokens", "output_tokens"):
            for invalid in (True, -1, 1.5, "1", None):
                with self.subTest(field=field, invalid=invalid):
                    value = events()
                    value[-1]["usage"][field] = invalid
                    self.reject(value, "CLI_USAGE_INVALID")

    def test_optional_reasoning_is_validated(self):
        value = events()
        value[-1]["usage"]["reasoning_output_tokens"] = 2
        self.assertEqual(decode_codex_turn(stream(value), exit_code=0).usage.reasoning_output_tokens, 2)
        value[-1]["usage"]["reasoning_output_tokens"] = False
        self.reject(value, "CLI_USAGE_INVALID")

    def test_cached_usage_cannot_exceed_input(self):
        value = events()
        value[-1]["usage"]["cached_input_tokens"] = 13
        self.reject(value, "CLI_USAGE_INVALID")

    def test_reconnect_cannot_be_hidden_by_later_success(self):
        value = events()
        value.insert(2, {"type": "error", "message": "private-text Reconnecting... 2/5"})
        self.reject(value, "CLI_ERROR_OR_RECONNECT")

    def test_tool_events_rejected(self):
        for kind in ("command_execution", "mcp_tool_call", "web_search", "file_change", "unknown"):
            value = events()
            value.insert(2, {"type": "item.started", "item": {"id": "tool", "type": kind}})
            self.reject(value, "CLI_TOOL_OR_UNSUPPORTED_ITEM")

    def test_partial_stream_and_process_failure(self):
        self.reject(events()[:-1], "CLI_TURN_INCOMPLETE")
        for exit_code in (None, 1, -1, False):
            with self.assertRaises(CodexCLIOutputError):
                decode_codex_turn(stream(events()), exit_code=exit_code)

    def test_multiple_turns_and_post_terminal_data(self):
        self.reject(events() + events(), "CLI_EVENT_AFTER_TERMINAL")
        self.reject(events() + [{"type": "turn.completed"}], "CLI_EVENT_AFTER_TERMINAL")

    def test_duplicate_final_not_silently_overwritten(self):
        value = events()
        second = copy.deepcopy(value[2])
        second["item"]["id"] = "b"
        value.insert(3, second)
        self.reject(value, "CLI_MULTIPLE_FINAL_MESSAGES")

    def test_lifecycle(self):
        value = events()
        value.insert(2, {"type": "item.started", "item": {"id": "a", "type": "agent_message"}})
        decode_codex_turn(stream(value), exit_code=0)
        value.insert(3, {"type": "item.updated", "item": {"id": "a", "type": "reasoning"}})
        self.reject(value, "CLI_ITEM_LIFECYCLE_INVALID")

    def test_reasoning_item_must_finish(self):
        value = events()
        value.insert(2, {"type": "item.started", "item": {"id": "r", "type": "reasoning"}})
        self.reject(value, "CLI_ITEM_INCOMPLETE")
        value.insert(3, {"type": "item.completed", "item": {"id": "r", "type": "reasoning", "text": "fixture"}})
        decode_codex_turn(stream(value), exit_code=0)

    def test_malformed_json_utf8_and_duplicate_keys(self):
        for data in (b'not json', b'\xff', b'{"type":"a","type":"b"}', b'{"value":NaN}', b'[]', b''):
            with self.assertRaises(CodexCLIOutputError):
                decode_codex_turn(data, exit_code=0)

    def test_limits(self):
        for kwargs in ({"max_stream_bytes": 1}, {"max_events": 1}, {"max_final_bytes": 1}, {"max_events": True}):
            with self.assertRaises(CodexCLIOutputError):
                decode_codex_turn(stream(events()), exit_code=0, **kwargs)

    def test_blank_final_and_missing_final(self):
        value = events()
        value[2]["item"]["text"] = " "
        self.reject(value, "CLI_FINAL_MISSING")
        value.pop(2)
        self.reject(value, "CLI_TURN_INCOMPLETE")

    def test_surrogate_in_final_rejected(self):
        value = events()
        value[2]["item"]["text"] = "\ud800"
        self.reject(value, "CLI_UTF8_INVALID")


if __name__ == "__main__":
    unittest.main()
