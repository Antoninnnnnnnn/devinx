#!/usr/bin/env python3
"""Offline regression tests for devinx.

One test per shipped fix: reverting the fix must fail the matching test.
Everything here runs with no network, no credentials and no Devin login —
the one upstream call in the compact path (devinx.summarise_turns) is
monkeypatched out, and every other function under test is pure or touches
only a temp file.

    .venv/bin/python tests/test_regressions.py
"""

import copy
import json
import os
import re
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

# Keep the run from writing .pyc files into the project's __pycache__.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import devinx
import install
import launcher


def _assemble(args, agents):
    """What launcher.main() does with the passthrough args: split at the bare
    `--`, inject --agents into the head only, hand the tail through."""
    head, tail = launcher.split_at_separator(args)
    return launcher.merge_agents(head, agents) + tail


def _image(n):
    return {"type": "image", "source": {
        "type": "base64", "media_type": "image/png", "data": "A" * n}}


class SeparatorTests(unittest.TestCase):
    """Injected options must never land after `--` or rewrite what does."""

    def test_agents_injected_before_double_dash(self):
        agents = launcher.packaged_agents()
        out = _assemble(["--", "literal prompt"], agents)
        cut = out.index("--")
        self.assertIn("--agents", out[:cut])
        self.assertEqual(json.loads(out[out.index("--agents") + 1]), agents)
        # Everything from `--` onward comes back byte-identical.
        self.assertEqual(out[cut:], ["--", "literal prompt"])

    def test_literal_agents_json_after_separator_untouched(self):
        args = ["--", "--agents", '{"literal":{}}']
        out = _assemble(args, launcher.packaged_agents())
        cut = out.index("--")
        self.assertIn("--agents", out[:cut])
        # The user's own --agents sits past the separator: passed through
        # verbatim, never parsed and never merged.
        self.assertEqual(out[cut:], args)
        self.assertEqual(out[cut + 2], '{"literal":{}}')
        injected = json.loads(out[out.index("--agents") + 1])
        self.assertNotIn("literal", injected)

    def test_merge_agents_merges_user_flag_in_head(self):
        mine = {"mine": {"description": "d", "prompt": "p"}}
        out = launcher.merge_agents(
            ["--agents", json.dumps(mine), "-p", "go"],
            {"swe2-x": {"description": "d", "prompt": "p"}})
        self.assertEqual(out.count("--agents"), 1)
        merged = json.loads(out[out.index("--agents") + 1])
        self.assertEqual(merged["mine"], mine["mine"])
        self.assertIn("swe2-x", merged)
        self.assertEqual(out[out.index("--agents") + 2:], ["-p", "go"])


class TomlStringTests(unittest.TestCase):
    """_toml_string must emit strings tomllib accepts and round-trips.

    The regression: json.dumps encodes a non-BMP character as a surrogate
    pair, which TOML rejects outright, breaking the whole Codex config over
    one emoji in the install path.
    """

    def test_toml_string_round_trips_through_tomllib(self):
        cases = [
            "/home/André/devinx",   # non-ASCII, BMP
            "/home/\U0001F680/devinx",  # emoji, non-BMP: the surrogate-pair bug
            '/a"b\\c',              # embedded quote and backslash
            "/tab\there",           # literal tab character
            "/tab\\there",          # literal backslash before a t
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                rendered = launcher._toml_string(raw)
                self.assertEqual(
                    tomllib.loads(f"x = {rendered}")["x"], raw)


class StripPluginEntryTests(unittest.TestCase):
    """install.strip_plugin_entry removes only the exact block
    `codex plugin add` wrote, and never re-parents a setting."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "config.toml")

    def _write(self, text):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_bare_enabled_block_is_removed(self):
        self._write('[profile.devin]\nname = "x"\n\n'
                    '[plugins."p@m"]\nenabled = true\n')
        self.assertTrue(install.strip_plugin_entry(self.path, "p@m"))
        with open(self.path, encoding="utf-8") as fh:
            parsed = tomllib.loads(fh.read())
        # Nothing re-parented into the preceding section.
        self.assertEqual(parsed, {"profile": {"devin": {"name": "x"}}})

    def test_block_with_own_settings_is_left_untouched(self):
        original = ('[plugins."p@m"]\nenabled = true\n'
                    '# user customisation\ncustom = "x"\n')
        self._write(original)
        self.assertFalse(install.strip_plugin_entry(self.path, "p@m"))
        with open(self.path, encoding="utf-8") as fh:
            content = fh.read()
        self.assertEqual(content, original)
        parsed = tomllib.loads(content)
        self.assertEqual(parsed, {"plugins": {"p@m": {
            "enabled": True, "custom": "x"}}})

    def test_trailing_comments_stay_with_the_next_section(self):
        self._write('[first]\na = 1\n\n'
                    '[plugins."p@m"]\nenabled = true\n\n'
                    '# introduces next\n[next]\nb = 2\n')
        self.assertTrue(install.strip_plugin_entry(self.path, "p@m"))
        with open(self.path, encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("# introduces next", content)
        parsed = tomllib.loads(content)
        self.assertEqual(parsed, {"first": {"a": 1}, "next": {"b": 2}})


class ToolIdTests(unittest.TestCase):
    """Cognition tool ids can contain characters Anthropic rejects."""

    def test_safe_tool_id_keeps_a_valid_id(self):
        self.assertEqual(devinx.safe_tool_id("toolu_01ABC"), "toolu_01ABC")

    def test_safe_tool_id_sanitises_without_colliding(self):
        fixed = devinx.safe_tool_id("read_file_0#abc")
        self.assertRegex(fixed, r"^[a-zA-Z0-9_-]+$")
        # Ids differing only in a replaced character must not collapse.
        self.assertNotEqual(devinx.safe_tool_id("a#b"),
                            devinx.safe_tool_id("a_b"))

    def test_repair_tool_ids_rewrites_pair_to_the_same_id(self):
        body = {"messages": [
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "read_file_0#abc",
                 "name": "read_file", "input": {}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "read_file_0#abc",
                 "content": "ok"}]}]}
        self.assertTrue(devinx.repair_tool_ids(body))
        new_id = body["messages"][0]["content"][0]["id"]
        self.assertRegex(new_id, r"^[a-zA-Z0-9_-]+$")
        self.assertEqual(
            new_id, body["messages"][1]["content"][0]["tool_use_id"])

    def test_repair_tool_ids_changes_nothing_without_tool_blocks(self):
        body = {"messages": [{"role": "user", "content": "hello"}]}
        snapshot = copy.deepcopy(body)
        self.assertFalse(devinx.repair_tool_ids(body))
        self.assertEqual(body, snapshot)


class AnthropicErrorTests(unittest.TestCase):
    """Upstream refusals must surface as the error types clients act on."""

    def test_rate_limit_maps_to_429_with_retry_after(self):
        kind, status, _, retry_after = devinx.anthropic_error(
            "resource_exhausted: … Your limit will reset in 11 minutes.")
        self.assertEqual(kind, "rate_limit_error")
        self.assertEqual(status, 429)
        self.assertEqual(retry_after, 11 * 60)

    def test_prompt_too_long_message_is_client_parseable(self):
        body = {"messages": [{"role": "user", "content": "x" * 4000}]}
        kind, status, message, _ = devinx.anthropic_error(
            "invalid_argument: The prompt is too long for this model", body)
        self.assertEqual(kind, "invalid_request_error")
        self.assertEqual(status, 400)
        # Claude Code recovers by parsing two numbers out of this message;
        # what matters is that the parse works, not the prose around it.
        m = re.search(
            r"prompt is too long[^0-9]*(\d+)\s*tokens?\s*>\s*(\d+)", message)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), devinx.estimate_tokens(body))
        self.assertEqual(int(m.group(2)), devinx.SWE_CONTEXT_TOKENS)

    def test_unknown_code_maps_to_api_error_502(self):
        kind, status, message, retry_after = devinx.anthropic_error(
            "weird_code: boom")
        self.assertEqual((kind, status), ("api_error", 502))
        self.assertEqual(message, "weird_code: boom")
        self.assertIsNone(retry_after)


class EstimateTokensTests(unittest.TestCase):
    """Images must count toward the estimate; uncounted images are why
    compaction never triggered and turns died upstream."""

    def test_image_block_counts(self):
        base = {"messages": [{"role": "user", "content": [
            {"type": "text", "text": "look at this"}]}]}
        with_img = copy.deepcopy(base)
        with_img["messages"][0]["content"].append(_image(50_000))
        self.assertGreater(devinx.estimate_tokens(with_img),
                           devinx.estimate_tokens(base))

    def test_image_inside_tool_result_counts(self):
        base = {"messages": [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1",
             "content": [{"type": "text", "text": "result"}]}]}]}
        with_img = copy.deepcopy(base)
        with_img["messages"][0]["content"][0]["content"].append(_image(50_000))
        self.assertGreater(devinx.estimate_tokens(with_img),
                           devinx.estimate_tokens(base))


class CompactBodyTests(unittest.TestCase):
    """An over-long turn is compacted in the proxy instead of dying."""

    def test_long_conversation_is_compacted_with_summary(self):
        marker = "SUMMARY-MARKER-12345"
        messages = [{"role": "user", "content": "task: " + "x" * 200}]
        for i in range(12):
            messages.append({
                "role": "assistant" if i % 2 else "user",
                "content": f"turn {i} " + "y" * 120})
        body = {"model": "swe-2-max", "messages": messages}
        with mock.patch.object(devinx, "COMPACT_AT", 200), \
             mock.patch.object(devinx, "summarise_turns",
                               return_value=marker) as summary:
            out = devinx.compact_body(body)
        self.assertTrue(summary.called)
        compacted = out["messages"]
        self.assertLess(len(compacted), len(messages))
        self.assertIs(compacted[0], messages[0])      # first turn intact
        self.assertEqual(compacted[-1], messages[-1])  # last turn intact
        self.assertIn(marker, json.dumps(compacted))
        self.assertEqual(len(body["messages"]), len(messages))

    def test_short_conversation_is_returned_unchanged(self):
        # summarise_turns is patched to explode: if compaction reaches for
        # the upstream here, that is the regression.
        with mock.patch.object(devinx, "summarise_turns",
                               side_effect=AssertionError("summarise called")):
            tiny = {"model": "swe-2-max", "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"}]}
            self.assertIs(devinx.compact_body(tiny), tiny)
            with mock.patch.object(devinx, "COMPACT_AT", 10 ** 9):
                small = {"model": "swe-2-max", "messages": [
                    {"role": "user" if i % 2 == 0 else "assistant",
                     "content": "ok"} for i in range(6)]}
                self.assertIs(devinx.compact_body(small), small)


class PackagedAgentsTests(unittest.TestCase):
    def setUp(self):
        # mcp__* is appended to disallowedTools unless DEVINX_SUBAGENT_MCP=1;
        # pin it so the assertions do not depend on the ambient environment.
        patcher = mock.patch.dict(os.environ, {"DEVINX_SUBAGENT_MCP": "0"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.agents = launcher.packaged_agents()

    def test_every_agent_has_description_and_prompt(self):
        self.assertTrue(self.agents)
        for name, agent in self.agents.items():
            with self.subTest(agent=name):
                self.assertTrue(agent.get("description"))
                self.assertTrue(agent.get("prompt"))

    def test_explorer_denies_editing_tools_and_mcp(self):
        blocked = self.agents["swe2-explorer"].get("disallowedTools") or []
        self.assertIn("mcp__*", blocked)
        self.assertTrue({"Edit", "Write", "NotebookEdit"} <= set(blocked))

    def test_worker_denies_mcp_but_keeps_edit(self):
        blocked = self.agents["swe2-worker"].get("disallowedTools") or []
        self.assertIn("mcp__*", blocked)
        self.assertNotIn("Edit", blocked)


if __name__ == "__main__":
    unittest.main(verbosity=2)
