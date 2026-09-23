#!/usr/bin/env python3
"""Offline regression tests for devinx.

One test per shipped fix: reverting the fix must fail the matching test.
Everything here runs with no network, no credentials and no Devin login —
the one upstream call in the compact path (devinx.summarise_turns) is
monkeypatched out, and every other function under test is pure or touches
only a temp file.

    .venv/bin/python tests/test_regressions.py
"""

import contextlib
import copy
import io
import json
import os
import re
import sys
import threading
import time
import tempfile
try:
    import tomllib
except ImportError:  # Python 3.10, tests only
    import tomli as tomllib
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


class FlattenedConversationTests(unittest.TestCase):
    """Claude Code does not always send one turn per message.

    Measured on the wire: the whole history arrives as five messages —
    `user, system, assistant, user, system` — one assistant message holding
    every tool_use of the run and one user message holding every tool_result,
    both growing block by block while len(messages) stays at five. Compaction
    judged its summary fresh by the message count, so on that shape the summary
    was built once and never again: 17 629 of 33 136 upstream calls left with
    the first message and a summary of what the agent had been doing hours
    earlier, which is what re-reading the same files forever looks like.
    """

    def setUp(self):
        self.calls = []
        # The summary cache outlives a request on purpose; it must not outlive
        # a test, or the second one starts from the first one's summary.
        devinx._summaries.clear()

        def fake(messages, model, system, previous):
            n = sum(len(devinx._blocks(m.get("content"))) for m in messages)
            self.calls.append(n)
            return f"SUMMARY#{len(self.calls)}"

        patcher = mock.patch.object(devinx, "summarise_turns", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Real uncovered blocks are now tracked by content; the old counter
        # accidentally carried old results twice. Use a budget that actually
        # fills with the new blocks in this fixture, keeping the same assertions.
        budget = mock.patch.object(devinx, "COMPACT_AT", 100000)
        budget.start()
        self.addCleanup(budget.stop)

    @staticmethod
    def _body(pairs):
        fat = "x" * 4000
        return {
            "model": "swe-2-max", "system": "you are an agent",
            "metadata": {"user_id": "u1"},
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "the task"}]},
                {"role": "system", "content": [
                    {"type": "text", "text": "<system-reminder>be careful</system-reminder>"}]},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": f"t{i}", "name": "Read",
                     "input": {"file_path": f"/f{i}"}} for i in range(pairs)]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": f"t{i}",
                     "content": [{"type": "text", "text": fat}]} for i in range(pairs)]},
                {"role": "system", "content": [
                    {"type": "text", "text": "<system-reminder>keep going</system-reminder>"}]},
            ],
        }

    def _summary_of(self, out):
        text = json.dumps(out["messages"][1])
        return re.findall(r"SUMMARY#\d+", text)

    def test_summary_is_extended_as_the_conversation_grows(self):
        # The steps are large on purpose. What the summary does not cover is
        # carried verbatim while it fits, so a few more turns cost no upstream
        # call at all — the summary only has to grow when the room runs out,
        # and that is what must still work.
        seen = []
        for pairs in (260, 300, 340, 380):
            out = devinx.compact_body(self._body(pairs))
            marks = self._summary_of(out)
            self.assertTrue(marks, "the body was not compacted at all")
            seen.append(marks[-1])
        self.assertGreater(len(set(seen)), 1,
                           f"the summary never changed: {seen}")
        # And it costs fewer upstream calls than there were compactions: the
        # quota that matters here is metered in requests, not tokens.
        self.assertLess(len(self.calls), len(seen),
                        f"a summary call on every compaction: {self.calls}")
        # The first pass covers the whole span; each later one only what
        # arrived since, which is what keeps a refresh worth a few seconds.
        self.assertGreater(self.calls[0], 100)
        self.assertTrue(all(c < 300 for c in self.calls[1:]), self.calls)

    def test_a_shorter_conversation_drops_the_previous_summary(self):
        devinx.compact_body(self._body(269))
        first = len(self.calls)
        devinx.compact_body(self._body(260))
        self.assertGreater(self.calls[-1], 100,
                           "a restarted run re-summarised only the new blocks")
        self.assertGreater(len(self.calls), first)


class UnflattenTests(unittest.TestCase):
    """Restoring turn order is what lets every later heuristic work.

    On the collapsed shape the verbatim tail was one small message — the agent
    kept a summary of its own recent work and none of it in clear, so it read
    the same files again to find out what it had just read.
    """

    @staticmethod
    def _flat(pairs):
        return [
            {"role": "user", "content": [{"type": "text", "text": "the task"}]},
            {"role": "assistant", "content":
                [{"type": "thinking", "thinking": "planning"}]
                + [{"type": "tool_use", "id": f"t{i}", "name": "Read",
                    "input": {"file_path": f"/f{i}"}} for i in range(pairs)]},
            {"role": "user", "content":
                [{"type": "tool_result", "tool_use_id": f"t{i}",
                  "content": [{"type": "text", "text": f"body of /f{i}"}]}
                 for i in range(pairs)]},
        ]

    def test_pairs_get_their_own_turns_in_order(self):
        out = devinx.unflatten_body({"messages": self._flat(40)})["messages"]
        # task, then what led into the run, then one turn per call and answer.
        self.assertEqual(len(out), 2 + 40 * 2)
        self.assertEqual(out[1]["content"][0]["type"], "thinking")
        for i in range(40):
            call = out[2 + 2 * i]
            answer = out[3 + 2 * i]
            self.assertEqual(call["role"], "assistant")
            self.assertEqual(call["content"][-1]["id"], f"t{i}")
            self.assertEqual(answer["role"], "user")
            self.assertEqual(answer["content"][0]["tool_use_id"], f"t{i}")

    def test_a_huge_narration_does_not_become_one_unsplittable_turn(self):
        flat = self._flat(40)
        flat[1]["content"] = (
            [{"type": "thinking", "thinking": "z" * 40000} for _ in range(4)]
            + [{"type": "text", "text": "what I am doing"}]
            + [b for b in flat[1]["content"] if b.get("type") == "tool_use"])
        out = devinx.unflatten_body({"messages": flat})["messages"]
        lead = out[1]["content"]
        self.assertTrue(all(b["type"] == "text" for b in lead),
                        "replayed thinking was kept past the cap")
        self.assertIn("what I am doing", json.dumps(lead))

    def test_nothing_is_invented_and_nothing_is_lost(self):
        flat = self._flat(20)
        # One answer never came back, one answers a call that is not there.
        flat[2]["content"] = [b for b in flat[2]["content"]
                              if b["tool_use_id"] != "t7"]
        flat[2]["content"].append({"type": "tool_result", "tool_use_id": "zz",
                                   "content": [{"type": "text", "text": "orphan"}]})
        out = devinx.unflatten_body({"messages": flat})["messages"]
        wire = json.dumps(out)
        self.assertIn("orphan", wire, "an unmatched answer was dropped")
        ids = [b["tool_use_id"] for m in out for b in m["content"]
               if b.get("type") == "tool_result"]
        self.assertNotIn("t7", ids, "an answer was invented for a call")
        self.assertEqual(len(ids), 20, "content went missing")

    def test_parallel_calls_in_a_real_turn_are_left_alone(self):
        """20 calls in one turn is the most this proxy has ever measured."""
        normal = [
            {"role": "user", "content": [{"type": "text", "text": "go"}]},
            {"role": "assistant", "content":
                [{"type": "tool_use", "id": f"t{i}", "name": "Read", "input": {}}
                 for i in range(20)]},
            {"role": "user", "content":
                [{"type": "tool_result", "tool_use_id": f"t{i}", "content": []}
                 for i in range(20)]},
        ]
        self.assertEqual(devinx.unflatten_body({"messages": normal})["messages"],
                         normal)

    def test_the_tail_survives_compaction_once_order_is_restored(self):
        fat = "x" * 4000
        flat = [
            {"role": "user", "content": [{"type": "text", "text": "the task"}]},
            {"role": "assistant", "content":
                [{"type": "tool_use", "id": f"t{i}", "name": "Read",
                  "input": {"file_path": f"/f{i}"}} for i in range(260)]},
            {"role": "user", "content":
                [{"type": "tool_result", "tool_use_id": f"t{i}",
                  "content": [{"type": "text", "text": fat}]} for i in range(260)]},
            # The shape measured on the wire ends on a system message, and that
            # one message is the whole verbatim tail compaction has to work with.
            {"role": "system", "content":
                [{"type": "text", "text": "<system-reminder>keep going</system-reminder>"}]},
        ]
        body = {"model": "swe-2-max", "system": "s", "metadata": {"user_id": "u"},
                "messages": flat}
        devinx._summaries.clear()
        with mock.patch.object(devinx, "summarise_turns",
                               lambda *a, **k: "SUMMARY"):
            flat_out = devinx.compact_body(copy.deepcopy(body))
            devinx._summaries.clear()
            restored = devinx.compact_body(devinx.unflatten_body(copy.deepcopy(body)))
        # Collapsed, the tail is whatever single message fits, and here that is
        # nothing at all. Restored, the recent turns come through in clear.
        self.assertNotIn("/f259", json.dumps(flat_out))
        self.assertIn("/f259", json.dumps(restored))
        self.assertGreater(devinx.estimate_tokens(restored),
                           10 * devinx.estimate_tokens(flat_out))


class SummaryResilienceTests(unittest.TestCase):
    """The summariser's own call is a request like any other, and was the only
    one in the process with no answer to a refusal. One rate limit on it and
    compaction gave up, so the turn went upstream whole — which for a subagent
    is not a slower turn, it is the end of the run."""

    class _Msg:
        delta_text = "SUMMARY"
        delta_thinking = delta_signature = None

    def test_a_rate_limited_summary_moves_to_the_other_credential(self):
        seen = []

        def flaky(req, acct=None, purpose="turn"):
            seen.append(acct and acct.get("name"))
            if len(seen) == 1:
                yield None, "upstream trailer error: resource_exhausted: Reached"
                return
            yield self._Msg(), None

        fake_accounts = [
            {"name": "test-a", "blocked_until": 0},
            {"name": "test-b", "blocked_until": 0},
        ]
        with mock.patch.object(devinx, "_accounts", fake_accounts), \
             mock.patch.object(devinx, "_turn", {"n": 0}), \
             mock.patch.object(devinx, "chat_stream", flaky), \
             mock.patch.object(devinx, "build_request", lambda b, **k: (None, None)):
            out = devinx.summarise_turns(
                [{"role": "user", "content": [{"type": "text", "text": "x"}]}],
                "swe-2-max", "sys")
        self.assertEqual(out, "SUMMARY")
        self.assertEqual(len(seen), 2, "it gave up instead of switching")
        self.assertNotEqual(seen[0], seen[1], "it retried the same credential")

    def test_a_turn_is_never_forwarded_oversized(self):
        """The last resort is dropping turns, never sending the body whole.

        An oversized body comes back refused and a refusal ends a subagent, so
        there is no state of the world in which forwarding it is the better
        move — not even when no summary can be made at all.
        """
        fat = "x" * 4000
        body = {"model": "swe-2-max", "system": "s",
                "metadata": {"user_id": "u-nosum"}, "messages": [
                    {"role": "user", "content": [{"type": "text", "text": "task"}]},
                    {"role": "assistant", "content": [
                        {"type": "tool_use", "id": f"t{i}", "name": "Read",
                         "input": {}} for i in range(260)]},
                    {"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": f"t{i}",
                         "content": [{"type": "text", "text": fat}]}
                        for i in range(260)]},
                    {"role": "system", "content": [
                        {"type": "text", "text": "keep going"}]},
                ]}
        devinx._summaries.clear()
        with mock.patch.object(devinx, "summarise_turns", lambda *a, **k: None):
            out = devinx.compact_body(devinx.unflatten_body(copy.deepcopy(body)))
        self.assertLess(devinx.estimate_tokens(out), devinx.COMPACT_AT,
                        "the turn went out over the limit and would be refused")
        self.assertIn("no summary of the removed turns could be made",
                      json.dumps(out), "the agent was not told what it lost")
        # The task and the recent work are what it keeps.
        self.assertIn("task", json.dumps(out["messages"][0]))

    def test_an_unextendable_summary_still_compacts_the_turn(self):
        fat = "x" * 4000

        def body(pairs):
            return {"model": "swe-2-max", "system": "s",
                    "metadata": {"user_id": "u-stale"}, "messages": [
                        {"role": "user", "content": [{"type": "text", "text": "task"}]},
                        {"role": "assistant", "content": [
                            {"type": "tool_use", "id": f"t{i}", "name": "Read",
                             "input": {}} for i in range(pairs)]},
                        {"role": "user", "content": [
                            {"type": "tool_result", "tool_use_id": f"t{i}",
                             "content": [{"type": "text", "text": fat}]}
                            for i in range(pairs)]},
                        {"role": "system", "content": [
                            {"type": "text", "text": "keep going"}]},
                    ]}

        devinx._summaries.clear()
        with mock.patch.object(devinx, "summarise_turns",
                               lambda *a, **k: "FIRST-SUMMARY"):
            devinx.compact_body(body(260))
        # Every credential is now refusing: the extension cannot be made.
        with mock.patch.object(devinx, "summarise_turns", lambda *a, **k: None):
            out = devinx.compact_body(body(300))
        self.assertIn("FIRST-SUMMARY", json.dumps(out),
                      "the standing summary was thrown away")
        self.assertLess(devinx.estimate_tokens(out),
                        devinx.estimate_tokens(body(300)) // 2,
                        "the turn went out whole and would have been refused")


class UnknownRoleTests(unittest.TestCase):
    """`system` messages inside `messages` are not in the Messages API, and
    Claude Code sends them anyway. The branch that only knew `user` dropped
    them with no warning — instructions to the agent, discarded on the way."""

    def test_system_role_content_reaches_upstream(self):
        body = {"model": "swe-2-max", "system": "s", "messages": [
            {"role": "user", "content": [{"type": "text", "text": "task"}]},
            {"role": "system", "content": [{"type": "text", "text": "MARKER-A"}]},
            {"role": "assistant", "content": [{"type": "text", "text": "ok"}]},
            {"role": "system", "content": [{"type": "text", "text": "MARKER-B"}]},
        ]}
        with mock.patch.object(devinx, "api_key", return_value="test-only"):
            req, _ = devinx.build_request(body)
        wire = str(req)
        self.assertIn("MARKER-A", wire)
        self.assertIn("MARKER-B", wire)


class EditLoopGuardTests(unittest.TestCase):
    """The loop that cost one agent a whole night ends on the fourth try."""

    GUARD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "plugin", "hooks", "edit_loop_guard.py")

    def _call(self, session, target="/a/b.py", old="X", new="Y", tool="Edit"):
        import subprocess
        event = json.dumps({"session_id": session, "tool_name": tool,
                            "tool_input": {"file_path": target,
                                           "old_string": old,
                                           "new_string": new}})
        return subprocess.run([sys.executable, self.GUARD], input=event,
                              capture_output=True, text=True)

    def setUp(self):
        self.session = "test-" + os.urandom(6).hex()

    def test_the_fourth_identical_edit_is_refused(self):
        for attempt in range(3):
            self.assertEqual(self._call(self.session).returncode, 0,
                             f"attempt {attempt + 1} should pass")
        blocked = self._call(self.session)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn("Read /a/b.py", blocked.stderr)
        self.assertIn("outside the Edit tool", blocked.stderr)

    def test_different_edits_never_collide(self):
        for i in range(12):
            r = self._call(self.session, old=f"X{i}", new=f"Y{i}")
            self.assertEqual(r.returncode, 0, "distinct edits were counted together")

    def test_a_malformed_event_never_blocks_work(self):
        import subprocess
        r = subprocess.run([sys.executable, self.GUARD], input="not json",
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)

    def test_other_tools_pass_through(self):
        for _ in range(8):
            self.assertEqual(self._call(self.session, tool="Write").returncode, 0)


class OwnershipGuardTests(unittest.TestCase):
    """The boundary the agent read, agreed to, and crossed for 12.6 hours."""

    GUARD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "plugin", "hooks", "ownership_guard.py")

    def _call(self, target, owned=None, tool="Edit", cwd="/repo"):
        import subprocess
        env = dict(os.environ)
        if owned is None:
            env.pop("DEVINX_OWNED_PATHS", None)
        else:
            env["DEVINX_OWNED_PATHS"] = owned
        event = json.dumps({"tool_name": tool, "cwd": cwd,
                            "tool_input": {"file_path": target}})
        return subprocess.run([sys.executable, self.GUARD], input=event,
                              capture_output=True, text=True, env=env)

    def test_an_unowned_file_is_refused(self):
        r = self._call("/repo/apps/backend/relay/pricing/rules.py",
                       owned="/repo/tests/test_pricing.py:/repo/tests/conftest.py")
        self.assertEqual(r.returncode, 2)
        self.assertIn("not one of the files you own", r.stderr)
        self.assertIn("stop and report", r.stderr)

    def test_owned_files_pass(self):
        for target in ("/repo/tests/test_pricing.py", "/repo/tests/conftest.py"):
            r = self._call(target, owned="/repo/tests/test_pricing.py:/repo/tests/conftest.py")
            self.assertEqual(r.returncode, 0, target)

    def test_a_directory_carries_what_is_under_it(self):
        r = self._call("/repo/tests/unit/test_deep.py", owned="/repo/tests")
        self.assertEqual(r.returncode, 0)

    def test_patterns_and_relative_paths_work(self):
        self.assertEqual(self._call("/repo/tests/test_a.py", owned="tests/*.py").returncode, 0)
        self.assertEqual(self._call("/repo/apps/x.py", owned="tests/*.py").returncode, 2)

    def test_without_a_declared_boundary_nothing_is_enforced(self):
        r = self._call("/anywhere/at/all.py", owned=None)
        self.assertEqual(r.returncode, 0)

    def test_reads_are_never_blocked(self):
        r = self._call("/repo/apps/x.py", owned="/repo/tests", tool="Read")
        self.assertEqual(r.returncode, 0)


class PacingTests(unittest.TestCase):
    """Under a rate limit, concurrency multiplies the bill instead of the work."""

    def test_a_credential_serving_normally_is_never_held_back(self):
        acct = {"name": "t", "blocked_until": 0}
        with devinx.paced(acct):
            pass
        self.assertIsNone(acct.get("pace"), "a semaphore was created for nothing")

    def test_the_cap_holds_when_a_long_block_ends(self):
        # Refused 30 minutes ago, blocked until 10 seconds ago: every turn held
        # for the block is released now, and that is when the cap matters.
        import time
        now = time.time()
        acct = {"name": "t", "refused_at": now - 1800, "blocked_until": now - 10}
        self.assertIsNot(type(devinx.paced(acct)), type(contextlib.nullcontext()),
                         "the cap had lapsed by the end of the block")

    def test_the_cap_lapses_once_the_credential_has_been_back_a_while(self):
        import time
        now = time.time()
        acct = {"name": "t", "refused_at": now - 1800,
                "blocked_until": now - devinx.PACE_WINDOW - 5}
        self.assertIs(type(devinx.paced(acct)), type(contextlib.nullcontext()))

    def test_a_credential_that_just_refused_is_capped(self):
        import threading, time
        acct = {"name": "t", "blocked_until": 0, "refused_at": time.time()}
        held, peak, lock = [0], [0], threading.Lock()

        def worker():
            with devinx.paced(acct):
                with lock:
                    held[0] += 1
                    peak[0] = max(peak[0], held[0])
                time.sleep(0.1)
                with lock:
                    held[0] -= 1

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertLessEqual(peak[0], devinx.PACE_CONCURRENCY)
        self.assertEqual(held[0], 0, "the cap was not released")


class ResetDelayTests(unittest.TestCase):
    """The upstream answers in whichever unit reads best."""

    def test_every_unit_is_understood(self):
        self.assertEqual(devinx.reset_delay("Your limit will reset in 20 seconds."), 20)
        self.assertEqual(devinx.reset_delay("reset in 2 minutes"), 120)
        self.assertEqual(devinx.reset_delay("reset in 1 hour"), 3600)

    def test_an_unparseable_message_falls_back(self):
        self.assertEqual(devinx.reset_delay("no idea", default=30), 30)


class EstimateTests(unittest.TestCase):
    """A body estimated at a hundredth of its weight is one compaction thinks
    it has room for. Measured on a real turn: a message of 97 598 tokens
    estimated at 801, the turn went out whole, the upstream refused it with
    invalid_argument and the session ended."""

    BIG = "z" * 200000

    def _one(self, block):
        body = {"messages": [{"role": "user", "content": [block]}]}
        raw = len(json.dumps(body, default=str)) // 4
        return raw, devinx.estimate_tokens(body)

    def test_every_tool_result_shape_is_counted(self):
        shapes = [
            {"type": "tool_result", "tool_use_id": "t", "content": self.BIG},
            {"type": "tool_result", "tool_use_id": "t",
             "content": [{"type": "text", "text": self.BIG}]},
            # No `type` key, and a bare string in the list: the two shapes that
            # were silently worth nothing.
            {"type": "tool_result", "tool_use_id": "t",
             "content": [{"text": self.BIG}]},
            {"type": "tool_result", "tool_use_id": "t", "content": [self.BIG]},
            {"type": "tool_result", "tool_use_id": "t",
             "content": [{"a": {"b": [{"c": self.BIG}]}}]},
        ]
        for block in shapes:
            raw, est = self._one(block)
            self.assertGreater(est, raw * 0.9,
                               f"{json.dumps(block)[:60]} estimated at {est} of {raw}")

    def test_an_image_is_counted_as_tokens_not_as_base64(self):
        raw, est = self._one({"type": "tool_result", "tool_use_id": "t", "content": [
            {"type": "image", "source": {"type": "base64",
                                         "media_type": "image/png",
                                         "data": "A" * 200000}}]})
        self.assertLess(est, 5000, "base64 was counted as text")
        self.assertGreater(est, 0)

    def test_thinking_and_text_still_count(self):
        for block in ({"type": "text", "text": self.BIG},
                      {"type": "thinking", "thinking": self.BIG},
                      {"type": "tool_use", "id": "t", "name": "Bash",
                       "input": {"command": self.BIG}}):
            raw, est = self._one(block)
            self.assertGreater(est, raw * 0.9, block.get("type"))


class KeepaliveTests(unittest.TestCase):
    """A turn that thinks for five minutes used to lose its connection.

    The client abandons a stream that has sent nothing for five minutes —
    max(CLAUDE_STREAM_IDLE_TIMEOUT_MS, 300000) in its own binary — and reports
    "The response stopped arriving". 158 turns ended that way, at a median
    latency of 343s. Anthropic's own API holds the line with `ping` events.
    """

    class Sock(io.RawIOBase):
        def __init__(self):
            self.buf = b""
            self.lock = threading.Lock()

        def write(self, b):
            with self.lock:
                self.buf += b
            return len(b)

        def flush(self):
            pass

    def setUp(self):
        self._every = devinx.KEEPALIVE_EVERY
        devinx.KEEPALIVE_EVERY = 1      # compress the clock
        self.addCleanup(setattr, devinx, "KEEPALIVE_EVERY", self._every)

    def test_a_silent_turn_holds_its_connection_open(self):
        w = self.Sock()
        out = devinx.AnthropicStream(w, "swe-2-max")
        out.arm()
        time.sleep(3.5)
        out.release()
        text = w.buf.decode()
        self.assertTrue(text.startswith("HTTP/1.1 200 OK"))
        self.assertEqual(text.count("event: message_start"), 1,
                         "message_start was sent more than once")
        self.assertGreaterEqual(text.count("event: ping"), 2)

    def test_nothing_is_written_after_release(self):
        w = self.Sock()
        out = devinx.AnthropicStream(w, "swe-2-max")
        out.arm()
        time.sleep(1.5)
        out.release()
        before = len(w.buf)
        time.sleep(2)
        # The caller puts an HTTP status on this same socket when a turn is
        # handed back as an error; a late ping would corrupt it.
        self.assertEqual(len(w.buf), before)

    def test_a_fast_turn_is_untouched(self):
        w = self.Sock()
        out = devinx.AnthropicStream(w, "swe-2-max")
        out.arm()
        out.start()
        out.text("bonjour")
        out.finish("end_turn", {"input_tokens": 1, "output_tokens": 1})
        time.sleep(2)
        text = w.buf.decode()
        self.assertNotIn("event: ping", text)
        self.assertEqual(text.count("event: message_start"), 1)
        self.assertIn("message_stop", text)


class HoldTests(unittest.TestCase):
    """A turn is held through what the upstream says will pass, not handed back."""

    class Msg:
        def __init__(self, text=None, stop=0):
            self.delta_thinking = None
            self.delta_signature = None
            self.delta_text = text
            self.delta_tool_calls = []
            self.stop_reason = stop
            self.latency = 0.1
            self.usage = mock.Mock(input_tokens=1, output_tokens=1,
                                   cache_read_tokens=0, cache_write_tokens=0)

    def _run(self, errors, stream=True):
        calls = []

        def fake(req, acct=None, purpose="turn"):
            calls.append(1)
            if len(calls) <= len(errors):
                yield None, errors[len(calls) - 1]
                return
            yield self.Msg("ok"), None
            yield self.Msg(stop=devinx.STOP_END_TURN if hasattr(devinx, "STOP_END_TURN") else 1), None

        body = {"model": "swe-2-max", "stream": stream, "max_tokens": 16,
                "messages": [{"role": "user", "content": "hi"}]}
        sock = KeepaliveTests.Sock()
        with mock.patch.object(devinx, "chat_stream", fake), \
             mock.patch.object(devinx.time, "sleep", lambda s: None):
            result = devinx.run_swe(body, sock if stream else None)
        return calls, result, sock.buf.decode()

    OUTAGE = ("upstream trailer error: unimplemented: The third-party model "
              "provider is experiencing issues and is currently not available. "
              "Please try this model again later.")

    def test_a_provider_outage_is_waited_out(self):
        calls, (_, err), wire = self._run([self.OUTAGE, self.OUTAGE])
        self.assertEqual(len(calls), 3, "the outage was not retried")
        self.assertIsNone(err)
        self.assertIn("ok", wire)

    def test_retrying_survives_the_stream_being_opened_by_a_keepalive(self):
        # A hold longer than the keepalive interval opens the response with a
        # message_start before any content. That must not switch retrying off.
        started = []
        real_start = devinx.AnthropicStream.start

        def start_early(self, usage=None):
            started.append(1)
            return real_start(self, usage)

        with mock.patch.object(devinx.AnthropicStream, "arm",
                               lambda self: self.start()):
            calls, (_, err), wire = self._run([self.OUTAGE, self.OUTAGE])
        self.assertEqual(len(calls), 3, "retry stopped once the stream was open")
        self.assertEqual(wire.count("event: message_start"), 1)
        self.assertIn("ok", wire)

    def test_the_wait_budget_covers_the_long_blocks(self):
        # Blocks of up to 35 minutes were announced on 2026-09-23.
        self.assertGreaterEqual(devinx.RATE_WAIT_BUDGET, 1800)


class SummaryNeverAbandonedTests(unittest.TestCase):
    """The summary is waited for, split if too big, and never replaced by nothing.

    On 2026-09-23, 39 agents lost the middle of their run because both accounts
    refused the summary call at the same instant and the summariser returned
    None without a log line.
    """

    class Msg:
        def __init__(self, text):
            self.delta_text = text
            self.delta_thinking = None

    TURNS = [{"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "Read",
                 "input": {"file_path": "/src/app.py"}}]},
             {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1",
                 "content": "def main(): pass"}]}]

    def _run(self, errors, claims=None, **kw):
        calls = []

        def fake(req, acct=None, purpose="turn"):
            calls.append(acct)
            if len(calls) <= len(errors):
                yield None, errors[len(calls) - 1]
                return
            yield self.Msg("SUMMARY"), None

        claims = list(claims or [])
        acct = {"name": "a", "blocked_until": 0}

        def claim(avoid=None):
            return claims.pop(0) if claims else (acct, 0.0)

        with mock.patch.object(devinx, "chat_stream", fake), \
             mock.patch.object(devinx, "build_request", lambda b, **k: (None, None)), \
             mock.patch.object(devinx, "claim_account", claim), \
             mock.patch.object(devinx, "block_account", lambda a, s: None), \
             mock.patch.object(devinx.time, "sleep", lambda s: None):
            out = devinx.summarise_turns(self.TURNS, "swe-2-max", "sys", **kw)
        return out, calls

    def test_every_credential_refusing_is_waited_out(self):
        # Both accounts blocked when the summary starts: before, None at once.
        out, calls = self._run([], claims=[(None, 20.0), (None, 5.0)])
        self.assertEqual(out, "SUMMARY")

    def test_a_refusal_then_every_credential_blocked_is_waited_out(self):
        out, calls = self._run(["resource_exhausted: reset in 30 seconds"],
                               claims=[({"name": "a"}, 0.0), (None, 30.0)])
        self.assertEqual(out, "SUMMARY")

    def test_a_provider_outage_is_waited_out(self):
        out, _ = self._run(["unimplemented: The third-party model provider is "
                            "experiencing issues and is currently not available."] * 3)
        self.assertEqual(out, "SUMMARY")

    def test_dropped_connections_are_retried_past_two(self):
        out, _ = self._run(["upstream ConnectionResetError: reset"] * 5)
        self.assertEqual(out, "SUMMARY")

    def test_a_spent_budget_gives_a_record_not_nothing(self):
        with mock.patch.object(devinx, "RATE_WAIT_BUDGET", 0):
            out, _ = self._run([])
        self.assertIn("Mechanical record", out)
        self.assertIn("/src/app.py", out, "the record lost what was done")

    def test_the_fold_keeps_its_summary_rather_than_a_record(self):
        with mock.patch.object(devinx, "RATE_WAIT_BUDGET", 0):
            out, _ = self._run([], never_empty=False)
        self.assertIsNone(out)

    def test_a_transcript_too_long_is_split_not_cut(self):
        seen = []

        def once(piece, model, system, previous, deadline):
            seen.append(len(piece))
            return devinx._TOO_LONG if len(piece) > 1 else f"S{len(seen)}"

        turns = self.TURNS * 2
        with mock.patch.object(devinx, "_summarise_once", once):
            out = devinx.summarise_turns(turns, "swe-2-max", "sys")
        self.assertNotIn("Mechanical record", out)
        self.assertEqual(sum(1 for n in seen if n == 1), len(turns),
                         "some turns were never summarised")


class MessageIdTests(unittest.TestCase):
    """The constant that collapsed every run into three messages.

    Claude Code builds its API messages with a normaliser that merges an
    assistant turn into an earlier one when the two share a message.id, and the
    window it keeps is cleared only by a user message that is not a tool_result
    — of which an agent run has none. A constant id therefore folded a whole
    run into one assistant message and one user message, which is what every
    captured swe-2 body looked like. The real API guarantees a unique id per
    response; this has to as well.
    """

    def test_every_response_gets_its_own_id(self):
        ids = {devinx.new_message_id() for _ in range(1000)}
        self.assertEqual(len(ids), 1000)
        self.assertTrue(all(i.startswith("msg_") for i in ids))
        self.assertNotIn("msg_devinx", ids)

    def test_no_constant_id_is_left_on_a_response(self):
        src = io.open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "devinx.py"), encoding="utf-8").read()
        # The Responses path builds per-item ids and is a different contract;
        # the Messages responses must never carry a literal.
        self.assertNotIn('"id": "msg_devinx"', src)
        self.assertNotIn("'id': 'msg_devinx'", src)
        # The Codex route correlates streamed pieces by item id the same way,
        # so no literal may survive there either.
        for literal in ('msg_devinx_', 'call_devinx_', 'resp_devinx'):
            self.assertNotIn(literal, src, f"{literal} is still a constant")

    def test_two_codex_streams_do_not_share_item_ids(self):
        a = devinx.ResponsesStream(io.BytesIO(), "swe-2-max")
        b = devinx.ResponsesStream(io.BytesIO(), "swe-2-max")
        self.assertNotEqual(a.item_prefix, b.item_prefix)
        self.assertNotEqual(a.response_id, b.response_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
