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
        seen = []
        for pairs in (260, 263, 266, 269):
            out = devinx.compact_body(self._body(pairs))
            marks = self._summary_of(out)
            self.assertTrue(marks, "the body was not compacted at all")
            seen.append(marks[-1])
        self.assertEqual(len(set(seen)), len(seen),
                         f"the summary never changed: {seen}")
        # The first pass covers the whole span; each later one only what arrived
        # since, which is what keeps a refresh worth a few seconds.
        self.assertGreater(self.calls[0], 100)
        self.assertTrue(all(c < 20 for c in self.calls[1:]), self.calls)

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
        self.assertEqual(len(out), 1 + 40 * 2)
        for i in range(40):
            call = out[1 + 2 * i]
            answer = out[2 + 2 * i]
            self.assertEqual(call["role"], "assistant")
            self.assertEqual(call["content"][-1]["id"], f"t{i}")
            self.assertEqual(answer["role"], "user")
            self.assertEqual(answer["content"][0]["tool_use_id"], f"t{i}")
        # What led into the run rides on its first turn, not on all of them.
        self.assertEqual(out[1]["content"][0]["type"], "thinking")

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

        def flaky(req, acct=None):
            seen.append(acct and acct.get("name"))
            if len(seen) == 1:
                yield None, "upstream trailer error: resource_exhausted: Reached"
                return
            yield self._Msg(), None

        with mock.patch.object(devinx, "chat_stream", flaky), \
             mock.patch.object(devinx, "build_request", lambda b, **k: (None, None)):
            out = devinx.summarise_turns(
                [{"role": "user", "content": [{"type": "text", "text": "x"}]}],
                "swe-2-max", "sys")
        self.assertEqual(out, "SUMMARY")
        self.assertEqual(len(seen), 2, "it gave up instead of switching")
        self.assertNotEqual(seen[0], seen[1], "it retried the same credential")

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
        req, _ = devinx.build_request(body)
        wire = str(req)
        self.assertIn("MARKER-A", wire)
        self.assertIn("MARKER-B", wire)


if __name__ == "__main__":
    unittest.main(verbosity=2)
