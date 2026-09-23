#!/usr/bin/env python3
"""Regression tests for the agent/skill packaging fixes in this pass
(I6, H6, and the small BOM/prompt/CLAUDE_CONFIG_DIR items).

    .venv/bin/python -m unittest tests.test_agents_fixes -v
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import install
import launcher


AGENT_TEMPLATE = """---
name: {name}
description: test agent
{extra}---

{body}
"""


class BomAndPromptTests(unittest.TestCase):
    """Small fixes: a UTF-8 BOM must not skip an agent file, and only
    whitespace should be stripped from the prompt body."""

    def _write(self, directory, name, body, bom=False, extra=""):
        text = AGENT_TEMPLATE.format(name=name, extra=extra, body=body)
        with open(os.path.join(directory, f"{name}.md"), "w", encoding="utf-8") as fh:
            if bom:
                fh.write("﻿")
            fh.write(text)

    def test_a_bom_prefixed_agent_file_is_not_skipped(self):
        with tempfile.TemporaryDirectory() as here:
            os.makedirs(os.path.join(here, "agents"))
            self._write(os.path.join(here, "agents"), "bommed", "You are a test agent.",
                       bom=True)
            with mock.patch.object(launcher, "HERE", here):
                agents = launcher.packaged_agents()
        self.assertIn("bommed", agents)

    def test_a_prompt_starting_with_a_markdown_list_keeps_its_dash(self):
        with tempfile.TemporaryDirectory() as here:
            os.makedirs(os.path.join(here, "agents"))
            self._write(os.path.join(here, "agents"), "lister",
                       "- Do the first thing\n- Do the second thing")
            with mock.patch.object(launcher, "HERE", here):
                agents = launcher.packaged_agents()
        self.assertTrue(agents["lister"]["prompt"].startswith("- Do the first thing"))


class FrontmatterFieldsCarryThroughTests(unittest.TestCase):
    """I6: tools/permissionMode/maxTurns must not be silently dropped."""

    def _agents_from(self, extra):
        with tempfile.TemporaryDirectory() as here:
            os.makedirs(os.path.join(here, "agents"))
            text = AGENT_TEMPLATE.format(name="full", extra=extra, body="Body.")
            with open(os.path.join(here, "agents", "full.md"), "w", encoding="utf-8") as fh:
                fh.write(text)
            with mock.patch.object(launcher, "HERE", here):
                return launcher.packaged_agents()

    def test_tools_field_is_carried_through(self):
        agents = self._agents_from("tools: Read, Grep\n")
        self.assertEqual(agents["full"]["tools"], ["Read", "Grep"])

    def test_permission_mode_is_carried_through(self):
        agents = self._agents_from("permissionMode: plan\n")
        self.assertEqual(agents["full"]["permissionMode"], "plan")

    def test_max_turns_is_carried_through_as_an_int(self):
        agents = self._agents_from("maxTurns: 12\n")
        self.assertEqual(agents["full"]["maxTurns"], 12)

    def test_non_numeric_max_turns_warns_and_is_dropped(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            agents = self._agents_from("maxTurns: soon\n")
        self.assertNotIn("maxTurns", agents["full"])
        self.assertIn("maxTurns", stderr.getvalue())


class GlobalAgentsMcpDenyTests(unittest.TestCase):
    """I6: --global-agents must include the same mcp__* deny as an injected
    agent, not a byte-for-byte copy of the source file."""

    def test_an_agent_with_no_disallowed_tools_gets_the_deny_added(self):
        text = AGENT_TEMPLATE.format(name="worker", extra="", body="Body.")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEVINX_SUBAGENT_MCP", None)
            patched = install._with_mcp_deny(text)
        self.assertIn("disallowedTools: mcp__*", patched)

    def test_an_agent_with_existing_disallowed_tools_gets_mcp_appended(self):
        text = AGENT_TEMPLATE.format(
            name="explorer", extra="disallowedTools: Edit, Write\n", body="Body.")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEVINX_SUBAGENT_MCP", None)
            patched = install._with_mcp_deny(text)
        self.assertIn("disallowedTools: Edit, Write, mcp__*", patched)

    def test_subagent_mcp_opt_out_leaves_the_file_untouched(self):
        text = AGENT_TEMPLATE.format(name="worker", extra="", body="Body.")
        with mock.patch.dict(os.environ, {"DEVINX_SUBAGENT_MCP": "1"}):
            patched = install._with_mcp_deny(text)
        self.assertEqual(patched, text)

    def test_install_agents_writes_the_deny_into_the_installed_copy(self):
        with tempfile.TemporaryDirectory() as here, \
             tempfile.TemporaryDirectory() as config:
            os.makedirs(os.path.join(here, "agents"))
            text = AGENT_TEMPLATE.format(name="worker", extra="", body="Body.")
            with open(os.path.join(here, "agents", "worker.md"), "w") as fh:
                fh.write(text)
            with mock.patch.object(install, "HERE", here), \
                 mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": config}, clear=False), \
                 contextlib.redirect_stdout(io.StringIO()):
                os.environ.pop("DEVINX_SUBAGENT_MCP", None)
                install.install_agents(force=True)
            with open(os.path.join(config, "agents", "worker.md")) as fh:
                installed = fh.read()
        self.assertIn("mcp__*", installed)


class ClaudeConfigDirTests(unittest.TestCase):
    """Small fix: honour CLAUDE_CONFIG_DIR instead of a hard-coded ~/.claude."""

    def test_claude_config_dir_env_var_is_honoured(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/somewhere/else"}):
            self.assertEqual(install.claude_config_dir(), "/somewhere/else")

    def test_falls_back_to_home_claude_without_it(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            self.assertEqual(install.claude_config_dir(),
                             os.path.expanduser("~/.claude"))


class StaleCodexCacheTests(unittest.TestCase):
    """H6: a cached Codex skill that no longer matches the packaged one
    should be detected and reported, not silently served stale."""

    def test_a_mismatched_cache_warns(self):
        with tempfile.TemporaryDirectory() as here, \
             tempfile.TemporaryDirectory() as codex_home:
            skill_dir = os.path.join(here, "codex", "marketplace", "plugins",
                                     "swe-orchestrator", "skills", "swe-orchestrator")
            os.makedirs(skill_dir)
            with open(os.path.join(skill_dir, "SKILL.md"), "w") as fh:
                fh.write("current content")
            cache_dir = os.path.join(codex_home, "plugins", "cache", "devinx",
                                     "swe-orchestrator", "1.0.0")
            os.makedirs(cache_dir)
            with open(os.path.join(cache_dir, "SKILL.md"), "w") as fh:
                fh.write("stale content")
            stderr = io.StringIO()
            with mock.patch.object(launcher, "HERE", here), \
                 mock.patch.dict(os.environ, {"CODEX_HOME": codex_home}, clear=False), \
                 contextlib.redirect_stderr(stderr):
                launcher._warn_stale_codex_cache()
        self.assertIn("does not match", stderr.getvalue())

    def test_a_matching_cache_is_silent(self):
        with tempfile.TemporaryDirectory() as here, \
             tempfile.TemporaryDirectory() as codex_home:
            skill_dir = os.path.join(here, "codex", "marketplace", "plugins",
                                     "swe-orchestrator", "skills", "swe-orchestrator")
            os.makedirs(skill_dir)
            with open(os.path.join(skill_dir, "SKILL.md"), "w") as fh:
                fh.write("same content")
            cache_dir = os.path.join(codex_home, "plugins", "cache", "devinx",
                                     "swe-orchestrator", "1.1.0")
            os.makedirs(cache_dir)
            with open(os.path.join(cache_dir, "SKILL.md"), "w") as fh:
                fh.write("same content")
            stderr = io.StringIO()
            with mock.patch.object(launcher, "HERE", here), \
                 mock.patch.dict(os.environ, {"CODEX_HOME": codex_home}, clear=False), \
                 contextlib.redirect_stderr(stderr):
                launcher._warn_stale_codex_cache()
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
