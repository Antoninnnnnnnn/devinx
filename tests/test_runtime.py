"""Hermetic tests for compaction state, local diagnostics and process coordination."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import devinx
import diagnostics
import launcher
import runtime_support


def conversation():
    messages = [{'role': 'user', 'content': 'Implement the requested change.'}]
    for i in range(10):
        messages.append({'role': 'assistant', 'content': f'Observation {i}: ' + 'x' * 600})
        messages.append({'role': 'user', 'content': [
            {'type': 'tool_result', 'tool_use_id': f't{i}', 'content': 'y' * 600}]})
    messages.append({'role': 'assistant', 'content': 'Continue from the verified result.'})
    return {'model': 'swe-2-max', 'metadata': {'user_id': 'test-session'},
            'messages': messages}


class CompactionStateTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for key, value in {'_summaries': {}, '_summary_flights': {},
                           'COMPACT_AT': 1200, 'COMPACT_STRICT': False}.items():
            self.stack.enter_context(mock.patch.object(devinx, key, value))

    def test_unchanged_history_reuses_summary_without_mutating_body(self):
        body = conversation()
        before = copy.deepcopy(body)
        with mock.patch.object(devinx, 'summarise_turns', return_value='summary') as summary:
            first = devinx.compact_body(body)
            second = devinx.compact_body(body)
        self.assertEqual(summary.call_count, 1)
        self.assertEqual(first, second)
        self.assertEqual(body, before)
        self.assertFalse(devinx._summary_flights)

    def test_same_length_rewrite_invalidates_summary(self):
        body = conversation()
        with mock.patch.object(devinx, 'summarise_turns', side_effect=['OLD', 'NEW']) as summary:
            devinx.compact_body(body)
            edited = copy.deepcopy(body)
            edited['messages'][1]['content'] = edited['messages'][1]['content'].replace('x', 'z')
            output = devinx.compact_body(edited)
        self.assertEqual(summary.call_count, 2)
        self.assertIsNone(summary.call_args.args[3])
        self.assertIn('NEW', json.dumps(output))
        self.assertNotIn('OLD', json.dumps(output))

    def test_flattened_insertions_do_not_duplicate_previously_covered_results(self):
        old = [('assistant', {'type': 'tool_use', 'id': 'a'}),
               ('user', {'type': 'tool_result', 'tool_use_id': 'a'})]
        call = ('assistant', {'type': 'tool_use', 'id': 'b'})
        result = ('user', {'type': 'tool_result', 'tool_use_id': 'b'})
        current = [old[0], call, old[1], result]
        hashes = devinx._block_hashes(old)
        self.assertEqual(devinx._uncovered_blocks(current, hashes, flattened=True), [call, result])
        self.assertIsNone(devinx._uncovered_blocks(current, hashes))
        current[2] = ('user', {'type': 'tool_result', 'tool_use_id': 'changed'})
        self.assertIsNone(devinx._uncovered_blocks(current, hashes, flattened=True))

    def test_same_conversation_concurrency_has_one_summary(self):
        barrier = threading.Barrier(6)
        results, errors = [], []
        def summarise(*args):
            time.sleep(0.05)
            return 'shared summary'
        def worker():
            try:
                barrier.wait(timeout=3)
                results.append(devinx.compact_body(conversation()))
            except BaseException as error:
                errors.append(error)
        with mock.patch.object(devinx, 'summarise_turns', side_effect=summarise) as summary:
            threads = [threading.Thread(target=worker) for _ in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)
            self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertFalse(errors)
        self.assertEqual(len(results), 6)
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(summary.call_count, 1)
        self.assertFalse(devinx._summary_flights)

    def test_different_conversations_do_not_share_global_inference_lock(self):
        barrier = threading.Barrier(2)
        errors = []
        def summarise(*args):
            barrier.wait(timeout=3)
            return 'independent summary'
        def worker(name):
            body = conversation()
            body['metadata']['user_id'] = name
            try:
                devinx.compact_body(body)
            except BaseException as error:
                errors.append(error)
        with mock.patch.object(devinx, 'summarise_turns', side_effect=summarise):
            threads = [threading.Thread(target=worker, args=(name,)) for name in ('a', 'b')]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)
        self.assertFalse(errors)
        self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertFalse(devinx._summary_flights)

    def test_strict_mode_retains_intermediate_user_text_verbatim(self):
        body = conversation()
        constraint = 'Never change the production database schema.'
        body['messages'].insert(3, {'role': 'user', 'content': constraint})
        with mock.patch.object(devinx, 'COMPACT_STRICT', True), \
             mock.patch.object(devinx, 'summarise_turns', return_value='A summary without the constraint'):
            output = devinx.compact_body(body)
        self.assertIn(constraint, json.dumps(output))
        self.assertLessEqual(devinx.estimate_tokens(output), devinx.COMPACT_AT)

    def test_strict_mode_fails_without_dropping_turns_if_no_summary(self):
        body = conversation()
        before = copy.deepcopy(body)
        with mock.patch.object(devinx, 'COMPACT_STRICT', True), \
             mock.patch.object(devinx, 'summarise_turns', return_value=None):
            with self.assertRaises(devinx.CompactionUnavailable):
                devinx.compact_body(body)
        self.assertEqual(body, before)
        self.assertFalse(devinx._summary_flights)

    def test_strict_mode_rejects_oversized_indivisible_input(self):
        with mock.patch.object(devinx, 'COMPACT_STRICT', True), \
             mock.patch.object(devinx, 'summarise_turns', return_value='summary'):
            for messages in ([{'role': 'user', 'content': 'x' * 12000}],
                             [{'role': 'user', 'content': 'task'}] +
                             [{'role': 'assistant', 'content': 'x' * 12000}] * 3):
                with self.subTest(length=len(messages)):
                    with self.assertRaises(devinx.CompactionUnavailable):
                        devinx.compact_body({'messages': messages})

    def test_strict_unexpected_failure_is_explicit_and_does_not_reach_upstream(self):
        with mock.patch.object(devinx, 'COMPACT_STRICT', True), \
             mock.patch.object(devinx, 'compact_body', side_effect=RuntimeError('private detail')), \
             mock.patch.object(devinx, 'build_request') as build:
            _, error = devinx.run_swe({'model': 'swe-2-max'}, None)
        self.assertEqual(devinx.anthropic_error(error)[1], 503)
        self.assertNotIn('private detail', error)
        build.assert_not_called()


class LiveRequestTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for key, value in {'_inflight': {'n': 0}, '_active_requests': {},
                           '_request_local': threading.local(), 'MAX_INFLIGHT': 1}.items():
            self.stack.enter_context(mock.patch.object(devinx, key, value))

    def test_phase_and_release_are_safe_and_idempotent(self):
        self.assertTrue(devinx._enter_request())
        devinx._request_phase('streaming', 'swe-2-max')
        entry = devinx.live_requests()[0]
        self.assertEqual(set(entry), {'id', 'model', 'phase', 'elapsed', 'phase_elapsed'})
        self.assertEqual(entry['phase'], 'streaming')
        self.assertEqual(entry['model'], 'swe-2-max')
        self.assertGreaterEqual(entry['elapsed'], 0)
        devinx._leave_request()
        devinx._leave_request()
        self.assertEqual(devinx._inflight['n'], 0)
        self.assertEqual(devinx.live_requests(), [])

    def test_capacity_rejects_only_new_work_and_reports_503(self):
        self.assertTrue(devinx._enter_request())
        handler = object.__new__(devinx.Handler)
        handler.send_error_json = mock.Mock()
        handler._do_POST = mock.Mock()
        thread = threading.Thread(target=handler.do_POST)
        thread.start()
        thread.join(3)
        handler._do_POST.assert_not_called()
        self.assertEqual(handler.send_error_json.call_args.args[0], 503)
        self.assertEqual(devinx._inflight['n'], 1)
        devinx._leave_request()
        self.assertTrue(devinx._enter_request())
        devinx._leave_request()

    def test_handler_exception_releases_slot(self):
        handler = object.__new__(devinx.Handler)
        handler._do_POST = mock.Mock(side_effect=ValueError('test'))
        with self.assertRaises(ValueError):
            handler.do_POST()
        self.assertEqual(devinx._inflight['n'], 0)
        self.assertEqual(devinx.live_requests(), [])


class DiagnosticTests(unittest.TestCase):
    def test_service_response_uses_explicit_allowlist(self):
        data = {'service': 'devinx', 'pid': 123, 'build': 'abc',
                'token': 'SECRET', 'configuration': {
                    'DEVINX_MAX_INFLIGHT': 64, 'DEVINX_API_KEY': 'SECRET',
                    'DEVINX_RATE_WAIT': {'nested': 'SECRET'}}}
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(data).encode()
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(diagnostics.urllib.request, 'build_opener', return_value=opener):
            state, report = diagnostics.read_service('127.0.0.1', 8316)
        self.assertEqual(state, 'running')
        self.assertEqual(report['configuration'], {'DEVINX_MAX_INFLIGHT': 64})
        self.assertNotIn('SECRET', json.dumps(report))

    def test_config_mismatch_is_reported_without_credentials_or_prompts(self):
        with mock.patch.object(diagnostics, 'read_service', return_value=('running', {
                'service': 'devinx', 'build': 'old',
                'configuration': {'DEVINX_MAX_INFLIGHT': 64}})), \
             mock.patch.dict(os.environ, {'DEVINX_MAX_INFLIGHT': '12',
                                          'DEVINX_API_KEY': 'PRIVATE-KEY'}, clear=True), \
             mock.patch.object(launcher, 'start_service') as start, \
             mock.patch.object(devinx.SESSION, 'post') as post:
            report = diagnostics.collect('--explain', ['--cx', '--or', 'SECRET-PROMPT'], launcher)
        text = json.dumps(report)
        self.assertNotIn('PRIVATE-KEY', text)
        self.assertNotIn('SECRET-PROMPT', text)
        self.assertEqual(report['launch']['client'], 'codex')
        self.assertTrue(report['launch']['orchestrator_enabled'])
        self.assertTrue(any('differs' in w for w in report['warnings']))
        start.assert_not_called()
        post.assert_not_called()

    def test_diagnostics_run_without_client_installed(self):
        with mock.patch.object(sys, 'argv', ['devinx', '--status', '--json']), \
             mock.patch.object(diagnostics, 'main', return_value=0) as main, \
             mock.patch.object(launcher.shutil, 'which', return_value=None) as which:
            self.assertEqual(launcher.main(), 0)
        main.assert_called_once()
        which.assert_not_called()
        self.assertEqual(launcher.split_args(['--', '--doctor'])[3], ['--', '--doctor'])

    def test_hello_and_launcher_build_match_without_accounts(self):
        self.assertEqual(launcher.local_build(), devinx.BUILD)
        self.assertTrue(devinx.BUILD and devinx.BUILD != 'unknown')
        self.assertEqual(set(devinx.effective_configuration()),
                         set(runtime_support.CONFIG_FIELDS) | set(devinx.RISKY_FLAGS))
        self.assertTrue(all(isinstance(devinx.effective_configuration()[k], bool)
                            for k in devinx.RISKY_FLAGS))
        self.assertTrue(all(isinstance(x, (int, float, bool, type(None)))
                            for x in devinx.effective_configuration().values()))

    def test_runtime_fingerprint_tracks_sources_not_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('devinx.py', 'runtime_support.py', 'diagnostics.py',
                         'tools/log_stats.py', 'tools/dashboard.html', 'descriptors/test.fdp'):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('original')
            before = runtime_support.build_id(directory)
            (root / 'credentials.toml').write_text('SECRET')
            self.assertEqual(runtime_support.build_id(directory), before)
            (root / 'tools/dashboard.html').write_text('changed')
            self.assertNotEqual(runtime_support.build_id(directory), before)


class StartupTests(unittest.TestCase):
    def test_lock_release_after_exception_and_exclusion_across_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            program = ('import sys; from runtime_support import startup_lock\n'
                       'try:\n'
                       ' with startup_lock(sys.argv[1], 8316, timeout=0.15): print("acquired")\n'
                       'except TimeoutError: print("busy"); sys.exit(2)\n')
            with self.assertRaisesRegex(ValueError, 'release'):
                with runtime_support.startup_lock(directory, 8316):
                    result = subprocess.run([sys.executable, '-c', program, directory],
                                            cwd=ROOT, capture_output=True, text=True, timeout=4)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('busy', result.stdout)
                    raise ValueError('release')
            result = subprocess.run([sys.executable, '-c', program, directory],
                                    cwd=ROOT, capture_output=True, text=True, timeout=4)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('acquired', result.stdout)

    def test_foreign_service_is_not_started_or_killed(self):
        with mock.patch.object(launcher, 'startup_lock', return_value=contextlib.nullcontext()), \
             mock.patch.object(launcher, 'service_state', return_value=('foreign', {})), \
             mock.patch.object(launcher, 'start_service') as start, \
             mock.patch.object(launcher, 'stop_service') as stop, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(launcher.ensure_service())
        start.assert_not_called()
        stop.assert_not_called()


if __name__ == '__main__':
    unittest.main()
