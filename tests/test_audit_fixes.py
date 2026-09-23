"""Regression tests for the 2026-09-23 audit findings (IDs in each class).

Hermetic like the rest of the suite: fake upstreams, fake credentials, local
sockets on port 0, and nothing that reaches a real service. Every test that
touches the credential machinery patches the account list, the credential
search and the DEVINX_API_KEY(S) variables, so a real login on this machine is
never read or changed.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import devinx

RATE_ZERO = ("upstream trailer error on a: resource_exhausted: Reached the "
             "limit. Your limit will reset in 0 seconds.")


def frame(text='', stop=0):
    return SimpleNamespace(
        delta_text=text, delta_thinking='', delta_signature='',
        delta_tool_calls=(), stop_reason=stop, latency=0.1,
        usage=SimpleNamespace(input_tokens=1, output_tokens=2,
                              cache_read_tokens=0, cache_write_tokens=0))


def fake_accounts(*names):
    return [{'name': n, 'key': f'devin-session-token$test-{n}', 'jwt': None,
             'exp': 0.0, 'base': None, 'blocked_until': 0.0} for n in names]


@contextlib.contextmanager
def isolated_accounts(accounts):
    """The credential machinery pointed at test data only."""
    env = {k: v for k, v in os.environ.items()
           if k not in ('DEVINX_API_KEYS', 'DEVINX_API_KEY')}
    with mock.patch.object(devinx, '_accounts', accounts), \
         mock.patch.object(devinx, '_turn', {'n': 0}), \
         mock.patch.object(devinx, '_credential_files', return_value=[]), \
         mock.patch.dict(os.environ, env, clear=True):
        yield accounts


class Sleeps:
    """time.sleep replaced by a recorder, so waits cost no real time."""

    def __init__(self):
        self.total = 0.0
        self.calls = []

    def __call__(self, seconds):
        self.calls.append(seconds)
        self.total += seconds


class ResetInZeroSecondsTests(unittest.TestCase):
    """P0 / P3: "reset in 0 seconds" must never become a loop with no pause."""

    BUDGET = 30

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.sleeps = Sleeps()
        for name, value in {'RATE_WAIT_BUDGET': self.BUDGET, 'RATE_FLOOR': 3.0,
                            'KEEPALIVE_EVERY': 0}.items():
            self.stack.enter_context(mock.patch.object(devinx, name, value))
        self.stack.enter_context(mock.patch.object(devinx.time, 'sleep', self.sleeps))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def refusing(self):
        calls = []

        def chat(req, acct=None, purpose='turn'):
            calls.append((acct['name'], self.sleeps.total))
            yield None, RATE_ZERO
        return calls, chat

    def run_turn(self, accounts, stream):
        calls, chat = self.refusing()
        body = {'model': 'swe-2-max', 'stream': stream, 'messages': []}
        with isolated_accounts(accounts), \
             mock.patch.object(devinx, 'compact_body', side_effect=lambda b: b), \
             mock.patch.object(devinx, 'build_request', return_value=(
                 SimpleNamespace(cascade_id='test'), 'swe-2-max')), \
             mock.patch.object(devinx, 'paced', return_value=contextlib.nullcontext()), \
             mock.patch.object(devinx, 'chat_stream', chat):
            result = devinx.run_swe(body, io.BytesIO() if stream else None)
        return calls, result

    def assert_paced(self, calls, accounts):
        # One call per credential per floor at the very most, over the budget.
        bound = len(accounts) * (self.BUDGET / devinx.RATE_FLOOR + 1) + 1
        self.assertLessEqual(len(calls), bound, f'{len(calls)} calls, no pause')
        self.assertGreaterEqual(self.sleeps.total, self.BUDGET - devinx.RATE_FLOOR - 1)
        # A credential is never asked again before a pause of at least the
        # floor — except for the one try the end of the budget may cut short.
        last = {}
        for name, at in calls:
            if name in last and at < self.BUDGET - devinx.RATE_FLOOR:
                self.assertGreaterEqual(at - last[name], devinx.RATE_FLOOR - 1e-6)
            last[name] = at

    def test_turn_with_one_account_waits_instead_of_handing_back(self):
        for stream in (True, False):
            with self.subTest(stream=stream):
                self.sleeps.total, self.sleeps.calls[:] = 0.0, []
                accounts = fake_accounts('a')
                calls, (_, err) = self.run_turn(accounts, stream)
                self.assertIn('resource_exhausted', err)
                self.assertGreater(len(calls), 1, 'handed back without waiting')
                self.assert_paced(calls, accounts)

    def test_turn_with_two_accounts_does_not_ping_pong(self):
        accounts = fake_accounts('a', 'b')
        calls, (_, err) = self.run_turn(accounts, True)
        self.assertIn('resource_exhausted', err)
        self.assertEqual({n for n, _ in calls}, {'a', 'b'})
        self.assert_paced(calls, accounts)

    def test_summary_with_one_or_two_accounts_pauses(self):
        for names in (('a',), ('a', 'b')):
            with self.subTest(accounts=names):
                self.sleeps.total, self.sleeps.calls[:] = 0.0, []
                accounts = fake_accounts(*names)
                calls, chat = self.refusing()
                with isolated_accounts(accounts), \
                     mock.patch.object(devinx, 'build_request', lambda b, **k: (None, None)), \
                     mock.patch.object(devinx, 'chat_stream', chat):
                    out = devinx.summarise_turns(
                        [{'role': 'user', 'content': [{'type': 'text', 'text': 'x'}]}],
                        'swe-2-max', 'sys')
                self.assertIn('Mechanical record', out)
                self.assert_paced(calls, accounts)

    def test_the_wait_is_for_the_first_account_back_including_the_one_that_refused(self):
        accounts = fake_accounts('a', 'b')
        now = time.time()
        accounts[1]['blocked_until'] = now + 1800
        with isolated_accounts(accounts):
            devinx.block_account(accounts[0], 5)
            acct, until = devinx.claim_account(avoid=accounts[0])
        self.assertIsNone(acct)
        self.assertLess(until, 10, 'waited for the other account instead')

    def test_block_floor(self):
        acct = fake_accounts('a')[0]
        devinx.block_account(acct, 0)
        self.assertGreaterEqual(acct['blocked_until'] - time.time(),
                                devinx.RATE_FLOOR - 0.5)
        # The hint the client gets is still what the upstream said.
        self.assertEqual(devinx.anthropic_error(
            'resource_exhausted: reset in 0 seconds')[3], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
