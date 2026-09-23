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


class LiveServer:
    """devinx's real Handler on an ephemeral loopback port."""

    def __init__(self, handler=None):
        self.server = devinx.Server(('127.0.0.1', 0), handler or devinx.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.02}, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def get(self, path, headers):
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            conn.request('GET', path, headers=headers)
            r = conn.getresponse()
            return r.status, json.loads(r.read())
        finally:
            conn.close()


class CodexCatalogTests(unittest.TestCase):
    """S1: /v1/models must not hand a Claude credential to chatgpt.com."""

    def setUp(self):
        self.live = LiveServer()
        self.addCleanup(self.live.close)
        upstream = mock.Mock(status_code=200)
        upstream.json.return_value = {'models': [{'slug': 'gpt-test'}]}
        patcher = mock.patch.object(devinx.SESSION, 'get', return_value=upstream)
        self.get = patcher.start()
        self.addCleanup(patcher.stop)

    def test_claude_code_gateway_discovery_never_reaches_chatgpt(self):
        for headers in (
                {'Authorization': 'Bearer claude-secret', 'anthropic-version': '2023-06-01'},
                {'Authorization': 'Bearer claude-secret'},
                {'x-api-key': 'sk-ant-secret'}):
            with self.subTest(headers=list(headers)):
                status, body = self.live.get('/v1/models?limit=1000', headers)
                self.assertEqual(status, 200)
                self.assertIn('swe-2', [m['id'] for m in body['data']])
        self.get.assert_not_called()

    def test_codex_like_request_with_claude_headers_is_not_forwarded(self):
        self.live.get('/v1/models?client_version=0.154.0',
                      {'Authorization': 'Bearer x', 'anthropic-beta': 'y'})
        self.live.get('/v1/models?client_version=0.154.0',
                      {'Authorization': 'Bearer x', 'x-api-key': 'sk-ant-secret'})
        self.get.assert_not_called()

    def test_codex_gets_its_catalog_with_only_the_headers_it_needs(self):
        status, body = self.live.get('/v1/models?client_version=0.154.0', {
            'Authorization': 'Bearer chatgpt-token', 'ChatGPT-Account-ID': 'acct',
            'originator': 'codex_cli_rs', 'Cookie': 'session=secret',
            'X-Unrelated': 'private'})
        self.assertEqual(status, 200)
        self.assertIn('gpt-test', [m.get('slug') for m in body['models']])
        self.get.assert_called_once()
        url = self.get.call_args.args[0]
        self.assertTrue(url.startswith(devinx.CODEX_UPSTREAM + '/models?client_version='))
        sent = {k.lower(): v for k, v in self.get.call_args.kwargs['headers'].items()}
        self.assertEqual(sent['authorization'], 'Bearer chatgpt-token')
        self.assertEqual(sent['chatgpt-account-id'], 'acct')
        for private in ('cookie', 'x-unrelated', 'host', 'x-api-key'):
            self.assertNotIn(private, sent)


class Wire(io.RawIOBase):
    """A socket stand-in the keepalive thread can write to safely."""

    def __init__(self):
        self.buf = b''
        self.lock = threading.Lock()

    def write(self, b):
        with self.lock:
            self.buf += b
        return len(b)

    def flush(self):
        pass


def sse(raw):
    return [json.loads(line[6:]) for line in raw.decode().splitlines()
            if line.startswith('data: ')]


class ResponsesUsageTests(unittest.TestCase):
    """P4: OpenAI's input_tokens include the cached part."""

    def test_cached_tokens_are_inside_input_tokens(self):
        buf = io.BytesIO()
        out = devinx.ResponsesStream(buf, 'swe-2-max')
        out.start()
        out.finish('end_turn', {'input_tokens': 100, 'output_tokens': 5,
                                'cache_read_input_tokens': 1000,
                                'cache_creation_input_tokens': 10})
        usage = sse(buf.getvalue())[-1]['response']['usage']
        self.assertEqual(usage['input_tokens'], 1110)
        self.assertEqual(usage['input_tokens_details']['cached_tokens'], 1000)
        self.assertEqual(usage['total_tokens'], 1115)
        self.assertLessEqual(usage['input_tokens_details']['cached_tokens'],
                             usage['input_tokens'])


class ResponsesKeepaliveTests(unittest.TestCase):
    """P5: the Codex route keeps a silent stream alive with its own events."""

    def setUp(self):
        patcher = mock.patch.object(devinx, 'KEEPALIVE_EVERY', 1)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_silent_turn_is_kept_alive_with_existing_events_only(self):
        w = Wire()
        out = devinx.ResponsesStream(w, 'swe-2-max')
        out.arm()
        time.sleep(3.5)
        out.release()
        text = w.buf.decode()
        self.assertTrue(text.startswith('HTTP/1.1 200 OK'))
        wire = sse(w.buf)
        kinds = [e['type'] for e in wire]
        self.assertEqual(kinds.count('response.created'), 1)
        self.assertGreaterEqual(kinds.count('response.in_progress'), 3)
        self.assertEqual(set(kinds), {'response.created', 'response.in_progress'})
        self.assertEqual([e['sequence_number'] for e in wire], list(range(len(wire))))
        self.assertEqual({e['response']['id'] for e in wire}, {out.response_id})
        self.assertEqual(len({e['response']['created_at'] for e in wire}), 1)
        before = len(w.buf)
        time.sleep(1.5)
        self.assertEqual(len(w.buf), before, 'written after release')

    def test_disabled_with_the_anthropic_one(self):
        with mock.patch.object(devinx, 'KEEPALIVE_EVERY', 0):
            w = Wire()
            out = devinx.ResponsesStream(w, 'swe-2-max')
            out.arm()
            time.sleep(1.5)
            out.release()
        self.assertEqual(w.buf, b'')

    def test_a_failed_keepalive_marks_the_client_gone(self):
        class Broken(Wire):
            def write(self, b):
                raise BrokenPipeError()
        for emitter in (devinx.AnthropicStream, devinx.ResponsesStream):
            with self.subTest(emitter=emitter.__name__):
                out = emitter(Broken(), 'swe-2-max')
                out.arm()
                self.assertTrue(out.gone.wait(3), 'the turn was never told')
                out.release()

    def _turn(self, attempts, arm_now=True):
        class Early(devinx.ResponsesStream):
            def arm(self):
                self.start()
        buf = io.BytesIO()
        body = {'model': 'swe-2-max', 'stream': True, 'messages': []}
        with isolated_accounts(fake_accounts('a')), \
             mock.patch.object(devinx, 'compact_body', side_effect=lambda b: b), \
             mock.patch.object(devinx, 'build_request', return_value=(
                 SimpleNamespace(cascade_id='test'), 'swe-2-max')), \
             mock.patch.object(devinx, 'paced', return_value=contextlib.nullcontext()), \
             mock.patch.object(devinx, 'chat_stream', side_effect=attempts), \
             mock.patch.object(devinx.time, 'sleep'), \
             contextlib.redirect_stdout(io.StringIO()):
            result = devinx.run_swe(body, buf, Early if arm_now else devinx.ResponsesStream)
        return result, buf.getvalue()

    def test_a_retry_after_the_keepalive_committed_reuses_the_stream(self):
        result, raw = self._turn([iter([(None, 'upstream ConnectionError: dropped')]),
                                  iter([(frame('complete'), None)])])
        self.assertEqual(result, (None, None))
        self.assertEqual(raw.count(b'HTTP/1.1 '), 1)
        kinds = [e['type'] for e in sse(raw)]
        self.assertEqual(kinds.count('response.created'), 1)
        self.assertEqual(kinds[-1], 'response.completed')

    def test_an_error_after_commit_is_sse_before_commit_is_http(self):
        result, raw = self._turn([iter([(None, 'invalid_argument: nope')])])
        self.assertEqual(result, (None, None))
        self.assertEqual(raw.count(b'HTTP/1.1 '), 1)
        self.assertEqual([e['type'] for e in sse(raw)][-2:],
                         ['error', 'response.incomplete'])
        result, raw = self._turn([iter([(None, 'invalid_argument: nope')])],
                                 arm_now=False)
        self.assertEqual(raw, b'')
        self.assertEqual(result, (None, 'invalid_argument: nope'))


class SharedDeadlineTests(unittest.TestCase):
    """P8: the summary, its fold and the turn's own waits share one budget."""

    def test_a_summary_that_waited_the_budget_leaves_the_turn_none(self):
        sleeps = Sleeps()
        calls = []

        def chat(req, acct=None, purpose='turn'):
            calls.append(purpose)
            yield None, RATE_ZERO

        messages = [{'role': 'user', 'content': 'task'}]
        for i in range(12):
            messages.append({'role': 'assistant' if i % 2 == 0 else 'user',
                             'content': f'turn {i} ' + 'y' * 400})
        body = {'model': 'swe-2-max', 'stream': False, 'messages': messages,
                'metadata': {'user_id': 'shared-deadline'}}
        with isolated_accounts(fake_accounts('a')), \
             mock.patch.object(devinx, 'RATE_WAIT_BUDGET', 30), \
             mock.patch.object(devinx, 'RATE_FLOOR', 3.0), \
             mock.patch.object(devinx, 'COMPACT_AT', 400), \
             mock.patch.object(devinx, '_summaries', {}), \
             mock.patch.object(devinx, 'build_request', return_value=(
                 SimpleNamespace(cascade_id='test'), 'swe-2-max')), \
             mock.patch.object(devinx, 'paced', return_value=contextlib.nullcontext()), \
             mock.patch.object(devinx, 'chat_stream', chat), \
             mock.patch.object(devinx.time, 'sleep', sleeps), \
             contextlib.redirect_stdout(io.StringIO()):
            _, err = devinx.run_swe(body, None)
        self.assertIn('resource_exhausted', err)
        self.assertIn('summary', calls)
        # One budget, plus at most one jittered wait that started inside it.
        self.assertLessEqual(sleeps.total, 30 + 5)
        self.assertLessEqual(calls.count('turn'), 2)


class ClientGoneTests(unittest.TestCase):
    """P1: a client that hangs up during a hold ends the hold, and the calls."""

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.calls = []
        self.lock = threading.Lock()

        def chat(req, acct=None, purpose='turn'):
            with self.lock:
                self.calls.append(purpose)
            yield None, RATE_ZERO

        self.stack.enter_context(isolated_accounts(fake_accounts('a')))
        for name, value in {'RATE_FLOOR': 0.2, 'RATE_WAIT_BUDGET': 120,
                            'KEEPALIVE_EVERY': 1, 'chat_stream': chat,
                            '_summaries': {}}.items():
            self.stack.enter_context(mock.patch.object(devinx, name, value))
        self.stack.enter_context(mock.patch.object(devinx, 'build_request', return_value=(
            SimpleNamespace(cascade_id='test'), 'swe-2-max')))
        self.stack.enter_context(mock.patch.object(
            devinx, 'paced', return_value=contextlib.nullcontext()))
        self.log = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.log))
        self.live = LiveServer()
        self.stack.callback(self.live.close)

    def hang_up(self, path, body):
        import socket
        data = json.dumps(body).encode()
        sock = socket.create_connection(('127.0.0.1', self.live.port), timeout=5)
        sock.sendall(f'POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                     f'Content-Type: application/json\r\n'
                     f'Content-Length: {len(data)}\r\n\r\n'.encode() + data)
        time.sleep(1.5)
        with self.lock:
            self.assertGreater(len(self.calls), 1, 'the turn was never held')
        sock.close()
        time.sleep(1.5)
        with self.lock:
            settled = len(self.calls)
        time.sleep(2)
        with self.lock:
            self.assertEqual(len(self.calls), settled,
                             'upstream calls went on after the client left')
        deadline = time.time() + 3
        while 'status=client_disconnected' not in self.log.getvalue() \
                and time.time() < deadline:
            time.sleep(0.05)
        self.assertIn('status=client_disconnected', self.log.getvalue())

    def test_messages_stream_and_non_stream(self):
        for stream in (True, False):
            with self.subTest(stream=stream):
                with mock.patch.object(devinx, 'compact_body', side_effect=lambda b: b):
                    self.hang_up('/v1/messages', {
                        'model': 'swe-2-max', 'stream': stream, 'max_tokens': 16,
                        'messages': [{'role': 'user', 'content': 'hi'}]})

    def test_responses_route(self):
        with mock.patch.object(devinx, 'compact_body', side_effect=lambda b: b):
            self.hang_up('/v1/responses', {
                'model': 'swe-2-max', 'stream': True,
                'input': [{'type': 'message', 'role': 'user', 'content': 'hi'}]})

    def test_during_the_summary(self):
        messages = [{'role': 'user', 'content': 'task'}]
        for i in range(12):
            messages.append({'role': 'assistant' if i % 2 == 0 else 'user',
                             'content': f'turn {i} ' + 'y' * 400})
        with mock.patch.object(devinx, 'COMPACT_AT', 400):
            self.hang_up('/v1/messages', {
                'model': 'swe-2-max', 'stream': True, 'max_tokens': 16,
                'metadata': {'user_id': 'gone-in-summary'}, 'messages': messages})
        self.assertEqual(set(self.calls), {'summary'},
                         'the turn went upstream after its client left')


class SweCapacityTests(unittest.TestCase):
    """P2: held SWE-2 turns must not starve the main session's relays."""

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.release = threading.Event()
        self.entered = threading.Semaphore(0)

        def chat(req, acct=None, purpose='turn'):
            self.entered.release()
            self.release.wait(10)
            yield frame('done', stop=1), None

        relayed = mock.Mock(status_code=200, headers={'content-type': 'application/json'})
        relayed.raw.stream.return_value = iter([b'{"relayed": true}'])
        self.stack.enter_context(isolated_accounts(fake_accounts('a')))
        for name, value in {'MAX_INFLIGHT': 2, 'MAX_SWE_INFLIGHT': 2,
                            'KEEPALIVE_EVERY': 0, 'chat_stream': chat,
                            '_inflight': {'n': 0, 'swe': 0},
                            '_active_requests': {}}.items():
            self.stack.enter_context(mock.patch.object(devinx, name, value))
        self.stack.enter_context(mock.patch.object(devinx, 'compact_body', side_effect=lambda b: b))
        self.stack.enter_context(mock.patch.object(devinx, 'build_request', return_value=(
            SimpleNamespace(cascade_id='test'), 'swe-2-max')))
        self.stack.enter_context(mock.patch.object(
            devinx, 'paced', return_value=contextlib.nullcontext()))
        self.relay = self.stack.enter_context(
            mock.patch.object(devinx.SESSION, 'request', return_value=relayed))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.live = LiveServer()
        self.stack.callback(self.live.close)
        self.stack.callback(self.release.set)

    def post(self, body, headers=None, path='/v1/messages'):
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', self.live.port, timeout=10)
        try:
            conn.request('POST', path, body=json.dumps(body),
                         headers=dict({'content-type': 'application/json'}, **(headers or {})))
            r = conn.getresponse()
            return r.status, r.read()
        finally:
            conn.close()

    def test_relays_and_count_tokens_are_served_while_swe_turns_are_held(self):
        swe = {'model': 'swe-2-max', 'max_tokens': 8,
               'messages': [{'role': 'user', 'content': 'hi'}]}
        results = []
        held = [threading.Thread(target=lambda: results.append(self.post(swe)))
                for _ in range(2)]
        for t in held:
            t.start()
        for _ in held:
            self.assertTrue(self.entered.acquire(timeout=5))
        # Every SWE-2 slot is taken: a third SWE-2 turn is refused ...
        self.assertEqual(self.post(swe)[0], 503)
        # ... and the main session is not.
        claude = {'model': 'claude-opus-5', 'max_tokens': 8,
                  'messages': [{'role': 'user', 'content': 'hi'}]}
        for _ in range(3):
            status, raw = self.post(claude, {'Authorization': 'Bearer test'})
            self.assertEqual(status, 200, raw)
        self.assertEqual(self.post(swe, path='/v1/messages/count_tokens')[0], 200)
        # The last reply can reach the client a moment before its handler
        # gives its slot back.
        deadline = time.time() + 2
        while devinx._inflight['n'] > 2 and time.time() < deadline:
            time.sleep(0.02)
        with devinx._inflight_lock:
            self.assertEqual(devinx._inflight, {'n': 2, 'swe': 2},
                             'a drain would not see the held turns')
        self.release.set()
        for t in held:
            t.join(5)
        self.assertEqual([s for s, _ in results], [200, 200])
        deadline = time.time() + 2
        while devinx._inflight['n'] and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(devinx._inflight, {'n': 0, 'swe': 0})

    def test_the_general_cap_still_bounds_everything_else(self):
        with mock.patch.object(devinx, '_request_local', threading.local()):
            self.assertTrue(devinx._enter_request())
            self.assertTrue(devinx._enter_swe())
            first = devinx._request_local.key
            devinx._request_local.key = None
            self.assertTrue(devinx._enter_request())
            self.assertTrue(devinx._enter_request())
            self.assertFalse(devinx._enter_request(), 'general cap not applied')
            devinx._request_local.key = first
            devinx._leave_request()
        self.assertEqual(devinx._inflight['swe'], 0)


class CredentialFiles:
    """Temporary credentials.toml files, the only ones devinx gets to see."""

    def __init__(self, test):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.paths = []
        env = {k: v for k, v in os.environ.items()
               if k not in ('DEVINX_API_KEYS', 'DEVINX_API_KEY')}
        for patcher in (mock.patch.object(devinx, '_accounts', []),
                        mock.patch.object(devinx, '_jwt_locks', {}),
                        mock.patch.object(devinx, '_credential_files',
                                          lambda: [str(p) for p in self.paths]),
                        mock.patch.dict(os.environ, env, clear=True)):
            patcher.start()
            test.addCleanup(patcher.stop)

    def write(self, name, text):
        path = self.root / name / 'devin' / 'credentials.toml'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        if path not in self.paths:
            self.paths.append(path)
        return path


class ReadKeyTests(unittest.TestCase):
    """P10: any valid TOML quoting, and one bad file never breaks the rest."""

    def setUp(self):
        self.files = CredentialFiles(self)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    CASES = [
        ('windsurf_api_key = "double"\n', 'double'),
        ("windsurf_api_key = 'single'\n", 'single'),
        ('other = 1\nwindsurf_api_key="tight"\n', 'tight'),
        ('[auth]\nwindsurf_api_key = "nested"\n', 'nested'),
        ('windsurf_api_key = \'broken\'\nthis is = = not toml\n', 'broken'),
    ]

    def test_every_quoting_style_with_and_without_a_toml_parser(self):
        for parser in (devinx.tomllib, None):
            for text, expected in self.CASES:
                with self.subTest(parser=bool(parser), text=text), \
                     mock.patch.object(devinx, 'tomllib', parser):
                    path = self.files.write('case', text)
                    self.assertEqual(devinx._read_key(str(path)), expected)

    def test_unreadable_files_give_none(self):
        path = self.files.write('empty', 'nothing = "here"\n')
        self.assertIsNone(devinx._read_key(str(path)))
        (self.files.root / 'bin').write_bytes(b'\xff\xfe\x00windsurf')
        self.assertIsNone(devinx._read_key(str(self.files.root / 'bin')))
        self.assertIsNone(devinx._read_key(str(self.files.root / 'missing')))

    def test_one_bad_file_does_not_break_the_others(self):
        self.files.write('bad', 'windsurf_api_key = \n[[[\n')
        self.files.write('good', "windsurf_api_key = 'good-key'\n")
        loaded = devinx._load_accounts()
        self.assertEqual([a['name'] for a in loaded], ['good'])
        self.assertEqual(loaded[0]['key'], devinx.SESSION_PREFIX + 'good-key')
        with mock.patch.object(devinx, '_read_key', side_effect=[IndexError('x'), 'k2']):
            self.assertEqual(len(devinx._load_accounts()), 1)


class ReloadTests(unittest.TestCase):
    """P6 / P7 / P9: re-authentication without forgetting or blocking others."""

    def setUp(self):
        self.files = CredentialFiles(self)
        self.a = self.files.write('acct-a', 'windsurf_api_key = "old-a"\n')
        self.files.write('acct-b', 'windsurf_api_key = "key-b"\n')
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def test_reset_key_keeps_every_accounts_state_and_updates_in_place(self):
        a, b = devinx.accounts()
        now = time.time()
        devinx.block_account(b, 600)
        b_block, b_refused = b['blocked_until'], b['refused_at']
        a['pace'] = 'sentinel'
        a['jwt'], a['exp'] = 'stale.jwt', now + 3600
        self.a.write_text('windsurf_api_key = "new-a"\n')
        devinx.reset_key()
        a2, b2 = devinx.accounts()
        self.assertIs(a2, a, 'the caller holding the dict would retry stale')
        self.assertEqual(a['key'], devinx.SESSION_PREFIX + 'new-a')
        self.assertIsNone(a['jwt'], 'a JWT for the old key was kept')
        self.assertEqual(a['pace'], 'sentinel')
        self.assertIs(b2, b)
        self.assertEqual((b['blocked_until'], b['refused_at']), (b_block, b_refused))
        self.assertIsNone(devinx.claim_account(avoid=a)[0], 'b was unblocked')

    def test_a_reload_that_finds_nothing_keeps_the_current_accounts(self):
        before = devinx.accounts()
        for p in list(self.files.paths):
            p.unlink()
        devinx.reset_key()
        self.assertEqual(devinx.accounts(), before)

    def _auth_response(self, status, jwt=None):
        import requests
        r = mock.Mock(status_code=status)
        if status == 200:
            r.content = devinx.protos()['GetUserJwtResponse'](
                user_jwt=jwt).SerializeToString()
            r.raise_for_status.return_value = None
        else:
            r.raise_for_status.side_effect = requests.HTTPError(
                f'{status} Client Error', response=r)
        return r

    def _sent_key(self, call):
        req = devinx.protos()['GetUserJwtRequest']()
        req.ParseFromString(call.kwargs['data'])
        return req.metadata.api_key

    def _req(self):
        return SimpleNamespace(metadata=SimpleNamespace(), chat_message_prompts=[],
                               chat_model_uid='swe-2-max', cascade_id='test',
                               SerializeToString=lambda: b'test')

    def test_a_refused_jwt_reloads_and_retries_with_the_new_key(self):
        a, _ = devinx.accounts()
        self.a.write_text("windsurf_api_key = 'new-a'\n")
        chat = mock.Mock(status_code=500, text='stop here')
        responses = [self._auth_response(401), self._auth_response(200, 'x.eyJ9.y'), chat]
        with mock.patch.object(devinx.SESSION, 'post', side_effect=responses) as post:
            out = list(devinx.chat_stream(self._req(), a))
        self.assertEqual(out, [(None, 'upstream 500: stop here')])
        auth = [c for c in post.call_args_list if c.args[0].endswith(devinx.AUTH_PATH)]
        self.assertEqual([self._sent_key(c) for c in auth],
                         [devinx.SESSION_PREFIX + 'old-a', devinx.SESSION_PREFIX + 'new-a'])

    def test_a_persistent_jwt_refusal_is_an_authentication_error(self):
        a, _ = devinx.accounts()
        with mock.patch.object(devinx.SESSION, 'post', side_effect=[
                self._auth_response(401), self._auth_response(403)]) as post:
            out = list(devinx.chat_stream(self._req(), a))
        self.assertEqual(post.call_count, 2, 'the chat endpoint was called anyway')
        (msg, err), = out
        self.assertIsNone(msg)
        self.assertEqual(devinx.anthropic_error(err)[:2], ('authentication_error', 401))

    def test_a_persistent_chat_refusal_is_an_authentication_error(self):
        a, _ = devinx.accounts()
        refused = mock.Mock(status_code=401, text='expired')
        with mock.patch.object(devinx, 'get_jwt', return_value=('jwt', None)), \
             mock.patch.object(devinx.SESSION, 'post', side_effect=[refused, refused]):
            (_, err), = list(devinx.chat_stream(self._req(), a))
        self.assertEqual(devinx.anthropic_error(err)[:2], ('authentication_error', 401))

    def test_a_slow_auth_call_for_one_account_does_not_hold_another(self):
        a, b = devinx.accounts()
        gate, entered = threading.Event(), threading.Event()
        fast = self._auth_response(200, 'x.eyJ9.y')

        def post(url, data=None, **kwargs):
            req = devinx.protos()['GetUserJwtRequest']()
            req.ParseFromString(data)
            if req.metadata.api_key == a['key']:
                entered.set()
                gate.wait(5)
            return fast

        with mock.patch.object(devinx.SESSION, 'post', side_effect=post):
            slow = threading.Thread(target=devinx.get_jwt, args=(a,))
            slow.start()
            self.assertTrue(entered.wait(3))
            t0 = time.time()
            self.assertEqual(devinx.get_jwt(b)[0], 'x.eyJ9.y')
            self.assertLess(time.time() - t0, 1, 'b waited behind a')
            gate.set()
            slow.join(5)


class DocumentBlockTests(unittest.TestCase):
    """P11: a document is carried as text when it is text, and never lost silently."""

    PDF = {'type': 'document', 'title': 'spec.pdf', 'source': {
        'type': 'base64', 'media_type': 'application/pdf', 'data': 'JVBERi0x'}}
    TXT = {'type': 'document', 'source': {
        'type': 'text', 'media_type': 'text/plain', 'data': 'PLAIN-DOC-TEXT'}}

    def build(self, messages):
        log = io.StringIO()
        with mock.patch.object(devinx, 'api_key', return_value='test-only'), \
             contextlib.redirect_stdout(log):
            req, _ = devinx.build_request({'model': 'swe-2-max', 'messages': messages})
        return req, log.getvalue()

    def test_documents_inside_a_tool_result(self):
        req, log = self.build([
            {'role': 'user', 'content': 'read it'},
            {'role': 'assistant', 'content': [
                {'type': 'tool_use', 'id': 't1', 'name': 'Read', 'input': {}}]},
            {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': 't1',
                                          'content': [{'type': 'text', 'text': 'head'},
                                                      self.PDF, self.TXT]}]}])
        tool = [p for p in req.chat_message_prompts if p.tool_call_id == 't1'][0]
        self.assertIn('head', tool.prompt)
        self.assertIn('PLAIN-DOC-TEXT', tool.prompt)
        self.assertIn("[document 'spec.pdf' (application/pdf) omitted", tool.prompt)
        self.assertNotIn('JVBERi0x', str(req))
        self.assertIn('dropped unsupported content blocks: document/base64', log)

    def test_top_level_text_document_is_carried(self):
        req, log = self.build([{'role': 'user', 'content': [
            {'type': 'text', 'text': 'see attached '}, self.TXT, self.PDF]}])
        self.assertIn('PLAIN-DOC-TEXT', req.chat_message_prompts[0].prompt)
        self.assertIn('omitted', req.chat_message_prompts[0].prompt)
        self.assertIn('document/base64', log)

    def test_text_only_results_are_unchanged(self):
        block = {'type': 'tool_result', 'tool_use_id': 't',
                 'content': [{'type': 'text', 'text': 'a'}, {'type': 'text', 'text': 'b'}]}
        self.assertEqual(devinx._tool_result_text(block), 'ab')

    def test_a_text_document_counts_toward_the_estimate(self):
        body = {'messages': [{'role': 'user', 'content': [
            {'type': 'document', 'source': {'type': 'text', 'data': 'x' * 40000}}]}]}
        self.assertGreater(devinx.estimate_tokens(body), 9000)


class SharedKeySummaryTests(unittest.TestCase):
    """P12: two runs sharing a conversation key keep a summary each."""

    @staticmethod
    def run_body(tag, turns):
        messages = [{'role': 'user', 'content': 'Same first task.'}]
        for i in range(turns):
            messages.append({'role': 'assistant', 'content': f'{tag} step {i}: ' + 'x' * 600})
            messages.append({'role': 'user', 'content': [
                {'type': 'tool_result', 'tool_use_id': f'{tag}{i}', 'content': 'y' * 600}]})
        messages.append({'role': 'assistant', 'content': f'{tag} continues.'})
        return {'model': 'swe-2-max', 'system': 'same agent',
                'metadata': {'user_id': 'same-session'}, 'messages': messages}

    def test_parallel_runs_do_not_rebuild_each_others_summary(self):
        calls = []

        def summarise(messages, model, system, previous=None, never_empty=True):
            calls.append(previous)
            return f'summary {len(calls)}'

        self.assertEqual(devinx._conv_key(self.run_body('A', 10)),
                         devinx._conv_key(self.run_body('B', 10)))
        log = io.StringIO()
        with mock.patch.object(devinx, '_summaries', {}), \
             mock.patch.object(devinx, '_summary_flights', {}), \
             mock.patch.object(devinx, 'COMPACT_AT', 1200), \
             mock.patch.object(devinx, 'COMPACT_STRICT', False), \
             mock.patch.object(devinx, 'summarise_turns', side_effect=summarise), \
             contextlib.redirect_stdout(log):
            devinx.compact_body(self.run_body('A', 10))
            devinx.compact_body(self.run_body('B', 10))
            first_round = len(calls)
            for turns in (14, 18):
                for tag in ('A', 'B'):
                    out = devinx.compact_body(self.run_body(tag, turns))
                    other = 'B' if tag == 'A' else 'A'
                    self.assertNotIn(f'{other} step', json.dumps(out['messages'][1]))
        self.assertEqual(first_round, 2)
        self.assertGreater(len(calls), first_round, 'the fixture never grew')
        self.assertTrue(all(p is not None for p in calls[first_round:]),
                        f'a run rebuilt its summary from scratch: {calls}')
        # Only B's first compaction found nothing of its own (A's was there).
        self.assertEqual(log.getvalue().count('none of the'), 1)

    def test_cascade_id_stays_stable_for_one_agent(self):
        with mock.patch.object(devinx, 'api_key', return_value='test-only'):
            a = devinx.build_request(self.run_body('A', 3))[0].cascade_id
            b = devinx.build_request(self.run_body('A', 9))[0].cascade_id
        self.assertEqual(a, b)


if __name__ == '__main__':
    unittest.main(verbosity=2)
