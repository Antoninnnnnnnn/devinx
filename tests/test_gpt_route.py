"""The gpt-* route: Claude Code on a GPT model, through the claude-code-proxy
sidecar. Hermetic: the sidecar is a fake upstream on an ephemeral loopback
port, and nothing reaches a real service.
"""
import http.client
import http.server
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import devinx
from test_audit_fixes import LiveServer


class FakeSidecar:
    """Records what reached it and answers with a canned status and body."""

    def __init__(self, status=200, body=b'{"type":"message"}'):
        self.seen = []
        outer = self

        class Echo(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get('content-length') or 0)
                outer.seen.append({'path': self.path,
                                   'headers': {k.lower(): v for k, v in self.headers.items()},
                                   'body': json.loads(self.rfile.read(length) or b'{}')})
                status, body = outer.status, outer.body
                if outer.answer is not None:
                    status, body = outer.answer(outer.seen[-1]['body'])
                self.send_response(status)
                self.send_header('content-type', 'application/json')
                self.send_header('content-length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.status, self.body, self.answer = status, body, None
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Echo)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def post(port, path, body, headers=()):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        raw = json.dumps(body).encode()
        conn.request('POST', path, body=raw, headers={
            'content-type': 'application/json', **dict(headers)})
        r = conn.getresponse()
        return r.status, json.loads(r.read() or b'{}')
    finally:
        conn.close()


GPT_BODY = {'model': 'gpt-6-luna', 'max_tokens': 8,
            'messages': [{'role': 'user', 'content': 'hi'}]}


class GptRouteTests(unittest.TestCase):

    def setUp(self):
        self.sidecar = FakeSidecar()
        self.addCleanup(self.sidecar.close)
        patcher = mock.patch.object(devinx, 'GPT_UPSTREAM', self.sidecar.url)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.live = LiveServer()
        self.addCleanup(self.live.close)

    def test_claude_credential_never_reaches_the_sidecar(self):
        status, _ = post(self.live.port, '/v1/messages?beta=true', GPT_BODY, {
            'AUTHORIZATION': 'Bearer claude-secret', 'X-Api-Key': 'sk-ant-secret',
            'Cookie': 'session=secret', 'Proxy-Authorization': 'Basic x',
            'x-claude-code-session-id': 'sid-1'})
        self.assertEqual(status, 200)
        (seen,) = self.sidecar.seen
        self.assertEqual(seen['path'], '/v1/messages?beta=true')
        for secret in ('authorization', 'x-api-key', 'cookie', 'proxy-authorization'):
            self.assertNotIn(secret, seen['headers'])
        # The session id is what the sidecar keys its prompt cache on.
        self.assertEqual(seen['headers']['x-claude-code-session-id'], 'sid-1')

    def test_count_tokens_goes_to_the_sidecar(self):
        status, _ = post(self.live.port, '/v1/messages/count_tokens', GPT_BODY)
        self.assertEqual(status, 200)
        self.assertEqual(self.sidecar.seen[0]['path'], '/v1/messages/count_tokens')

    def test_browser_requests_are_refused(self):
        for headers in ({'Origin': 'https://evil.example'},
                        {'Host': 'evil.example:8316'}):
            with self.subTest(headers=headers):
                status, body = post(self.live.port, '/v1/messages', GPT_BODY, headers)
                self.assertEqual(status, 403)
                self.assertEqual(body['error']['type'], 'permission_error')
        self.assertEqual(self.sidecar.seen, [])

    def test_responses_path_is_codex_not_the_sidecar(self):
        status, _ = post(self.live.port, '/v1/responses', {'model': 'gpt-6-sol'})
        self.assertEqual(status, 401)
        self.assertEqual(self.sidecar.seen, [])

    def test_models_lists_gpt_after_swe(self):
        status, body = self.live.get('/v1/models', {})
        self.assertEqual(status, 200)
        ids = [m['id'] for m in body['data']]
        self.assertEqual(body['first_id'], 'swe-2')
        for mid, _ in devinx.GPT_MODELS:
            self.assertIn(mid, ids)

    def test_sidecar_down_is_a_502(self):
        self.sidecar.close()
        status, body = post(self.live.port, '/v1/messages', GPT_BODY)
        self.assertEqual(status, 502)
        self.assertEqual(body['error']['type'], 'api_error')

    def test_sidecar_login_missing_does_not_look_like_claude_login(self):
        self.sidecar.status = 401
        self.sidecar.body = b'{"type":"error","error":{"type":"authentication_error"}}'
        status, body = post(self.live.port, '/v1/messages', GPT_BODY)
        self.assertEqual(status, 503)
        self.assertIn('claude-code-proxy codex auth login', body['error']['message'])

    def test_context_overflow_carries_the_figures_the_client_parses(self):
        self.sidecar.status = 413
        self.sidecar.body = b'{"type":"error","error":{"type":"request_too_large",' \
                            b'"message":"input exceeds the context window"}}'
        status, body = post(self.live.port, '/v1/messages', GPT_BODY)
        self.assertEqual(status, 400)
        self.assertRegex(body['error']['message'],
                         r'prompt is too long[^0-9]*\d+ tokens? > 272000')

    def test_other_errors_pass_through(self):
        self.sidecar.status = 429
        self.sidecar.body = b'{"type":"error","error":{"type":"rate_limit_error"}}'
        status, body = post(self.live.port, '/v1/messages', GPT_BODY)
        self.assertEqual(status, 429)
        self.assertEqual(body['error']['type'], 'rate_limit_error')


def long_history(turns=12, size=4000):
    msgs = [{'role': 'user', 'content': 'the task: fix the parser'}]
    for i in range(turns):
        msgs.append({'role': 'assistant', 'content': [
            {'type': 'tool_use', 'id': f'call_{i}', 'name': 'Read',
             'input': {'file_path': f'/src/f{i}.py'}}]})
        msgs.append({'role': 'user', 'content': [
            {'type': 'tool_result', 'tool_use_id': f'call_{i}',
             'content': f'contents {i} ' + 'x' * size}]})
    msgs.append({'role': 'assistant', 'content': [{'type': 'text', 'text': 'reading'}]})
    msgs.append({'role': 'user', 'content': 'continue'})
    return {'model': 'gpt-6.1-sol', 'max_tokens': 8, 'stream': True,
            'messages': msgs}


def summariser(delay=0.0):
    """The fake sidecar: a summary for the summary request, a turn otherwise."""
    def answer(body):
        text = json.dumps(body)
        if '<conversation>' in text:
            import time
            time.sleep(delay)
            return 200, json.dumps({'type': 'message', 'content': [
                {'type': 'text', 'text': 'SUMMARY: read f0..f9, parser bug in f3'}]}).encode()
        return 200, b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    return answer


class GptCompactionBase(unittest.TestCase):

    def setUp(self):
        self.sidecar = FakeSidecar()
        self.sidecar.answer = summariser()
        self.addCleanup(self.sidecar.close)
        for name, value in (('GPT_UPSTREAM', self.sidecar.url),
                            ('GPT_COMPACT_AT', 6000)):
            patcher = mock.patch.object(devinx, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        devinx._summaries.clear()
        self.live = LiveServer()
        self.addCleanup(self.live.close)

    def send(self, body, agent=True):
        headers = {'content-type': 'application/json',
                   'x-claude-code-session-id': 'sid'}
        if agent:
            headers['x-claude-code-agent-id'] = 'agent-1'
        conn = http.client.HTTPConnection('127.0.0.1', self.live.port, timeout=30)
        try:
            conn.request('POST', '/v1/messages', body=json.dumps(body).encode(),
                         headers=headers)
            r = conn.getresponse()
            return r.status, r.read()
        finally:
            conn.close()


class GptCompactionTests(GptCompactionBase):

    def test_subagent_is_compacted_by_gpt(self):
        status, _ = self.send(long_history())
        self.assertEqual(status, 200)
        summary_call, turn = self.sidecar.seen
        # The summary was written by GPT, on the agent's own model.
        self.assertIn('<conversation>', json.dumps(summary_call['body']))
        self.assertEqual(summary_call['body']['model'], 'gpt-6.1-sol')
        sent = turn['body']
        self.assertLess(devinx.estimate_tokens(sent), 6000)
        self.assertEqual(sent['messages'][0]['content'], 'the task: fix the parser')
        self.assertIn('SUMMARY: read f0..f9', json.dumps(sent['messages'][1]))
        self.assertEqual(sent['messages'][-1]['content'], 'continue')

    def test_next_turn_reuses_the_summary(self):
        body = long_history()
        self.send(body)
        body['messages'] += [
            {'role': 'assistant', 'content': [{'type': 'text', 'text': 'ok'}]},
            {'role': 'user', 'content': 'go on'}]
        self.send(body)
        summaries = [c for c in self.sidecar.seen
                     if '<conversation>' in json.dumps(c['body'])]
        self.assertEqual(len(summaries), 1)

    def test_main_session_is_left_to_compact_itself(self):
        self.send(long_history(), agent=False)
        (turn,) = self.sidecar.seen
        self.assertEqual(len(turn['body']['messages']), len(long_history()['messages']))

    def test_small_subagent_turn_is_relayed_byte_for_byte(self):
        self.send(GPT_BODY)
        (turn,) = self.sidecar.seen
        self.assertEqual(turn['body'], GPT_BODY)

    def test_slow_summary_keeps_the_stream_alive(self):
        self.sidecar.answer = summariser(delay=2.5)
        with mock.patch.object(devinx, 'KEEPALIVE_EVERY', 1):
            status, raw = self.send(long_history())
        self.assertEqual(status, 200)
        self.assertTrue(raw.startswith(b': devinx compacting'))
        self.assertIn(b'message_stop', raw)

    def test_error_after_keepalive_is_an_sse_error(self):
        slow = summariser(delay=2.5)

        def answer(body):
            if '<conversation>' in json.dumps(body):
                return slow(body)
            return 429, b'{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}'
        self.sidecar.answer = answer
        with mock.patch.object(devinx, 'KEEPALIVE_EVERY', 1):
            status, raw = self.send(long_history())
        self.assertEqual(status, 200)
        self.assertIn(b'event: error', raw)
        self.assertIn(b'rate_limit_error', raw)


class CodexRuleTests(GptCompactionBase):
    """Compaction decided the way Codex decides it: on the server's counts."""

    def setUp(self):
        super().setUp()
        devinx._gpt_usage.clear()

    def test_reported_usage_triggers_compaction_the_estimate_would_miss(self):
        def answer(body):
            if '<conversation>' in json.dumps(body):
                return summariser()(body)
            # The server counts far more than the estimate does.
            return 200, (b'event: message_delta\ndata: {"type":"message_delta",'
                         b'"usage":{"input_tokens":5900,"output_tokens":50}}\n\n')
        self.sidecar.answer = answer
        body = long_history(turns=4, size=1000)
        self.assertLess(devinx.estimate_tokens(body), 6000)
        self.send(body)
        self.assertEqual(len(self.sidecar.seen), 1)
        body['messages'] += [
            {'role': 'assistant', 'content': [{'type': 'text', 'text': 'more'}]},
            {'role': 'user', 'content': 'x' * 400}]
        self.send(body)
        summaries = [c for c in self.sidecar.seen
                     if '<conversation>' in json.dumps(c['body'])]
        self.assertEqual(len(summaries), 1)

    def test_context_refusal_is_retried_compacted_not_passed_on(self):
        refused = []

        def answer(body):
            text = json.dumps(body)
            if '<conversation>' in text:
                return summariser()(body)
            if not refused:
                refused.append(len(text))
                return 413, (b'{"type":"error","error":{"type":"request_too_large",'
                             b'"message":"exceeds the context window"}}')
            return 200, b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
        self.sidecar.answer = answer
        body = long_history(turns=4, size=1000)
        status, raw = self.send(body)
        self.assertEqual(status, 200)
        self.assertIn(b'message_stop', raw)
        turns = [c for c in self.sidecar.seen
                 if '<conversation>' not in json.dumps(c['body'])]
        self.assertEqual(len(turns), 2)
        self.assertLess(len(json.dumps(turns[1]['body'])), refused[0])

    def test_main_session_refusal_is_passed_on(self):
        self.sidecar.answer = lambda body: (413, b'{"type":"error","error":'
            b'{"type":"request_too_large","message":"exceeds the context window"}}')
        status, raw = self.send(long_history(turns=4, size=1000), agent=False)
        self.assertEqual(status, 400)
        self.assertIn(b'prompt is too long', raw)


class UsageSnifferTests(unittest.TestCase):

    def test_split_lines_and_final_counts(self):
        sniff = devinx.UsageSniffer()
        stream = (b'event: message_start\ndata: {"type":"message_start","message":'
                  b'{"usage":{"input_tokens":100,"cache_read_input_tokens":900}}}\n\n'
                  b'event: message_delta\ndata: {"type":"message_delta","usage":'
                  b'{"input_tokens":120,"output_tokens":30}}\n\n')
        for i in range(0, len(stream), 7):
            sniff.feed(stream[i:i + 7])
        self.assertEqual(sniff.total, 120 + 900 + 30)


def gpt_turn(tool=True):
    content = [{'type': 'thinking', 'thinking': 'plan',
                'signature': 'ccp:codex:v1:opaque'}]
    if tool:
        content.append({'type': 'tool_use', 'id': 'call_1', 'name': 'Read',
                        'input': {}})
    else:
        content.append({'type': 'text', 'text': 'done'})
    return {'role': 'assistant', 'content': content}


class ForeignThinkingTests(unittest.TestCase):

    def test_untouched_without_gpt_thinking(self):
        body = {'thinking': {'type': 'enabled'}, 'messages': [
            {'role': 'user', 'content': 'hi'},
            {'role': 'assistant', 'content': [
                {'type': 'thinking', 'thinking': 'x', 'signature': 'EqQBanthropic'},
                {'type': 'text', 'text': 'ok'}]}]}
        before = json.dumps(body)
        self.assertFalse(devinx.strip_foreign_thinking(body))
        self.assertEqual(json.dumps(body), before)

    def test_claude_route_drops_the_block_and_thinking_for_a_tool_turn(self):
        body = {'thinking': {'type': 'enabled'}, 'messages': [
            {'role': 'user', 'content': 'hi'}, gpt_turn(tool=True),
            {'role': 'user', 'content': [
                {'type': 'tool_result', 'tool_use_id': 'call_1', 'content': 'x'}]}]}
        self.assertTrue(devinx.strip_foreign_thinking(body))
        self.assertEqual([b['type'] for b in body['messages'][1]['content']],
                         ['tool_use'])
        self.assertNotIn('thinking', body)

    def test_earlier_turns_keep_thinking_on(self):
        body = {'thinking': {'type': 'enabled'}, 'messages': [
            {'role': 'user', 'content': 'hi'}, gpt_turn(tool=False),
            {'role': 'user', 'content': 'next'},
            {'role': 'assistant', 'content': [{'type': 'text', 'text': 'claude'}]},
            {'role': 'user', 'content': 'again'}]}
        self.assertTrue(devinx.strip_foreign_thinking(body))
        self.assertEqual(body['messages'][1]['content'],
                         [{'type': 'text', 'text': 'done'}])
        self.assertIn('thinking', body)

    def test_swe_route_keeps_the_text_without_the_signature(self):
        body = {'messages': [{'role': 'user', 'content': 'hi'}, gpt_turn()]}
        self.assertTrue(devinx.strip_foreign_thinking(body, keep_text=True))
        block = body['messages'][1]['content'][0]
        self.assertEqual(block, {'type': 'thinking', 'thinking': 'plan'})


class PickerSettingsTests(unittest.TestCase):

    def test_rows_effort_and_window(self):
        import launcher
        flag, raw = launcher.picker_settings([])
        self.assertEqual(flag, '--settings')
        settings = json.loads(raw)
        rows = settings['modelPicker']['options']
        self.assertEqual([r['label'] for r in rows], ['Sol', 'Astra', 'Luna'])
        for row in rows:
            self.assertEqual(row['behavesAs'], 'claude-opus-5-5')
            # Claude Code compacts its 33k buffer short of the window: there,
            # Codex's 90% of 272k.
            self.assertEqual(
                settings['modelSettings'][row['model']]['autoCompactWindow'] - 33000,
                devinx.GPT_COMPACT_AT)

    def test_the_users_own_settings_win(self):
        import launcher
        import io
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()):
            self.assertEqual(launcher.picker_settings(['--settings', '{}']), [])
            self.assertEqual(launcher.picker_settings(['--settings={}']), [])


class AgentEffortTests(unittest.TestCase):

    def test_every_gpt_model_at_every_effort_but_low(self):
        import launcher
        agents = launcher.packaged_agents()
        for short, model in (('sol', 'gpt-6.1-sol'), ('astra', 'gpt-6-astra'),
                             ('luna', 'gpt-6-luna')):
            self.assertNotIn(f'gpt-{short}-low', agents)
            for effort in ('medium', 'high', 'xhigh', 'max'):
                agent = agents[f'gpt-{short}-{effort}']
                self.assertEqual((agent['model'], agent['effort']), (model, effort))
                self.assertEqual(agent['disallowedTools'], ['mcp__*'])

    def test_low_effort_runs_as_medium(self):
        body = {'output_config': {'effort': 'low'}}
        self.assertTrue(devinx.gpt_raise_low_effort(body))
        self.assertEqual(body['output_config']['effort'], 'medium')
        for effort in ('medium', 'high', 'xhigh', 'max'):
            body = {'output_config': {'effort': effort}}
            self.assertFalse(devinx.gpt_raise_low_effort(body))
        self.assertFalse(devinx.gpt_raise_low_effort({}))

if __name__ == '__main__':
    unittest.main()
