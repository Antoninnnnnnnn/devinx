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
                self.send_response(outer.status)
                self.send_header('content-type', 'application/json')
                self.send_header('content-length', str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args):
                pass

        self.status, self.body = status, body
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


if __name__ == '__main__':
    unittest.main()
