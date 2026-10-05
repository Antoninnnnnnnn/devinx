"""The advisor on the gpt-* route, and the narrowed ban on report files.

Hermetic: the sidecar is a fake upstream on an ephemeral loopback port. It
answers a streamed turn with SSE and the advisor model's call with plain JSON,
telling the two apart by the advisor system prompt.
"""
import copy
import http.client
import http.server
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import devinx
from test_audit_fixes import LiveServer

ADVISOR_TOOL = {'type': 'advisor_20260301', 'name': 'advisor',
                'model': 'claude-opus-5-5', 'defer_loading': True}
BASH_TOOL = {'name': 'Bash', 'description': 'run',
             'input_schema': {'type': 'object', 'properties': {}}}


def turn_events(blocks, stop='end_turn', output=7):
    """The SSE the sidecar sends for one assistant turn."""
    events = [{'type': 'message_start', 'message': {
        'id': 'msg_1', 'type': 'message', 'role': 'assistant', 'content': [],
        'model': 'gpt-6.1-sol', 'usage': {'input_tokens': 100,
                                          'output_tokens': 1}}}]
    for i, block in enumerate(blocks):
        kind = block['type']
        start = dict(block)
        if kind == 'text':
            start['text'] = ''
        elif kind == 'tool_use':
            start['input'] = {}
        events.append({'type': 'content_block_start', 'index': i,
                       'content_block': start})
        if kind == 'text':
            delta = {'type': 'text_delta', 'text': block['text']}
        elif kind == 'tool_use':
            delta = {'type': 'input_json_delta',
                     'partial_json': json.dumps(block['input'])}
        else:
            delta = None
        if delta:
            events.append({'type': 'content_block_delta', 'index': i,
                           'delta': delta})
        events.append({'type': 'content_block_stop', 'index': i})
    events.append({'type': 'message_delta', 'delta': {'stop_reason': stop},
                   'usage': {'output_tokens': output}})
    events.append({'type': 'message_stop'})
    return ''.join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n"
                   for e in events).encode()


def text(s):
    return {'type': 'text', 'text': s}


def call(name, args=None, id='call_1'):
    return {'type': 'tool_use', 'id': id, 'name': name, 'input': args or {}}


class FakeSidecar:
    """Records requests; `turns(body)` answers a turn, `advice(body)` the
    advisor model."""

    def __init__(self):
        self.seen = []
        self.raw = []
        self.headers = []
        self.turns = lambda body: turn_events([text('ok')])
        self.advice = lambda body: (200, json.dumps({'content': [
            {'type': 'text', 'text': 'ADVICE: check the tests first.'}]}).encode())
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get('content-length') or 0))
                body = json.loads(raw or b'{}')
                outer.raw.append(raw)
                outer.headers.append({k.lower(): v for k, v in self.headers.items()})
                outer.seen.append(body)
                if body.get('system') == devinx.GPT_ADVISOR_SYSTEM:
                    status, payload = outer.advice(body)
                    ctype = 'application/json'
                else:
                    status, payload = 200, outer.turns(body)
                    ctype = 'text/event-stream'
                    if isinstance(payload, tuple):
                        status, payload = payload
                        ctype = 'application/json'
                self.send_response(status)
                self.send_header('content-type', ctype)
                self.send_header('content-length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'

    def advisor_calls(self):
        return [b for b in self.seen
                if b.get('system') == devinx.GPT_ADVISOR_SYSTEM]

    def turn_calls(self):
        return [b for b in self.seen
                if b.get('system') != devinx.GPT_ADVISOR_SYSTEM]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def parse_stream(raw):
    return [e for _, e in devinx.sse_events([raw]) if e]


def request(tools=(ADVISOR_TOOL,), stream=True, extra=()):
    return {'model': 'gpt-6.1-sol', 'max_tokens': 100, 'stream': stream,
            'tools': [copy.deepcopy(t) for t in tools],
            'messages': [{'role': 'user', 'content': 'fix the parser'}, *extra]}


class AdvisorBase(unittest.TestCase):
    MAX_CALLS = 3          # the feature is off by default; these tests turn it on

    def setUp(self):
        self.sidecar = FakeSidecar()
        self.addCleanup(self.sidecar.close)
        for name, value in (('GPT_UPSTREAM', self.sidecar.url),
                            ('GPT_ADVISOR_MAX_CALLS', self.MAX_CALLS)):
            patcher = mock.patch.object(devinx, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.live = LiveServer()
        self.addCleanup(self.live.close)

    def send(self, body, agent=True):
        headers = {'content-type': 'application/json'}
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

    @staticmethod
    def two_legs(first, second):
        """A sidecar that says `first` while it still has the advisor tool to
        call, and `second` once the advice is in the history."""
        def turns(body):
            if any(b.get('type') == 'tool_result' for m in body['messages']
                   if isinstance(m.get('content'), list)
                   for b in m['content']):
                return turn_events(*second)
            return turn_events(*first)
        return turns


class AdvisorFlowTests(AdvisorBase):

    def test_the_advisor_is_answered_and_the_turn_continues_in_one_message(self):
        self.sidecar.turns = self.two_legs(
            ([text('let me check'), call('advisor', id='call_a')], 'tool_use'),
            ([text('done')], 'end_turn'))
        status, raw = self.send(request())
        self.assertEqual(status, 200)
        events = parse_stream(raw)
        kinds = [e['type'] for e in events]
        self.assertEqual(kinds.count('message_start'), 1)
        self.assertEqual(kinds.count('message_stop'), 1)
        starts = [(e['index'], e['content_block']['type'])
                  for e in events if e['type'] == 'content_block_start']
        self.assertEqual(starts, [(0, 'text'), (1, 'server_tool_use'),
                                  (2, 'advisor_tool_result'), (3, 'text')])
        result = events[[e['type'] for e in events].index('content_block_start') + 0:]
        advice = next(e['content_block'] for e in events
                      if e['type'] == 'content_block_start'
                      and e['content_block']['type'] == 'advisor_tool_result')
        self.assertEqual(advice['content'], {
            'type': 'advisor_result', 'text': 'ADVICE: check the tests first.'})
        server = next(e['content_block'] for e in events
                      if e['type'] == 'content_block_start'
                      and e['content_block']['type'] == 'server_tool_use')
        self.assertEqual(advice['tool_use_id'], server['id'])
        self.assertTrue(server['id'].startswith('srvtoolu_'))
        # The advisor call never reaches the client as a tool_use.
        self.assertNotIn('tool_use', [s for _, s in starts])
        self.assertEqual(events[-2]['delta']['stop_reason'], 'end_turn')
        # Output tokens of both legs are counted.
        self.assertEqual(events[-2]['usage']['output_tokens'], 14)

    def test_the_advisor_model_sees_the_task_and_the_turn_and_has_no_tools(self):
        self.sidecar.turns = self.two_legs(
            ([text('let me check'), call('advisor', id='call_a')], 'tool_use'),
            ([text('done')], 'end_turn'))
        self.send(request())
        (asked,) = self.sidecar.advisor_calls()
        self.assertEqual(asked['model'], devinx.GPT_ADVISOR_MODEL)
        self.assertNotIn('tools', asked)
        prompt = json.dumps(asked['messages'])
        self.assertIn('fix the parser', prompt)
        self.assertIn('let me check', prompt)

    def test_the_advice_is_the_tool_result_of_the_next_leg(self):
        self.sidecar.turns = self.two_legs(
            ([text('let me check'), call('advisor', id='call_a')], 'tool_use'),
            ([text('done')], 'end_turn'))
        self.send(request())
        first, second = self.sidecar.turn_calls()
        self.assertEqual([t['name'] for t in first['tools']], ['advisor'])
        self.assertNotIn('type', first['tools'][0])
        assistant, user = second['messages'][-2:]
        self.assertEqual([b['type'] for b in assistant['content']],
                         ['text', 'tool_use'])
        self.assertEqual(assistant['content'][1]['id'], 'call_a')
        result = user['content'][0]
        self.assertEqual((result['type'], result['tool_use_id']),
                         ('tool_result', 'call_a'))
        self.assertIn('ADVICE: check the tests first.', result['content'])

    def test_thinking_of_the_asking_turn_survives_the_continuation(self):
        thinking = {'type': 'thinking', 'thinking': '', 'signature': 'sig-1'}
        self.sidecar.turns = self.two_legs(
            ([thinking, call('advisor', id='call_a')], 'tool_use'),
            ([text('done')], 'end_turn'))
        self.send(request())
        _, second = self.sidecar.turn_calls()
        self.assertEqual(second['messages'][-2]['content'][0]['signature'], 'sig-1')

    def test_other_tool_calls_beside_the_advisor_are_held_back_and_reported(self):
        self.sidecar.turns = self.two_legs(
            ([call('advisor', id='call_a'),
              call('Bash', {'command': 'ls'}, id='call_b')], 'tool_use'),
            ([call('Bash', {'command': 'ls'}, id='call_c')], 'tool_use'))
        status, raw = self.send(request(tools=(ADVISOR_TOOL, BASH_TOOL)))
        events = parse_stream(raw)
        calls = [e['content_block'] for e in events
                 if e['type'] == 'content_block_start'
                 and e['content_block']['type'] == 'tool_use']
        # Only the second leg's Bash call reached the client, once.
        self.assertEqual([(c['id'], c['name']) for c in calls],
                         [('call_c', 'Bash')])
        _, second = self.sidecar.turn_calls()
        assistant = second['messages'][-2]['content']
        self.assertEqual([b['id'] for b in assistant], ['call_a'])
        self.assertIn('were not run', second['messages'][-1]['content'][0]['content'])
        self.assertEqual(events[-2]['delta']['stop_reason'], 'tool_use')
        # The held call is sent whole: its arguments come with it.
        args = ''.join(e['delta']['partial_json'] for e in events
                       if e['type'] == 'content_block_delta')
        self.assertEqual(json.loads(args), {'command': 'ls'})
        indexes = [e['index'] for e in events if 'index' in e]
        self.assertEqual(sorted(set(indexes)), list(range(max(indexes) + 1)))

    def test_a_turn_without_the_advisor_passes_event_for_event(self):
        self.sidecar.turns = lambda body: turn_events(
            [text('hello'), call('Bash', {'command': 'ls'})], 'tool_use')
        status, raw = self.send(request(tools=(ADVISOR_TOOL, BASH_TOOL)))
        events = parse_stream(raw)
        self.assertEqual(
            [e['type'] for e in events],
            ['message_start', 'content_block_start', 'content_block_delta',
             'content_block_stop', 'content_block_start', 'content_block_delta',
             'content_block_stop', 'message_delta', 'message_stop'])
        self.assertEqual(events[4]['content_block']['name'], 'Bash')
        self.assertEqual(events[7]['delta']['stop_reason'], 'tool_use')
        self.assertEqual(self.sidecar.advisor_calls(), [])

    def test_a_failed_advisor_never_fails_the_turn(self):
        self.sidecar.advice = lambda body: (400, b'{"error":{"message":"no"}}')
        self.sidecar.turns = self.two_legs(
            ([call('advisor', id='call_a')], 'tool_use'),
            ([text('carried on')], 'end_turn'))
        status, raw = self.send(request())
        self.assertEqual(status, 200)
        events = parse_stream(raw)
        result = next(e['content_block'] for e in events
                      if e['type'] == 'content_block_start'
                      and e['content_block']['type'] == 'advisor_tool_result')
        self.assertEqual(result['content']['type'], 'advisor_tool_result_error')
        _, second = self.sidecar.turn_calls()
        self.assertIn('unavailable', second['messages'][-1]['content'][0]['content'])
        self.assertEqual(events[-2]['delta']['stop_reason'], 'end_turn')

    def test_calls_are_capped_and_a_model_that_keeps_asking_is_ended(self):
        self.sidecar.turns = lambda body: turn_events(
            [call('advisor', id='call_a')], 'tool_use')
        with mock.patch.object(devinx, 'GPT_ADVISOR_MAX_CALLS', 1):
            status, raw = self.send(request())
        self.assertEqual(status, 200)
        self.assertEqual(len(self.sidecar.advisor_calls()), 1)
        legs = self.sidecar.turn_calls()
        # The tool stays on offer (changing the tools would have the whole
        # history read again) until a call has been refused, and goes then.
        self.assertEqual([bool(t.get('tools')) for t in legs[:3]],
                         [True, True, False])
        events = parse_stream(raw)
        self.assertNotIn('tool_use', [e['content_block']['type'] for e in events
                                      if e['type'] == 'content_block_start'])
        self.assertEqual(events[-2]['delta']['stop_reason'], 'end_turn')
        self.assertLess(len(legs), 8)

    def test_the_advisor_calls_travel_under_a_key_of_their_own(self):
        self.sidecar.turns = self.two_legs(
            ([call('advisor', id='call_a')], 'tool_use'),
            ([text('done')], 'end_turn'))
        body = {**request(), 'metadata': {'user_id': json.dumps({'session_id': 'S1'})}}
        self.send(body)
        i = next(n for n, b in enumerate(self.sidecar.seen)
                 if b.get('system') == devinx.GPT_ADVISOR_SYSTEM)
        key = self.sidecar.headers[i]['x-claude-code-session-id']
        self.assertEqual(key, 'S1:advisor:agent-1')
        self.assertEqual(json.loads(self.sidecar.seen[i]['metadata']['user_id']),
                         {'session_id': key})
        # Never the conversation's own key, which the sidecar keeps state for.
        self.assertNotEqual(key, 'S1')

    def test_without_a_session_the_advisor_calls_carry_no_key(self):
        self.sidecar.turns = self.two_legs(
            ([call('advisor', id='call_a')], 'tool_use'),
            ([text('done')], 'end_turn'))
        self.send(request(), agent=False)
        i = next(n for n, b in enumerate(self.sidecar.seen)
                 if b.get('system') == devinx.GPT_ADVISOR_SYSTEM)
        self.assertNotIn('x-claude-code-session-id', self.sidecar.headers[i])
        self.assertNotIn('metadata', self.sidecar.seen[i])

    def test_a_slow_advisor_keeps_the_stream_alive(self):
        def slow(body):
            time.sleep(2.5)
            return 200, json.dumps({'content': [text('late advice')]}).encode()
        self.sidecar.advice = slow
        self.sidecar.turns = self.two_legs(
            ([call('advisor', id='call_a')], 'tool_use'),
            ([text('done')], 'end_turn'))
        with mock.patch.object(devinx, 'KEEPALIVE_EVERY', 1):
            status, raw = self.send(request())
        self.assertIn(b': devinx advising', raw)
        self.assertIn(b'late advice', raw)
        self.assertEqual(parse_stream(raw)[-1]['type'], 'message_stop')

    def test_an_upstream_error_on_the_first_leg_is_an_ordinary_error(self):
        self.sidecar.turns = lambda body: (
            429, b'{"type":"error","error":{"type":"rate_limit_error","message":"slow"}}')
        status, raw = self.send(request())
        self.assertEqual(status, 429)
        self.assertIn(b'slow', raw)

    def test_an_error_after_the_stream_started_is_an_sse_error(self):
        def turns(body):
            if any(b.get('type') == 'tool_result' for m in body['messages']
                   if isinstance(m.get('content'), list) for b in m['content']):
                return 500, b'{"type":"error","error":{"type":"api_error","message":"boom"}}'
            return turn_events([call('advisor', id='call_a')], 'tool_use')
        self.sidecar.turns = turns
        status, raw = self.send(request())
        self.assertEqual(status, 200)
        self.assertIn(b'event: error', raw)
        self.assertIn(b'boom', raw)

    def test_a_client_that_leaves_ends_the_turn_quietly(self):
        gate = threading.Event()

        def slow(body):
            gate.wait(5)
            return 200, json.dumps({'content': [text('too late')]}).encode()
        self.sidecar.advice = slow
        self.sidecar.turns = self.two_legs(
            ([call('advisor', id='call_a')], 'tool_use'),
            ([text('done')], 'end_turn'))
        with mock.patch.object(devinx, 'KEEPALIVE_EVERY', 1):
            conn = http.client.HTTPConnection('127.0.0.1', self.live.port,
                                              timeout=10)
            conn.request('POST', '/v1/messages', body=json.dumps(request()).encode(),
                         headers={'content-type': 'application/json',
                                  'x-claude-code-agent-id': 'agent-1'})
            r = conn.getresponse()
            r.read1(64)
            # The response holds the socket too: both have to let go, or the
            # connection stays open and nobody has left.
            r.close()
            conn.close()
            time.sleep(1.5)
            gate.set()
            deadline = time.time() + 5
            while time.time() < deadline and len(self.sidecar.turn_calls()) < 1:
                time.sleep(0.05)
        time.sleep(1)
        # The leg after the advice was never asked for.
        self.assertEqual(len(self.sidecar.turn_calls()), 1)

    def test_non_streamed_requests_lose_the_tool_instead(self):
        self.sidecar.turns = lambda body: (200, json.dumps({
            'type': 'message', 'content': [text('ok')]}).encode())
        status, raw = self.send(request(tools=(ADVISOR_TOOL, BASH_TOOL),
                                        stream=False))
        self.assertEqual(status, 200)
        (seen,) = self.sidecar.seen
        self.assertEqual([t['name'] for t in seen['tools']], ['Bash'])

    def test_a_request_without_the_advisor_is_relayed_unchanged(self):
        body = request(tools=(BASH_TOOL,))
        self.sidecar.turns = lambda b: turn_events([text('ok')])
        self.send(body)
        self.assertEqual(self.sidecar.raw, [json.dumps(body).encode()])

    def test_the_main_session_gets_the_advisor_too(self):
        self.sidecar.turns = self.two_legs(
            ([call('advisor', id='call_a')], 'tool_use'),
            ([text('done')], 'end_turn'))
        status, raw = self.send(request(), agent=False)
        self.assertEqual(len(self.sidecar.advisor_calls()), 1)
        self.assertIn(b'advisor_result', raw)


class AdvisorOffTests(AdvisorBase):
    MAX_CALLS = 0

    def test_it_is_off_unless_asked_for(self):
        import os
        if 'DEVINX_ADVISOR_MAX_CALLS' not in os.environ:
            code = ("import devinx; print(devinx.GPT_ADVISOR_MAX_CALLS)")
            import subprocess
            out = subprocess.run([sys.executable, '-c', code], cwd=ROOT,
                                 capture_output=True, text=True).stdout.split()
            self.assertEqual(out[-1], '0')

    def test_the_tool_is_withdrawn_and_the_turn_is_relayed_as_it_is(self):
        self.sidecar.turns = lambda body: turn_events([text('hello')])
        status, raw = self.send(request(tools=(ADVISOR_TOOL, BASH_TOOL)))
        self.assertEqual(status, 200)
        (seen,) = self.sidecar.seen
        self.assertEqual([t['name'] for t in seen['tools']], ['Bash'])
        self.assertEqual(self.sidecar.advisor_calls(), [])
        self.assertIn(b'hello', raw)

    def test_history_with_advice_still_continues(self):
        # Turning the feature off must not strand a conversation that has
        # advice in it: the pair is still translated.
        body = request(extra=[])
        body['messages'] = AdvisorHistoryTests().history(
            {'type': 'advisor_result', 'text': 'do X'})['messages']
        self.sidecar.turns = lambda b: turn_events([text('ok')])
        self.send(body)
        self.assertNotIn('server_tool_use', json.dumps(self.sidecar.seen[0]))


class AdvisorHistoryTests(unittest.TestCase):

    def history(self, result):
        return {'model': 'gpt-6.1-sol', 'messages': [
            {'role': 'user', 'content': 'do it'},
            {'role': 'assistant', 'content': [
                text('asking'),
                {'type': 'server_tool_use', 'id': 'srvtoolu_1',
                 'name': 'advisor', 'input': {}},
                {'type': 'advisor_tool_result', 'tool_use_id': 'srvtoolu_1',
                 'content': result},
                text('so I will')]},
            {'role': 'user', 'content': 'thanks, go on'}]}

    def test_a_pair_becomes_an_ordinary_tool_call_and_result(self):
        body = devinx.gpt_translate_advisor_history(self.history(
            {'type': 'advisor_result', 'text': 'do X'}))
        roles = [m['role'] for m in body['messages']]
        self.assertEqual(roles, ['user', 'assistant', 'user', 'assistant', 'user'])
        assistant, result, rest, last = body['messages'][1:]
        self.assertEqual([b['type'] for b in assistant['content']],
                         ['text', 'tool_use'])
        self.assertEqual(assistant['content'][1]['name'], 'advisor')
        self.assertEqual(result['content'][0], {
            'type': 'tool_result', 'tool_use_id': 'srvtoolu_1', 'content': 'do X'})
        self.assertEqual(rest['content'], [text('so I will')])
        self.assertEqual(last['content'], 'thanks, go on')
        self.assertNotIn('server_tool_use', json.dumps(body))

    def test_an_assistant_turn_that_ends_on_the_result_merges_the_next_user_turn(self):
        history = self.history({'type': 'advisor_result', 'text': 'do X'})
        history['messages'][1]['content'].pop()
        body = devinx.gpt_translate_advisor_history(history)
        roles = [m['role'] for m in body['messages']]
        self.assertEqual(roles, ['user', 'assistant', 'user'])
        self.assertEqual([b['type'] for b in body['messages'][2]['content']],
                         ['tool_result', 'text'])

    def test_what_claude_wrote_for_itself_is_said_so(self):
        body = devinx.gpt_translate_advisor_history(self.history(
            {'type': 'advisor_redacted_result', 'encrypted_content': 'AAAA'}))
        result = body['messages'][2]['content'][0]
        self.assertIn('cannot be read', result['content'])
        self.assertNotIn('AAAA', json.dumps(body))

    def test_an_advisor_error_is_an_error_result(self):
        body = devinx.gpt_translate_advisor_history(self.history(
            {'type': 'advisor_tool_result_error', 'error_code': 'unavailable'}))
        result = body['messages'][2]['content'][0]
        self.assertTrue(result['is_error'])
        self.assertIn('unavailable', result['content'])

    def test_a_call_that_never_got_a_result_is_closed(self):
        history = self.history({'type': 'advisor_result', 'text': 'x'})
        del history['messages'][1]['content'][2]
        body = devinx.gpt_translate_advisor_history(history)
        result = next(b for m in body['messages'] if m['role'] == 'user'
                      and isinstance(m['content'], list)
                      for b in m['content'] if b.get('type') == 'tool_result')
        self.assertEqual(result['tool_use_id'], 'srvtoolu_1')
        self.assertTrue(result['is_error'])

    def test_a_result_with_no_call_is_dropped(self):
        history = self.history({'type': 'advisor_result', 'text': 'x'})
        del history['messages'][1]['content'][1]
        body = devinx.gpt_translate_advisor_history(history)
        self.assertNotIn('advisor_tool_result', json.dumps(body))

    def test_nothing_to_translate_is_the_same_object(self):
        body = {'messages': [{'role': 'user', 'content': 'hi'}]}
        self.assertIs(devinx.gpt_translate_advisor_history(body), body)

    def test_a_replayed_history_reaches_the_sidecar_translated(self):
        sidecar = FakeSidecar()
        self.addCleanup(sidecar.close)
        for target, value in (('GPT_UPSTREAM', sidecar.url),):
            patcher = mock.patch.object(devinx, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        live = LiveServer()
        self.addCleanup(live.close)
        body = self.history({'type': 'advisor_result', 'text': 'do X'})
        body.update(stream=True, max_tokens=10)
        conn = http.client.HTTPConnection('127.0.0.1', live.port, timeout=10)
        conn.request('POST', '/v1/messages', body=json.dumps(body).encode(),
                     headers={'content-type': 'application/json'})
        conn.getresponse().read()
        (seen,) = sidecar.seen
        self.assertNotIn('server_tool_use', json.dumps(seen))
        self.assertNotIn('advisor_tool_result', json.dumps(seen))
        self.assertIn('do X', json.dumps(seen))


class AdvisorToolTests(unittest.TestCase):

    def test_the_server_tool_becomes_a_plain_function(self):
        body = {'tools': [BASH_TOOL, ADVISOR_TOOL]}
        swapped = devinx.gpt_swap_advisor(body, keep=True)
        self.assertEqual([t['name'] for t in swapped['tools']], ['Bash', 'advisor'])
        self.assertNotIn('type', swapped['tools'][1])
        self.assertNotIn('defer_loading', swapped['tools'][1])
        self.assertEqual(body['tools'][1], ADVISOR_TOOL)

    def test_it_can_be_taken_out(self):
        swapped = devinx.gpt_swap_advisor({'tools': [BASH_TOOL, ADVISOR_TOOL]},
                                          keep=False)
        self.assertEqual([t['name'] for t in swapped['tools']], ['Bash'])

    def test_a_body_without_it_is_the_same_object(self):
        body = {'tools': [BASH_TOOL]}
        self.assertIs(devinx.gpt_swap_advisor(body, keep=True), body)
        self.assertFalse(devinx.gpt_declares_advisor(body))
        self.assertFalse(devinx.gpt_declares_advisor(
            {'tools': [{'name': 'advisor', 'input_schema': {}}]}))

    def test_stream_parser_survives_chunks_cut_anywhere(self):
        raw = turn_events([text('hello')])
        for cut in (1, 7, 50, len(raw) - 3):
            events = list(devinx.sse_events([raw[:cut], raw[cut:]]))
            self.assertEqual([n for n, _ in events if n][-1], 'message_stop')
        self.assertEqual(len(list(devinx.sse_events([raw.replace(b'\n', b'\r\n')]))),
                         len(list(devinx.sse_events([raw]))))


class ReportBanTests(unittest.TestCase):
    CLAUDE_CODE_NOTE = (
        "- Do NOT Write report/summary/findings/analysis .md files. Return "
        "findings directly as your final assistant message — the parent agent "
        "reads your text output, not files you create. (Files written as input "
        "to another tool are fine; this note is about report files.)")

    def body(self, note=None):
        return {'system': [{'type': 'text', 'text': 'billing'},
                           {'type': 'text', 'text': 'You are a subagent.\n\nNotes:\n- a\n'
                            + (note or self.CLAUDE_CODE_NOTE)}]}

    def test_a_requested_report_is_allowed_and_an_unrequested_one_is_not(self):
        out = devinx.relax_report_ban(self.body())
        rewritten = out['system'][1]['text']
        self.assertIn('on your own initiative', rewritten)
        self.assertIn('names a path to write', rewritten)
        self.assertNotIn('Do NOT Write report', rewritten)
        self.assertTrue(rewritten.startswith('You are a subagent.'))
        self.assertIn('- a\n', rewritten)
        self.assertEqual(out['system'][0], {'type': 'text', 'text': 'billing'})

    def test_it_is_applied_once(self):
        once = devinx.relax_report_ban(self.body())
        self.assertIs(devinx.relax_report_ban(once), once)

    def test_a_system_prompt_without_the_sentence_is_the_same_object(self):
        body = {'system': 'You are a subagent.'}
        self.assertIs(devinx.relax_report_ban(body), body)
        body = {'system': [{'type': 'text', 'text': 'x'}]}
        self.assertIs(devinx.relax_report_ban(body), body)

    def test_string_system_prompts_too(self):
        out = devinx.relax_report_ban({'system': self.CLAUDE_CODE_NOTE})
        self.assertIn('on your own initiative', out['system'])

    def test_the_swe_route_is_left_as_it_was(self):
        # SWE-2 subagents were measured writing a requested report with the
        # sentence in place, so that route is not touched.
        scrubbed = devinx._scrub_system(self.CLAUDE_CODE_NOTE)
        self.assertNotIn('on your own initiative', scrubbed)
        self.assertIn('Do NOT Write report', scrubbed)

    def test_a_gpt_subagent_request_is_rewritten_on_the_way_out(self):
        sidecar = FakeSidecar()
        self.addCleanup(sidecar.close)
        patcher = mock.patch.object(devinx, 'GPT_UPSTREAM', sidecar.url)
        patcher.start()
        self.addCleanup(patcher.stop)
        live = LiveServer()
        self.addCleanup(live.close)
        for agent, expect in ((True, True), (False, False)):
            sidecar.seen.clear()
            body = {**self.body(), 'model': 'gpt-6.1-sol', 'max_tokens': 10,
                    'stream': True,
                    'messages': [{'role': 'user', 'content': 'hi'}]}
            headers = {'content-type': 'application/json'}
            if agent:
                headers['x-claude-code-agent-id'] = 'a1'
            conn = http.client.HTTPConnection('127.0.0.1', live.port, timeout=10)
            conn.request('POST', '/v1/messages', body=json.dumps(body).encode(),
                         headers=headers)
            conn.getresponse().read()
            (seen,) = sidecar.seen
            self.assertEqual('on your own initiative' in json.dumps(seen), expect)

    def test_gpt_subagents_are_told_the_same_in_their_own_prompt(self):
        import launcher
        for name, agent in launcher.gpt_agents().items():
            self.assertIn('names a report or any other file to write',
                          agent['prompt'], name)
            self.assertIn(agent['model'], agent['prompt'])


if __name__ == '__main__':
    unittest.main()
