"""Offline failure-path tests: use the real proxy, fake upstreams and local sockets.

No inference request or account credential is needed. Tests deliberately cover
wire output and shutdown, not just helper return values.
"""
import contextlib
import gzip
import http.client
import io
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import devinx


def events(raw):
    return [json.loads(line[6:]) for line in raw.decode().splitlines()
            if line.startswith('data: ')]


def message(text='', stop=0, tools=()):
    return SimpleNamespace(
        delta_text=text, delta_thinking='', delta_signature='',
        delta_tool_calls=tools, stop_reason=stop, latency=0.1,
        usage=SimpleNamespace(input_tokens=1, output_tokens=2,
                              cache_read_tokens=0, cache_write_tokens=0))


class ProtocolTests(unittest.TestCase):
    def test_retry_after_units_and_absent_hint(self):
        for text, expected in [('20 seconds', 20), ('11 minutes', 660),
                               ('1 hour', 3600), ('0 seconds', 0)]:
            with self.subTest(text=text):
                self.assertEqual(devinx.anthropic_error(
                    'resource_exhausted: reset in ' + text)[3], expected)
        self.assertIsNone(devinx.anthropic_error('resource_exhausted: busy')[3])

    def test_error_signature_is_shared(self):
        for emitter in (devinx.AnthropicStream, devinx.ResponsesStream):
            with self.subTest(emitter=emitter.__name__):
                buf = io.BytesIO()
                out = emitter(buf, 'swe-2-max')
                out.start()
                out.error('test failure', 'overloaded_error')
                out.stop()
                self.assertEqual(out.failure, 'overloaded_error')
                self.assertIn('overloaded_error', buf.getvalue().decode())
                self.assertNotIn('response.completed', buf.getvalue().decode())

    def test_responses_truncation_has_incomplete_details(self):
        buf = io.BytesIO()
        out = devinx.ResponsesStream(buf, 'swe-2-max')
        out.start()
        out.text('partial')
        out.finish('max_tokens', {'input_tokens': 1, 'output_tokens': 2})
        wire = events(buf.getvalue())
        self.assertNotIn('response.completed', [e['type'] for e in wire])
        self.assertEqual(wire[-1]['type'], 'response.incomplete')
        self.assertEqual(wire[-1]['response']['status'], 'incomplete')
        self.assertEqual(wire[-1]['response']['incomplete_details'],
                         {'reason': 'max_output_tokens'})
        self.assertEqual(wire[-1]['response']['usage']['output_tokens'], 2)

    def test_responses_success_stays_completed(self):
        for stop in ('end_turn', 'tool_use'):
            buf = io.BytesIO()
            out = devinx.ResponsesStream(buf, 'swe-2-max')
            out.start()
            out.finish(stop, {'input_tokens': 1, 'output_tokens': 2})
            self.assertEqual(events(buf.getvalue())[-1]['type'], 'response.completed')

    def test_early_responses_error_has_http_status(self):
        handler = object.__new__(devinx.Handler)
        handler.wfile = io.BytesIO()
        handler.send_error_json = mock.Mock()
        with mock.patch.object(devinx, 'responses_to_messages', return_value=(
                {'model': 'swe-2-max', 'stream': True}, set())), \
             mock.patch.object(devinx, 'run_swe', return_value=(
                None, 'unauthenticated: expired credential')):
            handler.serve_swe_responses({'model': 'swe-2-max', 'stream': True})
        handler.send_error_json.assert_called_once_with(
            401, 'authentication_error', 'unauthenticated: expired credential', None)
        self.assertTrue(handler.close_connection)

    def test_nonstreaming_responses_still_refused(self):
        handler = object.__new__(devinx.Handler)
        handler.send_error_json = mock.Mock()
        with mock.patch.object(devinx, 'run_swe') as run:
            handler.serve_swe_responses({'model': 'swe-2-max', 'stream': False})
        self.assertEqual(handler.send_error_json.call_args.args[0], 400)
        run.assert_not_called()


class TurnTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.account = {'name': 'test', 'blocked_until': 0}
        self.stack.enter_context(mock.patch.object(devinx, 'compact_body', side_effect=lambda b: b))
        self.stack.enter_context(mock.patch.object(devinx, 'build_request', return_value=(
            SimpleNamespace(cascade_id='test-conversation'), 'swe-2-max')))
        self.stack.enter_context(mock.patch.object(devinx, 'claim_account', return_value=(self.account, 0)))
        self.stack.enter_context(mock.patch.object(devinx, 'KEEPALIVE_EVERY', 0))
        self.stack.enter_context(mock.patch.object(devinx, 'paced', return_value=contextlib.nullcontext()))
        self.body = {'model': 'swe-2-max', 'stream': True, 'messages': []}

    def run_turn(self, frames, emitter=devinx.AnthropicStream):
        buf, outcome = io.BytesIO(), {}
        with mock.patch.object(devinx, 'chat_stream', return_value=iter(frames)):
            result = devinx.run_swe(self.body, buf, emitter, outcome=outcome)
        return result, buf.getvalue(), outcome

    def test_both_streams_report_midstream_errors(self):
        for emitter in (devinx.AnthropicStream, devinx.ResponsesStream):
            with self.subTest(emitter=emitter.__name__):
                result, raw, outcome = self.run_turn([
                    (message('partial'), None), (None, 'unavailable: unavailable')], emitter)
                self.assertEqual(result, (None, None))
                self.assertEqual(outcome['status'], 'stream_error')
                self.assertIn('overloaded_error', raw.decode())
                self.assertNotIn('response.completed', raw.decode())
                self.assertNotIn('"stop_reason": "end_turn"', raw.decode())

    def test_invalid_tool_is_never_emitted(self):
        valid = SimpleNamespace(id='good', name='Read', arguments_json='{"path":"x"}')
        invalid = SimpleNamespace(id='bad', name='Write', arguments_json='{"path":')
        result, raw, outcome = self.run_turn([(message(tools=[valid, invalid]), None)],
                                             devinx.ResponsesStream)
        self.assertEqual(result, (None, None))
        calls = [e['item'] for e in events(raw) if e['type'] == 'response.output_item.added']
        self.assertEqual([c['call_id'] for c in calls], ['good'])
        self.assertEqual(events(raw)[-1]['type'], 'response.incomplete')

    def test_build_failure_is_http_before_commit(self):
        with mock.patch.object(devinx, 'build_request', side_effect=ValueError('broken')):
            result, raw, outcome = self.run_turn([])
        self.assertEqual(raw, b'')
        self.assertIn('request build:', result[1])
        self.assertEqual(outcome['status'], '502')

    def test_heartbeat_is_armed_before_compaction_and_error_stays_sse(self):
        buf = io.BytesIO()
        class InstantHeartbeat(devinx.AnthropicStream):
            def arm(self):
                self.start()
        def compact(body):
            self.assertIn(b'HTTP/1.1 200', buf.getvalue())
            return body
        with mock.patch.object(devinx, 'compact_body', side_effect=compact), \
             mock.patch.object(devinx, 'build_request', side_effect=ValueError('broken')):
            response, err = devinx.run_swe(self.body, buf, InstantHeartbeat)
        self.assertIsNone(err)
        self.assertEqual(buf.getvalue().count(b'HTTP/1.1 '), 1)
        self.assertIn(b'event: error', buf.getvalue())
        self.assertIn(b'event: message_stop', buf.getvalue())

    def test_transport_retry_after_only_heartbeat_keeps_one_response(self):
        class InstantHeartbeat(devinx.AnthropicStream):
            def arm(self):
                self.start()
        attempts = [iter([(None, 'upstream ConnectionError: dropped')]),
                    iter([(message('complete'), None)])]
        buf = io.BytesIO()
        with mock.patch.object(devinx, 'chat_stream', side_effect=attempts) as chat, \
             mock.patch.object(devinx.time, 'sleep'):
            result = devinx.run_swe(self.body, buf, InstantHeartbeat)
        self.assertEqual(chat.call_count, 2)
        self.assertEqual(result, (None, None))
        self.assertEqual(buf.getvalue().count(b'HTTP/1.1 '), 1)
        self.assertEqual(buf.getvalue().count(b'event: message_start'), 1)
        self.assertIn(b'complete', buf.getvalue())
        self.assertNotIn(b'event: error', buf.getvalue())

    def test_no_retry_after_content_reached_client(self):
        with mock.patch.object(devinx, 'chat_stream', return_value=iter([
                (message('partial'), None), (None, 'upstream ConnectionError: dropped')])) as chat:
            devinx.run_swe(self.body, io.BytesIO())
        self.assertEqual(chat.call_count, 1)

    def test_emitter_released_on_unexpected_failure(self):
        out = devinx.AnthropicStream(io.BytesIO(), 'swe-2-max')
        with mock.patch.object(devinx, '_run_swe', side_effect=RuntimeError('unexpected')):
            with self.assertRaises(RuntimeError):
                devinx.run_swe(self.body, out.w, lambda *args: out)
        self.assertTrue(out._done.is_set())


class FrameTests(unittest.TestCase):
    def test_valid_plain_and_gzip_frames(self):
        raw = b'{"answer":"ok"}'
        self.assertEqual(devinx._frame_payload(raw, False), raw)
        self.assertEqual(devinx._frame_payload(gzip.compress(raw), True), raw)

    def test_decoded_size_limit(self):
        for compressed in (False, True):
            raw = b'a' * 1000
            payload = gzip.compress(raw) if compressed else raw
            with mock.patch.object(devinx, 'MAX_INFLATED_FRAME_BYTES', 50):
                with self.assertRaisesRegex(ValueError, 'decoded size limit'):
                    devinx._frame_payload(payload, compressed)

    def test_gzip_concatenation_is_also_bounded(self):
        payload = gzip.compress(b'a' * 30) + gzip.compress(b'b' * 30)
        with mock.patch.object(devinx, 'MAX_INFLATED_FRAME_BYTES', 50):
            with self.assertRaises(ValueError):
                devinx._frame_payload(payload, True)

    def test_declared_frame_size_is_rejected_before_buffering_body(self):
        req = SimpleNamespace(metadata=SimpleNamespace(), chat_message_prompts=[],
                              chat_model_uid='swe-2-max', cascade_id='test',
                              SerializeToString=lambda: b'test')
        response = mock.Mock(status_code=200)
        response.iter_content.return_value = iter([b'\x00' + struct.pack('>I', 1000)])
        with mock.patch.object(devinx, 'MAX_FRAME_BYTES', 50), \
             mock.patch.object(devinx, 'get_jwt', return_value=('test-jwt', None)), \
             mock.patch.object(devinx.SESSION, 'post', return_value=response):
            with self.assertRaisesRegex(ValueError, 'wire size limit'):
                list(devinx.chat_stream(req, {'name': 'test', 'key': 'test'}))
        response.close.assert_called_once()

    def test_adapter_does_not_implicitly_replay_post_reads(self):
        retry = devinx.SESSION.get_adapter('https://').max_retries
        self.assertNotIn('POST', retry.allowed_methods)
        self.assertIn('GET', retry.allowed_methods)
        self.assertGreater(retry.connect, 0)


class HTTPFramingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = devinx.Server(('127.0.0.1', 0), devinx.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      kwargs={'poll_interval': 0.02}, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def request(self, lengths, data=b'', transfer=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=2)
        self.addCleanup(conn.close)
        conn.putrequest('POST', '/v1/messages/count_tokens')
        for length in lengths:
            conn.putheader('Content-Length', length)
        if transfer is not None:
            conn.putheader('Transfer-Encoding', transfer)
        conn.endheaders(data)
        response = conn.getresponse()
        payload = json.loads(response.read())
        return response.status, payload

    def test_negative_length_is_rejected_without_waiting_for_eof(self):
        self.assertEqual(self.request(['-1'])[0], 400)

    def test_missing_duplicate_or_ambiguous_length_is_rejected(self):
        for lengths, transfer in [([], None), (['0', '0'], None),
                                  (['0'], 'chunked'), (['1x'], None), (['+1'], None)]:
            with self.subTest(lengths=lengths, transfer=transfer):
                self.assertEqual(self.request(lengths, transfer=transfer)[0], 400)

    def test_oversized_body_is_refused_before_read(self):
        self.assertEqual(self.request([str(devinx.MAX_BODY_BYTES + 1)])[0], 413)

    def test_valid_count_tokens_request_still_works(self):
        data = json.dumps({'model': 'swe-2-max', 'messages': [
            {'role': 'user', 'content': 'test message'}]}).encode()
        status, body = self.request([str(len(data))], data)
        self.assertEqual(status, 200)
        self.assertGreater(body['input_tokens'], 0)


class DiagnosticsTests(unittest.TestCase):
    def test_stats_extractor_inherits_the_actual_log_path(self):
        handler = object.__new__(devinx.Handler)
        handler.path = '/api/stats'
        handler.send_json = mock.Mock()
        with mock.patch.object(devinx, '_stats', {}), \
             mock.patch.object(devinx, 'DATA_DIR', '/custom/data'), \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(devinx, '_log_tail', return_value=[]), \
             mock.patch.object(devinx.subprocess, 'run', return_value=SimpleNamespace(
                 returncode=0, stdout='{}', stderr='')) as run:
            handler.serve_stats()
        self.assertEqual(run.call_args.kwargs['env']['DEVINX_LOG'],
                         os.path.join('/custom/data', 'devinx.log'))

    def test_compaction_shape_logging_does_not_quote_content(self):
        body = {'model': 'swe-2-max', 'messages': [
            {'role': 'user', 'content': 'task'}] + [
            {'role': 'assistant' if i % 2 else 'user',
             'content': 'PRIVATE-CONTENT-MARKER-' * 10} for i in range(12)]}
        log = io.StringIO()
        with mock.patch.object(devinx, 'COMPACT_AT', 200), \
             mock.patch.object(devinx, '_summaries', {}), \
             mock.patch.object(devinx, 'summarise_turns', return_value='SUMMARY'), \
             contextlib.redirect_stdout(log):
            devinx.compact_body(body)
        self.assertIn('compaction:', log.getvalue())
        self.assertNotIn('PRIVATE-CONTENT-MARKER', log.getvalue())


@unittest.skipUnless(os.name == 'posix', 'POSIX signal integration test')
class DrainTests(unittest.TestCase):
    def test_busy_sigterm_closes_both_listeners_and_finishes_accepted_turn(self):
        script = r'''
import json, threading, time
import devinx
class Slow(devinx.Handler):
    def _do_POST(self):
        self.send_response(200)
        self.send_header('content-length', '4')
        self.send_header('connection', 'close')
        self.end_headers()
        self.wfile.flush()
        time.sleep(2)
        self.wfile.write(b'done')
        self.close_connection = True
srv = devinx.Server(('127.0.0.1', 0), Slow)
extra = devinx.Server(('127.0.0.1', 0), devinx.DashboardHandler)
threading.Thread(target=extra.serve_forever, daemon=True).start()
devinx.DRAIN_SECONDS = 5
devinx.drain_and_exit(srv, (extra,))
print(json.dumps([srv.server_address[1], extra.server_address[1]]), flush=True)
srv.serve_forever(poll_interval=0.02)
'''
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        with tempfile.TemporaryFile(mode='w+b') as errors:
            proc = subprocess.Popen([sys.executable, '-u', '-c', script], cwd=ROOT,
                                    stdout=subprocess.PIPE, stderr=errors, env=env)
            self.addCleanup(lambda: proc.kill() if proc.poll() is None else None)
            try:
                ports = json.loads(proc.stdout.readline())
                conn = http.client.HTTPConnection('127.0.0.1', ports[0], timeout=8)
                self.addCleanup(conn.close)
                conn.request('POST', '/slow', body=b'')
                response = conn.getresponse()  # proves the accepted turn is active
                self.assertEqual(response.status, 200)
                os.kill(proc.pid, signal.SIGTERM)
                time.sleep(0.02)
                os.kill(proc.pid, signal.SIGTERM)
                deadline = time.monotonic() + 1.3
                pending = set(ports)
                while pending and time.monotonic() < deadline:
                    for port in list(pending):
                        with socket.socket() as sock:
                            sock.settimeout(0.1)
                            if sock.connect_ex(('127.0.0.1', port)) != 0:
                                pending.remove(port)
                    time.sleep(0.02)
                self.assertFalse(pending, 'draining listeners still accept dead-end connections')
                self.assertIsNone(proc.poll(), 'process exited before the accepted turn finished')
                self.assertEqual(response.read(), b'done')
                self.assertEqual(proc.wait(timeout=6), 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=3)
                proc.stdout.close()


class OutcomeLoggingTests(unittest.TestCase):
    def _capture(self, responses, fail=False):
        handler = object.__new__(devinx.Handler)
        handler.wfile = io.BytesIO()
        def execute(*args, outcome=None):
            if fail:
                raise ValueError('unexpected test error')
            outcome['status'] = 'stream_error'
            return None, None
        log = io.StringIO()
        with mock.patch.object(devinx, 'run_swe', side_effect=execute), \
             contextlib.redirect_stdout(log):
            method = handler.serve_swe_responses if responses else handler.serve_swe
            method({'model': 'swe-2-max', 'stream': True})
        return log.getvalue()

    def test_both_wires_count_as_swe_client_errors_not_relay_latency(self):
        from tools import log_stats
        for responses in (False, True):
            with self.subTest(responses=responses), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'test.log'
                path.write_text(self._capture(responses), encoding='utf-8')
                stats = log_stats.collect(str(path))
                self.assertEqual(stats['client_status'], {'stream_error': 1})
                self.assertEqual(stats['relay_latency'], [])

    def test_unexpected_failure_is_counted_once_on_each_wire(self):
        from tools import log_stats
        for responses in (False, True):
            with self.subTest(responses=responses), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'test.log'
                path.write_text(self._capture(responses, fail=True), encoding='utf-8')
                stats = log_stats.collect(str(path))
                self.assertEqual(stats['client_status'], {'ValueError': 1})
                self.assertEqual(stats['relay_latency'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
