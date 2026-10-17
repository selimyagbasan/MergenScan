"""Offline regression tests: no requests are sent to external targets."""
import html
import queue
import sys
import threading
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as api
import scanner

URL = 'https://fixture.invalid/'


def response(body='', status=200, headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = body.encode()
    result.headers.update(headers or {})
    return result


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setattr(scanner.time, 'sleep', lambda _: None)
    monkeypatch.setattr(scanner, '_is_ip_safe', lambda _: True)
    monkeypatch.setattr(requests.sessions.Session, 'request', Mock(side_effect=AssertionError('Unexpected network')))
    monkeypatch.setattr(api.limiter, 'enabled', False)
    monkeypatch.setattr(api, 'REQUIRE_AUTH', False)
    for state in (api.scan_queues, api.scan_results, api.scan_events, api.scan_timestamps):
        state.clear()


def run(method, replies):
    instance = scanner.WebShieldScanner()
    instance._safe_get = Mock(side_effect=replies) if isinstance(replies, list) else Mock(return_value=replies)
    getattr(instance, method)(URL)
    return instance


@pytest.mark.parametrize('method,replies,count', [
    ('test_sqli', [response('ok'), response('SQL syntax error', 500)], 1),
    ('test_sqli', response('ok'), 0),
    ('test_sqli', response('SQL syntax reference documentation'), 0),
    ('test_xss', response("<script>alert('XSS')</script>"), 1),
    ('test_xss', response(html.escape("<script>alert('XSS')</script>")), 0),
    ('test_csrf', response('<p>Static page</p>'), 0),
    ('test_csrf', response('<form method="get"><input name="q"></form>'), 0),
    ('test_csrf', response('<form method="post"><input name="email"></form>'), 1),
    ('test_csrf', response('<form method="post"><input name="csrf_token"></form>'), 0),
    ('test_csrf', response('<form method="post"><input name="csrf_token"></form><form method="post"><input name="email"></form>'), 1),
    ('test_headers', response(), 3),
    ('test_headers', response(headers={'Strict-Transport-Security': 'max-age=1', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'self'"}), 0),
    ('test_traversal', response('root:x:0:0:root:/root:/bin/bash'), 1),
    ('test_sensitive_files', response('<html><body>Welcome to app</body></html>'), 0),
    ('test_sensitive_files', response(status=404), 0),
    ('test_sensitive_files', [response('DB_PASSWORD=secret'), response('[core]\nrepositoryformatversion = 0'), response("<?php define('DB_NAME', 'app');"), response('CREATE TABLE users (id INT);')], 4),
    ('test_cmdi', response('uid=1000(user)'), 1),
    ('test_cors', response(headers={'Access-Control-Allow-Origin': '*'}), 1),
    ('test_clickjacking', response(), 1),
    ('test_clickjacking', response(headers={'X-Frame-Options': 'DENY'}), 0),
    ('test_tech_detect', response(headers={'Server': 'nginx/1.2.3'}), 1),
    ('test_robots_sitemap', [response('User-agent: *\nDisallow: /admin'), response(status=404)], 1),
    ('test_waf', response(), 1),
    ('crawl_site', response('<a href="/page">link</a>'), 0),
])
def test_module_cases(method, replies, count):
    assert len(run(method, replies).findings) == count


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
@pytest.mark.parametrize('location,expected', [('https://evil.com', 1), ('//evil.com/path', 1), ('/help/evil.com', 0), ('https://evil.com.fixture.invalid', 0)])
def test_redirect(status, location, expected):
    assert len(run('test_open_redirect', response(status=status, headers={'Location': location})).findings) == expected


@pytest.mark.parametrize('cookie,expected', [('session=abc; Path=/', 1), ('session=secure_httponly_samesite; Path=/', 1), ('session=abc; Secure; HttpOnly; SameSite=Strict', 0)])
def test_cookie_flags(cookie, expected):
    reply = response()
    reply.raw = Mock()
    reply.raw.headers = {'Set-Cookie': cookie}
    assert len(run('test_cookies', reply).findings) == expected


def test_methods():
    instance = scanner.WebShieldScanner()
    instance.session.options = Mock(return_value=response(headers={'Allow': 'GET, TRACE'}))
    instance.test_http_methods(URL)
    assert instance.findings


def test_rate_limit():
    instance = scanner.WebShieldScanner()
    instance.session.get = Mock(return_value=response(status=429))
    instance.test_rate_limiting(URL)
    assert not instance.findings


def test_ssl_http():
    instance = scanner.WebShieldScanner()
    instance.test_ssl('http://fixture.invalid')
    assert instance.findings


def test_ports(monkeypatch):
    sock = Mock()
    sock.connect_ex.side_effect = lambda addr: 0 if addr[1] == 6379 else 1
    monkeypatch.setattr(scanner.socket, 'socket', lambda *args: sock)
    instance = scanner.WebShieldScanner()
    instance.test_subdomain_port(URL)
    assert instance.findings and sock.connect_ex.call_count == 19


def worker(modules, event=None):
    api.scan_queues['test'] = queue.Queue()
    api.scan_results['test'] = None
    api.run_scan('test', URL, modules, event or threading.Event())
    return api.scan_results['test']


def test_worker_success_and_polling(monkeypatch):
    monkeypatch.setattr(scanner.WebShieldScanner, '_safe_get', lambda *args, **kwargs: response())
    result = worker(['headers'])
    assert result['counts']['MEDIUM'] == 3 and result['score'] == 85
    assert result['status'] == 'completed'
    client = api.app.test_client()
    assert client.get('/api/status/test').json['done']
    assert client.get('/api/status/test').json['done']
    assert client.get('/api/results/test').json == result


def test_worker_failure_preserves_findings(monkeypatch):
    monkeypatch.setattr(scanner.WebShieldScanner, '_safe_get', lambda *args, **kwargs: response())
    monkeypatch.setattr(scanner.WebShieldScanner, 'test_xss', Mock(side_effect=RuntimeError('fixture failure')))
    result = worker(['headers', 'xss'])
    assert result['status'] == 'error' and result['score'] is None
    assert result['counts']['MEDIUM'] == 3


def test_cancel_has_no_score():
    event = threading.Event()
    event.set()
    result = worker(['xss'], event)
    assert result['status'] == 'cancelled' and result['score'] is None


def test_network_failure_has_no_score(monkeypatch):
    monkeypatch.setattr(requests.sessions.Session, 'get', Mock(side_effect=requests.Timeout()))
    result = worker(['xss'])
    assert result['status'] == 'error' and result['score'] is None


@pytest.mark.parametrize('payload', [{}, [], ['bad'], {'url': 123, 'modules': ['xss']}, {'url': URL, 'modules': ['unknown']}, {'url': URL, 'modules': 'xss'}, {'url': URL, 'modules': [None]}, {'url': URL, 'modules': []}])
def test_invalid_api_input(payload, monkeypatch):
    monkeypatch.setattr(api, 'is_safe_url', lambda _: (True, ''))
    assert api.app.test_client().post('/api/scan', json=payload).status_code == 400


def test_start_cancel(monkeypatch):
    monkeypatch.setattr(api, 'is_safe_url', lambda _: (True, ''))
    submit = Mock()
    monkeypatch.setattr(api.executor, 'submit', submit)
    monkeypatch.setattr(api.threading.Thread, 'start', lambda _: None)
    client = api.app.test_client()
    result = client.post('/api/scan', json={'url': URL, 'modules': ['xss', 'xss']})
    assert result.status_code == 200
    assert submit.call_args.args[3] == ['xss']
    scan_id = result.json['scan_id']
    assert client.get('/api/results/' + scan_id).status_code == 202
    assert client.post('/api/cancel/' + scan_id).status_code == 200
    assert api.scan_events[scan_id].is_set()


def test_timeout_result_cannot_be_overwritten():
    pending = queue.Queue()
    timeout = {'status': 'timeout', 'score': None}
    api.finish_scan('test', timeout, pending)
    api.finish_scan('test', {'status': 'completed', 'score': 100}, pending)
    assert api.scan_results['test'] == timeout
    assert list(pending.queue) == ['__DONE__']


def test_private_url_rejected(monkeypatch):
    monkeypatch.setattr(api.socket, 'gethostbyname', lambda _: '127.0.0.1')
    assert not api.is_safe_url('http://localhost')[0]
