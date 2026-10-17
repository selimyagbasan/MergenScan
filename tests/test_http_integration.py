"""Real HTTP against an isolated loopback fixture, never an external target.

Only this fixture's resolver is allowed to return loopback. Production validation
is covered independently by test_security.py; there is no app bypass flag.
"""
import html
import sqlite3
import threading
import socket
import time
import requests
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

import app as api
import safe_network
import scanner


@pytest.mark.parametrize('mode', ['headers', 'compressed-body'])
def test_dripping_response_hard_deadline(monkeypatch, mode):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0)); listener.listen(1)
    stopped = threading.Event()
    def drip():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.recv(4096)
                if mode == 'headers':
                    conn.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                    piece = b'x'
                else:
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n')
                    # Valid gzip header, then an arbitrarily long comment field;
                    # decoder consumes bytes but cannot yield any output yet.
                    conn.sendall(b'a\r\n\x1f\x8b\x08\x10\x00\x00\x00\x00\x00\x03\r\n')
                    piece = b'1\r\nx\r\n'
                while not stopped.wait(0.02): conn.sendall(piece)
        except OSError:
            pass
    thread = threading.Thread(target=drip, daemon=True); thread.start()
    monkeypatch.setattr(safe_network, 'public_addresses', lambda *a: ['127.0.0.1'])
    monkeypatch.setattr(safe_network, 'MAX_REQUEST_SECONDS', 0.2)
    started = time.monotonic()
    try:
        with safe_network.public_session() as session:
            with pytest.raises(requests.Timeout):
                session.get(f'http://lab.invalid:{listener.getsockname()[1]}', timeout=0.15)
        assert time.monotonic()-started < 1.5
    finally:
        stopped.set(); listener.close(); thread.join(timeout=2)


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        parsed=urlsplit(self.path); query=parse_qs(parsed.query)
        status=200; headers={'Content-Type':'text/html'}; body='Fixture page'
        if parsed.path.startswith('/sql/'):
            connection=sqlite3.connect(':memory:')
            connection.executescript('CREATE TABLE items (id TEXT); INSERT INTO items VALUES ("1");')
            value=query.get('item',query.get('id',['1']))[0]
            try:
                if parsed.path.endswith('/unsafe'):
                    rows=connection.execute("SELECT id FROM items WHERE id='"+value+"'").fetchall()
                else:
                    rows=connection.execute('SELECT id FROM items WHERE id=?',(value,)).fetchall()
                body=str(rows)
            except sqlite3.Error as exc:
                status=500; body='sqlite3: '+str(exc)
            finally: connection.close()
        elif parsed.path.startswith('/xss/'):
            value=query.get('q',[''])[0]
            body=value if parsed.path.endswith('/unsafe') else html.escape(value)
        elif parsed.path.startswith('/traversal/'):
            file=query.get('file',[''])[0]
            body='root:x:0:0:root:/root:/bin/sh' if parsed.path.endswith('/unsafe') and file.endswith('/etc/passwd') else 'No file'
        elif parsed.path.startswith('/cors/'):
            headers['Access-Control-Allow-Origin']=self.headers.get('Origin','') if parsed.path.endswith('/unsafe') else '*'
            if parsed.path.endswith('/unsafe'): headers['Access-Control-Allow-Credentials']='true'
        elif parsed.path=='/protected':
            status=403; body='Access denied'
        elif parsed.path=='/redirect':
            status=302; headers['Location']='/healthy'
        elif parsed.path=='/healthy':
            headers.update({'Content-Security-Policy':"default-src 'self'; frame-ancestors 'none'",'X-Frame-Options':'DENY','Strict-Transport-Security':'max-age=31536000'})
        data=body.encode()
        self.send_response(status)
        for key,value in headers.items(): self.send_header(key,value)
        self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)


@pytest.fixture
def lab(monkeypatch):
    server=ThreadingHTTPServer(('127.0.0.1',0),FixtureHandler)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    def fixture_addresses(host,port):
        assert host=='lab.invalid', 'Unexpected outbound host'
        return ['127.0.0.1']
    monkeypatch.setattr(safe_network,'public_addresses',fixture_addresses)
    monkeypatch.setattr(scanner,'public_addresses',fixture_addresses)
    monkeypatch.setattr(scanner.time,'sleep',lambda _:None)
    yield f'http://lab.invalid:{server.server_port}'
    server.shutdown(); server.server_close(); thread.join()


@pytest.mark.parametrize('module,path', [('sqli','sql'),('xss','xss'),('traversal','traversal'),('cors','cors')])
@pytest.mark.parametrize('unsafe',[True,False])
def test_actual_http_detection(lab,module,path,unsafe):
    instance=scanner.WebShieldScanner()
    try:
        getattr(instance,'test_'+module)(lab+'/'+path+('/unsafe' if unsafe else '/safe'))
        assert bool(instance.findings)==unsafe
    finally: instance.session.close()


def test_public_redirect_and_headers(lab):
    instance=scanner.WebShieldScanner()
    try:
        instance.test_headers(lab+'/redirect')
        assert not instance.findings
    finally: instance.session.close()


def test_api_scan_to_result_with_real_http(lab,monkeypatch):
    import time
    monkeypatch.setattr(api,'REQUIRE_AUTH',True)
    monkeypatch.setattr(api,'API_KEY','integration-fixture-key')
    monkeypatch.setattr(api.limiter,'enabled',False)
    monkeypatch.setattr(api,'scan_slots',threading.BoundedSemaphore(5))
    client=api.app.test_client(); headers={'X-API-Key':'integration-fixture-key'}
    result=client.post('/api/scan',json={'url':lab+'/xss/unsafe','modules':['xss']},headers=headers)
    assert result.status_code==200
    sid=result.json['scan_id']
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        result=client.get('/api/results/'+sid,headers=headers)
        if result.status_code==200: break
        threading.Event().wait(0.01)
    assert result.status_code==200
    assert result.json['status']=='completed' and result.json['counts']['HIGH']==1
    assert client.get('/api/status/'+sid,headers=headers).json['done']
