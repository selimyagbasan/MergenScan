"""Security boundary regressions. All DNS and outbound sockets are simulated."""
import io
import queue
import socket
import ssl
import threading
from unittest.mock import Mock

import pytest
import requests
import urllib3

import app as api
import safe_network as net
import scanner


def dns(*addresses):
    return [(socket.AF_INET6 if ':' in a else socket.AF_INET, socket.SOCK_STREAM,
             socket.IPPROTO_TCP, '', (a, 443)) for a in addresses]


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setattr(api.limiter, 'enabled', False)
    monkeypatch.setattr(api, 'API_KEY', 'fixture-secret')
    monkeypatch.setattr(api, 'REQUIRE_AUTH', True)
    monkeypatch.setattr(api, 'scan_slots', threading.BoundedSemaphore(5))
    monkeypatch.setattr(net.socket, 'getaddrinfo', lambda *a, **k: dns('8.8.8.8'))
    monkeypatch.setattr(net.socket, 'create_connection', Mock(side_effect=AssertionError('Real network forbidden')))
    monkeypatch.setattr(scanner.time, 'sleep', lambda _: None)
    for state in (api.scan_queues, api.scan_results, api.scan_events, api.scan_timestamps):
        state.clear()


@pytest.mark.parametrize('address', ['127.0.0.1', '10.1.2.3', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', 'fc00::1', 'fe80::1',
    '::ffff:127.0.0.1', '64:ff9b::7f00:1', '2002:7f00:1::'])
def test_non_public_dns_never_connects(monkeypatch,address):
    monkeypatch.setattr(net.socket, 'getaddrinfo', lambda *a, **k: dns(address))
    pool=Mock(); monkeypatch.setattr(net.urllib3, 'HTTPConnectionPool', pool)
    with pytest.raises(net.UnsafeTarget):
        net.public_session().get('http://fixture.invalid')
    pool.assert_not_called()


def test_mixed_dns_rejected(monkeypatch):
    monkeypatch.setattr(net.socket, 'getaddrinfo', lambda *a, **k: dns('8.8.8.8','127.0.0.1'))
    with pytest.raises(net.UnsafeTarget): net.validated_target('https://fixture.invalid')


@pytest.mark.parametrize('url',['file:///etc/passwd','http://user:pass@fixture.invalid',
    'http://fixture.invalid:0','http://fixture.invalid:99999','http://[fe80::1%25eth0]/',
    'http://fixture.invalid/\nsecret','http://user@fixture.invalid'])
def test_invalid_urls(url):
    with pytest.raises(net.UnsafeTarget): net.validated_target(url)


def fake_transport(monkeypatch, replies):
    calls=[]
    class Pool:
        ConnectionCls = urllib3.connection.HTTPConnection
        def __init__(self, host, **options):
            self.host=host; self.options=options
        def urlopen(self, method, path, **options):
            calls.append((self.host,self.options,method,path,options))
            status,headers,body=replies.pop(0)
            return urllib3.HTTPResponse(status=status,headers=headers,body=io.BytesIO(body),preload_content=False)
        def close(self): pass
    monkeypatch.setattr(net.urllib3,'HTTPConnectionPool',Pool)
    monkeypatch.setattr(net.urllib3,'HTTPSConnectionPool',Pool)
    return calls


@pytest.mark.parametrize('method',['GET','OPTIONS','TRACE'])
def test_redirect_private_blocked_for_all_methods(monkeypatch,method):
    monkeypatch.setattr(net.socket,'getaddrinfo',lambda host,*a,**k: dns('127.0.0.1' if host=='127.0.0.1' else '8.8.8.8'))
    calls=fake_transport(monkeypatch,[(302,{'Location':'http://127.0.0.1/private'},b'')])
    with pytest.raises(net.UnsafeTarget): net.public_session().request(method,'http://fixture.invalid')
    assert len(calls)==1


def test_public_redirect_tls_host_and_query_preserved(monkeypatch):
    calls=fake_transport(monkeypatch,[(302,{'Location':'https://next.invalid:8443/path'},b''),(200,{},b'OK')])
    response=net.public_session().get('http://fixture.invalid',params={'q':'safe'})
    assert response.content==b'OK'
    assert calls[0][3]=='/?q=safe'
    assert calls[1][0]=='8.8.8.8'
    assert calls[1][1]['port']==8443
    assert calls[1][1]['server_hostname']==calls[1][1]['assert_hostname']=='next.invalid'
    assert calls[1][1]['cert_reqs']==ssl.CERT_REQUIRED
    assert calls[1][4]['headers']['Host']=='next.invalid:8443'


def test_dns_rebinding_is_pinned(monkeypatch):
    resolve=Mock(side_effect=[dns('8.8.8.8'),dns('127.0.0.1')])
    monkeypatch.setattr(net.socket,'getaddrinfo',resolve)
    calls=fake_transport(monkeypatch,[(200,{},b'OK')])
    net.public_session().get('https://fixture.invalid')
    assert resolve.call_count==1 and calls[0][0]=='8.8.8.8'


def test_redirect_detector_can_disable_following(monkeypatch):
    calls=fake_transport(monkeypatch,[(307,{'Location':'http://127.0.0.1/private'},b'')])
    response=net.public_session().get('https://fixture.invalid',allow_redirects=False)
    assert response.status_code==307 and len(calls)==1


def test_redirect_loop_bounded(monkeypatch):
    calls=fake_transport(monkeypatch,[(302,{'Location':'https://fixture.invalid/'},b'')]*6)
    with pytest.raises(requests.TooManyRedirects): net.public_session().get('https://fixture.invalid')
    assert len(calls)==6


@pytest.mark.parametrize('compressed',[False,True])
def test_body_limit(monkeypatch,compressed):
    import gzip
    monkeypatch.setattr(net,'MAX_RESPONSE_BYTES',128)
    body=b'a'*129
    headers={}
    if compressed: body=gzip.compress(body); headers={'Content-Encoding':'gzip'}
    fake_transport(monkeypatch,[(200,headers,body)])
    with pytest.raises(requests.RequestException,match='boyutu'):
        net.public_session().get('https://fixture.invalid')


def test_body_deadline(monkeypatch):
    fake_transport(monkeypatch,[(200,{},b'OK')])
    ticks=iter([0,13])
    # Patch module's clock only: requests uses the shared time module too.
    monkeypatch.setattr(net,'time',Mock(monotonic=lambda:next(ticks)))
    with pytest.raises(requests.Timeout): net.public_session().get('https://fixture.invalid')


def test_no_ambient_credentials_or_proxy(monkeypatch):
    calls=fake_transport(monkeypatch,[(200,{},b'OK')])
    session=net.public_session()
    assert session.trust_env is False
    session.get('https://fixture.invalid',headers={'Authorization':'secret','Cookie':'secret','Proxy-Authorization':'secret'})
    assert not any(k.lower() in ('authorization','cookie','proxy-authorization') for k in calls[0][4]['headers'])


@pytest.mark.parametrize('path,method',[('/api/scan','post'),('/api/status/id','get'),('/api/results/id','get'),('/api/cancel/id','post')])
def test_scan_routes_require_key(path,method):
    client=api.app.test_client()
    for key in ('','wrong'):
        assert getattr(client,method)(path,headers={'X-API-Key':key}).status_code==401


def test_empty_server_key_fails_closed(monkeypatch):
    monkeypatch.setattr(api,'API_KEY','')
    r=api.app.test_client().post('/api/scan',json={'url':'https://fixture.invalid','modules':['headers']})
    assert r.status_code==401
    assert api.app.test_client().get('/api/config').json=={'auth_required':True,'scan_available':False}


def test_unauthorized_poll_does_not_consume_log():
    api.scan_queues['id']=queue.Queue(); api.scan_queues['id'].put('private log')
    client=api.app.test_client()
    assert client.get('/api/status/id').status_code==401
    assert client.get('/api/status/id',headers={'X-API-Key':'fixture-secret'}).json['messages']==['private log']


def test_authenticated_lifecycle(monkeypatch):
    from concurrent.futures import Future
    future=Future()
    monkeypatch.setattr(api.executor,'submit',lambda *a:future)
    monkeypatch.setattr(api.threading.Thread,'start',lambda _:None)
    headers={'X-API-Key':'fixture-secret'}; c=api.app.test_client()
    r=c.post('/api/scan',json={'url':'https://fixture.invalid','modules':['headers']},headers=headers)
    assert r.status_code==200
    sid=r.json['scan_id']
    assert c.get('/api/results/'+sid,headers=headers).status_code==202
    assert c.post('/api/cancel/'+sid,headers=headers).status_code==200
    future.set_result(None)
    assert api.scan_slots.acquire(blocking=False)


def test_capacity_rejects_without_allocating(monkeypatch):
    monkeypatch.setattr(api,'scan_slots',threading.BoundedSemaphore(0))
    r=api.app.test_client().post('/api/scan',json={'url':'https://fixture.invalid','modules':['headers']},headers={'X-API-Key':'fixture-secret'})
    assert r.status_code==503 and not api.scan_results


def test_large_request_413():
    r=api.app.test_client().post('/api/scan',json={'url':'https://fixture.invalid','padding':'x'*17000},headers={'X-API-Key':'fixture-secret'})
    assert r.status_code==413


def test_log_queue_bounded_keeps_terminal():
    q=api.ScanLogQueue()
    for _ in range(300): q.put('x'*5000)
    q.put('__DONE__')
    assert q.qsize()==256
    assert max(map(len,q.queue))<=2048 and list(q.queue)[-1]=='__DONE__'


@pytest.mark.parametrize('url',['javascript:alert(1)','data:text/html,test','file:///etc/passwd','//fixture.invalid','https://user:password@fixture.invalid'])
def test_news_invalid_schemes(url): assert api.safe_web_url(url)==''


def test_news_public_http_control():
    assert api.safe_web_url('https://fixture.invalid/a')=='https://fixture.invalid/a'


def test_feed_redirect_private_blocked(monkeypatch):
    monkeypatch.setattr(net.socket,'getaddrinfo',lambda host,*a,**k: dns('127.0.0.1' if host=='127.0.0.1' else '8.8.8.8'))
    calls=fake_transport(monkeypatch,[(302,{'Location':'http://127.0.0.1/'},b'')])
    assert api._fetch_url('https://fixture.invalid/feed') is None
    assert len(calls)==1


def test_ports_connect_pinned_ip(monkeypatch):
    sock=Mock(); sock.connect_ex.return_value=1
    monkeypatch.setattr(scanner.socket,'socket',Mock(return_value=sock))
    scanner.WebShieldScanner().test_subdomain_port('https://fixture.invalid')
    assert all(call.args[0][0]=='8.8.8.8' for call in sock.connect_ex.call_args_list)


def test_port_failure_is_not_a_success_and_closes_socket(monkeypatch):
    sock = Mock(); sock.connect_ex.side_effect = OSError('fixture socket failure')
    monkeypatch.setattr(scanner.socket, 'socket', Mock(return_value=sock))
    with pytest.raises(RuntimeError, match='tamamlanamadı'):
        scanner.WebShieldScanner().test_subdomain_port('https://fixture.invalid')
    sock.close.assert_called_once()


def test_tls_pinned_ip_original_hostname(monkeypatch):
    connect=Mock(); context=Mock()
    context.wrap_socket.return_value.__enter__=Mock(side_effect=ssl.SSLCertVerificationError('fixture'))
    context.wrap_socket.return_value.__exit__=Mock()
    connect.return_value.__enter__=Mock(return_value='socket'); connect.return_value.__exit__=Mock()
    monkeypatch.setattr(scanner.socket,'create_connection',connect)
    monkeypatch.setattr(scanner.ssl,'create_default_context',lambda:context)
    scanner.WebShieldScanner().test_ssl('https://fixture.invalid:8443')
    connect.assert_called_once_with(('8.8.8.8',8443),timeout=8)
    context.wrap_socket.assert_called_once_with('socket',server_hostname='fixture.invalid')
