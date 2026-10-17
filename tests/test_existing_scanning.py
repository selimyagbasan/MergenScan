import sys, html, queue, threading, ssl
from types import SimpleNamespace
from unittest.mock import Mock
import pytest, requests
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scanner, app as api
U='https://scanner-fixture.invalid'
def response(body='', status=200, headers=None):
    r=requests.Response(); r.status_code=status; r._content=body.encode(); r.headers.update(headers or {}); r.raw=None
    return r
@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setattr(api, 'REQUIRE_AUTH', False)
    monkeypatch.setattr(api, 'scan_slots', threading.BoundedSemaphore(5))
    monkeypatch.setattr(scanner, 'public_addresses', lambda host, port: ['8.8.8.8'])
    monkeypatch.setattr(scanner.time,'sleep',lambda _:None)
    monkeypatch.setattr(scanner,'_is_ip_safe',lambda _:True)
    monkeypatch.setattr(requests.sessions.Session,'request',Mock(side_effect=AssertionError('Unexpected real network')))
    monkeypatch.setattr(scanner.socket,'create_connection',Mock(side_effect=AssertionError('Unexpected real socket')))
    api.limiter.enabled=False
@pytest.mark.parametrize('method,body,headers,status,count',[
 ('sqli','sql syntax',{},200,1),('sqli','normal',{},200,0),
 ('xss',"<script>alert('XSS')</script>",{},200,0),('xss','normal',{},200,0),
 ('csrf','<form method="post"><input name="csrf_token"></form>',{},200,0),('csrf','<form method="post"></form>',{},200,1),
 ('headers','',{},200,3),('headers','',{'Strict-Transport-Security':'max-age=1','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'"},200,0),
 ('traversal','root:x:0:0',{},200,0),('traversal','normal',{},200,0),
 ('sensitive_files','DB_PASSWORD=test_fixture',{},200,1),('sensitive_files','Not Found',{},404,0),
 ('open_redirect','',{'Location':'https://evil.com'},302,1),('open_redirect','',{},200,0),
 ('cmdi','uid=1000(test)',{},200,0),('cmdi','normal',{},200,0),
 ('cors','',{'Access-Control-Allow-Origin':'*'},200,0),('cors','',{},200,0),
 ('clickjacking','',{},200,1),('clickjacking','',{'X-Frame-Options':'DENY'},200,0),
 ('tech_detect','',{'Server':'nginx/1.2','X-Powered-By':'PHP'},200,2),('tech_detect','',{},200,0),
 ('robots_sitemap','User-agent: *\nDisallow: /admin',{},200,1),('robots_sitemap','',{},404,0),
 ('waf','cloudflare',{'cf-ray':'fixture'},200,0),('waf','normal',{},200,0),
])
def test_module_baselines(method,body,headers,status,count):
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=response(body,status,headers))
    if method == 'sqli' and count:
        s._safe_get=Mock(side_effect=[response('normal'),response(body,status,headers)])
    getattr(s,'test_'+method)(U); assert len(s.findings)==count

def test_encoded_xss_not_vulnerable():
    s=scanner.WebShieldScanner(); s._safe_get=Mock(side_effect=lambda url,**kw: response(html.escape(kw['params']['q'])))
    s.test_xss(U); assert not s.findings

def test_sqli_error_status_detected():
    s=scanner.WebShieldScanner(); s._safe_get=Mock(side_effect=[response('ok')]+[response('SQL syntax error',500)]*4)
    s.test_sqli(U); assert s.findings

def test_csrf_no_form_no_finding():
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=response('<html>static page</html>'))
    s.test_csrf(U); assert not s.findings

def test_csrf_each_post_form_checked():
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=response('<form method="post"><input name="csrf_token"></form><form method="post"><input name="email"></form>'))
    s.test_csrf(U); assert s.findings

def test_soft404_not_sensitive_file():
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=response('<html>Page not found</html>'))
    s.test_sensitive_files(U); assert not s.findings

def test_redirect_307_detected():
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=response('',307,{'Location':'https://evil.com'}))
    s.test_open_redirect(U); assert s.findings

def test_cookie_value_not_attributes():
    s=scanner.WebShieldScanner(); r=response(); r.raw=SimpleNamespace(headers={'Set-Cookie':'session=secure_httponly_samesite; Path=/'})
    s._safe_get=Mock(return_value=r); s.test_cookies(U); assert s.findings

@pytest.mark.parametrize('secure', [True,False])
def test_cookies_baseline(secure):
    s=scanner.WebShieldScanner(); r=response(); r.raw=SimpleNamespace(headers={'Set-Cookie':'session=abc; Path=/'+('; Secure; HttpOnly; SameSite=Strict' if secure else '')})
    s._safe_get=Mock(return_value=r); s.test_cookies(U); assert bool(s.findings)==(not secure)

@pytest.mark.parametrize('blocked',[True,False])
def test_rate_limit(blocked):
    s=scanner.WebShieldScanner(); s.session.get=Mock(return_value=response('',429 if blocked else 200))
    s.test_rate_limiting(U); assert not s.findings and s.observations

def test_http_methods():
    s=scanner.WebShieldScanner(); s.session.options=Mock(return_value=response('',headers={'Allow':'GET, PUT, TRACE'}))
    s.session.request=Mock(side_effect=lambda method,url,**kw:response('TRACE / HTTP/1.1\r\nX-Mergen-Probe: '+kw['headers']['X-Mergen-Probe']))
    s.test_http_methods(U); assert len(s.findings)==1

def test_ports(monkeypatch):
    sock=Mock(); sock.connect_ex.side_effect=lambda target: 0 if target[1]==6379 else 1
    monkeypatch.setattr(scanner.socket,'socket',Mock(return_value=sock))
    s=scanner.WebShieldScanner(); s.test_subdomain_port(U); assert '6379/Redis' in s.findings[0]['detail']

def test_ssl_http():
    s=scanner.WebShieldScanner(); s.test_ssl('http://scanner-fixture.invalid'); assert s.findings[0]['severity']=='HIGH'

def test_ssl_invalid_cert(monkeypatch):
    monkeypatch.setattr(scanner.socket,'create_connection',Mock(side_effect=ssl.SSLCertVerificationError('fixture')))
    s=scanner.WebShieldScanner(); s.test_ssl(U); assert s.findings[0]['severity']=='HIGH'

def test_crawl():
    logs=[]; s=scanner.WebShieldScanner(log_callback=logs.append); s._safe_get=Mock(return_value=response('<a href="/inside">in</a><a href="https://outside.invalid">out</a>'))
    s.crawl_site(U); assert any('1 dahili' in line for line in logs)

def test_cancel():
    event=threading.Event(); event.set(); s=scanner.WebShieldScanner(cancel_event=event)
    with pytest.raises(Exception,match='iptal'): s.test_xss(U)

def init_scan():
    sid='test'; api.scan_queues[sid]=queue.Queue(); api.scan_results[sid]=None
    return sid

def test_run_scoring_and_status(monkeypatch):
    def finding(self,url): self.add_finding('fixture','HIGH','test','test')
    monkeypatch.setattr(scanner.WebShieldScanner,'test_xss',finding)
    sid=init_scan(); api.run_scan(sid,U,['xss'],threading.Event()); assert api.scan_results[sid]['score']==80
    c=api.app.test_client(); assert c.get('/api/status/test').json['done']; assert c.get('/api/status/test').json['done']

def test_run_error_not_perfect_score(monkeypatch):
    monkeypatch.setattr(scanner.WebShieldScanner,'test_xss',Mock(side_effect=RuntimeError('fixture failed')))
    sid=init_scan(); api.run_scan(sid,U,['xss'],threading.Event()); assert api.scan_results[sid].get('score')!=100

def test_unknown_module_rejected(monkeypatch):
    monkeypatch.setattr(api,'is_safe_url',lambda url:(True,'')); monkeypatch.setattr(api.executor,'submit',Mock())
    c=api.app.test_client(); r=c.post('/api/scan',json={'url':U,'modules':['nonexistent']}); assert r.status_code==400

@pytest.mark.parametrize('body',[{'url':123,'modules':['xss']},['wrong-shape']])
def test_malformed_input_400(body):
    r=api.app.test_client().post('/api/scan',json=body); assert r.status_code==400

@pytest.mark.parametrize('ip',['127.0.0.1','10.0.0.1','169.254.169.254'])
def test_private_url_rejected(monkeypatch,ip):
    monkeypatch.setattr(api.socket,'getaddrinfo',lambda *a, **kw: [(2,1,6,'',(ip,443))]); assert not api.is_safe_url(U)[0]

@pytest.mark.parametrize('path,content',[
    ('.env','DB_PASSWORD=fixture'),
    ('.git/config','[core]\nrepositoryformatversion = 0'),
    ('wp-config.php',"<?php define('DB_NAME', 'fixture');"),
    ('backup.sql','CREATE TABLE fixture (id INTEGER);'),
])
def test_sensitive_file_signatures_and_root(path,content):
    s=scanner.WebShieldScanner()
    s._safe_get=Mock(side_effect=lambda url: response(content) if url==U+'/'+path else response('',404))
    s.test_sensitive_files(U+'/nested/page?query=1')
    assert [f['title'] for f in s.findings]==['Hassas Dosya: '+path]

@pytest.mark.parametrize('status',[301,302,303,307,308])
def test_redirect_statuses(status):
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=response('',status,{'Location':'https://evil.com/path'}))
    s.test_open_redirect(U); assert len(s.findings)==1

def test_redirect_safe_path_not_external():
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=response('',302,{'Location':'/help/evil.com'}))
    s.test_open_redirect(U); assert not s.findings

def test_multiple_cookies():
    from urllib3._collections import HTTPHeaderDict
    headers=HTTPHeaderDict(); headers.add('Set-Cookie','safe=abc; Secure; HttpOnly; SameSite=Strict')
    headers.add('Set-Cookie','unsafe=abc; Path=/')
    r=response(); r.raw=SimpleNamespace(headers=headers)
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=r)
    s.test_cookies(U); assert [f['title'] for f in s.findings]==['Güvensiz Cookie: unsafe']

def test_cancelled_run_has_no_score():
    sid=init_scan(); event=threading.Event(); event.set()
    api.run_scan(sid,U,['xss'],event)
    assert api.scan_results[sid]['status']=='cancelled'
    assert api.scan_results[sid]['score'] is None

def test_timeout_result_not_overwritten():
    sid=init_scan(); api.scan_results[sid]={'status':'timeout','score':None}
    event=threading.Event(); event.set(); api.run_scan(sid,U,['xss'],event)
    assert api.scan_results[sid]=={'status':'timeout','score':None}

@pytest.mark.parametrize('modules',['xss',[{}],[1],None,[],['bad']])
def test_invalid_modules_400(modules):
    r=api.app.test_client().post('/api/scan',json={'url':U,'modules':modules})
    assert r.status_code==400

def test_all_modules_visible():
    import re
    html=(Path(__file__).resolve().parents[1]/'static/app.js').read_text()
    block=html.split('const modules = [',1)[1].split('];',1)[0]
    assert set(re.findall(r"id: '([^']+)'",block))==api.SCAN_MODULES-{'crawl'}

