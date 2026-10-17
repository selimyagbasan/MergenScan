"""Differential detection tests: safe controls and vulnerable-shaped replies."""
import html
import queue
import re
import threading
from urllib.parse import parse_qs, urlparse
from unittest.mock import Mock
import pytest
import requests
import app as api
import scanner
from detection import frame_policy
from detection import active_html_reflection

URL = 'https://fixture.invalid/'


@pytest.mark.parametrize('markup', [
    '<img onerror="" onerror="alert(\'m\')">',
    '<script type="application/json" type="text/javascript">alert(\'m\')</script>',
])
def test_duplicate_attributes_keep_first(markup):
    assert not active_html_reflection(reply(markup), 'm')


@pytest.mark.parametrize('source', ['https://*', 'http://*', 'https://*:443'])
def test_wildcard_frame_ancestor_is_permissive(source):
    assert frame_policy('frame-ancestors '+source) == 'permissive'


def test_invalid_uppercase_cors_credentials():
    s = scanner.WebShieldScanner()
    s._safe_get = Mock(side_effect=lambda url, **kw: reply(headers={
        'Access-Control-Allow-Origin': kw['headers']['Origin'],
        'Access-Control-Allow-Credentials': 'True'}))
    s.test_cors(URL)
    assert not s.findings


def test_redirect_existing_next_is_replaced():
    def first_parameter_server(url, **kw):
        query = parse_qs(urlparse(url).query)
        for key, value in kw['params'].items():
            query.setdefault(key, []).append(value)
        return reply(status=302, headers={'Location': query['next'][0]})
    s = scanner.WebShieldScanner()
    s._safe_get = Mock(side_effect=first_parameter_server)
    s.test_open_redirect(URL+'?next=/safe')
    assert len(s.findings) == 1


def reply(text='',status=200,content_type='text/html',headers=None):
    r=requests.Response(); r.status_code=status; r._content=text.encode()
    r.headers['Content-Type']=content_type; r.headers.update(headers or {})
    return r


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(scanner.time,'sleep',lambda _:None)
    monkeypatch.setattr(requests.sessions.Session,'request',Mock(side_effect=AssertionError('Unexpected network')))
    monkeypatch.setattr(api,'REQUIRE_AUTH',False)
    monkeypatch.setattr(api.limiter,'enabled',False)


@pytest.mark.parametrize('context,expected',[
    ('{}',True),('<div>{}</div>',True),('<textarea>{}</textarea>',False),
    ('<title>{}</title>',False),('<!--{}-->',False),('<template>{}</template>',False),
    ('<script type="application/json">{{"value": "{}"}}</script>',False),
])
def test_xss_contexts(context,expected):
    s=scanner.WebShieldScanner()
    s._safe_get=Mock(side_effect=lambda url,**kw:reply(context.format(kw['params']['q'])))
    s.test_xss(URL)
    assert bool(s.findings)==expected


@pytest.mark.parametrize('kind',['escaped','json','plain','attribute','script-string'])
def test_xss_inert_reflection(kind):
    def respond(url,**kw):
        value=kw['params']['q']
        if kind=='escaped': return reply(html.escape(value))
        if kind=='json': return reply(value,content_type='application/json')
        if kind=='plain': return reply(value,content_type='text/plain')
        if kind=='attribute': return reply('<input value="'+html.escape(value,quote=True)+'">')
        return reply('<script>const value='+repr(value.replace('</script>','<\\/script>'))+';</script>')
    s=scanner.WebShieldScanner(); s._safe_get=Mock(side_effect=respond)
    s.test_xss(URL); assert not s.findings


def test_sqli_new_error_even_when_baseline_has_another_signature():
    s=scanner.WebShieldScanner(); s._safe_get=Mock(side_effect=[reply('sqlite3 documentation'),reply('sqlite3 documentation; PDOException',500)])
    s.test_sqli(URL); assert len(s.findings)==1


def test_existing_parameter_replaced_and_others_preserved():
    seen=[]
    def respond(url,**kw):
        query=parse_qs(urlparse(url).query); params=kw['params']; seen.append((query,params))
        assert not set(query)&set(params)
        assert query['lang']==['tr']
        return reply('sql syntax',500) if params.get('item')=="'" else reply('ok')
    s=scanner.WebShieldScanner(); s._safe_get=Mock(side_effect=respond)
    s.test_sqli(URL+'?item=5&lang=tr')
    assert s.findings and 'item' in s.findings[0]['detail']


@pytest.mark.parametrize('mode',['executed','reflected','static-uid'])
def test_command_unique_output(mode):
    def respond(url,**kw):
        cmd=kw['params']['cmd']
        if mode=='executed' and cmd.startswith('; printf'):
            token=re.search(r"'([a-f0-9]{16})'$",cmd).group(1)
            return reply('mergen_'+token)
        if mode=='reflected': return reply(cmd)
        return reply('uid=1000(user) gid=1000(user) groups=1000(user)')
    s=scanner.WebShieldScanner(); s._safe_get=Mock(side_effect=respond)
    s.test_cmdi(URL); assert bool(s.findings)==(mode=='executed')


@pytest.mark.parametrize('static',[False,True])
def test_traversal_requires_new_record(static):
    s=scanner.WebShieldScanner()
    s._safe_get=Mock(side_effect=lambda url,**kw:reply('root:x:0:0:root:/root:/bin/sh' if static or '../' in kw['params']['file'] else 'not found'))
    s.test_traversal(URL); assert bool(s.findings)==(not static)


@pytest.mark.parametrize('mode',['public','reflect-credentials','reflect-only','fixed'])
def test_cors_evidence(mode):
    def respond(url,**kw):
        origin=kw['headers']['Origin']
        headers={'Access-Control-Allow-Origin': '*' if mode=='public' else 'https://trusted.invalid' if mode=='fixed' else origin}
        if mode=='reflect-credentials': headers['Access-Control-Allow-Credentials']='true'
        return reply(headers=headers)
    s=scanner.WebShieldScanner(); s._safe_get=Mock(side_effect=respond)
    s.test_cors(URL); assert bool(s.findings)==(mode=='reflect-credentials')


@pytest.mark.parametrize('normal,probe',[(200,200),(503,503),(200,403),(403,403)])
def test_waf_is_observation_not_vulnerability(normal,probe):
    s=scanner.WebShieldScanner(); s._safe_get=Mock(side_effect=[reply(status=normal),reply(status=probe)])
    s.test_waf(URL); assert not s.findings and len(s.observations)==1
    if normal!=200 or probe!=403: assert 'doğrulanamadı' in s.observations[0]['detail']


@pytest.mark.parametrize('policy,expected',[
    ("frame-ancestors 'self'",'restrictive'),("frame-ancestors 'none'",'restrictive'),
    ('frame-ancestors *','permissive'),('frame-ancestors https:','permissive'),
    ("default-src 'self'; report-uri /frame-ancestors",'missing'),
    ('frame-ancestors','unknown'),("frame-ancestors *; frame-ancestors 'none'",'permissive'),
    ("frame-ancestors *, frame-ancestors 'none'",'restrictive'),
])
def test_frame_policy_values(policy,expected): assert frame_policy(policy)==expected


def test_permissive_csp_overrides_xfo():
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=reply(headers={'X-Frame-Options':'DENY','Content-Security-Policy':'frame-ancestors *'}))
    s.test_clickjacking(URL); assert s.findings


def test_options_allow_not_proof_of_unauthorized_write():
    s=scanner.WebShieldScanner(); s.session.options=Mock(return_value=reply(headers={'Allow':'GET, PUT, DELETE'}))
    s.session.request=Mock(return_value=reply(status=405))
    s.test_http_methods(URL); assert not s.findings and s.observations
    assert s.session.request.call_args.args[0]=='TRACE'


@pytest.mark.parametrize('method',['test_csrf','test_headers','test_cookies','test_clickjacking','test_tech_detect'])
def test_blocked_page_not_claimed_success(method):
    s=scanner.WebShieldScanner(); s._safe_get=Mock(return_value=reply(status=403))
    with pytest.raises(RuntimeError): getattr(s,method)(URL)


def test_worker_continues_and_reports_failed_module(monkeypatch):
    api.scan_queues['accuracy']=queue.Queue(); api.scan_results['accuracy']=None
    monkeypatch.setattr(scanner.WebShieldScanner,'test_xss',Mock(side_effect=RuntimeError('blocked')))
    monkeypatch.setattr(scanner.WebShieldScanner,'_safe_get',lambda *a,**kw:reply())
    api.run_scan('accuracy',URL,['xss','headers'],threading.Event())
    result=api.scan_results['accuracy']
    assert result['score'] is None and result['status']=='error'
    assert result['counts']['MEDIUM']==3
    assert [c['status'] for c in result['checks']]==['error','completed']
