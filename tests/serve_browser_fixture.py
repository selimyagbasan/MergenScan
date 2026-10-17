"""Start the real app and a local target for browser tests only."""
import json
import sys
import threading
import time
from pathlib import Path
from http.server import ThreadingHTTPServer
from werkzeug.serving import make_server
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as api
import safe_network
import scanner
from test_http_integration import FixtureHandler

lab=ThreadingHTTPServer(('127.0.0.1',0),FixtureHandler)
threading.Thread(target=lab.serve_forever,daemon=True).start()
def fixture_addresses(host,port):
    if host!='lab.invalid': raise safe_network.UnsafeTarget('Unexpected test target')
    return ['127.0.0.1']
safe_network.public_addresses=fixture_addresses
scanner.public_addresses=fixture_addresses
api.REQUIRE_AUTH=True
api.API_KEY='browser-fixture-key'
api.limiter.enabled=False
api._news_cache.update(data=[
    {'title':'Bad link','link':'javascript:alert(1)','image':''},
    {'title':'<img src=x onerror=alert(1)>','link':'https://news.invalid/','image':'data:text/html,bad'},
],ts=time.time())
server=make_server('127.0.0.1',0,api.app,threaded=True)
print(json.dumps({'app':f'http://127.0.0.1:{server.server_port}','target':f'http://lab.invalid:{lab.server_port}'}),flush=True)
server.serve_forever()
