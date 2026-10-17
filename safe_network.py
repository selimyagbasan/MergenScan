"""Outbound HTTP and socket policy for untrusted scan/feed destinations.

Resolve once, reject *every* non-public DNS answer, and connect to a numeric
address. Host headers, TLS SNI and certificate verification retain the name.
Requests redirects pass through the adapter again, including OPTIONS/TRACE.
"""
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REQUEST_SECONDS = 12


class UnsafeTarget(requests.RequestException):
    pass


class RequestDeadline:
    """Interrupt headers, TLS and body reads, including a continuously dripping peer.

    Keep a duplicate descriptor: wrapping the original in TLS transfers its file
    descriptor, but shutdown on this duplicate still interrupts the same socket.
    DNS resolution precedes this network I/O deadline.
    """
    def __init__(self, seconds):
        self.lock = threading.Lock()
        self.socket = None
        self.expired = False
        self.timer = threading.Timer(seconds, self.expire)
        self.timer.daemon = True
        self.timer.start()

    def bind(self, sock):
        with self.lock:
            if self.expired:
                sock.close()
                raise requests.Timeout('Bağlantı zaman sınırını aştı.')
            self.socket = sock.dup()

    def expire(self):
        with self.lock:
            self.expired = True
            if self.socket is not None:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.socket.close()
                self.socket = None

    def close(self):
        self.timer.cancel()
        with self.lock:
            if self.socket is not None:
                self.socket.close()
                self.socket = None


def public_addresses(host, port):
    if not host or '%' in host:
        raise UnsafeTarget('Geçersiz hedef adresi.')
    try:
        addresses = list(dict.fromkeys(
            item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ))
        if not addresses:
            raise ValueError('empty DNS answer')
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global or ip.is_multicast:
                raise ValueError('non-public address')
            if isinstance(ip, ipaddress.IPv6Address):
                # Avoid mapped/transition addresses carrying a second destination.
                if (ip.ipv4_mapped or ip.sixtofour or ip.teredo
                        or ip in ipaddress.ip_network('64:ff9b::/96')
                        or ip in ipaddress.ip_network('64:ff9b:1::/48')):
                    raise ValueError('transition address')
        return addresses
    except (OSError, ValueError) as exc:
        raise UnsafeTarget('Hedef çözümlenemedi veya genel internete açık değil.') from exc


def validated_target(url):
    try:
        if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 32 for c in url):
            raise ValueError('invalid URL')
        parsed = urlsplit(url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or '\\' in parsed.netloc):
            raise ValueError('unsupported URL')
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
        if not 1 <= port <= 65535:
            raise ValueError('invalid port')
        return parsed, public_addresses(parsed.hostname, port), port
    except ValueError as exc:
        raise UnsafeTarget('Geçerli bir HTTP/HTTPS adresi girin; kullanıcı bilgisi eklemeyin.') from exc


class PublicHTTPAdapter(HTTPAdapter):
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        parsed, addresses, port = validated_target(request.url)
        host = parsed.hostname.encode('idna').decode('ascii')
        authority = f'[{host}]' if ':' in host else host
        default_port = 443 if parsed.scheme == 'https' else 80
        if port != default_port:
            authority += f':{port}'
        headers = dict(request.headers)
        headers['Host'] = authority
        # Never forward caller credentials or session cookies to arbitrary targets.
        for key in list(headers):
            if key.lower() in ('authorization', 'proxy-authorization', 'cookie'):
                del headers[key]
        pool_cls = urllib3.HTTPSConnectionPool if parsed.scheme == 'https' else urllib3.HTTPConnectionPool
        options = {}
        if parsed.scheme == 'https':
            options.update(cert_reqs=ssl.CERT_REQUIRED, ca_certs=requests.certs.where(),
                           assert_hostname=host, server_hostname=host)
        seconds = min(float(timeout or 8), MAX_REQUEST_SECONDS)
        pool = pool_cls(addresses[0], port=port, timeout=seconds, retries=False, **options)
        deadline = RequestDeadline(MAX_REQUEST_SECONDS)
        class DeadlineConnection(pool.ConnectionCls):
            def _new_conn(self):
                sock = super()._new_conn()
                deadline.bind(sock)
                return sock
        pool.ConnectionCls = DeadlineConnection
        raw = None
        started = time.monotonic()
        try:
            raw = pool.urlopen(request.method, request.path_url, body=request.body,
                               headers=headers, redirect=False, retries=False,
                               preload_content=False, decode_content=True)
            chunks, size = [], 0
            while True:
                if deadline.expired or time.monotonic() - started > MAX_REQUEST_SECONDS:
                    raise requests.Timeout('Yanıt zaman sınırını aştı.')
                chunk = raw.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size), decode_content=True)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise requests.RequestException('Yanıt izin verilen boyutu aştı.')
                chunks.append(chunk)
            if deadline.expired:
                raise requests.Timeout('Yanıt zaman sınırını aştı.')
            response = self.build_response(request, raw)
            response._content = b''.join(chunks)
            response._content_consumed = True
            return response
        except urllib3.exceptions.HTTPError as exc:
            if deadline.expired:
                raise requests.Timeout('Yanıt zaman sınırını aştı.') from exc
            raise requests.ConnectionError('Hedef bağlantısı tamamlanamadı.') from exc
        finally:
            deadline.close()
            if raw is not None:
                raw.close()
            pool.close()


def public_session():
    session = requests.Session()
    session.trust_env = False  # No environment proxies or netrc credentials.
    session.max_redirects = 5
    session.mount('http://', PublicHTTPAdapter())
    session.mount('https://', PublicHTTPAdapter())
    return session
