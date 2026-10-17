#!/usr/bin/env python3
import time
from http.cookies import SimpleCookie, CookieError
import socket
import ssl
import datetime
import re as _re
import requests
import secrets
from detection import active_html_reflection, frame_policy
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse

from safe_network import public_session, public_addresses, UnsafeTarget

def _is_ip_safe(host):
    try:
        public_addresses(host, 443)
        return True
    except Exception:
        return False

class WebShieldScanner:
    def __init__(self, log_callback=None, cancel_event=None):
        self.log_callback = log_callback
        self.cancel_event = cancel_event
        self.findings     = []
        self.observations = []
        self.session = public_session()
        self.session.verify = True
        self.session.headers.update({"User-Agent": "WebShield-Scanner/2.0"})

    def _log(self, msg):
        try:
            print(msg)
        except UnicodeEncodeError:
            print(msg.encode('ascii', 'replace').decode('ascii'))
        if self.log_callback:
            self.log_callback(msg)

    def _check_cancel(self):
        if self.cancel_event and self.cancel_event.is_set():
            raise Exception("Tarama kullanıcı tarafından iptal edildi.")

    def add_finding(self, title, severity, detail, fix, confidence="heuristic"):
        self.findings.append({"title": title, "severity": severity, "detail": detail,
                              "fix": fix, "confidence": confidence})

    def observe(self, module, detail):
        self.observations.append({"module": module, "detail": detail})
        self._log(f"[i] {detail}")

    def _parameters(self, url, default):
        names = list(dict.fromkeys(key for key, _ in parse_qsl(urlparse(url).query)))
        return names[:3] if names else [default]

    def _probe(self, url, parameter, value, **kwargs):
        self._check_cancel()
        parsed = urlparse(url)
        query = [(key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True)
                 if key != parameter]
        clean = urlunparse(parsed._replace(query=urlencode(query), fragment=""))
        return self._safe_get(clean, params={parameter: value}, **kwargs)

    def _safe_get(self, url, timeout=8, **kwargs):
        self._check_cancel()
        host = urlparse(url).hostname or ""
        if not _is_ip_safe(host):
            self._log(f"[!] Güvensiz IP, istek engellendi: {url}")
            raise UnsafeTarget("Hedef güvenlik denetimini geçemedi.")
        try:
            return self.session.get(url, timeout=timeout, **kwargs)
        except Exception as e:
            self._log(f"[!] İstek hatası ({url}): {e}")
            raise RuntimeError(f"İstek tamamlanamadı: {url}") from e

    def _page(self, url, **kwargs):
        reply = self._safe_get(url, **kwargs)
        if reply.status_code >= 400:
            raise RuntimeError(f"Sayfa HTTP {reply.status_code} döndürdü; kontrol tamamlanamadı.")
        return reply

    def crawl_site(self, url, limit=50):
        self._check_cancel()
        self._log(f"[i] Crawl başlatılıyor → {url}")
        r = self._page(url)
        if not r:
            return
        links = set()
        for m in _re.finditer(r'href=["\']([^"\'\ >]+)', r.text):
            href = m.group(1)
            full = urljoin(url, href)
            parsed = urlparse(full)
            base   = urlparse(url)
            if parsed.netloc == base.netloc and parsed.scheme in ('http','https'):
                links.add(full)
        self._log(f"[i] {len(links)} dahili bağlantı keşfedildi.")
        for link in list(links)[:limit]:
            self._log(f"  → {link}")
        time.sleep(0.5)

    def test_sqli(self, url):
        self._check_cancel()
        errors = ["sql syntax", "mysql_fetch", "ora-", "sqlite3", "pdoexception",
                  "unclosed quotation mark", "unterminated quoted string", "syntax error at or near"]
        for parameter in self._parameters(url, "id"):
            baseline = self._probe(url, parameter, "1")
            if baseline.status_code in (401, 403, 429):
                raise RuntimeError("SQL kontrolü hedef tarafından engellendi.")
            known = {error for error in errors if error in baseline.text.lower()}
            for payload in ["'", "' OR '1'='1", "' OR 1=1--", "admin'--"]:
                reply = self._probe(url, parameter, payload)
                new_errors = {error for error in errors if error in reply.text.lower()} - known
                if new_errors:
                    self.add_finding("Olası SQL Injection", "HIGH",
                        f"{parameter!r} parametresi normal yanıtta olmayan SQL hata izleri üretti: {', '.join(sorted(new_errors))}. Manuel doğrulama gerekir.",
                        "Parametreli sorgu kullanın ve ayrıntılı veritabanı hatalarını istemciye göstermeyin.", "differential")
                    return
        self.observe("sqli", "Hata tabanlı kontrol tamamlandı; kör SQLi ve POST gövdeleri test edilmedi.")

    def test_xss(self, url):
        self._check_cancel()
        marker = "mergen_" + secrets.token_hex(8)
        for parameter in self._parameters(url, "q"):
            for payload in [f"<script>alert('{marker}')</script>", f"\"><img src=x onerror=alert('{marker}')>"]:
                reply = self._probe(url, parameter, payload)
                if reply.status_code in (401, 403, 429):
                    raise RuntimeError("XSS kontrolü hedef tarafından engellendi.")
                if active_html_reflection(reply, marker):
                    self.add_finding("Olası Yansıtılan XSS", "HIGH",
                        f"{parameter!r} parametresindeki benzersiz işaret HTML script/olay bağlamında yansıtıldı. Tarayıcıda çalıştırma ve CSP etkisi ayrıca doğrulanmalıdır.",
                        "Çıktı bağlamına uygun kodlama ve sıkı Content-Security-Policy uygulayın.", "contextual")
                    return
        self.observe("xss", "Test edilen HTML bağlamlarında aktif yansıma bulunamadı; DOM ve stored XSS test edilmedi.")

    def test_csrf(self, url):
        self._check_cancel()
        self._log("[i] CSRF korumaları kontrol ediliyor...")
        r = self._page(url)
        if not r:
            return

        from html.parser import HTMLParser
        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
                self.current = None

            def handle_starttag(self, tag, attrs):
                d = dict(attrs)
                if tag == "form":
                    self.current = {
                        "id": d.get("id"),
                        "post": (d.get("method") or "get").lower() == "post",
                        "token": False,
                    }
                    self.forms.append(self.current)
                elif tag == "input":
                    name = (d.get("name") or "").lower()
                    if "csrf" in name or "token" in name:
                        owner = d.get("form")
                        if owner:
                            token_owners.add(owner)
                        elif self.current is not None:
                            self.current["token"] = True

            def handle_endtag(self, tag):
                if tag == "form":
                    self.current = None

        token_owners = set()
        parser = FormParser()
        parser.feed(r.text)
        missing = sum(1 for form in parser.forms if form["post"]
                      and not form["token"] and form["id"] not in token_owners)
        if missing:
            self.add_finding(
                "CSRF Token Eksik", "MEDIUM",
                f"{missing} POST formunda CSRF token alanı bulunamadı; sunucu koruması ayrıca doğrulanmalıdır.",
                "Durum değiştiren formlarda CSRF korumasını doğrulayın."
            )
            self._log(f"[!] {missing} POST formunda CSRF token eksik.")
        else:
            self._log("[✓] Tokensiz POST formu tespit edilmedi.")
        time.sleep(0.5)

    def test_headers(self, url):
        self._check_cancel()
        self._log("[i] HTTP güvenlik başlıkları inceleniyor...")
        r = self._page(url)
        if not r:
            return
        required = {
            "Strict-Transport-Security": "MEDIUM",
            "X-Frame-Options":           "MEDIUM",
            "Content-Security-Policy":   "MEDIUM",
        }
        missing = [h for h in required if h not in r.headers]
        for h in missing:
            self.add_finding(
                f"Eksik Başlık: {h}", required[h],
                "Güvenlik başlığı eksik.",
                f"Sunucuya {h} ekleyin."
            )
        if missing:
            self._log(f"[!] Eksik başlıklar: {missing}")
        else:
            self._log("[✓] Güvenlik başlıkları mevcut.")
        time.sleep(0.5)

    def test_traversal(self, url):
        self._check_cancel()
        signature = r"(?m)^root:[^:\r\n]*:0:0:[^:\r\n]*:[^:\r\n]*:[^\r\n]+$"
        for parameter in self._parameters(url, "file"):
            baseline = self._probe(url, parameter, "mergen-nonexistent-" + secrets.token_hex(8))
            if _re.search(signature, baseline.text):
                self.observe("traversal", "Normal yanıtta dosya imzası zaten var; traversal doğrulanamadı.")
                continue
            for payload in ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]:
                reply = self._probe(url, parameter, payload)
                if _re.search(signature, reply.text):
                    self.add_finding("Olası Path Traversal", "HIGH",
                        f"{parameter!r} parametresinde normal yanıtta olmayan passwd dosyası kaydı döndü.",
                        "Dosya yollarını izin listesiyle kısıtlayın ve uygulama kökü dışını engelleyin.", "differential")
                    return

    def test_sensitive_files(self, url):
        self._check_cancel()
        self._log("[i] Hassas dosya sızıntıları kontrol ediliyor...")
        signatures = {
            ".env": r"(?m)^\s*(?:export\s+)?[A-Z_][A-Z0-9_]*\s*=\s*[^\r\n]+",
            ".git/config": r"(?m)^\s*\[(?:core|remote\s+[^\]]+)\]\s*$",
            "wp-config.php": r"(?s)<\?php.*define\s*\(\s*['\"]DB_(?:NAME|USER|PASSWORD|HOST)['\"]",
            "backup.sql": r"(?im)^\s*(?:CREATE\s+TABLE|INSERT\s+INTO|--\s*(?:MySQL|PostgreSQL).*dump)\b",
        }
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}/"
        found = False
        for path, signature in signatures.items():
            r = self._safe_get(urljoin(base, path))
            if (r is not None and r.status_code == 200
                    and not _re.search(r"<\s*(?:!doctype|html|body)\b", r.text, _re.I)
                    and _re.search(signature, r.text)):
                self.add_finding(
                    f"Hassas Dosya: {path}", "HIGH",
                    f"{path} herkese açık.",
                    "Dosyayı gizleyin veya erişimi engelleyin."
                )
                self._log(f"[✗] Bulundu: {path}")
                found = True
        if not found:
            self._log("[✓] Hassas dosya sızıntısı yok.")
        time.sleep(0.5)

    def test_open_redirect(self, url):
        self._check_cancel()
        self._log("[i] Open Redirect denemeleri yapılıyor...")
        r = self._probe(url, "next", "https://evil.com", allow_redirects=False)
        destination = urlparse(urljoin(url, r.headers.get("Location", ""))) if r is not None else None
        if r is not None and r.status_code in (301, 302, 303, 307, 308) and destination.hostname == "evil.com":
            self.add_finding(
                "Open Redirect", "MEDIUM",
                "Dış URL'ye yönlendirme yapıldı.",
                "İzin verilen URL'leri whitelist ile kısıtlayın."
            )
            self._log("[✗] Open Redirect bulundu!")
        else:
            self._log("[✓] Open Redirect tespit edilmedi.")
        time.sleep(0.5)

    def test_cmdi(self, url):
        self._check_cancel()
        # The output marker is deliberately absent from the request text, so an
        # ordinary echo cannot look like command execution. No file is modified.
        token = secrets.token_hex(8)
        marker = "mergen_" + token
        for parameter in self._parameters(url, "cmd"):
            baseline = self._probe(url, parameter, "mergen-control-" + token)
            payload = f"; printf 'mergen_%s' '{token}'"
            reply = self._probe(url, parameter, payload)
            if baseline.status_code in (401, 403, 429) or reply.status_code in (401, 403, 429):
                raise RuntimeError("Komut enjeksiyonu kontrolü hedef tarafından engellendi.")
            if marker in reply.text and marker not in baseline.text:
                self.add_finding("Olası Command Injection", "HIGH",
                    f"{parameter!r} parametresi, istekte bitişik bulunmayan benzersiz komut çıktısını döndürdü.",
                    "Kullanıcı girdisini shell komutuna birleştirmeyin; shell=False ve izinli argümanlar kullanın.", "differential")
                return
        self.observe("cmdi", "Unix printf çıktısı doğrulanamadı; kör ve Windows komut enjeksiyonu kapsam dışıdır.")

    def test_ssl(self, url):
        self._check_cancel()
        self._log("[i] SSL/TLS sertifikası kontrol ediliyor...")
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        if parsed.scheme != "https":
            self.add_finding("HTTPS Kullanılmıyor", "HIGH",
                "Site HTTPS yerine HTTP kullanıyor.",
                "SSL/TLS sertifikası edinin ve HTTPS'e geçin.")
            self._log("[✗] Site HTTPS kullanmıyor!")
            time.sleep(0.5)
            return
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((public_addresses(host, port)[0], port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    na = cert.get('notAfter', '')
                    exp = datetime.datetime.strptime(na, '%b %d %H:%M:%S %Y %Z')
                    days = (exp - datetime.datetime.utcnow()).days
                    if days < 0:
                        self.add_finding("SSL Sertifikası Süresi Dolmuş", "HIGH",
                            f"Sertifika {abs(days)} gün önce doldu.",
                            "SSL sertifikanızı acilen yenileyin.")
                        self._log("[✗] SSL sertifikası süresi dolmuş!")
                    elif days < 30:
                        self.add_finding("SSL Sertifikası Yakında Dolacak", "MEDIUM",
                            f"Sertifika {days} gün içinde dolacak.",
                            "SSL sertifikanızı yenileyin.")
                        self._log(f"[!] SSL sertifikası {days} gün içinde dolacak.")
                    else:
                        self._log(f"[✓] SSL sertifikası geçerli ({days} gün kaldı).")
                    proto = ssock.version()
                    if proto and proto in ('TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3'):
                        self.add_finding(f"Eski TLS Protokolü: {proto}", "MEDIUM",
                            f"Sunucu güvensiz protokol kullanıyor: {proto}.",
                            "TLS 1.2 veya TLS 1.3'e yükseltin.")
                        self._log(f"[!] Eski TLS protokolü: {proto}")
                    else:
                        self.observe("ssl", f"Bu bağlantı {proto} kullanıyor; diğer TLS protokolleri için uyumluluk taraması yapılmadı.")
        except ssl.SSLCertVerificationError as e:
            self.add_finding("SSL Sertifika Doğrulama Hatası", "HIGH",
                f"Sertifika doğrulanamadı: {str(e)[:200]}",
                "Güvenilir bir CA'dan geçerli SSL sertifikası edinin.")
            self._log("[✗] SSL sertifikası doğrulanamadı!")
        except Exception as e:
            raise RuntimeError("SSL kontrolü tamamlanamadı.") from e
        time.sleep(0.5)

    def test_cors(self, url):
        self._check_cancel()
        origin = "https://" + secrets.token_hex(8) + ".mergen-test.invalid"
        reply = self._page(url, headers={"Origin": origin})
        allowed = reply.headers.get("Access-Control-Allow-Origin", "")
        credentials = reply.headers.get("Access-Control-Allow-Credentials", "") == "true"
        if allowed == origin and credentials:
            self.add_finding("Olası CORS Origin Yansıtma", "MEDIUM",
                "Rastgele origin, credentials izniyle birlikte kabul edildi. Hassas veriye erişim ayrıca doğrulanmalıdır.",
                "Origin değerini güvenilir adreslerle karşılaştırın; kullanıcı girdisini doğrudan yansıtmayın.", "differential")
        elif allowed == "*":
            self.observe("cors", "Wildcard CORS görüldü. Genel kaynaklarda geçerli olabilir; tek başına açık değildir.")
        else:
            self.observe("cors", "Test edilen origin için credentials ile yansıtma görülmedi; farklı uç noktalar ayrı incelenmelidir.")

    def test_cookies(self, url):
        self._check_cancel()
        self._log("[i] Cookie bayrakları kontrol ediliyor...")
        r = self._page(url)
        if not r:
            return
        raw_headers = getattr(r.raw, 'headers', None)
        if raw_headers is not None and hasattr(raw_headers, 'getlist'):
            cookie_hdrs = raw_headers.getlist('Set-Cookie')
        else:
            cookie_hdrs = [v for k, v in (raw_headers or r.headers).items() if k.lower() == 'set-cookie']
        if not cookie_hdrs:
            self._log("[✓] Yanıtta Set-Cookie başlığı yok.")
            time.sleep(0.5)
            return
        found_issue = False
        for cs in cookie_hdrs:
            cookie = SimpleCookie()
            try:
                cookie.load(cs)
            except CookieError:
                self._log("[!] Cookie başlığı ayrıştırılamadı.")
                continue
            if not cookie:
                continue
            name, morsel = next(iter(cookie.items()))
            missing = [label for attr, label in
                       [('secure', 'Secure'), ('httponly', 'HttpOnly'), ('samesite', 'SameSite')]
                       if not morsel[attr]]
            if missing:
                self.add_finding(f"Güvensiz Cookie: {name}", "MEDIUM",
                    f"Cookie '{name}' eksik bayraklar: {', '.join(missing)}.",
                    "Tüm cookie'lere Secure, HttpOnly ve SameSite=Strict ekleyin.")
                self._log(f"[!] Cookie '{name}': eksik → {', '.join(missing)}")
                found_issue = True
        if not found_issue:
            self._log("[✓] Cookie bayrakları uygun.")
        time.sleep(0.5)

    def test_http_methods(self, url):
        self._check_cancel()
        response = self.session.options(url, timeout=8)
        allowed = {method.strip().upper() for method in response.headers.get('Allow', '').split(',')}
        if allowed & {'PUT', 'DELETE'}:
            self.observe("methods", "PUT/DELETE ilan ediliyor; veri değiştiren istek gönderilmedi, yetkisiz yazma doğrulanmadı.")
        marker = secrets.token_hex(8)
        traced = self.session.request('TRACE', url, headers={'X-Mergen-Probe': marker}, timeout=8)
        if traced.status_code == 200 and _re.search(r"(?im)^X-Mergen-Probe:\s*" + marker + r"\s*$", traced.text):
            self.add_finding("TRACE İsteği Yansıtılıyor", "LOW",
                "Benzersiz test başlığı TRACE yanıtında yansıtıldı; duyarlı veri gönderilmedi.",
                "Gerekmiyorsa TRACE metodunu kapatın.", "differential")
        else:
            self.observe("methods", "TRACE yansıması doğrulanmadı; Allow başlığı tek başına metod erişimini kanıtlamaz.")

    def test_clickjacking(self, url):
        self._check_cancel()
        self._log("[i] Clickjacking kontrolü...")
        r = self._page(url)
        if not r:
            return
        xfo = r.headers.get('X-Frame-Options', '').upper()
        csp = r.headers.get('Content-Security-Policy', '')
        has_xfo = xfo in ('DENY', 'SAMEORIGIN')
        policy = frame_policy(csp)
        protected = policy == 'restrictive' or (policy == 'missing' and has_xfo)
        if not protected:
            self.add_finding("Clickjacking Koruması Eksik", "MEDIUM",
                "Kısıtlayıcı bir frame-ancestors politikası veya geçerli X-Frame-Options doğrulanamadı. Başlık kontrolü, tarayıcı testi değildir.",
                "X-Frame-Options: DENY veya CSP frame-ancestors: 'self' ekleyin.")
            self._log("[!] Clickjacking koruması eksik.")
        else:
            self._log("[✓] Clickjacking koruması mevcut.")
        time.sleep(0.5)

    def test_rate_limiting(self, url):
        self._check_cancel()
        self._log("[i] Rate Limiting test ediliyor...")
        host = urlparse(url).hostname or ""
        if not _is_ip_safe(host):
            raise UnsafeTarget("Hedef güvenlik denetimini geçemedi.")
        blocked = False
        try:
            for i in range(15):
                self._check_cancel()
                r = self.session.get(url, timeout=5)
                if r.status_code >= 400 and r.status_code != 429:
                    raise RuntimeError(f'Rate limit kontrolü HTTP {r.status_code} ile engellendi.')
                if r.status_code == 429:
                    blocked = True
                    break
        except Exception as exc:
            raise RuntimeError("Rate limit kontrolü tamamlanamadı.") from exc
        self.observe("ratelimit", "429 yanıtı gözlendi; limit eşiği ve kapsamı ölçülmedi." if blocked else
                     "15 istekte 429 gözlenmedi. Daha yüksek, kullanıcıya veya uç noktaya özel limitler olabilir; açık olarak puanlanmadı.")

    def test_tech_detect(self, url):
        self._check_cancel()
        self._log("[i] Teknoloji tespiti yapılıyor...")
        r = self._page(url)
        if not r:
            return
        techs = []
        server = r.headers.get('Server', '')
        if server:
            techs.append(f"Server: {server}")
            if any(c.isdigit() for c in server):
                self.add_finding("Sunucu Versiyon Sızıntısı", "LOW",
                    f"Server başlığı versiyon bilgisi içeriyor: {server}.",
                    "Server başlığından versiyon bilgisini kaldırın.")
        powered = r.headers.get('X-Powered-By', '')
        if powered:
            techs.append(f"X-Powered-By: {powered}")
            self.add_finding("Teknoloji Bilgisi Sızıntısı", "LOW",
                f"X-Powered-By başlığı teknoloji bilgisi sızdırıyor: {powered}.",
                "X-Powered-By başlığını kaldırın.")
        aspnet = r.headers.get('X-AspNet-Version', '')
        if aspnet:
            techs.append(f"ASP.NET: {aspnet}")
            self.add_finding("ASP.NET Versiyon Sızıntısı", "LOW",
                f"X-AspNet-Version başlığı versiyon sızdırıyor: {aspnet}.",
                "X-AspNet-Version başlığını kaldırın.")
        body = r.text.lower()
        if 'wp-content' in body or 'wp-includes' in body:
            techs.append("CMS: WordPress")
        elif 'joomla' in body:
            techs.append("CMS: Joomla")
        elif 'drupal' in body:
            techs.append("CMS: Drupal")
        if techs:
            self._log(f"[i] Tespit edilen teknolojiler: {', '.join(techs)}")
        else:
            self._log("[✓] Belirgin teknoloji bilgisi sızıntısı yok.")
        time.sleep(0.5)

    def test_robots_sitemap(self, url):
        self._check_cancel()
        self._log("[i] robots.txt ve sitemap inceleniyor...")
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        r = self._safe_get(f"{base}/robots.txt")
        if r and r.status_code == 200 and len(r.text) > 5:
            self._log("[i] robots.txt bulundu, analiz ediliyor...")
            sensitive = ['/admin','/api','/backup','/config','/database',
                         '/debug','/env','/internal','/private','/secret','/staging','/test']
            exposed = []
            for line in r.text.splitlines():
                line = line.strip().lower()
                if line.startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    for pat in sensitive:
                        if pat in path:
                            exposed.append(path)
                            break
            if exposed:
                self.add_finding("robots.txt Hassas Yol İfşası", "LOW",
                    f"robots.txt'de hassas yollar listeleniyor: {', '.join(exposed[:5])}",
                    "Hassas dizinleri robots.txt'de listelemek yerine erişim kontrolü uygulayın.")
                self._log(f"[!] robots.txt'de hassas yollar: {', '.join(exposed[:5])}")
            else:
                self._log("[✓] robots.txt'de hassas yol ifşası yok.")
        else:
            self._log("[i] robots.txt bulunamadı veya boş.")
        r2 = self._safe_get(f"{base}/sitemap.xml")
        if r2 and r2.status_code == 200 and 'xml' in r2.headers.get('Content-Type', '').lower():
            self._log("[✓] sitemap.xml mevcut.")
        else:
            self._log("[i] sitemap.xml bulunamadı.")
        time.sleep(0.5)

    def test_waf(self, url):
        self._check_cancel()
        baseline = self._safe_get(url)
        probe = self._safe_get(url, params={"test": "<script>alert(1)</script>../../etc/passwd' OR 1=1--"})
        blocked = baseline.status_code < 400 and probe.status_code in (403, 406, 419, 429)
        if blocked:
            self.observe("waf", "Test girdisinde engelleme yanıtı gözlendi; bunun WAF mı uygulama kontrolü mü olduğu doğrulanmadı.")
        else:
            self.observe("waf", "WAF varlığı veya yokluğu doğrulanamadı; bu kontrol güvenlik puanını düşürmez.")

    def test_subdomain_port(self, url):
        self._check_cancel()
        self._log("[i] Yaygın port taraması yapılıyor...")
        host = urlparse(url).hostname
        if not _is_ip_safe(host):
            self._log("[!] Güvensiz IP, port taraması atlandı.")
            raise UnsafeTarget("Hedef güvenlik denetimini geçemedi.")
        address = public_addresses(host, 443)[0]
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        common_ports = {
            21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
            80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
            993:'IMAPS', 995:'POP3S', 3306:'MySQL', 3389:'RDP',
            5432:'PostgreSQL', 6379:'Redis', 8080:'HTTP-Alt', 8443:'HTTPS-Alt',
            27017:'MongoDB'
        }
        open_ports = []
        for port, svc in common_ports.items():
            self._check_cancel()
            s = None
            try:
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(1.5)
                result = s.connect_ex((address, port))
                if result == 0:
                    open_ports.append(f"{port}/{svc}")
                    self._log(f"  → Port {port} ({svc}) açık")
            except OSError as exc:
                raise RuntimeError("Port kontrolü tamamlanamadı.") from exc
            finally:
                if s is not None:
                    s.close()
        if open_ports:
            risky = [p for p in open_ports if any(x in p for x in ['Telnet','FTP','Redis','MongoDB','MySQL','PostgreSQL','SMB','RDP'])]
            if risky:
                self.add_finding("Riskli Açık Portlar", "MEDIUM",
                    f"Potansiyel riskli portlar açık: {', '.join(risky)}.",
                    "Gereksiz portları güvenlik duvarı ile kapatın.")
                self._log(f"[!] Riskli portlar: {', '.join(risky)}")
            else:
                self._log(f"[✓] Açık portlar: {', '.join(open_ports)} (standart)")
        else:
            self._log("[✓] Yaygın portlarda açık port bulunamadı.")
        time.sleep(0.5)
