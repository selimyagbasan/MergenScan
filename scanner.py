#!/usr/bin/env python3
import time
import html as html_module
import socket
import ipaddress
import ssl
import datetime
import re as _re
import requests
import urllib3
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _is_ip_safe(host):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return not (ip.is_loopback or ip.is_private or
                    ip.is_link_local or ip.is_reserved or
                    ip.is_multicast or ip.is_unspecified)
    except Exception:
        return False

class WebShieldScanner:
    def __init__(self, log_callback=None, cancel_event=None):
        self.log_callback = log_callback
        self.cancel_event = cancel_event
        self.findings     = []
        self.session = requests.Session()
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

    def add_finding(self, title, severity, detail, fix):
        self.findings.append({"title": title, "severity": severity, "detail": detail, "fix": fix})

    def _safe_get(self, url, timeout=8, **kwargs):
        host = urlparse(url).hostname or ""
        if not _is_ip_safe(host):
            self._log(f"[!] Güvensiz IP, istek engellendi: {url}")
            return None
        try:
            return self.session.get(url, timeout=timeout, **kwargs)
        except Exception as e:
            self._log(f"[!] İstek hatası ({url}): {e}")
            return None

    def crawl_site(self, url, limit=50):
        self._check_cancel()
        self._log(f"[i] Crawl başlatılıyor → {url}")
        r = self._safe_get(url)
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
        self._log("[i] SQL Injection testi başladı...")
        payloads   = ["'", "' OR '1'='1", "' OR 1=1--", "admin'--"]
        sql_errors = ["sql syntax", "mysql_fetch", "ora-", "sqlite3", "pdoexception"]

        r = self._safe_get(url, params={"id": "1"})
        if r:
            for payload in payloads:
                test_r = self._safe_get(url, params={"id": payload})
                if test_r and any(err in test_r.text.lower() for err in sql_errors):
                    self.add_finding(
                        "SQL Injection", "HIGH",
                        "'id' parametresi SQL hatasına yol açtı.",
                        "Parametrized query kullanın."
                    )
                    self._log("[✗] SQL Injection açığı bulundu!")
                    return
            self._log("[✓] SQL Injection açığı tespit edilmedi.")
        time.sleep(0.5)

    def test_xss(self, url):
        self._check_cancel()
        self._log("[i] XSS testi başladı...")
        payloads = ["<script>alert('XSS')</script>", "\"><img src=x onerror=alert(1)>"]
        for payload in payloads:
            r = self._safe_get(url, params={"q": payload})
            if r:
                # FİX: HTML decode edip karşılaştır — encode edilmiş payload yanlış pozitif vermez
                decoded_text = html_module.unescape(r.text)
                if payload in decoded_text:
                    self.add_finding(
                        "Cross-Site Scripting (XSS)", "HIGH",
                        "Payload encode edilmeden yansıtıldı.",
                        "Kullanıcı girdisini HTML encode edin."
                    )
                    self._log("[✗] XSS açığı bulundu!")
                    return
        self._log("[✓] XSS açığı tespit edilmedi.")
        time.sleep(0.5)

    def test_csrf(self, url):
        self._check_cancel()
        self._log("[i] CSRF korumaları kontrol ediliyor...")
        r = self._safe_get(url)
        if not r:
            return

        from html.parser import HTMLParser
        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.has_csrf = False
            def handle_starttag(self, tag, attrs):
                if tag == "input":
                    d = dict(attrs)
                    name = (d.get("name") or "").lower()
                    if "csrf" in name or "token" in name:
                        self.has_csrf = True

        parser = FormParser()
        parser.feed(r.text)

        if not parser.has_csrf:
            self.add_finding(
                "CSRF Token Eksik", "MEDIUM",
                "Form input'larında CSRF token alanı bulunamadı.",
                "Her POST formuna gizli CSRF token alanı ekleyin."
            )
            self._log("[!] CSRF token eksik.")
        else:
            self._log("[✓] CSRF token mevcut.")
        time.sleep(0.5)

    def test_headers(self, url):
        self._check_cancel()
        self._log("[i] HTTP güvenlik başlıkları inceleniyor...")
        r = self._safe_get(url)
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
        self._log("[i] Path Traversal aranıyor...")
        payloads = ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]
        for payload in payloads:
            r = self._safe_get(url, params={"file": payload})
            if r and "root:x:0:0" in r.text:
                self.add_finding(
                    "Path Traversal", "HIGH",
                    "Sunucu /etc/passwd döndürdü.",
                    "Dosya yollarını kısıtlayın."
                )
                self._log("[✗] Path Traversal açığı bulundu!")
                return
        self._log("[✓] Path Traversal tespit edilmedi.")
        time.sleep(0.5)

    def test_sensitive_files(self, url):
        self._check_cancel()
        self._log("[i] Hassas dosya sızıntıları kontrol ediliyor...")
        paths = [".env", ".git/config", "wp-config.php", "backup.sql"]
        found = False
        for path in paths:
            r = self._safe_get(f"{url.rstrip('/')}/{path}")
            if r and r.status_code == 200 and len(r.text) > 10:
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
        r = self._safe_get(url, params={"next": "https://evil.com"}, allow_redirects=False)
        if r and r.status_code in (301, 302) and "evil.com" in r.headers.get("Location", ""):
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
        self._log("[i] Command Injection test ediliyor...")
        r = self._safe_get(url, params={"cmd": "; id"})
        if r and "uid=" in r.text:
            self.add_finding(
                "Command Injection", "HIGH",
                "Sunucu komut çalıştırdı.",
                "Kullanıcı girdisini izole edin, subprocess.run kullanmaktan kaçının."
            )
            self._log("[✗] Command Injection bulundu!")
        else:
            self._log("[✓] Command Injection tespit edilmedi.")
        time.sleep(0.5)

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
            with socket.create_connection((host, port), timeout=8) as sock:
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
                        self._log(f"[✓] TLS protokolü güvenli: {proto}")
        except ssl.SSLCertVerificationError as e:
            self.add_finding("SSL Sertifika Doğrulama Hatası", "HIGH",
                f"Sertifika doğrulanamadı: {str(e)[:200]}",
                "Güvenilir bir CA'dan geçerli SSL sertifikası edinin.")
            self._log("[✗] SSL sertifikası doğrulanamadı!")
        except Exception as e:
            self._log(f"[!] SSL kontrolü sırasında hata: {e}")
        time.sleep(0.5)

    def test_cors(self, url):
        self._check_cancel()
        self._log("[i] CORS inceleniyor...")
        r = self._safe_get(url, headers={"Origin": "https://evil.com"})
        if r and r.headers.get("Access-Control-Allow-Origin") == "*":
            self.add_finding(
                "Wildcard CORS", "MEDIUM",
                "Her origin kabul ediliyor.",
                "Access-Control-Allow-Origin değerini belirli originlerle kısıtlayın."
            )
            self._log("[!] Wildcard CORS tespit edildi.")
        else:
            self._log("[✓] CORS güvenli.")
        time.sleep(0.5)

    def test_cookies(self, url):
        self._check_cancel()
        self._log("[i] Cookie bayrakları kontrol ediliyor...")
        r = self._safe_get(url)
        if not r:
            return
        cookie_hdrs = [v for k, v in r.raw.headers.items() if k.lower() == 'set-cookie'] if r.raw else []
        if not cookie_hdrs:
            self._log("[✓] Yanıtta Set-Cookie başlığı yok.")
            time.sleep(0.5)
            return
        found_issue = False
        for cs in cookie_hdrs:
            name = cs.split('=')[0].strip()
            low = cs.lower()
            missing = []
            if 'secure' not in low:
                missing.append('Secure')
            if 'httponly' not in low:
                missing.append('HttpOnly')
            if 'samesite' not in low:
                missing.append('SameSite')
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
        self._log("[i] HTTP metodları test ediliyor...")
        host = urlparse(url).hostname or ""
        if not _is_ip_safe(host):
            return
        dangerous_found = []
        try:
            r = self.session.options(url, timeout=8)
            allow = r.headers.get('Allow', '').upper()
            for m in ['PUT', 'DELETE', 'TRACE']:
                if m in allow:
                    dangerous_found.append(m)
        except Exception:
            pass
        if 'TRACE' not in dangerous_found:
            try:
                r = self.session.request('TRACE', url, timeout=8)
                if r.status_code == 200 and 'trace' in r.text.lower():
                    dangerous_found.append('TRACE')
            except Exception:
                pass
        if dangerous_found:
            self.add_finding("Tehlikeli HTTP Metodları Açık", "MEDIUM",
                f"Aktif tehlikeli metodlar: {', '.join(dangerous_found)}.",
                "Gereksiz HTTP metodlarını sunucu konfigürasyonunda devre dışı bırakın.")
            self._log(f"[!] Tehlikeli metodlar: {', '.join(dangerous_found)}")
        else:
            self._log("[✓] Tehlikeli HTTP metodları kapalı.")
        time.sleep(0.5)

    def test_clickjacking(self, url):
        self._check_cancel()
        self._log("[i] Clickjacking kontrolü...")
        r = self._safe_get(url)
        if not r:
            return
        xfo = r.headers.get('X-Frame-Options', '').upper()
        csp = r.headers.get('Content-Security-Policy', '')
        has_xfo = xfo in ('DENY', 'SAMEORIGIN')
        has_frame_anc = 'frame-ancestors' in csp.lower()
        if not has_xfo and not has_frame_anc:
            self.add_finding("Clickjacking Koruması Eksik", "MEDIUM",
                "X-Frame-Options veya CSP frame-ancestors başlığı bulunamadı.",
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
            return
        blocked = False
        try:
            for i in range(15):
                self._check_cancel()
                r = self.session.get(url, timeout=5)
                if r.status_code == 429:
                    blocked = True
                    break
        except Exception:
            pass
        if not blocked:
            self.add_finding("Rate Limiting Eksik", "LOW",
                "15 ardışık istekte sunucu rate limit uygulamadı.",
                "Brute-force ve DDoS koruması için rate limiting uygulayın.")
            self._log("[!] Rate limiting tespit edilemedi.")
        else:
            self._log("[✓] Rate limiting aktif (429 yanıtı alındı).")
        time.sleep(0.5)

    def test_tech_detect(self, url):
        self._check_cancel()
        self._log("[i] Teknoloji tespiti yapılıyor...")
        r = self._safe_get(url)
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
        self._log("[i] WAF tespiti yapılıyor...")
        waf_payload = "<script>alert(1)</script>../../etc/passwd' OR 1=1--"
        r_normal = self._safe_get(url)
        r_mal = self._safe_get(url, params={"test": waf_payload})
        waf_detected = False
        waf_name = "Bilinmeyen"
        if r_mal:
            if r_mal.status_code in (403, 406, 419, 429, 503):
                waf_detected = True
            hdrs = str(r_mal.headers).lower()
            body = r_mal.text.lower()
            if 'cf-ray' in hdrs or 'cloudflare' in body:
                waf_detected, waf_name = True, "Cloudflare"
            elif 'x-sucuri' in hdrs or 'sucuri' in body:
                waf_detected, waf_name = True, "Sucuri"
            elif 'mod_security' in body or 'modsecurity' in body:
                waf_detected, waf_name = True, "ModSecurity"
            elif 'awselb' in hdrs or 'x-amzn' in hdrs:
                waf_detected, waf_name = True, "AWS WAF"
            elif 'akamai' in hdrs:
                waf_detected, waf_name = True, "Akamai"
        elif r_normal:
            waf_detected = True
        if waf_detected:
            self._log(f"[✓] WAF tespit edildi: {waf_name}")
        else:
            self.add_finding("WAF Tespit Edilemedi", "LOW",
                "Web Application Firewall (WAF) koruması tespit edilemedi.",
                "WAF (Cloudflare, AWS WAF, ModSecurity vb.) kullanmayı değerlendirin.")
            self._log("[!] WAF koruması tespit edilemedi.")
        time.sleep(0.5)

    def test_subdomain_port(self, url):
        self._check_cancel()
        self._log("[i] Yaygın port taraması yapılıyor...")
        host = urlparse(url).hostname
        if not _is_ip_safe(host):
            self._log("[!] Güvensiz IP, port taraması atlandı.")
            return
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
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                result = s.connect_ex((host, port))
                s.close()
                if result == 0:
                    open_ports.append(f"{port}/{svc}")
                    self._log(f"  → Port {port} ({svc}) açık")
            except Exception:
                pass
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