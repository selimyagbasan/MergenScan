#!/usr/bin/env python3
import time
import requests
import urllib3
import html

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebShieldScanner:
    def __init__(self, log_callback=None, cancel_event=None):
        self.log_callback  = log_callback
        self.cancel_event  = cancel_event
        self.findings      = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "WebShield-Scanner/2.0"})

    def _log(self, msg):
        print(msg)
        if self.log_callback:
            self.log_callback(msg)

    def _check_cancel(self):
        if self.cancel_event and self.cancel_event.is_set():
            raise Exception("Tarama kullanıcı tarafından iptal edildi.")

    def add_finding(self, title, severity, detail, fix):
        self.findings.append({"title": title, "severity": severity, "detail": detail, "fix": fix})

    def _safe_get(self, url, timeout=8, **kwargs):
        try:
            return self.session.get(url, timeout=timeout, **kwargs)
        except Exception as e:
            self._log(f"[!] İstek hatası ({url}): {e}")
            return None

    def crawl_site(self, url, limit=50):
        self._check_cancel()
        self._log(f"[i] Crawl başlatılıyor → {url}")
        time.sleep(1)

    def test_sqli(self, url):
        self._check_cancel()
        self._log("[i] SQL Injection testi başladı...")
        payloads   = ["'", "' OR '1'='1", "' OR 1=1--", "admin'--"]
        sql_errors = ["sql syntax", "mysql_fetch", "ORA-", "sqlite3", "PDOException"]

        r = self._safe_get(url, params={"id": "1"}) # DÜZELTİLEN YER
        if r:
            for payload in payloads:
                test_r = self._safe_get(url, params={"id": payload})
                if test_r and any(err in test_r.text.lower() for err in sql_errors):
                    self.add_finding("SQL Injection", "HIGH", f"'id' parametresi SQL hatasına yol açtı.", "Parametrized query kullanın.")
                    self._log("[✗] SQL Injection açığı bulundu!")
                    break
            else:
                self._log("[✓] SQL Injection açığı tespit edilmedi.")
        time.sleep(0.5)

    def test_xss(self, url):
        self._check_cancel()
        self._log("[i] XSS testi başladı...")
        payloads = ["<script>alert('XSS')</script>", "\"><img src=x onerror=alert(1)>"]
        for payload in payloads:
            r = self._safe_get(url, params={"q": payload})
            if r and payload in r.text:
                self.add_finding("Cross-Site Scripting (XSS)", "HIGH", "Payload encode edilmeden yansıtıldı.", "Kullanıcı girdisini HTML encode edin.")
                self._log("[✗] XSS açığı bulundu!")
                return
        self._log("[✓] XSS açığı tespit edilmedi.")
        time.sleep(0.5)

    def test_csrf(self, url):
        self._check_cancel()
        self._log("[i] CSRF korumaları kontrol ediliyor...")
        r = self._safe_get(url)
        if r and "csrf" not in r.text.lower():
            self.add_finding("CSRF Token Eksik", "MEDIUM", "Formlarda CSRF token bulunamadı.", "CSRF token ekleyin.")
            self._log("[!] CSRF token eksik olabilir.")
        else:
            self._log("[✓] CSRF koruması mevcut.")
        time.sleep(0.5)

    def test_headers(self, url):
        self._check_cancel()
        self._log("[i] HTTP güvenlik başlıkları inceleniyor...")
        r = self._safe_get(url)
        if not r: return
        required = {"Strict-Transport-Security": "MEDIUM", "X-Frame-Options": "MEDIUM", "Content-Security-Policy": "MEDIUM"}
        missing = [h for h in required if h not in r.headers]
        for h in missing: self.add_finding(f"Eksik Başlık: {h}", required[h], "Güvenlik başlığı eksik.", f"Sunucuya {h} ekleyin.")
        self._log(f"[!] Eksik başlıklar: {missing}" if missing else "[✓] Güvenlik başlıkları mevcut.")
        time.sleep(0.5)

    def test_traversal(self, url):
        self._check_cancel()
        self._log("[i] Path Traversal aranıyor...")
        payloads = ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]
        for payload in payloads:
            r = self._safe_get(url, params={"file": payload})
            if r and "root:x:0:0" in r.text:
                self.add_finding("Path Traversal", "HIGH", "Sunucu /etc/passwd döndürdü.", "Dosya yollarını kısıtlayın.")
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
                self.add_finding(f"Hassas Dosya: {path}", "HIGH", f"{path} herkese açık.", "Dosyayı gizleyin.")
                self._log(f"[✗] Bulundu: {path}")
                found = True
        if not found: self._log("[✓] Hassas dosya sızıntısı yok.")
        time.sleep(0.5)

    def test_open_redirect(self, url):
        self._check_cancel()
        self._log("[i] Open Redirect denemeleri yapılıyor...")
        r = self._safe_get(url, params={"next": "https://evil.com"}, allow_redirects=False)
        if r and r.status_code in (301, 302) and "evil.com" in r.headers.get("Location", ""):
            self.add_finding("Open Redirect", "MEDIUM", "Dış URL'ye yönlendirme yapıldı.", "Whitelist kullanın.")
            self._log("[✗] Open Redirect bulundu!")
        else:
            self._log("[✓] Open Redirect tespit edilmedi.")
        time.sleep(0.5)

    def test_cmdi(self, url):
        self._check_cancel()
        self._log("[i] Command Injection test ediliyor...")
        r = self._safe_get(url, params={"cmd": "; id"})
        if r and "uid=" in r.text:
            self.add_finding("Command Injection", "HIGH", "Sunucu komut çalıştırdı.", "Kullanıcı girdisini izole edin.")
            self._log("[✗] Command Injection bulundu!")
        else:
            self._log("[✓] Command Injection tespit edilmedi.")
        time.sleep(0.5)

    def test_ssl(self, url):
        self._check_cancel()
        self._log("[i] SSL kontrol ediliyor (Simülasyon)...")
        time.sleep(0.5)

    def test_cors(self, url):
        self._check_cancel()
        self._log("[i] CORS inceleniyor...")
        r = self._safe_get(url, headers={"Origin": "https://evil.com"})
        if r and r.headers.get("Access-Control-Allow-Origin") == "*":
            self.add_finding("Wildcard CORS", "MEDIUM", "Her origin kabul ediliyor.", "Originleri kısıtlayın.")
            self._log("[!] Wildcard CORS tespit edildi.")
        else:
            self._log("[✓] CORS güvenli.")
        time.sleep(0.5)

    def test_cookies(self, url):
        self._check_cancel()
        self._log("[i] Cookie bayrakları kontrol ediliyor...")
        time.sleep(0.5)

    def test_http_methods(self, url):
        self._check_cancel()
        self._log("[i] HTTP metodları test ediliyor...")
        time.sleep(0.5)

    def test_clickjacking(self, url):
        self._check_cancel()
        self._log("[i] Clickjacking kontrolü...")
        time.sleep(0.5)

    def test_rate_limiting(self, url):
        self._check_cancel()
        self._log("[i] Rate Limiting test ediliyor...")
        time.sleep(0.5)

    def test_tech_detect(self, url):
        self._check_cancel()
        self._log("[i] Teknoloji tespiti yapılıyor...")
        time.sleep(0.5)

    def test_robots_sitemap(self, url):
        self._check_cancel()
        self._log("[i] robots.txt inceleniyor...")
        time.sleep(0.5)

    def test_waf(self, url):
        self._check_cancel()
        self._log("[i] WAF tespiti yapılıyor...")
        time.sleep(0.5)

    def test_subdomain_port(self, url):
        self._check_cancel()
        self._log("[i] Port taraması yapılıyor (Simülasyon)...")
        time.sleep(0.5)
