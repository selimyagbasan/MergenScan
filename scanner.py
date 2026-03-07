#!/usr/bin/env python3
# =============================================================================
#  WebShield Scanner — Güvenlik Test Modülleri
#
#  Kullanım (doğrudan):
#      python scanner.py  (bağımsız çalışmaz; app_new.py üzerinden çağrılır)
#
#  Bağımlılıklar:
#      pip install requests beautifulsoup4 urllib3
#
#  ÖNEMLİ: Bu araç yalnızca kendi sitenizi veya
#           yazılı izin aldığınız siteleri test etmek için kullanılabilir.
# =============================================================================

import time
import requests
import urllib3
import html # BÜTÜN ZARARLI KARAKTERLERİ TEMİZLEMEK İÇİN
import time
import requests
import urllib3

# Öz-imzalı sertifika uyarılarını sustur (test ortamları için)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebShieldScanner:
    """
    Tüm güvenlik test modüllerini barındıran ana sınıf.

    Parametreler:
        log_callback  (callable): Her log satırını web arayüzüne ileten fonksiyon.
                                  None ise loglar yalnızca konsola yazdırılır.
        cancel_event  (threading.Event): Set edildiğinde tarama durdurulur.
                                         None ise iptal kontrolü yapılmaz.
    """

    def __init__(self, log_callback=None, cancel_event=None):
        self.log_callback  = log_callback
        self.cancel_event  = cancel_event
        self.findings      = []   # Bulunan zafiyetlerin listesi

        # ── HTTP oturumu ──────────────────────────────────────────────────────
        # Tüm istekler aynı oturum üzerinden yapılır; bu cookie ve header
        # yönetimini kolaylaştırır.
        self.session = requests.Session()
        self.session.verify = False   # SSL doğrulamasını kapat (test için)
        self.session.headers.update({
            # User-Agent: hedef sitenin sunucu loglarında görünür; test amaçlı olduğunu belirtir
            "User-Agent": "WebShield-Scanner/2.0 (authorized-security-test)"
        })

    # =========================================================================
    #  YARDIMCI METOTLAR
    # =========================================================================

    def _log(self, msg):
        """
        Hem konsola hem de web arayüzüne log mesajı gönderir.
        log_callback tanımlı değilse yalnızca stdout'a yazar.
        """
        print(msg)
        if self.log_callback:
            self.log_callback(msg)

    def _check_cancel(self):
        """
        Kullanıcının iptal düğmesine basıp basmadığını kontrol eder.
        İptal edildiyse Exception fırlatır; bu exception run_scan() tarafından yakalanır.
        """
        if self.cancel_event and self.cancel_event.is_set():
            raise Exception("Tarama kullanıcı tarafından iptal edildi.")

    def add_finding(self, title, severity, detail, fix):
        """
        Tespit edilen bir güvenlik açığını bulgular listesine ekler.

        Parametreler:
            title    (str): Açığın kısa başlığı (ör. "SQL Injection")
            severity (str): Önem derecesi → "HIGH", "MEDIUM", "LOW" veya "PASS"
            detail   (str): Teknik detay ve kanıt
            fix      (str): Önerilen düzeltme adımı
        """
        self.findings.append({
            "title"   : title,
            "severity": severity,
            "detail"  : detail,
            "fix"     : fix,
        })

    def _safe_get(self, url, timeout=8, **kwargs):
        """
        requests.get() çağrısını try/except ile sarmalar.
        Bağlantı hatası veya zaman aşımında None döner; tarama devam eder.
        """
        try:
            return self.session.get(url, timeout=timeout, **kwargs)
        except Exception as e:
            self._log(f"[!] İstek hatası ({url}): {e}")
            return None

    # =========================================================================
    #  TARAMA MODÜLLERİ
    #  Her metot app_new.py'deki test_map sözlüğü ile eşleşir.
    # =========================================================================

    def crawl_site(self, url, limit=50):
        """
        Hedef sitenin bağlantı haritasını çıkarır.
        Diğer testlere form ve URL listesi sağlamak için ilk çalıştırılması önerilir.

        limit: Taranacak maksimum sayfa sayısı
        """
        self._check_cancel()
        self._log(f"[i] Crawl başlatılıyor → {url}  (limit: {limit} sayfa)")
        # TODO: BeautifulSoup ile dahili linkleri takip eden crawler eklenecek
        time.sleep(1)

    def test_sqli(self, url):
        """
        SQL Injection (SQLi) testi.
        Yaygın payload'ları URL parametrelerine ve form alanlarına enjekte eder;
        dönen yanıtta SQL hata izleri arar.

        Risk: HIGH — Veritabanı sızıntısı, veri silme, kimlik doğrulama atlatma
        """
        self._check_cancel()
        self._log("[i] SQL Injection testi başladı...")

        # Örnek payload listesi (gerçek uygulama için genişletilmeli)
        payloads   = ["'", "' OR '1'='1", "' OR 1=1--", "admin'--"]
        sql_errors = ["sql syntax", "mysql_fetch", "ORA-", "sqlite3", "PDOException"]

        r = self._safe_get(url + "?id=1")
        if r:
            for payload in payloads:
                test_r = self._safe_get(url, params={"id": payload})
                if test_r and any(err in test_r.text.lower() for err in sql_errors):
                    self.add_finding(
                        title    = "SQL Injection",
                        severity = "HIGH",
                        detail   = f"'id' parametresi SQL hatasına yol açtı. Payload: {payload}",
                        fix      = "Tüm sorguları parametrized query / prepared statement ile yazın."
                    )
                    self._log("[✗] SQL Injection açığı bulundu!")
                    break
            else:
                self._log("[✓] SQL Injection açığı tespit edilmedi.")

        time.sleep(0.5)

    def test_xss(self, url):
        # ...
        for payload in payloads:
            r = self._safe_get(url, params={"q": payload})
            if r and payload in r.text:
                # Güvenli hale getirme işlemi:
                guvenli_payload = html.escape(payload[:60])
                
                self.add_finding(
                    title    = "Cross-Site Scripting (XSS)",
                    severity = "HIGH",
                    detail   = f"Payload yanıtta encode edilmeden yansıtıldı: {guvenli_payload}",
                    fix      = "Tüm kullanıcı girdilerini HTML encode edin; Content-Security-Policy başlığı ekleyin."
                )
                self._log("[✗] XSS açığı bulundu!")
                return

        for payload in payloads:
            r = self._safe_get(url, params={"q": payload})
            if r and payload in r.text:
                self.add_finding(
                    title    = "Cross-Site Scripting (XSS)",
                    severity = "HIGH",
                    detail   = f"Payload yanıtta encode edilmeden yansıtıldı: {payload[:60]}",
                    fix      = "Tüm kullanıcı girdilerini HTML encode edin; Content-Security-Policy başlığı ekleyin."
                )
                self._log("[✗] XSS açığı bulundu!")
                return

        self._log("[✓] XSS açığı tespit edilmedi.")
        time.sleep(0.5)

    def test_csrf(self, url):
        """
        CSRF (Cross-Site Request Forgery) koruması kontrolü.
        Formların CSRF token içerip içermediğini ve SameSite cookie politikasını denetler.

        Risk: MEDIUM — Oturum açık kullanıcı adına yetkisiz işlem yaptırma
        """
        self._check_cancel()
        self._log("[i] CSRF korumaları kontrol ediliyor...")

        r = self._safe_get(url)
        if r and "csrf" not in r.text.lower() and "csrftoken" not in r.text.lower():
            self.add_finding(
                title    = "CSRF Token Eksik",
                severity = "MEDIUM",
                detail   = "Sayfa formlarında CSRF token bulunamadı.",
                fix      = "Her form için benzersiz, tahmin edilemez CSRF token kullanın."
            )
            self._log("[!] CSRF token eksik olabilir.")
        else:
            self._log("[✓] CSRF koruması mevcut görünüyor.")

        time.sleep(0.5)

    def test_headers(self, url):
        """
        HTTP güvenlik başlıkları analizi.
        Eksik başlıklar tarayıcı tabanlı saldırılara kapı aralayabilir.

        Kontrol edilen başlıklar:
          - Strict-Transport-Security (HSTS)
          - X-Content-Type-Options
          - X-Frame-Options
          - Content-Security-Policy
          - Referrer-Policy
        """
        self._check_cancel()
        self._log("[i] HTTP güvenlik başlıkları inceleniyor...")

        r = self._safe_get(url)
        if not r:
            return

        # Zorunlu başlıklar ve önem dereceleri
        required = {
            "Strict-Transport-Security" : ("MEDIUM", "HSTS eksik; HTTP downgrade saldırılarına açık."),
            "X-Content-Type-Options"    : ("LOW",    "X-Content-Type-Options eksik; MIME sniffing riski."),
            "X-Frame-Options"           : ("MEDIUM", "X-Frame-Options eksik; Clickjacking riski."),
            "Content-Security-Policy"   : ("MEDIUM", "CSP başlığı eksik; XSS zararını artırır."),
            "Referrer-Policy"           : ("LOW",    "Referrer-Policy eksik; hassas URL sızıntısı olabilir."),
        }

        missing = []
        for header, (sev, detail) in required.items():
            if header not in r.headers:
                missing.append(header)
                self.add_finding(
                    title    = f"Eksik Başlık: {header}",
                    severity = sev,
                    detail   = detail,
                    fix      = f"Sunucu yapılandırmasına `{header}` başlığını ekleyin."
                )

        if missing:
            self._log(f"[!] Eksik başlıklar: {', '.join(missing)}")
        else:
            self._log("[✓] Tüm temel güvenlik başlıkları mevcut.")

        time.sleep(0.5)

    def test_traversal(self, url):
        """
        Path Traversal (Dizin Geçişi) testi.
        ../../../ dizileriyle sunucunun hassas dosyalarına erişim denenebilir.

        Risk: HIGH — /etc/passwd gibi sistem dosyası okuma
        """
        self._check_cancel()
        self._log("[i] Path Traversal açıkları aranıyor...")

        payloads  = ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]
        linux_sig = "root:x:0:0"   # /etc/passwd imzası

        for payload in payloads:
            r = self._safe_get(url, params={"file": payload})
            if r and linux_sig in r.text:
                self.add_finding(
                    title    = "Path Traversal",
                    severity = "HIGH",
                    detail   = f"Sunucu /etc/passwd içeriğini döndürdü. Payload: {payload}",
                    fix      = "Dosya yollarını mutlak kök dizine kilitleyin; kullanıcı girdisini doğrulayın."
                )
                self._log("[✗] Path Traversal açığı bulundu!")
                return

        self._log("[✓] Path Traversal açığı tespit edilmedi.")
        time.sleep(0.5)

    def test_sensitive_files(self, url):
        """
        Hassas dosya sızıntısı kontrolü.
        Yanlışlıkla herkese açık bırakılmış yapılandırma ve gizli dosyaları tarar.

        Risk: HIGH — API anahtarları, şifreler, kaynak kod ifşası
        """
        self._check_cancel()
        self._log("[i] Hassas dosya sızıntıları kontrol ediliyor...")

        # Yaygın hassas dosya yolları
        sensitive_paths = [
            ".env", ".git/config", ".htaccess",
            "config.php", "wp-config.php", "database.yml",
            "backup.sql", "dump.sql",
        ]

        found_any = False
        for path in sensitive_paths:
            r = self._safe_get(f"{url.rstrip('/')}/{path}")
            # 200 dönen VE anlamlı içerik barındıran dosyaları raporla
            if r and r.status_code == 200 and len(r.text) > 30:
                self.add_finding(
                    title    = f"Hassas Dosya Erişilebilir: {path}",
                    severity = "HIGH",
                    detail   = f"/{path} dosyası herkese açık. İçerik boyutu: {len(r.text)} karakter.",
                    fix      = f"/{path} dosyasını web kökünden kaldırın veya sunucu kuralıyla engelleyin."
                )
                self._log(f"[✗] Erişilebilir hassas dosya: {path}")
                found_any = True

        if not found_any:
            self._log("[✓] Hassas dosya sızıntısı tespit edilmedi.")

        time.sleep(0.5)

    def test_open_redirect(self, url):
        """
        Open Redirect (Açık Yönlendirme) testi.
        Kontrol edilmemiş yönlendirme parametreleri kimlik avı saldırılarında kullanılır.

        Risk: MEDIUM — Kullanıcıları sahte sitelere yönlendirme
        """
        self._check_cancel()
        self._log("[i] Open Redirect denemeleri yapılıyor...")

        payloads       = ["https://evil.com", "//evil.com", "/\\evil.com"]
        redirect_params = ["next", "url", "redirect", "return", "returnUrl", "goto"]

        for param in redirect_params:
            for payload in payloads:
                r = self._safe_get(url, params={param: payload}, allow_redirects=False)
                if r and r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("Location", "")
                    if "evil.com" in location:
                        self.add_finding(
                            title    = "Open Redirect",
                            severity = "MEDIUM",
                            detail   = f"'{param}' parametresi dış URL'ye yönlendirdi: {location}",
                            fix      = "Yönlendirme hedeflerini izin listesiyle (whitelist) kısıtlayın."
                        )
                        self._log(f"[✗] Open Redirect açığı bulundu! Param: {param}")
                        return

        self._log("[✓] Open Redirect açığı tespit edilmedi.")
        time.sleep(0.5)

    def test_cmdi(self, url):
        """
        Command Injection (Komut Enjeksiyonu) testi.
        Parametre değerlerine OS komutları enjekte edilmeye çalışılır.

        Risk: HIGH (Kritik) — Sunucuda uzaktan komut çalıştırma
        """
        self._check_cancel()
        self._log("[i] Command Injection testleri çalıştırılıyor...")

        payloads  = ["; ls", "| whoami", "`id`", "$(id)"]
        cmd_signs = ["root", "uid=", "www-data", "bin/bash"]

        for payload in payloads:
            r = self._safe_get(url, params={"cmd": payload, "exec": payload})
            if r and any(sign in r.text for sign in cmd_signs):
                self.add_finding(
                    title    = "Command Injection",
                    severity = "HIGH",
                    detail   = f"Sunucu komut çıktısı döndürdü. Payload: {payload}",
                    fix      = "Kullanıcı girdisini sistem çağrılarından kesinlikle izole edin."
                )
                self._log("[✗] Command Injection açığı bulundu!")
                return

        self._log("[✓] Command Injection açığı tespit edilmedi.")
        time.sleep(0.5)

    def test_ssl(self, url):
        """
        SSL/TLS sertifika ve yapılandırma analizi.
        Süresi dolmuş veya güvensiz sertifikaları tespit eder.

        Risk: MEDIUM-HIGH — Ortadaki adam (MITM) saldırıları
        """
        self._check_cancel()
        self._log("[i] SSL/TLS sertifika analizi yapılıyor...")

        import ssl, socket
        from urllib.parse import urlparse
        from datetime import datetime

        parsed   = urlparse(url)
        hostname = parsed.hostname

        try:
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
            conn.settimeout(5)
            conn.connect((hostname, 443))
            cert     = conn.getpeercert()
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.utcnow()).days
            conn.close()

            if days_left < 30:
                self.add_finding(
                    title    = "SSL Sertifikası Yakında Sona Erecek",
                    severity = "MEDIUM",
                    detail   = f"Sertifika {days_left} gün sonra sona eriyor.",
                    fix      = "Sertifikayı yenileyin ve otomatik yenileme (örn. Let's Encrypt) ayarlayın."
                )
                self._log(f"[!] Sertifika {days_left} gün içinde sona erecek.")
            else:
                self._log(f"[✓] SSL sertifikası geçerli ({days_left} gün kaldı).")

        except ssl.SSLError as e:
            self.add_finding(
                title    = "SSL/TLS Yapılandırma Hatası",
                severity = "HIGH",
                detail   = f"SSL el sıkışma hatası: {e}",
                fix      = "Sunucunun TLS 1.2/1.3 desteklediğinden emin olun; zayıf şifreleme suitelerini devre dışı bırakın."
            )
            self._log(f"[✗] SSL hatası: {e}")
        except Exception as e:
            self._log(f"[i] SSL testi tamamlanamadı: {e}")

        time.sleep(0.5)

    def test_cors(self, url):
        """
        CORS (Cross-Origin Resource Sharing) politikası kontrolü.
        Wildcard (*) veya yansıtılan Origin değerleri kimlik bilgisi sızıntısına yol açar.

        Risk: MEDIUM — Başka domainlerin API verilerine erişmesi
        """
        self._check_cancel()
        self._log("[i] CORS politikaları inceleniyor...")

        r = self._safe_get(url, headers={"Origin": "https://evil.com"})
        if r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self.add_finding(
                    title    = "Gevşek CORS Politikası (Wildcard)",
                    severity = "MEDIUM",
                    detail   = "Access-Control-Allow-Origin: * tüm domainlere izin veriyor.",
                    fix      = "İzin verilen originleri açıkça listeleyin; wildcard kullanmayın."
                )
                self._log("[!] Wildcard CORS tespit edildi.")
            elif "evil.com" in acao and acac.lower() == "true":
                self.add_finding(
                    title    = "CORS + Credentials Açığı",
                    severity = "HIGH",
                    detail   = "Yabancı origin yansıtılıyor ve credentials izni var.",
                    fix      = "credentials: true kullanılıyorsa origin'i asla yansıtmayın."
                )
                self._log("[✗] CORS credentials açığı bulundu!")
            else:
                self._log("[✓] CORS politikası güvenli görünüyor.")

        time.sleep(0.5)

    def test_cookies(self, url):
        """
        Cookie güvenlik bayrakları denetimi.
        Eksik HttpOnly/Secure/SameSite bayrakları oturum ele geçirme riskini artırır.

        Risk: MEDIUM — XSS ile oturum çalma, ağ dinleme
        """
        self._check_cancel()
        self._log("[i] Cookie güvenlik bayrakları kontrol ediliyor...")

        r = self._safe_get(url)
        if not r:
            return

        issues = []
        for cookie in r.cookies:
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append(f"{cookie.name}: HttpOnly eksik")
            if not cookie.secure:
                issues.append(f"{cookie.name}: Secure bayrağı eksik")

        if issues:
            self.add_finding(
                title    = "Güvensiz Cookie Yapılandırması",
                severity = "MEDIUM",
                detail   = "\n".join(issues),
                fix      = "Set-Cookie başlığına HttpOnly; Secure; SameSite=Strict ekleyin."
            )
            self._log(f"[!] Cookie sorunları: {len(issues)} adet")
        else:
            self._log("[✓] Cookie bayrakları güvenli.")

        time.sleep(0.5)

    def test_http_methods(self, url):
        """
        İzin verilen HTTP metodları testi.
        PUT/DELETE/TRACE gibi tehlikeli metodlar açık bırakılmamalıdır.

        Risk: MEDIUM — Yetkisiz dosya yükleme, XST saldırısı
        """
        self._check_cancel()
        self._log("[i] İzin verilen HTTP metodları test ediliyor...")

        dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"]
        allowed   = []

        for method in dangerous:
            try:
                r = self.session.request(method, url, timeout=5)
                # 405 Method Not Allowed dışındaki yanıtlar metodun aktif olduğunu gösterir
                if r.status_code != 405:
                    allowed.append(method)
            except Exception:
                pass

        if allowed:
            self.add_finding(
                title    = "Tehlikeli HTTP Metodları Aktif",
                severity = "MEDIUM",
                detail   = f"Etkin tehlikeli metodlar: {', '.join(allowed)}",
                fix      = "Sunucu yapılandırmasında yalnızca GET ve POST'a izin verin."
            )
            self._log(f"[!] Tehlikeli metodlar açık: {', '.join(allowed)}")
        else:
            self._log("[✓] Tehlikeli HTTP metodları devre dışı.")

        time.sleep(0.5)

    def test_clickjacking(self, url):
        """
        Clickjacking (IFrame) koruması testi.
        X-Frame-Options veya CSP frame-ancestors eksikse site iframe içine alınabilir.

        Risk: MEDIUM — Kullanıcı tıklamalarını gizli arayüzlere yönlendirme
        """
        self._check_cancel()
        self._log("[i] Clickjacking zafiyetleri aranıyor...")

        r = self._safe_get(url)
        if r:
            xfo = r.headers.get("X-Frame-Options", "")
            csp = r.headers.get("Content-Security-Policy", "")

            if not xfo and "frame-ancestors" not in csp:
                self.add_finding(
                    title    = "Clickjacking Koruması Eksik",
                    severity = "MEDIUM",
                    detail   = "X-Frame-Options başlığı ve CSP frame-ancestors direktifi bulunamadı.",
                    fix      = "Yanıta X-Frame-Options: DENY veya CSP: frame-ancestors 'none' ekleyin."
                )
                self._log("[!] Clickjacking koruması eksik.")
            else:
                self._log("[✓] Clickjacking koruması mevcut.")

        time.sleep(0.5)

    def test_rate_limiting(self, url):
        """
        Rate Limiting (hız sınırlama) koruması testi.
        Kısa sürede çok sayıda istek yapılarak sunucunun yavaşlayıp yavaşlamadığı,
        ya da 429 Too Many Requests döndürüp döndürmediği kontrol edilir.

        Risk: MEDIUM — Brute-force, kaba kuvvet saldırıları
        """
        self._check_cancel()
        self._log("[i] Rate Limiting korumaları test ediliyor...")

        request_count = 10   # Ardışık istek sayısı
        blocked       = False

        for i in range(request_count):
            r = self._safe_get(url)
            if r and r.status_code == 429:
                blocked = True
                self._log(f"[✓] {i+1}. istekte 429 döndü — Rate Limiting aktif.")
                break

        if not blocked:
            self.add_finding(
                title    = "Rate Limiting Koruması Eksik",
                severity = "MEDIUM",
                detail   = f"{request_count} ardışık istekte 429 yanıtı alınmadı.",
                fix      = "Nginx limit_req / Flask-Limiter gibi hız sınırlama araçları ekleyin."
            )
            self._log("[!] Rate Limiting tespit edilmedi.")

        time.sleep(0.5)

    def test_tech_detect(self, url):
        """
        Teknoloji tespiti (Fingerprinting).
        Server, X-Powered-By ve diğer başlıklardaki sürüm bilgileri saldırganlara
        hedef sistem hakkında ipucu sağlar.

        Risk: LOW — Bilgi ifşası, hedefli exploit araması
        """
        self._check_cancel()
        self._log("[i] Teknoloji tespiti (fingerprinting) yapılıyor...")

        r = self._safe_get(url)
        if not r:
            return

        leaks = {}
        for header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
            val = r.headers.get(header)
            if val:
                leaks[header] = val

        if leaks:
            detail = "\n".join(f"{k}: {v}" for k, v in leaks.items())
            self.add_finding(
                title    = "Sunucu Teknoloji Bilgisi İfşa",
                severity = "LOW",
                detail   = f"Başlıklarda sürüm bilgisi açıklanıyor:\n{detail}",
                fix      = "Server ve X-Powered-By başlıklarını sunucu yapılandırmasından kaldırın veya gizleyin."
            )
            self._log(f"[!] Teknoloji sızıntısı: {leaks}")
        else:
            self._log("[✓] Sunucu bilgisi ifşa edilmiyor.")

        time.sleep(0.5)

    def test_robots_sitemap(self, url):
        """
        robots.txt ve sitemap.xml analizi.
        Gizlenmek istenen yollar genellikle Disallow direktiflerinde listelenir.

        Risk: LOW — Gizli yönetim paneli veya endpoint tespiti
        """
        self._check_cancel()
        self._log("[i] robots.txt ve sitemap.xml analiz ediliyor...")

        base = url.rstrip("/")
        findings_added = False

        # robots.txt kontrolü
        r = self._safe_get(f"{base}/robots.txt")
        if r and r.status_code == 200 and "disallow" in r.text.lower():
            # Disallow edilen yolları çıkar
            disallowed = [
                line.split(":", 1)[1].strip()
                for line in r.text.splitlines()
                if line.lower().startswith("disallow") and ":" in line
            ]
            if disallowed:
                self.add_finding(
                    title    = "robots.txt Hassas Yollar İçeriyor",
                    severity = "LOW",
                    detail   = f"Disallow edilen yollar: {', '.join(disallowed[:10])}",
                    fix      = "Hassas yolları robots.txt'de listelemeyin; bunun yerine erişim kontrolü uygulayın."
                )
                self._log(f"[!] robots.txt'de {len(disallowed)} gizli yol bulundu.")
                findings_added = True

        if not findings_added:
            self._log("[✓] robots.txt'de önemli bir bulgu yok.")

        time.sleep(0.5)

    def test_waf(self, url):
        """
        WAF (Web Application Firewall) / IPS varlık tespiti.
        Saldırı payload'ları gönderilerek 403/406 yanıtı veya özel hata sayfaları aranır.
        WAF tespiti hem savunmayı hem saldırı yüzeyini anlamaya yardımcı olur.

        Risk: Bilgi (INFO) — WAF varsa saldırı zor, yoksa risk artar
        """
        self._check_cancel()
        self._log("[i] WAF / IPS varlığı tespit edilmeye çalışılıyor...")

        # WAF imzaları (response header veya body'de aranır)
        waf_signatures = {
            "Cloudflare"    : ["cloudflare", "cf-ray"],
            "AWS WAF"       : ["x-amzn-requestid", "awselb"],
            "Sucuri"        : ["sucuri", "x-sucuri-id"],
            "ModSecurity"   : ["mod_security", "modsecurity"],
            "Imperva"       : ["x-iinfo", "incapsula"],
        }

        r = self._safe_get(url, params={"test": "<script>alert(1)</script>"})
        if not r:
            return

        all_text = " ".join([
            r.text.lower(),
            " ".join(k.lower() + " " + v.lower() for k, v in r.headers.items())
        ])

        detected = [name for name, sigs in waf_signatures.items()
                    if any(sig in all_text for sig in sigs)]

        if detected:
            self._log(f"[✓] WAF/CDN tespit edildi: {', '.join(detected)}")
        elif r.status_code in (403, 406):
            self._log("[i] WAF/IPS varlığı olası (403/406 yanıtı).")
        else:
            self.add_finding(
                title    = "WAF / IPS Tespit Edilemedi",
                severity = "LOW",
                detail   = "Bilinen WAF imzaları bulunamadı. Site koruma altında olmayabilir.",
                fix      = "Cloudflare, AWS WAF veya benzeri bir WAF çözümü değerlendirin."
            )
            self._log("[!] WAF tespit edilemedi.")

        time.sleep(0.5)

    def test_subdomain_port(self, url):
        """
        Subdomain ve açık port taraması.
        Yaygın subdomain adlarını dener; temel portların açık olup olmadığını kontrol eder.

        Risk: LOW-MEDIUM — Saldırı yüzeyinin genişlemesi
        """
        self._check_cancel()
        self._log("[i] Subdomain ve port taraması yapılıyor...")

        import socket
        from urllib.parse import urlparse

        parsed   = urlparse(url)
        hostname = parsed.hostname

        # Yaygın subdomain adayları
        subdomains = ["www", "mail", "admin", "api", "dev", "staging", "test", "ftp"]
        found_subs = []

        for sub in subdomains:
            self._check_cancel()
            try:
                full = f"{sub}.{hostname}"
                socket.gethostbyname(full)   # DNS çözümlemesi başarılıysa aktiftir
                found_subs.append(full)
                self._log(f"[i] Subdomain bulundu: {full}")
            except socket.gaierror:
                pass   # Subdomain yok, devam et

        if found_subs:
            self.add_finding(
                title    = "Aktif Subdomainler Tespit Edildi",
                severity = "LOW",
                detail   = f"Bulunan subdomainler: {', '.join(found_subs)}",
                fix      = "Kullanılmayan subdomainleri kapatın; hepsinin güncel güvenlik yapılandırmasına sahip olduğunu doğrulayın."
            )

        # Yaygın tehlikeli portlar
        dangerous_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL"}
        open_ports      = []

        for port, service in dangerous_ports.items():
            self._check_cancel()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((hostname, port)) == 0:
                    open_ports.append(f"{port}/{service}")
                    self._log(f"[!] Açık port: {port} ({service})")
                sock.close()
            except Exception:
                pass

        if open_ports:
            self.add_finding(
                title    = "Açık Tehlikeli Portlar",
                severity = "MEDIUM",
                detail   = f"Dışarıdan erişilebilen portlar: {', '.join(open_ports)}",
                fix      = "Güvenlik duvarı kurallarıyla bu portları yalnızca yetkili IP'lere açın."
            )
        else:
            self._log("[✓] Taranan tehlikeli portlar kapalı.")

        time.sleep(0.5)
