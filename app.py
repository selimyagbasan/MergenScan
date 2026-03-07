#!/usr/bin/env python3
# =============================================================================
#  WebShield Scanner — Flask Web Sunucusu
#  Görev: scanner.py'deki güvenlik testlerini web arayüzüne bağlar.
#  Çalıştırmak için: python app.py
#  Tarayıcıda aç  : http://localhost:5000
# =============================================================================

from flask import Flask, render_template, request, jsonify, Response, send_from_directory, abort
import threading
import json
import os
import queue
import time
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

# ── .env dosyasını yükle ──────────────────────────────────────────────────────
load_dotenv()

# ── Flask-Limiter ─────────────────────────────────────────────────────────────
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Flask Uygulaması ──────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=".", template_folder=".")

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://"
)

# ── Ortam değişkenleri ────────────────────────────────────────────────────────
API_KEY       = os.environ.get("WEBSHIELD_API_KEY", "")   # Boşsa auth devre dışı
REQUIRE_AUTH  = os.environ.get("REQUIRE_AUTH", "false").lower() == "true"

# ── SSRF Koruması: İç ağ adresleri engellenir ─────────────────────────────────
BLOCKED_HOSTS = [
    "localhost", "127.", "0.0.0.0",
    "169.254.",           # Link-local
    "10.",                # RFC1918
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",           # RFC1918
    "::1", "fc00:", "fe80:",  # IPv6 loopback / link-local
    "metadata.google.internal",  # GCP metadata
    "169.254.169.254",           # AWS/Azure metadata
]

def is_safe_url(url: str) -> tuple[bool, str]:
    """
    URL'nin iç ağa veya metadata servislerine işaret edip etmediğini kontrol eder.
    Döner: (güvenli_mi, hata_mesajı)
    """
    try:
        parsed = urlparse(url)
        host   = (parsed.hostname or "").lower()

        if not host:
            return False, "Geçerli bir URL giriniz."

        # Protokol kontrolü
        if parsed.scheme not in ("http", "https"):
            return False, "Yalnızca http ve https protokolleri desteklenir."

        # Engellenen host kontrolü
        for blocked in BLOCKED_HOSTS:
            if host == blocked or host.startswith(blocked):
                return False, "Bu adrese tarama yapılamaz (iç ağ veya özel adres)."

        return True, ""

    except Exception:
        return False, "URL ayrıştırılamadı. Lütfen geçerli bir URL girin."


# ── API Key Doğrulama ─────────────────────────────────────────────────────────
def check_api_key() -> bool:
    """
    REQUIRE_AUTH=true ise X-API-Key header'ını doğrular.
    API_KEY boşsa veya REQUIRE_AUTH=false ise her zaman True döner.
    """
    if not REQUIRE_AUTH or not API_KEY:
        return True
    token = request.headers.get("X-API-Key", "")
    return token == API_KEY


# =============================================================================
#  MIDDLEWARE
# =============================================================================

@app.after_request
def add_security_headers(response):
    """Güvenlik + önbellek engelleme başlıkları."""
    response.headers["Cache-Control"]             = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"]                    = "no-cache"
    response.headers["Expires"]                   = "0"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["Referrer-Policy"]           = "no-referrer"
    return response


# ── Global Durum Değişkenleri ─────────────────────────────────────────────────
scan_queues  = {}
scan_results = {}
scan_events  = {}


# =============================================================================
#  ROTALAR
# =============================================================================

@app.route("/")
def index():
    try:
        html_path = os.path.join(os.path.dirname(__file__), "security_scanner.html")
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
    except Exception as e:
        return f"Hata: {e}", 500


@app.route("/api/scan", methods=["POST"])
@limiter.limit("5 per hour; 20 per day")
def start_scan():
    # ── Kimlik doğrulama ──
    if not check_api_key():
        return jsonify({"error": "Yetkisiz erişim"}), 401

    data    = request.get_json()
    url     = (data.get("url") or "").strip()
    modules = data.get("modules", [])

    if not url:
        return jsonify({"error": "URL gerekli"}), 400

    if not url.startswith("http"):
        url = "https://" + url

    # ── SSRF kontrolü ──
    safe, err_msg = is_safe_url(url)
    if not safe:
        return jsonify({"error": err_msg}), 400

    if not modules:
        return jsonify({"error": "En az bir modül seçin"}), 400

    # ── Tarama başlat ──
    scan_id               = str(int(time.time() * 1000))
    scan_queues[scan_id]  = queue.Queue()
    scan_results[scan_id] = None
    cancel_event          = threading.Event()
    scan_events[scan_id]  = cancel_event

    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, url, modules, cancel_event),
        daemon=True
    )
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/cancel/<scan_id>", methods=["POST"])
def cancel_scan(scan_id):
    if scan_id in scan_events:
        scan_events[scan_id].set()
        return jsonify({"status": "cancelled"})
    return jsonify({"error": "Tarama bulunamadı"}), 404


# =============================================================================
#  TARAMA MOTORU
# =============================================================================

def run_scan(scan_id, url, modules, cancel_event):
    q = scan_queues[scan_id]

    print("\n" + "=" * 50)
    print(f">>> TARAMA BAŞLADI  |  Hedef: {url}")
    print("=" * 50 + "\n")

    try:
        from scanner import WebShieldScanner

        def log_callback(msg):
            q.put(msg)

        scanner = WebShieldScanner(log_callback=log_callback, cancel_event=cancel_event)

        test_map = {
            "crawl"    : lambda: scanner.crawl_site(url),
            "sqli"     : lambda: scanner.test_sqli(url),
            "xss"      : lambda: scanner.test_xss(url),
            "csrf"     : lambda: scanner.test_csrf(url),
            "headers"  : lambda: scanner.test_headers(url),
            "traversal": lambda: scanner.test_traversal(url),
            "files"    : lambda: scanner.test_sensitive_files(url),
            "redirect" : lambda: scanner.test_open_redirect(url),
            "cmdi"     : lambda: scanner.test_cmdi(url),
            "ssl"      : lambda: scanner.test_ssl(url),
            "cors"     : lambda: scanner.test_cors(url),
            "cookies"  : lambda: scanner.test_cookies(url),
            "methods"  : lambda: scanner.test_http_methods(url),
            "clickjack": lambda: scanner.test_clickjacking(url),
            "ratelimit": lambda: scanner.test_rate_limiting(url),
            "tech"     : lambda: scanner.test_tech_detect(url),
            "robots"   : lambda: scanner.test_robots_sitemap(url),
            "waf"      : lambda: scanner.test_waf(url),
            "ports"    : lambda: scanner.test_subdomain_port(url),
        }

        total = len(modules)

        for i, mod in enumerate(modules):
            if cancel_event.is_set():
                q.put("[!] Tarama kullanıcı tarafından iptal edildi.")
                break

            pct = int((i / total) * 100)
            q.put(f"__PROGRESS__:{pct}")

            test_fn = test_map.get(mod)
            if test_fn:
                print(f">>> %{pct:3d}  |  Modül: {mod}")
                test_fn()
            else:
                q.put(f"[!] Bilinmeyen modül atlandı: {mod}")

        q.put("__PROGRESS__:100")

        findings = scanner.findings
        counts   = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev in counts:
                counts[sev] += 1

        score = max(0, 100 - counts["HIGH"] * 20 - counts["MEDIUM"] * 5 - counts["LOW"] * 1)

        result = {"findings": findings, "counts": counts, "score": score}
        scan_results[scan_id] = result
        q.put("__DONE__")

        print(f"\n>>> TARAMA TAMAMLANDI  |  Skor: {score}  |  Bulgular: {len(findings)}\n")

    except Exception as e:
        print(f"\n!!! HATA: {e}\n")
        q.put(f"[✗] Tarama hatası: {e}")
        q.put("__DONE__")


# =============================================================================
#  POLLING
# =============================================================================

@app.route("/api/status/<scan_id>", methods=["GET"])
@limiter.limit("120 per minute")
def get_status(scan_id):
    q = scan_queues.get(scan_id)
    if not q:
        return jsonify({"status": "error", "msg": "Tarama bulunamadı"})

    msgs = []
    while True:
        try:
            msgs.append(q.get_nowait())
        except queue.Empty:
            break

    is_done = "__DONE__" in msgs

    if is_done:
        scan_queues.pop(scan_id, None)
        scan_events.pop(scan_id, None)

    return jsonify({"status": "ok", "messages": msgs, "done": is_done})


# =============================================================================
#  SSE (opsiyonel fallback)
# =============================================================================

@app.route("/api/stream/<scan_id>", methods=["GET"])
def stream(scan_id):
    def generate():
        yield ": heartbeat\n\n"
        q = scan_queues.get(scan_id)
        if not q:
            yield 'data: {"type":"error","msg":"Tarama bulunamadı"}\n\n'
            return
        while True:
            try:
                msg = q.get(timeout=10)
                if msg == "__DONE__":
                    result      = scan_results.get(scan_id, {})
                    result_json = json.dumps(result, ensure_ascii=False)
                    yield f'data: {{"type":"done","result":{result_json}}}\n\n'
                    scan_queues.pop(scan_id, None)
                    scan_events.pop(scan_id, None)
                    break
                elif msg.startswith("__PROGRESS__:"):
                    pct = msg.split(":")[1]
                    yield f'data: {{"type":"progress","pct":{pct}}}\n\n'
                else:
                    safe = json.dumps(msg, ensure_ascii=False)
                    yield f'data: {{"type":"log","msg":{safe}}}\n\n'
            except queue.Empty:
                yield 'data: {"type":"ping"}\n\n'
            except GeneratorExit:
                break

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.route("/api/results/<scan_id>", methods=["GET"])
def get_results(scan_id):
    result = scan_results.get(scan_id)
    if result:
        return jsonify(result)
    return jsonify({"error": "Sonuç bulunamadı"}), 404


# =============================================================================
#  STATİK DOSYA & HATA YÖNETİCİLERİ
# =============================================================================

@app.route("/<path:filename>")
def serve_static(filename):
    try:
        base      = os.path.dirname(__file__)
        file_path = os.path.join(base, filename)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return send_from_directory(base, filename)
    except Exception:
        pass
    abort(404)


@app.errorhandler(404)
def not_found(error):
    path = request.path.lower()
    if path == "/favicon.ico":
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
            '<rect width="100" height="100" fill="#f5f3f0"/>'
            '<text x="50" y="60" font-size="70" text-anchor="middle">🛡</text>'
            "</svg>",
            200,
            {"Content-Type": "image/svg+xml"},
        )
    if path == "/manifest.json":
        return jsonify({}), 200
    if path == "/robots.txt":
        return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain"}
    silent_paths = {"/x", "/.env", "/.git", "/wp-admin", "/admin", "/phpmyadmin"}
    if path in silent_paths:
        return "", 204
    return "", 404


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        "error": "Çok fazla istek gönderildi. Lütfen bir süre bekleyip tekrar deneyin."
    }), 429


# =============================================================================
#  HABER RSS
# =============================================================================

import urllib.request
import xml.etree.ElementTree as ET
import re

_news_cache    = {"data": [], "ts": 0}
NEWS_CACHE_TTL = 600
NEWS_FEED_URL  = "https://shiftdelete.net/feed"
NEWS_COUNT     = 10


def _fetch_url(url, timeout=6):
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; WebShield-NewsReader/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None


def _og_image(html_bytes):
    if not html_bytes:
        return ""
    html = html_bytes.decode("utf-8", errors="ignore")
    m = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', html)
    if m:
        return m.group(1)
    m = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']', html)
    return m.group(1) if m else ""


def _extract_image_from_item(item, NS_MEDIA, NS_CONTENT):
    t = item.find(f"{{{NS_MEDIA}}}thumbnail")
    if t is not None and t.get("url"):
        return t.get("url")
    c = item.find(f"{{{NS_MEDIA}}}content")
    if c is not None and c.get("url"):
        url = c.get("url", "")
        if any(url.lower().endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".webp", ".gif")):
            return url
    e = item.find("enclosure")
    if e is not None:
        url  = e.get("url", "")
        mime = e.get("type", "")
        if "image" in mime or any(url.lower().endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".webp")):
            return url
    ce = item.find(f"{{{NS_CONTENT}}}encoded")
    if ce is not None and ce.text:
        m = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', ce.text)
        if m:
            return m.group(1)
    return ""


@app.route("/api/news", methods=["GET"])
@limiter.limit("30 per hour")
def get_news():
    now = time.time()
    if _news_cache["data"] and (now - _news_cache["ts"]) < NEWS_CACHE_TTL:
        return jsonify({"articles": _news_cache["data"]})
    try:
        raw = _fetch_url(NEWS_FEED_URL, timeout=8)
        if not raw:
            raise Exception("RSS beslemesi indirilemedi.")

        root    = ET.fromstring(raw)
        channel = root.find("channel")
        items   = channel.findall("item") if channel else []

        NS_MEDIA   = "http://search.yahoo.com/mrss/"
        NS_CONTENT = "http://purl.org/rss/1.0/modules/content/"

        articles = []
        for item in items[:NEWS_COUNT]:
            title_el = item.find("title")
            title    = title_el.text.strip() if title_el is not None and title_el.text else "Başlıksız"
            link_el  = item.find("link")
            link     = (link_el.text or "").strip() if link_el is not None else "#"
            if not link:
                guid = item.find("guid")
                link = (guid.text or "#").strip() if guid is not None else "#"
            date_el  = item.find("pubDate")
            date     = date_el.text.strip() if date_el is not None and date_el.text else ""
            desc_el  = item.find("description")
            raw_desc = desc_el.text if desc_el is not None and desc_el.text else ""
            summary  = re.sub(r"<[^>]+>", "", raw_desc).strip()[:200]
            image    = _extract_image_from_item(item, NS_MEDIA, NS_CONTENT)
            if not image and link and link != "#":
                page  = _fetch_url(link, timeout=6)
                image = _og_image(page)
            articles.append({"title": title, "link": link, "date": date, "summary": summary, "image": image})

        _news_cache["data"] = articles
        _news_cache["ts"]   = now
        return jsonify({"articles": articles})

    except Exception as e:
        print(f"[!] RSS çekme hatası: {e}")
        if _news_cache["data"]:
            return jsonify({"articles": _news_cache["data"]})
        return jsonify({"articles": [], "error": str(e)}), 500


# =============================================================================
#  BAŞLANGIÇ
# =============================================================================

if __name__ == "__main__":
    print("=" * 55)
    print("  WebShield Scanner — Web Sunucusu")
    print("  http://localhost:5000  adresinde çalışıyor")
    if REQUIRE_AUTH:
        print("  API Key doğrulaması: AÇIK")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)