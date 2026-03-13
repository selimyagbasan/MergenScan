#!/usr/bin/env python3
# =============================================================================
#  WebShield Scanner — Flask Web Sunucusu
# =============================================================================

from flask import Flask, request, jsonify, abort
import requests
import threading
import os
import queue
import time
import socket
import ipaddress
import smtplib
from email.mime.text import MIMEText
from urllib.parse import urlparse
from dotenv import load_dotenv

import defusedxml.ElementTree as ET
import urllib.request
import re
import bleach
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# FİX: static_folder="." kaldırıldı — kaynak kod sızıntısı riski giderildi
app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://"
)

executor = ThreadPoolExecutor(max_workers=5)

API_KEY      = os.environ.get("WEBSHIELD_API_KEY", "")
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() == "true"

# ── URL Güvenlik Kontrolü ──────────────────────────────────────────────────────

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        host   = (parsed.hostname or "").lower()

        if not host:
            return False, "Geçerli bir URL giriniz."

        if parsed.scheme not in ("http", "https"):
            return False, "Yalnızca http ve https protokolleri desteklenir."

        try:
            ip_str = socket.gethostbyname(host)
        except socket.gaierror:
            return False, "Alan adı çözümlenemedi. Geçersiz veya kapalı bir site olabilir."

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, "Geçersiz bir IP adresi formatı."

        if ip_obj.is_loopback:
            return False, "Yerel ağa (localhost) tarama yapılamaz."
        if ip_obj.is_private:
            return False, "Özel/İç ağ (Private IP) adreslerine tarama yapılamaz."
        if ip_obj.is_link_local:
            return False, "Bulut metadata adreslerine erişim yasaktır."
        if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
            return False, "Rezerve edilmiş IP adresleri taranamaz."

        return True, ""
    except Exception as e:
        return False, f"URL ayrıştırılamadı: {str(e)}"


def check_api_key():
    if not REQUIRE_AUTH or not API_KEY:
        return True
    return request.headers.get("X-API-Key", "") == API_KEY


# ── Güvenlik Başlıkları ────────────────────────────────────────────────────────

@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"]             = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"]                    = "no-cache"
    response.headers["Expires"]                   = "0"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["Referrer-Policy"]           = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: https:; "
    "connect-src 'self';"
)
    return response

# ── Tarama Durumu (bellek) ─────────────────────────────────────────────────────

scan_queues     = {}
scan_results    = {}
scan_events     = {}
scan_timestamps = {}

# ── Hata İşleyiciler ──────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "API Endpoint bulunamadı."}), 404
    path = request.path.lower()
    if path == "/favicon.ico":
        svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="#f5f3f0"/><text x="50" y="60" font-size="70" text-anchor="middle">🛡</text></svg>'
        return svg, 200, {"Content-Type": "image/svg+xml"}
    if path in {"/x", "/.env", "/.git", "/wp-admin", "/admin"}:
        return "", 204
    return "", 404


@app.errorhandler(405)
def method_not_allowed(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Bu metoda izin verilmiyor."}), 405
    return "Method Not Allowed", 405


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Çok fazla istek gönderildi. Lütfen bekleyin."}), 429


@app.errorhandler(Exception)
def handle_global_exception(error):
    logger.exception("Beklenmeyen hata")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Beklenmeyen bir sunucu hatası oluştu."}), 500
    return "Sunucu Hatası", 500


# ── Ana Sayfa ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    try:
        html_path = os.path.join(os.path.dirname(__file__), "security_scanner.html")
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
    except Exception as e:
        return f"Hata: {e}", 500


# ── Tarama Başlat ─────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@limiter.limit("5 per hour; 20 per day")
def start_scan():
    if not check_api_key():
        return jsonify({"error": "Yetkisiz erişim"}), 401

    data    = request.get_json(silent=True) or {}
    url     = (data.get("url") or "").strip()
    modules = data.get("modules", [])

    if not url:
        return jsonify({"error": "URL gerekli"}), 400
    if not url.startswith("http"):
        url = "https://" + url

    safe, err_msg = is_safe_url(url)
    if not safe:
        return jsonify({"error": err_msg}), 400
    if not modules:
        return jsonify({"error": "En az bir modül seçin"}), 400

    # Süresi dolmuş taramaları temizle
    now     = time.time()
    expired = [sid for sid, ts in scan_timestamps.items() if now - ts > 600]
    for sid in expired:
        scan_queues.pop(sid, None)
        scan_results.pop(sid, None)
        scan_events.pop(sid, None)
        scan_timestamps.pop(sid, None)

    scan_id                  = str(uuid.uuid4())
    scan_queues[scan_id]     = queue.Queue()
    scan_results[scan_id]    = None
    cancel_event             = threading.Event()
    scan_events[scan_id]     = cancel_event
    scan_timestamps[scan_id] = now

    future = executor.submit(run_scan, scan_id, url, modules, cancel_event)

    def _watch_timeout(fut, sid, limit=120):
        try:
            fut.result(timeout=limit)
        except TimeoutError:
            if sid in scan_events:
                scan_events[sid].set()
            if sid in scan_queues:
                scan_queues[sid].put("[!] Tarama zaman aşımına uğradı.")
                scan_queues[sid].put("__DONE__")
        except Exception:
            pass

    threading.Thread(target=_watch_timeout, args=(future, scan_id), daemon=True).start()
    return jsonify({"scan_id": scan_id})


@app.route("/api/cancel/<scan_id>", methods=["POST"])
def cancel_scan(scan_id):
    if not check_api_key():
        return jsonify({"error": "Yetkisiz erişim"}), 401
    if scan_id in scan_events:
        scan_events[scan_id].set()
        return jsonify({"status": "cancelled"})
    return jsonify({"error": "Tarama bulunamadı"}), 404


# ── Tarama İşlemi ─────────────────────────────────────────────────────────────

def run_scan(scan_id, url, modules, cancel_event):
    q = scan_queues.get(scan_id)
    if not q:
        return

    try:
        from scanner import WebShieldScanner

        def log_callback(msg):
            q.put(msg)

        scanner = WebShieldScanner(log_callback=log_callback, cancel_event=cancel_event)

        test_map = {
            "crawl":     lambda: scanner.crawl_site(url),
            "sqli":      lambda: scanner.test_sqli(url),
            "xss":       lambda: scanner.test_xss(url),
            "csrf":      lambda: scanner.test_csrf(url),
            "headers":   lambda: scanner.test_headers(url),
            "traversal": lambda: scanner.test_traversal(url),
            "files":     lambda: scanner.test_sensitive_files(url),
            "redirect":  lambda: scanner.test_open_redirect(url),
            "cmdi":      lambda: scanner.test_cmdi(url),
            "ssl":       lambda: scanner.test_ssl(url),
            "cors":      lambda: scanner.test_cors(url),
            "cookies":   lambda: scanner.test_cookies(url),
            "methods":   lambda: scanner.test_http_methods(url),
            "clickjack": lambda: scanner.test_clickjacking(url),
            "ratelimit": lambda: scanner.test_rate_limiting(url),
            "tech":      lambda: scanner.test_tech_detect(url),
            "robots":    lambda: scanner.test_robots_sitemap(url),
            "waf":       lambda: scanner.test_waf(url),
            "ports":     lambda: scanner.test_subdomain_port(url),
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
                test_fn()

        q.put("__PROGRESS__:100")

        findings = scanner.findings
        counts   = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f.get("severity", "LOW")] += 1

        score = max(0, 100 - counts["HIGH"] * 20 - counts["MEDIUM"] * 5 - counts["LOW"] * 1)
        scan_results[scan_id] = {"findings": findings, "counts": counts, "score": score}
        q.put("__DONE__")

    except Exception as e:
        q.put(f"[✗] Tarama hatası: {e}")
        q.put("__DONE__")


# ── Durum / Sonuç ─────────────────────────────────────────────────────────────

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

    return jsonify({"status": "ok", "messages": msgs, "done": is_done})


@app.route("/api/results/<scan_id>", methods=["GET"])
def get_results(scan_id):
    if not check_api_key():
        return jsonify({"error": "Yetkisiz erişim"}), 401
    result = scan_results.get(scan_id)
    if result:
        return jsonify(result)
    return jsonify({"error": "Sonuç bulunamadı"}), 404


# ── Haberler ──────────────────────────────────────────────────────────────────

_news_cache    = {"data": [], "ts": 0}
NEWS_CACHE_TTL = 600
# app.py içinde — birden fazla kaynak, biri çalışmazsa diğerine geç
NEWS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",   # The Hacker News - Siber güvenlik
    "https://feeds.feedburner.com/securityweek",     # SecurityWeek
    "https://cloudsecurityalliance.org/blog/feed/",  # Cloud Security Alliance
]
NEWS_COUNT = 10


def _fetch_url(url, timeout=8):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
        }
        r = requests.get(url, headers=headers, timeout=timeout, verify=True)
        if r.status_code == 200:
            return r.content
        return None
    except Exception:
        return None


def _og_image(html_bytes):
    if not html_bytes:
        return ""
    html = html_bytes.decode("utf-8", errors="ignore")
    # Her iki attribute sırasını da yakala
    m = re.search(
        r'<meta[^>]+(?:property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']'
        r'|content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\'])',
        html
    )
    if m:
        return m.group(1) or m.group(2)
    return ""


def _extract_image_from_item(item, NS_MEDIA, NS_CONTENT):
    # 1. Standart medya etiketi kontrolü
    t = item.find(f"{{{NS_MEDIA}}}thumbnail")
    if t is not None and t.get("url"):
        return t.get("url")
    t_content = item.find(f"{{{NS_MEDIA}}}content")
    if t_content is not None and t_content.get("url"):
        return t_content.get("url")
        
    # 2. Enclosure etiketi kontrolü
    e = item.find("enclosure")
    if e is not None and "image" in e.get("type", ""):
        return e.get("url", "")
        
    # 3. Metin içi (Content) gömülü resimleri arama
    ce = item.find(f"{{{NS_CONTENT}}}encoded")
    if ce is not None and ce.text:
        m = re.search(r'<img[^>]+src=["\']([^"\']+(?:jpg|jpeg|png|webp|gif))["\']', ce.text, re.IGNORECASE)
        if m:
            return m.group(1)
            
    # 4. Description içi resimleri arama
    desc = item.find("description")
    if desc is not None and desc.text:
        m = re.search(r'<img[^>]+src=["\']([^"\']+(?:jpg|jpeg|png|webp|gif))["\']', desc.text, re.IGNORECASE)
        if m:
            return m.group(1)
            
    return ""

def _translate_titles(titles):
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not anthropic_key:
        return titles
    try:
        numbered = "\n".join(f"{i+1}. {t}" for i, t in enumerate(titles))
        payload = {
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 1024,
            "messages": [{
                "role": "user",
                "content": (
                    "Aşağıdaki İngilizce haber başlıklarını Türkçeye çevir. "
                    "Sadece numaralı listeyi döndür, başka hiçbir şey yazma. "
                    "Her satır '1. Başlık' formatında olsun.\n\n" + numbered
                )
            }]
        }
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         anthropic_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json=payload, timeout=15, verify=True
        )
        if r.status_code != 200:
            return titles
        text = r.json()["content"][0]["text"].strip()
        translated = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line[0].isdigit() and ". " in line:
                line = line.split(". ", 1)[1]
            translated.append(line)
        return translated if len(translated) == len(titles) else titles
    except Exception:
        return titles

@app.route("/api/news", methods=["GET"])
@limiter.limit("30 per hour")
def get_news():
    now = time.time()
    if _news_cache["data"] and (now - _news_cache["ts"]) < NEWS_CACHE_TTL:
        return jsonify({"articles": _news_cache["data"]})
    
    for feed_url in NEWS_FEEDS:
        try:
            raw = _fetch_url(feed_url, timeout=8)
            if not raw:
                continue
            root    = ET.fromstring(raw)
            channel = root.find("channel")
            items   = channel.findall("item") if channel else []
            if not items:
                continue
            articles = []
            for item in items[:NEWS_COUNT]:
                title_el = item.find("title")
                link_el  = item.find("link")
                date_el  = item.find("pubDate")
                desc_el  = item.find("description")
                title   = title_el.text.strip() if title_el is not None and title_el.text else "Başlıksız"
                link    = (link_el.text or "").strip() if link_el is not None else "#"
                date    = date_el.text.strip() if date_el is not None and date_el.text else ""
                summary = bleach.clean(desc_el.text or "", tags=[], strip=True).strip()[:200] if desc_el is not None and desc_el.text else ""
                image   = _extract_image_from_item(item, "http://search.yahoo.com/mrss/", "http://purl.org/rss/1.0/modules/content/")
                if not image and link and link != "#":
                    image = _og_image(_fetch_url(link, timeout=5))
                articles.append({"title": title, "link": link, "date": date, "summary": summary, "image": image})
                original_titles   = [a["title"] for a in articles]
            translated_titles = _translate_titles(original_titles)
            for article, tr_title in zip(articles, translated_titles):
                article["title"] = tr_title

            _news_cache["data"] = articles
            
            _news_cache["data"] = articles
            _news_cache["ts"]   = now
            return jsonify({"articles": articles})
        except Exception:
            continue
    
    if _news_cache["data"]:
        return jsonify({"articles": _news_cache["data"]})
    return jsonify({"articles": [], "error": "Haber kaynağına ulaşılamadı."}), 500


# ── Başlat ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)