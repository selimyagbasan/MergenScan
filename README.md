# 🛡 MergenScan — Web Güvenlik Tarayıcısı

Kapsamlı web uygulama güvenlik tarayıcısı. Flask tabanlı web arayüzü ile SQL Injection, XSS, CORS, SSL ve daha fazlasını test eder.

---

## ⚠️ Yasal Uyarı

> Bu araç **yalnızca kendi web sitelerinizi** veya yazılı izin aldığınız sistemleri test etmek için tasarlanmıştır.
> İzinsiz sistemlerde kullanmak **yasaldır ve hukuki sonuçlar doğurabilir.**
> Geliştirici, aracın kötüye kullanımından doğacak hiçbir zarardan sorumlu tutulamaz.

---

## 🔒 Güvenlik Özellikleri

| Özellik | Açıklama |
|---|---|
| **Rate Limiting** | IP başına saatte 5, günde 20 tarama |
| **SSRF Koruması** | İç ağ ve metadata adreslerine erişim engeli |
| **API Key Auth** | İsteğe bağlı, `.env` üzerinden yapılandırılır |
| **Güvenlik Headers** | Her yanıtta X-Frame-Options, X-Content-Type-Options vb. |

---

## 🧪 Test Modülleri

- SQL Injection
- XSS (Reflected)
- CSRF Token Kontrolü
- HTTP Güvenlik Başlıkları
- SSL/TLS Analizi
- CORS Politikası
- Cookie Güvenliği
- Path Traversal
- Hassas Dosya Keşfi
- Open Redirect
- Command Injection
- Clickjacking
- Rate Limiting Testi
- WAF Tespiti
- Teknoloji Tespiti
- HTTP Methods
- robots.txt / Sitemap Analizi
- Subdomain & Port Tarama
- Site Crawler

---

### Gunicorn + Nginx (Önerilen)
```bash
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

Nginx yapılandırması için `DEPLOY.md` dosyasına bakın.

---

## 📁 Proje Yapısı

```
mergenscan/
├── app.py                 # Flask web sunucusu
├── scanner.py             # Güvenlik test modülleri
├── security_scanner.html  # Web arayüzü
├── requirements.txt       # Python bağımlılıkları
├── .env.example           # Örnek ortam değişkenleri
├── .gitignore
└── README.md
```

---

## 📄 Lisans

MIT License — Ayrıntılar için `LICENSE` dosyasına bakın.
