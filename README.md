# MergenScan

Web uygulamalarındaki güvenlik açıklarını otomatik olarak tespit eden, tarayıcı tabanlı bir güvenlik tarama aracı.

www.mergenscan.tech

## Özellikler

18 farklı test modülü ile OWASP Top 10 kapsamında güvenlik analizi yapar. Tarama sonuçlarını önem derecesine göre (Yüksek / Orta / Düşük) sınıflandırır ve genel bir güvenlik skoru üretir.

**Test Modülleri**

| Modül | Açıklama |
|---|---|
| SQL Injection | Veritabanı parametrelerinde hata tabanlı SQLi tespiti |
| XSS | Reflect edilen Cross-Site Scripting açıkları |
| CSRF | Form bazlı CSRF token varlığı kontrolü |
| HTTP Headers | Strict-Transport-Security, CSP, X-Frame-Options kontrolü |
| Path Traversal | Dizin geçişi ile dosya okuma açıkları |
| Hassas Dosyalar | `.env`, `.git/config`, `wp-config.php` erişim kontrolü |
| Open Redirect | Harici URL yönlendirme açıkları |
| Command Injection | Sunucu tarafı komut çalıştırma tespiti |
| SSL/TLS | Sertifika ve protokol kontrolü |
| CORS | Wildcard origin politikası tespiti |
| Cookie Bayrakları | Secure / HttpOnly bayrak kontrolü |
| HTTP Metodları | Tehlikeli metod (PUT, DELETE, TRACE) tespiti |
| Clickjacking | X-Frame-Options ve CSP frame politikası |
| Rate Limiting | Brute-force koruması varlığı |
| Teknoloji Tespiti | Sunucu, framework ve CMS tespiti |
| Robots / Sitemap | Gizli yol ve endpoint tespiti |
| WAF Tespiti | Web Application Firewall varlığı |
| Port Taraması | Açık port ve servis tespiti |


## Güvenlik

- Özel IP adresleri ve localhost taraması engellenir (SSRF koruması)
- Her IP için saatlik istek limiti uygulanır
- Tüm kullanıcı girdileri doğrulanır
- Güvenlik başlıkları (CSP, HSTS, X-Frame-Options) tüm yanıtlara eklenir

