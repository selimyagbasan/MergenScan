# MergenScan

Web uygulamaları için 18 seçilebilir güvenlik ön kontrolü. Bulgular kanıt türüyle,
tamamlanamayan kontroller hata durumuyla ve bilgi amaçlı gözlemler ayrı gösterilir.
Kapsamlı sızma testi veya OWASP uygunluk belgesi sağlamaz.

## Çalıştırma

Python 3.12 ile doğrulandı. Yalnızca sahibi olduğunuz veya test izniniz bulunan
hedeflerde kullanın.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Üretilen değeri `.env` içindeki `WEBSHIELD_API_KEY` alanına yazın;
`REQUIRE_AUTH=true` bırakın. `python app.py` ile çalıştırıp
`http://localhost:5000` adresini açın. Erişim bölümüne aynı anahtarı girin.
Anahtar tarayıcı depolamasına yazılmaz; sayfa yenilenince yeniden girilir.
Sunucuda anahtar boşsa tarama kapalı kalır. Gerçek `.env` dosyasını paylaşmayın.

Üretimde HTTPS sonlandıran ters proxy ve Procfile'daki tek Gunicorn worker /
sekiz thread yapılandırmasını kullanın. Anahtarı barındırma ortamının gizli
değişkenlerine ekleyin. Mevcut dağıtımda `REQUIRE_AUTH=false` varsa ayrıca değiştirin;
depo güncellemesi barındırma ortamının değişkenlerini değiştirmez.

Tarama durumu ve istek limitleri süreç belleğindedir. Yeniden başlatmada sonuçlar
kaybolur; birden fazla worker/örnek için ortak görev, sonuç ve limit deposu gerekir.
Paylaşılan API anahtarı kullanıcı bazında sonuç sahipliği sağlamaz.

## Kontroller ve sınırları

| Kontrol | Kanıt / kapsam |
|---|---|
| SQL Injection | Kontrol yanıtına göre yeni SQL hata imzası; hata tabanlı GET kontrolü |
| XSS | Benzersiz işaretin etkin HTML script/olay bağlamında yansıması; tarayıcıda çalıştırma doğrulanmaz |
| CSRF | POST formlarında token adları; token geçerliliği ve tüm savunmalar test edilmez |
| HTTP Headers | Seçili başlıklar; bütün politika semantiğini kapsamaz |
| Path Traversal | Kontrol yanıtında olmayan tam passwd kaydı |
| Hassas Dosyalar | Dört sabit dosyada içerik imzası; sıradan HTML soft-404 yanıtları elenir |
| Open Redirect | next parametresindeki harici hedefe yönlendirme; hedef takip edilmez |
| Command Injection | İstekte bitişik bulunmayan benzersiz çıktı; Unix printf tabanlı sınırlı kontrol |
| SSL/TLS | Sertifika ve tek bağlantının protokolü; tüm TLS sürümleri denenmez |
| CORS | Rastgele origin yansıtma + credentials izni; hassas veri erişimi ayrıca doğrulanmalı |
| Cookie | Secure / HttpOnly / SameSite öznitelikleri; çerezin işlevi ayrıca değerlendirilir |
| HTTP Metodları | OPTIONS gözlemi ve TRACE yansıtma; PUT/DELETE ile veri değiştirilmez |
| Clickjacking | X-Frame-Options ve CSP frame-ancestors; tarayıcıda çerçeveleme denenmez |
| Rate Limiting | 15 istekte 429 gözlemi; 429 görülmemesi açık sayılmaz |
| Teknoloji | Başlık/gövde imzaları; ürün veya sürüm kesinliği sağlamaz |
| Robots / Sitemap | Yayınlanan yollar; yolun erişilebilirliğini kanıtlamaz |
| WAF | Yanıt farkı; WAF varlığı/yokluğu kesinleştirilmez, puanı etkilemez |
| Portlar | 19 yaygın TCP portu; hizmet adı port eşlemesidir, servis tanımlama değildir |

Enjeksiyon kontrolleri en fazla ilk üç mevcut GET parametresini dener; yoksa
varsayılan parametreyi kullanır. POST/JSON, oturum açılmış akışlar, DOM tabanlı/
depolanan XSS, blind SQLi ve tüm sayfalar kapsam dışıdır. API'deki ek `crawl`
kontrolü bağlantıları sayar; bu sayfaları otomatik taramaz.

Bir modül hata verirse diğerleri devam eder. Sonuç `checks`, `observations`,
`findings` içerir. Hata/iptal/zaman aşımında `score: null` olur. Tamamlanan
taramanın puanı seçili kontrollerin bulgu özetidir; güvenlik garantisi veya ölçülmüş
doğruluk oranı değildir. İzleyici zaman aşımında kısmi bulgular korunmayabilir;
bu durumda sonuç tamamlanmamış olarak gösterilir.

## Ağ ve kaynak sınırları

- Tüm DNS adresleri denetlenir; özel/yerel, CGNAT ve geçiş adresleri reddedilir.
- Bağlantı doğrulanan IP'ye sabitlenir; HTTPS isim/SNI doğrulaması korunur.
- Her yönlendirme yeniden denetlenir; en fazla beş yönlendirme izlenir.
- Yanıt açılmış halde 2 MiB ile sınırlıdır. Her isteğin ağ I/O'su 12 saniyelik
  kesiciyle korunur; işletim sisteminin DNS çözümleme süresi bunun dışındadır.
- Beş tarama yuvası, sınırlı log kuyruğu ve en fazla 200 tarama kaydı tutulur.
  Sonraki tarama başlatılırken 10 dakikadan eski tamamlanmış kayıtlar temizlenir.
- 120 saniyelik izleyici sonucu timeout yapar; çalışan kontrol çıkana kadar
  kapasite yuvası tutulur. İptal anında her sistem çağrısı kesilmez.
- Ortam proxy/netrc bilgileri ve kullanıcı çerezleri hedeflere gönderilmez.

Haberlerde yalnızca HTTP(S) bağlantıları kabul edilir. Makale sayfaları ayrıca
sunucudan indirilmez. Google yazı tipleri ve Kaspersky haritası dış servislerdir.

## Test ve arayüz derleme

```sh
python -m pytest tests -q
node tests/test_ui.cjs
```

Testler taklit yanıtlar ve yerel HTTP hedefleri kullanır; dış siteler taranmaz.
Yalnızca test düzeneğinin DNS çözümleyicisi loopback'e izin verir; üretimde
korumayı kapatan bir seçenek yoktur.

Gerçek tarayıcı testi (Node.js ve Playwright gerekir):

```sh
npm install --no-save playwright
npx playwright install chromium
PYTHON=python node tests/browser_smoke.cjs
```

`BROWSER_EXECUTABLE` hazır Chromium yolu, `SCREENSHOT_DIR` ekran görüntüsü
klasörü olabilir. Test 1440px ve 390px genişlikte Flask tarama akışını sınar;
dış kaynak isteklerini engeller.

CSS depoda derlenmiş haldedir; sunucu Node.js gerektirmez. HTML/JS'deki Tailwind
sınıfları değişince yeniden üretin:

```sh
npx --yes --package tailwindcss@3.4.17 tailwindcss -c tailwind.config.cjs -i static/input.css -o static/theme.css --minify
```

Değerlendirme ve kanıtlar: [Test raporu](docs/TEST_REPORT.md).
