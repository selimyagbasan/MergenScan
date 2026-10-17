# URL tarama erişimi düzeltmesi — 17 Ekim 2026

Taban sürüm: `25b0254`. Canlı sitenin `/api/config` yanıtı:

```json
{"auth_required":true,"scan_available":false}
```

Sunucuda anahtar zorunlu, ancak WEBSHIELD_API_KEY tanımlı değil. Bu nedenle
tarama kapalı. HTML alanına yazılan sabit anahtar sunucunun ortam değişkenini
oluşturmuyor ve sayfa kaynağını gören herkese açılıyor.

Düzeltmeler:

- Kaynak koddaki sabit anahtar kaldırıldı; tasarım öğeleri korundu.
- Sunucu yapılandırma eksikliği 503, yanlış/eksik kullanıcı anahtarı 401 olarak
  ayrı hata kodlarıyla bildiriliyor. Erişim denetimi kapatılmadı.
- Tarama öncesinde yapılandırma ve boş anahtar kontrol ediliyor. Enter tuşu da
  bu kontrollerden geçiyor. Anahtarın çevresindeki boşluklar temizleniyor.
- Yalnızca açıkça `REQUIRE_AUTH=false` seçilirse anahtarsız mod etkinleşiyor;
  bilinmeyen değerler korumayı sessizce kapatmıyor.

Doğrulama: 256 pytest testi, Node UI kontrolleri ve 1440px/390px Chromium testleri
geçti. Tarayıcı testleri eksik sunucu anahtarı, boş kullanıcı anahtarı ve etrafında
boşluk bulunan geçerli anahtarla gerçek yerel tarama akışını kapsıyor. API testleri
yanlış anahtarın reddini ve açıkça seçilen anahtarsız modu da doğruluyor.

Tasarım kontrolü: HTML'nin tek farkı anahtarın value özniteliğinin kaldırılması;
CSS dosyaları ve Tailwind ayarları değişmedi.

Canlı hizmetin açılması için kalan adım: barındırma ortamında yeni ve güçlü bir
WEBSHIELD_API_KEY tanımlanmalı, REQUIRE_AUTH=true bırakılmalı ve yeniden dağıtım
yapılmalı. Açığa çıkmış eski anahtar yeniden kullanılmamalı. Bu oturumda
barındırma yönetimine erişim olmadığı için ortam değişkeni değiştirilmedi.
