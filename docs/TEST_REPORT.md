# MergenScan doğruluk ve güvenlik düzeltme raporu

17 Ekim 2026. İnceleme tabanı: `f71f1abe8a7906a0aee80ce426f202c2fa5bafaa`.
Bu rapor kendisini içeren değişiklik setinin yerel doğrulamasını anlatır.

## Değerlendirme

Önceki 137 testin geçmesi doğruluk güvencesi oluşturmuyordu. Ağ sınırları taklit
edildiğinden DNS/yönlendirme açıkları, sabit metinlerin bulgu sayılması ve sezgisel
kontrollerin kesin sonuç gibi gösterilmesi kaçıyordu. Yeni paket güvenli negatif
kontrolleri, savunmasız pozitif örnekleri, gerçek yerel HTTP ve tarayıcı akışını
birleştirir. Test sayısı doğruluk yüzdesi değildir; geniş bağımsız bir hedef veri
kümesinde precision/recall ölçülmedi.

## Düzeltilen sorunlar

| Alan | Sorun | Düzeltme / kanıt |
|---|---|---|
| SQLi | Sabit hata metni ve yinelenen parametreler | Kontrol yanıtıyla hata kümesi karşılaştırması; gerçek SQLite savunmasız/parametreli güvenli hedef |
| XSS | Metin yansıması çalışabilir kodla karışıyordu | Benzersiz işaret; MIME/HTML bağlamı, escaped metin, yorum, textarea/template, JSON ve yinelenen öznitelik testleri |
| Komut enjeksiyonu | Sayfadaki uid metni yeterliydi | İstekte bitişik olmayan printf çıktı işareti; echo/statik metin negatif kontrolü |
| Traversal | Kısmi/sabit passwd metni | Tam kayıt ve kontrol yanıtında bulunmama şartı |
| Yönlendirme | Mevcut next parametresi yineleniyordu | Eski değer kaldırılır; ilk parametreyi seçen hedef için regresyon |
| CORS | Wildcard ve geçersiz True değeri | Origin yansıması + tam true eşleşmesi; wildcard yalnızca gözlem |
| Clickjacking | frame-ancestors https://* koruma sanılıyordu | Direktif, çoklu politika ve wildcard host ayrımı |
| Metot/WAF/limit | OPTIONS, WAF yokluğu veya 429 yokluğu açık sayılabiliyordu | Gözlemler ayrıldı; TRACE gerçek işaret yansımasıyla değerlendirilir |
| API | Boş anahtar ve anahtarsız log erişimi | Boş anahtarla erişim kapalı; başlat/durum/sonuç/iptal doğrulaması |
| SSRF | Yönlendirme/yeniden DNS çözümleme özel ağa gidebiliyordu | Tüm DNS yanıtları, IP sabitleme, her yönlendirmede kontrol; TLS/port yolları da sabit IP kullanır |
| Kaynak tüketimi | Yanıt/bekleyen iş sınırsız; yavaş başlıklar süreyi aşabiliyordu | 2 MiB yanıt, socket kesici, beş yuva, sınırlı log/geçmiş; yavaş başlık/gzip testleri |
| Yaşam döngüsü | Tek modül hatası diğerlerini durduruyordu | Modül bazında hata ve devam; eksik taramada puan yok |
| Site | 12/18 tutarsızlığı, temelsiz canlı sayaçlar, anahtar girişi yok | 18 modül, kapsam açıklaması, anahtar girişi, gözlem/kanıt türü gösterimi |
| İçerik güvenliği | Haber şemaları ve CDN script gereksinimi | HTTP(S) doğrulaması, HTML kaçışlama, yerel JS/CSS, script-src self |

## Doğrulama

- Python: `python -m pytest tests -q` — **250 test geçti**.
- Node: `node tests/test_ui.cjs` — söz dizimi, 18 modül, sonuç/hata/iptal/timeout,
  kısmi bulgular, URL filtreleme, anahtar saklamama ve yerel script kontrolleri geçti.
- Chromium: `tests/browser_smoke.cjs` — **1440px masaüstü ve 390px mobil geçti**.
  Modül seçimi, anahtarın tarama uçlarına taşınması, Flask→yerel hedef→sonuç akışı,
  bulgu açılması, hatada puansız görünüm, kaçışlama ve yatay taşma kontrol edildi.
  Beklenmeyen JavaScript hatası veya iletişim kutusu oluşmadı.
- Yavaş HTTP başlığı ve sıkıştırılmış ancak çıktı üretmeyen akış 0,2 saniyelik
  test kesicisiyle durduruldu; 1,5 saniyeden kısa sürdüğü doğrulandı.
- `git diff --check` temiz.

Ortam: Python 3.12.14, pytest 9.1.1, Flask 3.1.3, requests 2.34.2, urllib3 2.8.0,
Node.js 24.19.0, Playwright istemcisi 1.62.1, Chromium 134.0.6998.35.
Varsayılan Chromium indirmesi başarısız olduğundan indirilebilen Chromium yolu
BROWSER_EXECUTABLE ile belirtildi. Bu, tüm güncel tarayıcılarla uyumluluk testi
değildir. Dış font/harita/haber servisleri tarayıcı testinde engellendi.

## Kalan sınırlar

XSS HTML bağlamı kanıtıdır; CSP altında gerçekten çalışması kanıtlanmaz.
Ayrıştırıcı tam tarayıcı motoru değildir. CSRF, çerez, başlık, teknoloji, robots
ve port bulguları bağlama göre uzman doğrulaması gerektirir. Hassas dosya imzaları
özel soft-404 metinleriyle karışabilir. Komut enjeksiyonu testi yerel shell
çalıştırmaz; pozitif yanıt düzeneği kullanır. TLS/portlar canlı dış hizmetlerle
denenmedi. Kapsam sınırları README'deki modül tablosunda belirtilmiştir.

DNS süresi işletim sistemine bağlıdır; socket kesicisinin dışındadır. İptal
kontrol noktalarında işlenir. İzleyici timeout sonucunda kısmi bulgular korunmayabilir.
Paylaşılan anahtar çok kullanıcılı yetkilendirme değildir. İş/sonuç ve rate-limit
durumu tek süreç belleğindedir. Ayrı bağımlılık/CVE denetimi yapılmadı.

Bu çalışma kaynak incelemesi ve kontrollü yerel doğrulamadır. Codex Security
becerisinin yardımcı kaynak/araçları erişilebilir olmadığından kanonik Codex
Security taraması tamamlandı iddiası yoktur. Bağımsız kaynak ve yama incelemesi
yapıldı; bildirilen beş yama sorunu regresyon testleriyle düzeltildi.

Canlı mergenscan.tech dağıtımı, barındırma değişkenleri ve dış hizmetler
doğrulanmadı. GitHub'a gönderim canlı dağıtımın tamamlandığı anlamına gelmez.
