# AntiGravity — Network Traffic Manager

> ⚠️ **UYARI**: Bu araç **yalnızca eğitim amaçlıdır**. Kendi ağınızda, izinli cihazlarda ve
> izole bir lab ortamında kullanın. Yetkisiz erişim ve müdahale **yasal suç** teşkil eder.

---

## 📖 Genel Bakış

AntiGravity, yerel ağınızdaki cihazları keşfetmenize, izole etmenize ve trafik akışını
yönetmenize olanak sağlayan bir ağ trafik yönetim aracıdır. Hem CLI hem de modern Web UI
arayüzü sunar.

### Temel Özellikler

| Özellik | Açıklama |
|---|---|
| 🔍 ARP Tarama | Yerel ağdaki tüm cihazları keşfeder |
| 🚫 Cihaz İzolasyonu | ARP + NDP spoofing ile internet erişimini keser |
| 📊 Paket Akış Kontrolü | Forward / Drop / Throttle / Inspect modları |
| 🌐 IPv6 NDP Spoofing | IPv6 neighbor cache zehirleme |
| 👁 Website Monitor | DNS + TLS SNI ile ziyaret edilen siteleri izler |
| 🖥 Web UI | Modern dark-theme arayüz (SSE ile canlı güncelleme) |

---

## 🏗 Proje Yapısı

```
ping_project/
├── main.py                    # CLI arayüzü (menü sistemi)
├── web_app.py                 # Flask web uygulaması (REST API + SSE)
├── config.py                  # Merkezi konfigürasyon
├── requirements.txt           # Python bağımlılıkları
├── README.md                  # Bu dosya
│
├── modules/
│   ├── utils.py               # ANSI renkler, yardımcı fonksiyonlar, logging
│   ├── node_discovery.py      # ARP tabanlı ağ keşfi
│   ├── traffic_redirection.py # ARP cache poisoning (IPv4)
│   ├── packet_flow_control.py # Paket yakalama ve akış kontrolü
│   ├── ipv6_ndp.py            # IPv6 NDP keşfi ve NA spoofing
│   ├── dns_monitor.py         # DNS sorgu ve TLS SNI izleme
│   ├── oui_table.py           # MAC OUI → vendor/cihaz tanıma
│   ├── passive_sniffer.py     # Pasif mDNS/DHCP/LLMNR/NetBIOS dinleyici
│   └── app_state.py           # Thread-safe uygulama durumu (AppState)
│
├── static/
│   ├── index.html             # Web UI ana sayfa
│   ├── style.css              # Dark theme, glassmorphism tasarım
│   └── app.js                 # Frontend JavaScript (API, SSE, animasyonlar)
│
└── tests/
    ├── test_utils.py          # utils.py birim testleri
    ├── test_oui.py            # oui_table.py birim testleri
    ├── test_dns_monitor.py    # dns_monitor.py birim testleri
    └── test_passive.py        # passive_sniffer.py birim testleri
```

---

## 🚀 Kurulum

### Gereksinimler

- **Python 3.10+**
- **Root/sudo yetkisi** (raw socket erişimi için)
- macOS veya Linux

### Bağımlılıklar

```bash
pip install -r requirements.txt
```

### Çalıştırma

#### CLI Arayüzü
```bash
sudo python3 main.py
```

#### Web Arayüzü
```bash
sudo python3 web_app.py
```
Tarayıcıda `http://localhost:8080` adresine gidin.

---

## 📋 CLI Menü Yapısı

```
[1] Node Discovery      (ARP Keşfi)       — ARP ile yerel ağ tarama
[2] Traffic Redirection (ARP Yönlendirme) — ARP cache poisoning
[3] Packet Flow Control (Akış Kontrolü)   — Forward/Drop/Throttle/Inspect
[4] Sistem Durumu                         — Modül durumları ve aktif hedefler
[5] Yönlendirmeyi Durdur + ARP Onar       — Orijinal ARP cache tablosunu geri yükle
[6] Akış Kontrolünü Durdur                 — Paket yakalama/manipülasyonu sonlandır
[7] IPv6 Node Discovery (ICMPv6 Keşfi)    — Link-local IPv6 keşfi
[8] IPv6 NDP Spoofing   (NA Zehirleme)    — IPv6 neighbor cache poisoning
[9] IPv6 Durdur + Cache Onar              — Orijinal IPv6 neighbor cache geri yükle
[W] DNS / Website Monitor (Canlı İzleme)  — Gerçek zamanlı DNS ve TLS SNI izleme
[I] Tam İzolasyon Modu  (ARP + NDP)       — Seçili cihazın hem IPv4 hem IPv6 erişimini kes
[M] MAC / IPv6 Yardımcı Araçlar           — MAC→IPv6 çevirici, EUI-64, ping6
[0] Çıkış
```

---

## 🌐 Web API Endpoint'leri

| Endpoint | Metod | Açıklama |
|---|---|---|
| `/api/scan` | POST | ARP tarama başlat |
| `/api/scan/status` | GET | Tarama durumu |
| `/api/devices` | GET | Keşfedilen cihaz listesi |
| `/api/isolate` | POST | Cihaz izole et |
| `/api/restore` | POST | İzolasyonu kaldır |
| `/api/restore-all` | POST | Tüm izolasyonları kaldır |
| `/api/status` | GET | Sistem durumu |
| `/api/stream` | GET | SSE log akışı |
| `/api/expert/arp-start` | POST | ARP spoofing başlat |
| `/api/expert/arp-stop` | POST | ARP spoofing durdur |
| `/api/expert/ndp-start` | POST | NDP spoofing başlat |
| `/api/expert/ndp-stop` | POST | NDP spoofing durdur |
| `/api/expert/flow-start` | POST | Flow control başlat |
| `/api/expert/flow-stop` | POST | Flow control durdur |
| `/api/monitor/start` | POST | Website monitor başlat |
| `/api/monitor/stop` | POST | Website monitor durdur |
| `/api/monitor/stream/<ip>` | GET | SSE domain akışı |
| `/api/neighbor-cache` | GET | IPv6 neighbor cache |
| `/api/mac-to-ipv6` | GET | MAC → IPv6 çevirici |

---

## ⚙️ Konfigürasyon

Tüm sabitler `config.py` dosyasında merkezi olarak yönetilir. Ortam değişkenleri ile geçersiz kılınabilir:

| Ortam Değişkeni | Varsayılan | Açıklama |
|---|---|---|
| `AG_WEB_HOST` | `127.0.0.1` | Web sunucu adresi |
| `AG_WEB_PORT` | `8080` | Web sunucu portu |
| `AG_PACKET_INTERVAL` | `1.5` | ARP paket gönderme aralığı (sn) |
| `AG_NDP_INTERVAL` | `1.5` | NDP paket gönderme aralığı (sn) |
| `AG_MAX_HISTORY` | `300` | DNS monitor hafıza limiti |
| `AG_LOG_LEVEL` | `INFO` | Log seviyesi |
| `AG_LOG_FILE` | _(boş)_ | Log dosyası yolu |

---

## 🧪 Testler

```bash
# Tüm testleri çalıştır
python -m pytest tests/ -v

# Tek bir dosyayı çalıştır
python -m pytest tests/test_utils.py -v
```

---

## 📚 Modül Açıklamaları

### `node_discovery.py`
ARP (Address Resolution Protocol) tabanlı ağ keşfi. Scapy ile ARP-Request yayınları gönderir,
yanıt veren cihazların IP, MAC ve hostname bilgilerini toplar.

### `traffic_redirection.py`
ARP Cache Poisoning tekniği ile ağ trafiğini yönlendirir. Hedef cihaz ve gateway arasına
girilerek (MITM) trafik kontrolü sağlanır. IP Forwarding desteği ile şeffaf veya izolasyon
modları desteklenir.

### `packet_flow_control.py`
MITM konumundayken paket akışını kontrol eder. Dört mod sunar:
- **FORWARD**: Trafiği olduğu gibi ilet
- **DROP**: Paketleri sessizce düşür
- **THROTTLE**: Bant genişliğini kısıtla (kbps)
- **INSPECT**: Paket detaylarını logla ve ilet

### `ipv6_ndp.py`
IPv6 Neighbor Discovery Protocol keşfi ve Neighbor Advertisement (NA) spoofing.
IPv4 ARP'ın IPv6 karşılığı olan NDP mekanizmasını kullanarak IPv6 tabanlı
cihaz izolasyonu sağlar.

### `dns_monitor.py`
Hedef cihazın ziyaret ettiği web sitelerini DNS sorguları (UDP 53) ve
TLS ClientHello SNI (TCP 443) alanları üzerinden gerçek zamanlı izler.

### `oui_table.py`
MAC adresinin ilk 3 oktetinden (OUI) cihaz üreticisini ve türünü belirler.
iOS 14+ / Android 10+ rastgele MAC (locally-administered) desteği dahildir.

### `passive_sniffer.py`
Arka planda mDNS (Bonjour), DHCP Option 12, LLMNR ve NetBIOS paketlerini
pasif olarak dinleyerek cihaz isimlerini ve sahip adlarını tespit eder.

### `app_state.py`
Flask web uygulaması için thread-safe global state yöneticisi. Tüm paylaşılan
veriler (devices, isolations, monitors) RLock koruması altındadır.

---

## 📝 Lisans

Bu proje eğitim amaçlı geliştirilmiştir. Sorumluluk kullanıcıya aittir.
