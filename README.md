# AntiGravity 🚀
### Ağ Trafiği Yönetimi ve Topoloji Analizi — Eğitim Modülü

> **⚠️ YASAL UYARI**: Bu araç **yalnızca kendi kontrolündeki, izole test
> ortamlarında** ağ protokollerini anlamak amacıyla kullanılabilir.
> İzinsiz ağlarda kullanmak birçok ülkede **yasadışıdır**.

---

## 📁 Proje Yapısı

```
ping_project/
├── main.py                          # Ana giriş noktası & interaktif menü
├── requirements.txt
└── modules/
    ├── __init__.py
    ├── utils.py                     # Renk çıktısı, yetki kontrolü, tablo
    ├── node_discovery.py            # Modül 1: ARP tabanlı host keşfi
    ├── traffic_redirection.py       # Modül 2: Çift taraflı ARP güncelleme
    └── packet_flow_control.py       # Modül 3: Akış kontrolü (drop/throttle/inspect)
```

---

## 🚀 Kurulum & Çalıştırma

```bash
# 1. Bağımlılıkları yükle
pip install -r requirements.txt

# 2. Root yetkisi ile çalıştır (ham soket gerektirir)
sudo python3 main.py
```

---

## 📖 Modüller

### Modül 1 — Node Discovery (Düğüm Keşfi)

**Dosya:** `modules/node_discovery.py`

ARP broadcast istekleri göndererek yerel ağdaki tüm aktif hostları tespit eder.

| Özellik | Açıklama |
|---|---|
| Protokol | ARP (Layer 2) |
| Yöntem | Ethernet Broadcast → ff:ff:ff:ff:ff:ff |
| Çıktı | IP / MAC / Hostname tablosu |
| Threading | Kilit korumalı (`threading.Lock`) |

**Çalışma Prensibi:**
```
[Analiz PC]  →  ARP Request  →  [Broadcast ff:ff:ff:ff:ff:ff]
             ←  ARP Reply    ←  [Aktif Host X]
```
Sonuç: `srp()` ile toplanan yanıtlardan `(IP, MAC)` çiftleri çıkarılır.

---

### Modül 2 — Traffic Redirection (Trafik Yönlendirme)

**Dosya:** `modules/traffic_redirection.py`

Çift taraflı ARP cache zehirleme ile belirli bir düğümün trafiğini analiz
makinesinden geçirir.

| Özellik | Açıklama |
|---|---|
| Protokol | ARP Reply (op=2) |
| Yön | Hem Kurban → Analiz, hem Gateway → Analiz |
| Temizlik | `stop()` çağrısı ile orijinal cache onarılır |
| IP Forwarding | Linux/macOS için otomatik ayarlanır |

**Çalışma Prensibi:**
```
Normal    : Kurban ←→ Gateway
Yönlendirilmiş: Kurban ←→ [Analiz PC] ←→ Gateway
```

**ARP Paketin Anatomisi:**
```
ARP(op=2,              # Reply (is-at)
    pdst=target_ip,    # Kime (kurban veya gateway)
    hwdst=target_mac,  # Kime (MAC)
    psrc=spoof_ip)     # Sahte kaynak IP
# hwsrc = analiz makinesi MAC'i (otomatik)
```

---

### Modül 3 — Packet Flow Control (Akış Kontrolü)

**Dosya:** `modules/packet_flow_control.py`

Yakalacan paketler üzerinde dört farklı kontrol modu sunar.

| Mod | Davranış |
|---|---|
| **FORWARD** | Tüm paketleri şeffaf ilet |
| **DROP** | Tüm paketleri düşür (bağlantı kesmek) |
| **THROTTLE** | Bant genişliği sınırlı iletim (kbps simülasyonu) |
| **INSPECT** | Layer 2/3/4 analizi yap + ilet |

**BPF Filtre Örnekleri:**
```bash
tcp port 80         # Yalnızca HTTP
udp port 53         # Yalnızca DNS
host 192.168.1.5    # Yalnızca belirli IP
icmp                # Yalnızca ping
```

**THROTTLE Hesabı:**
```python
delay = (paket_boyutu_bit) / (hedef_bps)
# Örn: 1500 B × 8 / (512 × 1024) = ~0.023s gecikme
```

---

## ⚙️ Teknik Notlar

### Root Yetkisi
Ham soket açmak (`SOCK_RAW`) için root/Administrator yetkisi zorunludur:
```bash
sudo python3 main.py          # Linux/macOS
# Windows: Yönetici olarak çalıştır
```

### IP Forwarding
Traffic Redirection aktifken paketlerin iletilmesi için:
```bash
# Linux (otomatik yapılır):
echo 1 > /proc/sys/net/ipv4/ip_forward

# macOS (otomatik yapılır):
sysctl -w net.inet.ip.forwarding=1
```

### Güvenli Çıkış
`Ctrl+C` veya menü `[0]` ile çıkıldığında:
1. ARP cache'ler orijinal hâline döndürülür
2. IP Forwarding devre dışı bırakılır
3. Tüm thread'ler temiz sonlandırılır

---

## 🔬 Eğitim Senaryoları

### Senaryo 1: Ağ Keşfi
```
Menü [1] → Ağ aralığı: 192.168.1.0/24 → Tablo gör
```

### Senaryo 2: Trafik Analizi (Sanal Makine Çifti)
```
Menü [1] → Hedef IP'yi keşfet
Menü [2] → Yönlendirme başlat (VM hedef, VM gateway)
Menü [3] → INSPECT modu → DNS/HTTP paketlerini gözlemle
Menü [5] → Yönlendirmeyi durdur (ARP onar)
```

### Senaryo 3: Bant Genişliği Simülasyonu
```
Menü [2] → Yönlendirmeyi başlat
Menü [3] → THROTTLE modu → 64 kbps → speedtest yap
```

---

## 📚 Kaynaklar

- [Scapy Belgeleri](https://scapy.readthedocs.io/)
- [RFC 826 — ARP Protokolü](https://www.rfc-editor.org/rfc/rfc826)
- [BPF Filtre Sözdizimi](https://www.tcpdump.org/manpages/pcap-filter.7.html)
