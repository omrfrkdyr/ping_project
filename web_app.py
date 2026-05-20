"""
AntiGravity — Web Application Backend
======================================
Flask tabanlı REST API + Server-Sent Events.

Çalıştırma:
    sudo python3 web_app.py

Adres:
    http://localhost:5000
"""

import os
import sys
import json
import time
import queue
import threading
import subprocess
from typing import Optional
from datetime import datetime

from flask import Flask, jsonify, request, Response, send_from_directory

# ─── Proje Modülleri ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

try:
    from modules.node_discovery      import NodeDiscovery
    from modules.traffic_redirection import TrafficRedirector
    from modules.packet_flow_control import PacketFlowController, FlowMode
    from modules.ipv6_ndp import (
        IPv6Discovery, NDPSpoofer,
        mac_to_ipv6_link_local, get_local_ipv6, _strip_zone
    )
    from modules.utils import get_local_ip, guess_network_range
    from modules.dns_monitor import DnsMonitor
    MODULES_OK = True
except ImportError as e:
    MODULES_OK = False
    print(f"[!] Modül uyarısı: {e}")

# ─── Flask ────────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_STATIC = os.path.join(_HERE, "static")

app = Flask(__name__, static_folder=_STATIC, static_url_path="/static")
app.config["JSON_SORT_KEYS"] = False

# ─── OUI Vendor Tablosu ───────────────────────────────────────────────────────
OUI_TABLE = {
    # ── Router / Gateway ───────────────────────────────────────────
    "20:e8:82": ("Router",    "router"), "d8:07:b6": ("Router",    "router"),
    "c8:d7:19": ("Router",    "router"), "a8:6b:d9": ("Router",    "router"),
    "74:da:38": ("Router",    "router"), "c0:4a:00": ("Router",    "router"),
    "b0:be:76": ("Router",    "router"), "e4:ab:89": ("Router",    "router"),
    "f8:1a:67": ("Router",    "router"), "00:1a:2b": ("Router",    "router"),

    # ── Apple (iPhone/iPad/MacBook) ────────────────────────────────
    "84:90:0a": ("Apple",     "phone"),  "a4:c3:61": ("Apple",     "phone"),
    "3c:22:fb": ("Apple",     "phone"),  "f0:b3:ec": ("Apple",     "phone"),
    "40:cb:c0": ("Apple",     "phone"),  "bc:92:6b": ("Apple",     "phone"),
    "dc:2b:61": ("Apple",     "phone"),  "f4:d4:88": ("Apple",     "phone"),
    "34:c0:59": ("Apple",     "phone"),  "70:3c:69": ("Apple",     "phone"),
    "f0:18:98": ("Apple",     "phone"),  "28:6a:b8": ("Apple",     "phone"),
    "d8:bb:c1": ("Apple",     "phone"),  "14:99:e2": ("Apple",     "phone"),
    "60:f8:1d": ("Apple",     "phone"),  "e0:b9:ba": ("Apple",     "phone"),
    "a8:51:ab": ("Apple",     "phone"),  "70:56:81": ("Apple",     "phone"),
    "dc:a9:04": ("Apple",     "phone"),  "f0:d1:a9": ("Apple",     "phone"),
    "9c:f4:8e": ("Apple",     "phone"),  "bc:d0:74": ("Apple",     "phone"),
    "b8:09:8a": ("Apple",     "phone"),  "4c:57:ca": ("Apple",     "phone"),
    "94:e9:6a": ("Apple",     "phone"),  "d8:1d:72": ("Apple",     "phone"),
    "f4:f1:5a": ("Apple",     "phone"),  "00:cd:fe": ("Apple",     "phone"),
    "d8:f8:83": ("Apple",     "phone"),  "20:7d:74": ("Apple",     "phone"),
    "78:4f:43": ("Apple",     "phone"),  "68:96:7b": ("Apple",     "phone"),
    "18:af:61": ("Apple",     "phone"),  "74:1b:b2": ("Apple",     "phone"),
    "90:72:40": ("Apple",     "phone"),  "e8:8d:28": ("Apple",     "phone"),
    "d4:61:9d": ("Apple",     "phone"),  "b8:53:ac": ("Apple",     "phone"),
    "48:bf:6b": ("Apple",     "phone"),  "ac:37:43": ("Apple",     "phone"),
    "68:fb:7e": ("Apple",     "phone"),  "a0:56:f3": ("Apple",     "phone"),
    "24:18:c6": ("Apple",     "laptop"), "8c:85:90": ("Apple",     "laptop"),
    "ac:bc:32": ("Apple",     "laptop"), "a4:83:e7": ("Apple",     "laptop"),
    "f0:9f:c2": ("Apple",     "laptop"), "3c:07:54": ("Apple",     "laptop"),
    "60:f8:1d": ("Apple",     "laptop"), "88:66:5a": ("Apple",     "laptop"),
    "f8:27:93": ("Apple",     "laptop"), "64:76:ba": ("Apple",     "laptop"),
    "78:7b:8a": ("Apple",     "laptop"), "a4:5e:60": ("Apple",     "laptop"),
    "84:a1:34": ("Apple",     "laptop"), "34:36:3b": ("Apple",     "laptop"),

    # ── Samsung ────────────────────────────────────────────────────
    "8c:c8:4b": ("Samsung",   "phone"),  "2c:f0:ee": ("Samsung",   "phone"),
    "f4:42:8f": ("Samsung",   "phone"),  "70:f9:27": ("Samsung",   "phone"),
    "94:35:0a": ("Samsung",   "phone"),  "cc:07:ab": ("Samsung",   "phone"),
    "5c:49:7d": ("Samsung",   "phone"),  "b4:3a:28": ("Samsung",   "phone"),
    "b0:72:bf": ("Samsung",   "phone"),  "3c:8b:fe": ("Samsung",   "phone"),
    "7c:1c:4e": ("Samsung TV","tv"),     "f4:7b:5e": ("Samsung TV","tv"),
    "14:49:bc": ("Samsung TV","tv"),     "8c:71:f8": ("Samsung TV","tv"),

    # ── Xiaomi ─────────────────────────────────────────────────────
    "28:6c:07": ("Xiaomi",    "phone"),  "64:cc:2e": ("Xiaomi",    "phone"),
    "00:9e:c8": ("Xiaomi",    "phone"),  "ac:c1:ee": ("Xiaomi",    "phone"),
    "f8:a4:5f": ("Xiaomi",    "phone"),  "34:80:b3": ("Xiaomi",    "phone"),

    # ── Huawei ─────────────────────────────────────────────────────
    "b4:cd:27": ("Huawei",    "phone"),  "04:f9:38": ("Huawei",    "phone"),
    "6c:b7:f4": ("Huawei",    "phone"),  "00:9a:cd": ("Huawei",    "phone"),

    # ── Smart TV / LG ─────────────────────────────────────────────
    "94:27:70": ("Smart TV",  "tv"),     "8c:79:67": ("Smart TV",  "tv"),
    "a8:23:fe": ("LG TV",     "tv"),     "c4:36:6c": ("LG TV",     "tv"),
    "48:59:29": ("LG TV",     "tv"),     "cc:2d:8c": ("LG TV",     "tv"),
    "b8:ad:3e": ("LG TV",     "tv"),     "78:5d:c8": ("LG TV",     "tv"),
    "ac:9b:0a": ("Sony TV",   "tv"),     "04:5d:4b": ("Sony TV",   "tv"),
    "f4:f5:24": ("Sony TV",   "tv"),     "7c:c3:a1": ("Sony TV",   "tv"),
    "90:e7:c4": ("Hisense",   "tv"),     "f4:43:02": ("Hisense",   "tv"),
    "00:17:88": ("Philips",   "tv"),     "78:84:e1": ("Philips",   "tv"),

    # ── IoT / Diğer ─────────────────────────────────────────────--
    "b4:75:0e": ("IoT",       "iot"),    "18:fe:34": ("IoT",       "iot"),
    "50:02:91": ("IoT",       "iot"),    "a0:20:a6": ("IoT",       "iot"),
    "ac:cf:23": ("IoT",       "iot"),

    # ── VM ──────────────────────────────────────────────────────--
    "00:50:56": ("VMware",    "laptop"), "00:0c:29": ("VMware",    "laptop"),
    "08:00:27": ("VBox",      "laptop"),
}

# Hostname anahtar kelimesi → (vendor, type)
_HOSTNAME_HINTS = {
    "iphone":  ("iPhone",   "phone"),
    "ipad":    ("iPad",     "phone"),
    "macbook": ("MacBook",  "laptop"),
    "mac-":    ("MacBook",  "laptop"),
    "android": ("Android",  "phone"),
    "samsung": ("Samsung",  "phone"),
    "xiaomi":  ("Xiaomi",   "phone"),
    "huawei":  ("Huawei",   "phone"),
    "appletv": ("Apple TV", "tv"),
    "firetv":  ("Amazon",   "tv"),
    "roku":    ("Roku TV",  "tv"),
    "xbox":    ("Xbox",     "laptop"),
    "playstation": ("PlayStation", "laptop"),
    "ps4":     ("PlayStation", "laptop"),
    "ps5":     ("PlayStation", "laptop"),
}


def _is_locally_administered(mac: str) -> bool:
    """
    MAC adresinin yerel olarak atanmış (locally-administered) olup olmadığını kontrol eder.
    iOS 14+ Private Wi-Fi Address özelliği bu bit'i 1 yapar.
    İlk oktetin bit 1 (LSB+1) = 1 ise locally-administered.
    """
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def get_vendor(mac: str, hostname: str = ""):
    """
    MAC OUI + hostname + locally-administered flag'inden vendor/tip çözer.
    iOS 14+ rastgele MAC kullanır -- OUI tablosu çalışmaz, ama LA bit tespit edilebilir.
    """
    # 1. Hostname ipucu (en güvenilir)
    hn = (hostname or "").lower()
    for kw, (vendor, dtype) in _HOSTNAME_HINTS.items():
        if kw in hn:
            return vendor, dtype

    # 2. OUI tablosu
    prefix = mac.lower()[:8]
    if prefix in OUI_TABLE:
        return OUI_TABLE[prefix]

    # 3. Locally-administered MAC → büyük ihtimalle iPhone/Android (iOS 14+ / Android 10+)
    if _is_locally_administered(mac):
        return ("iPhone?", "phone")

    return ("Bilinmiyor", "unknown")


def scapy_iface():
    try:
        from scapy.all import conf as sc
        return sc.iface
    except Exception:
        return "en0"


def ts():
    return datetime.now().strftime("%H:%M:%S")


# ─── Global Uygulama Durumu ───────────────────────────────────────────────────

class AppState:
    def __init__(self):
        self._lock = threading.Lock()

        # Keşif
        self.devices: dict = {}      # {ip: DeviceInfo dict}
        self.scanning: bool = False
        self.scan_progress: int = 0

        # Aktif izolasyonlar: {ip: {"arp": redirector, "ndp": spoofer}}
        self.isolations: dict = {}

        # Aktif monitörler: {ip: {"mitm": redirector|None, "sniffer": DnsMonitor, "queues": [queue,...]}}
        self.monitors: dict = {}

        # Flow Control
        self.flow_ctrl: Optional[PacketFlowController] = None

        # Log kuyruğu (SSE)
        self._log_q: queue.Queue = queue.Queue(maxsize=500)

    def log(self, msg: str, level: str = "info"):
        entry = {"ts": ts(), "msg": msg, "level": level}
        try:
            self._log_q.put_nowait(entry)
        except queue.Full:
            pass

    def log_stream(self):
        """SSE generator: log kuyruğunu akış halinde döndürür."""
        while True:
            try:
                entry = self._log_q.get(timeout=30)
                yield f"data: {json.dumps(entry)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'ts': ts(), 'msg': '', 'level': 'ping'})}\n\n"

    def device_dict(self, ip: str, entry) -> dict:
        """HostEntry nesnesini JSON-serialize edilebilir dict'e çevirir."""
        mac = entry.mac if hasattr(entry, "mac") else str(entry.get("mac", ""))
        hostname_val = entry.hostname if hasattr(entry, "hostname") else str(entry.get("hostname", ""))
        vendor, dev_type = get_vendor(mac, hostname_val)
        isolated = ip in self.isolations
        return {
            "ip":           ip,
            "mac":          mac,
            "hostname":     entry.hostname if hasattr(entry, "hostname") else str(entry.get("hostname", "")),
            "first_seen":   entry.first_seen if hasattr(entry, "first_seen") else str(entry.get("first_seen", "")),
            "vendor":       vendor,
            "type":         dev_type,
            "isolated":     isolated,
            "pkt_count":    self.isolations[ip]["arp"].packet_count if isolated and self.isolations[ip].get("arp") else 0,
            "friendly_name": "",
            "owner_name":   "",
        }

    def cleanup(self):
        """Tüm aktif izolasyonları onarır."""
        state.log("Temizlik: tüm izolasyonlar onarılıyor...", "warn")
        for ip in list(self.isolations.keys()):
            _do_restore(ip)
        for ip in list(self.monitors.keys()):
            _do_monitor_stop(ip)
        if self.flow_ctrl and self.flow_ctrl.active:
            self.flow_ctrl.stop()


state = AppState()


# ─── Yardımcı: Otomatik Gateway Bul ──────────────────────────────────────────

def auto_gateway() -> tuple:
    """Sistemdeki varsayılan gateway IP ve MAC'i döndürür."""
    try:
        r = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=3
        )
        gw_ip = None
        for line in r.stdout.splitlines():
            if "gateway:" in line:
                gw_ip = line.split(":")[1].strip()
                break

        if not gw_ip:
            # macOS netstat
            r2 = subprocess.run(
                ["netstat", "-rn", "-f", "inet"],
                capture_output=True, text=True, timeout=3
            )
            for line in r2.stdout.splitlines():
                if line.startswith("default"):
                    gw_ip = line.split()[1]
                    break

        if gw_ip and gw_ip in state.devices:
            gw_mac = state.devices[gw_ip]["mac"]
        else:
            gw_mac = None

        return gw_ip, gw_mac

    except Exception:
        return "192.168.1.1", None


def auto_gateway_ipv6() -> tuple:
    """Varsayılan IPv6 gateway'i döndürür."""
    try:
        r = subprocess.run(
            ["netstat", "-rn", "-f", "inet6"],
            capture_output=True, text=True, timeout=3
        )
        for line in r.stdout.splitlines():
            if line.strip().startswith("default"):
                parts = line.split()
                if len(parts) >= 2:
                    gw = _strip_zone(parts[1])
                    return gw, None
    except Exception:
        pass
    return "fe80::1", None


# ─── Yardımcı: İzolasyon ─────────────────────────────────────────────────────

def _do_isolate(ip: str, target_mac: str) -> dict:
    """Bir cihazı hem ARP hem NDP ile izole eder."""
    gw_ip, gw_mac = auto_gateway()
    result = {"arp": False, "ndp": False, "errors": []}

    # ── ARP Spoofing ──
    try:
        r = TrafficRedirector()
        r.start(ip, gw_ip, enable_forwarding=False)
        state.isolations.setdefault(ip, {})["arp"] = r
        result["arp"] = True
        state.log(f"[ARP] ✓ {ip} izole edildi (ARP)", "success")
    except Exception as e:
        result["errors"].append(f"ARP: {e}")
        state.log(f"[ARP] ✗ {ip}: {e}", "error")

    # ── IP Forwarding kapat ──
    try:
        subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"],
                       capture_output=True, timeout=3)
        subprocess.run(["sysctl", "-w", "net.inet6.ip6.forwarding=0"],
                       capture_output=True, timeout=3)
        state.log("[SYS] IP Forwarding kapatıldı.", "warn")
    except Exception:
        pass

    # ── NDP Spoofing ─── (IPv6 adresi biliniyorsa)
    try:
        iface = scapy_iface()
        # Sistem NDP tablosundan IPv6 adresini bul
        ndp_out = subprocess.run(["ndp", "-n", "-a"],
                                  capture_output=True, text=True, timeout=3).stdout
        target_v6 = None
        for line in ndp_out.splitlines():
            if target_mac.lower() in line.lower():
                parts = line.split()
                if parts:
                    target_v6 = _strip_zone(parts[0])
                    break

        if target_v6:
            gw_v6, _ = auto_gateway_ipv6()
            spoofer = NDPSpoofer(iface=iface)
            spoofer.start(target_v6, gw_v6)
            state.isolations.setdefault(ip, {})["ndp"] = spoofer
            result["ndp"] = True
            state.log(f"[NDP] ✓ {ip} izole edildi (IPv6: {target_v6})", "success")
        else:
            state.log(f"[NDP] IPv6 adresi bulunamadı ({ip}), sadece ARP aktif.", "warn")
    except Exception as e:
        result["errors"].append(f"NDP: {e}")
        state.log(f"[NDP] ✗ {ip}: {e}", "warn")

    return result


def _do_restore(ip: str) -> bool:
    """Bir cihazın izolasyonunu kaldırır, bağlantısını onarır."""
    iso = state.isolations.pop(ip, {})
    ok = False

    if iso.get("arp"):
        try:
            iso["arp"].stop(restore=True)
            state.log(f"[ARP] ✓ {ip} ARP onarıldı.", "success")
            ok = True
        except Exception as e:
            state.log(f"[ARP] Onarım hatası: {e}", "error")

    if iso.get("ndp"):
        try:
            iso["ndp"].stop(restore=True)
            state.log(f"[NDP] ✓ {ip} NDP onarıldı.", "success")
        except Exception as e:
            state.log(f"[NDP] Onarım hatası: {e}", "error")

    # Başka aktif izolasyon yoksa forwarding'i geri aç
    if not state.isolations:
        try:
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                           capture_output=True, timeout=3)
            subprocess.run(["sysctl", "-w", "net.inet6.ip6.forwarding=1"],
                           capture_output=True, timeout=3)
            state.log("[SYS] IP Forwarding yeniden açıldı.", "info")
        except Exception:
            pass

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# API ENDPOINT'LERİ
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory(_STATIC, "index.html")


# ── mDNS / Hostname Çözümleyici + Pasif Sniffer ──────────────────────────────

import socket as _socket
import re as _re
import struct as _struct


def _is_service_name(raw: str) -> bool:
    """
    Bonjour/mDNS servis kayıtlarını cihaz isimlerinden ayırt eder.
    '_spotify-connect._tcp.local', 'lb._dns-sd._udp.local' gibi
    servis yayınları cihaz adı değildir, filtrele.
    """
    # Alt çizgi ile başlayan etiket içeren isimler servis protokolünden
    parts = raw.split('.')
    for part in parts:
        if part.startswith('_'):
            return True
    # Sadece 'lb' gibi bilinen DNS-SD sorguları
    if raw.lower().startswith('lb.'):
        return True
    return False


def _clean_mdns_name(raw: str) -> str:
    """mDNS hostname'den servis eklerini, .local/.lan uzantısını ve tireleri temizler."""
    name = raw
    # Servis tipi eklerini temizle: '._device-info._tcp', '._tcp.local' vb.
    name = _re.sub(r'\._[^.]+\._(?:tcp|udp)(?:\.local)?$', '', name, flags=_re.IGNORECASE)
    name = _re.sub(r'\._(?:tcp|udp)(?:\.local)?$', '', name, flags=_re.IGNORECASE)
    # .local / .lan uzantısını temizle
    name = _re.sub(r'\.(local|lan|home|localdomain)$', '', name, flags=_re.IGNORECASE)
    # Tireleri boşlukla değiştir
    name = name.replace('-', ' ').strip()
    return name


def _extract_owner_from_hostname(hostname: str) -> str:
    """
    'Omers-iPhone.local'  -> 'Omers'
    'Efe-s-iPad'          -> 'Efe'
    'DESKTOP-ABC123'      -> ''
    Cihaz adından önceki kısımı sahip adı olarak döndürür.
    """
    clean = _re.sub(r'\.(local|lan|home|localdomain)$', '', hostname, flags=_re.IGNORECASE)
    clean = clean.replace("'s", "-s").replace("\u2019s", "-s")
    device_kw = [
        'iphone', 'ipad', 'macbook', 'mac', 'android', 'galaxy', 'samsung',
        'laptop', 'desktop', 'pc', 'tablet', 'watch', 'airpods', 'appletv',
        'homepod', 'xbox', 'playstation', 'ps4', 'ps5',
    ]
    low = clean.lower()
    for kw in device_kw:
        idx = low.find(kw)
        if idx > 0:
            prefix = clean[:idx].strip('-').strip()
            prefix = _re.sub(r'-s$', '', prefix, flags=_re.IGNORECASE).strip('-').strip()
            if prefix:
                return ' '.join(w.capitalize() for w in prefix.replace('-', ' ').split())
    return ''


def _parse_mdns_name_from_payload(payload: bytes) -> list:
    """mDNS/DNS binary paketten sorgu/yanıt isimlerini okur."""
    names = []
    try:
        i = 12
        while i < len(payload):
            labels = []
            safety = 0
            while i < len(payload) and safety < 64:
                safety += 1
                length = payload[i]
                if length == 0:
                    i += 1
                    break
                if (length & 0xC0) == 0xC0:
                    i += 2
                    break
                i += 1
                if i + length > len(payload):
                    break
                labels.append(payload[i:i+length].decode('utf-8', errors='ignore'))
                i += length
            if labels:
                names.append('.'.join(labels))
            i += 4
    except Exception:
        pass
    return names


class PassiveSnifferEngine:
    """
    Arka planda mDNS (Bonjour), DHCP Opt-12, LLMNR ve NetBIOS paketlerini
    pasif olarak dinler; cihaz isimlerini ve sahip adlarını state.devices'a yazar.
    """

    def __init__(self):
        self._thread = None
        self._stop   = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name='PassiveSniffer')
        self._thread.start()
        state.log("[SNIFF] Pasif dinleyici başlatıldı (mDNS/DHCP/LLMNR/NetBIOS)", "info")

    def stop(self):
        self._stop.set()

    def _update_device(self, ip: str, hostname: str, source: str):
        """Keşfedilen ismi state'e yaz."""
        if not ip or not hostname:
            return
        if ip not in state.devices:
            return
        # Bonjour servis yayınlarını filtrele (_spotify-connect._tcp vb.)
        if _is_service_name(hostname):
            return
        old = state.devices[ip].get('friendly_name', '')
        clean = _clean_mdns_name(hostname)
        owner = _extract_owner_from_hostname(hostname)
        # Temizlenmiş isim boşsa veya aynıysa atla
        if not clean or clean == old:
            return
        state.devices[ip]['hostname']      = hostname
        state.devices[ip]['friendly_name'] = clean
        state.devices[ip]['owner_name']    = owner
        mac = state.devices[ip].get('mac', '')
        vendor, dtype = get_vendor(mac, hostname)
        state.devices[ip]['vendor'] = vendor
        state.devices[ip]['type']   = dtype
        display = f"{owner} / {clean}" if owner else clean
        state.log(f"[{source}] {ip} \u2192 {display}", "success")

    def _run(self):
        """Scapy sniff — sadece ilgili portları dinler."""
        try:
            from scapy.all import sniff, DNS, UDP, IP, Raw
        except ImportError:
            state.log("[SNIFF] Scapy yok, pasif dinleyici devre dışı.", "warn")
            return

        def _pkt_handler(pkt):
            if self._stop.is_set():
                return
            try:
                self._process(pkt)
            except Exception:
                pass

        bpf = "udp and (port 5353 or port 67 or port 68 or port 5355 or port 137)"
        try:
            sniff(filter=bpf, prn=_pkt_handler, store=False,
                  stop_filter=lambda _: self._stop.is_set(),
                  timeout=None)
        except Exception as e:
            state.log(f"[SNIFF] Hata: {e}", "warn")

    def _process(self, pkt):
        from scapy.all import DNS, UDP, IP, Raw
        if not pkt.haslayer(IP):
            return
        src_ip = pkt[IP].src
        dport  = pkt[UDP].dport if pkt.haslayer(UDP) else 0
        sport  = pkt[UDP].sport if pkt.haslayer(UDP) else 0

        # ── mDNS (port 5353) ──
        if (dport == 5353 or sport == 5353) and pkt.haslayer(DNS):
            dns = pkt[DNS]
            for i in range(dns.ancount + dns.arcount):
                try:
                    rr = dns.an[i] if i < dns.ancount else dns.ar[i - dns.ancount]
                    rrname = rr.rrname.decode('utf-8', errors='ignore').rstrip('.')
                    if rrname:
                        self._update_device(src_ip, rrname, 'mDNS')
                except Exception:
                    pass
            for i in range(dns.qdcount):
                try:
                    q = dns.qd[i]
                    qname = q.qname.decode('utf-8', errors='ignore').rstrip('.')
                    if qname:
                        self._update_device(src_ip, qname, 'mDNS')
                except Exception:
                    pass

        # ── DHCP Option 12 (Hostname) ──
        elif dport in (67, 68) or sport in (67, 68):
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])
                hostname = self._parse_dhcp_hostname(payload)
                if hostname:
                    self._update_device(src_ip, hostname, 'DHCP')

        # ── LLMNR (port 5355) ──
        elif dport == 5355 or sport == 5355:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])
                names = _parse_mdns_name_from_payload(payload)
                for name in names:
                    if name:
                        self._update_device(src_ip, name, 'LLMNR')

        # ── NetBIOS (port 137) ──
        elif dport == 137 or sport == 137:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])
                name = self._parse_netbios_name(payload)
                if name:
                    self._update_device(src_ip, name, 'NetBIOS')

    @staticmethod
    def _parse_dhcp_hostname(payload: bytes) -> str:
        """DHCP paketinden Option 12 (Hostname) değerini çıkarır."""
        try:
            if len(payload) < 240:
                return ''
            magic = payload[236:240]
            if magic != b'\x63\x82\x53\x63':
                return ''
            i = 240
            while i < len(payload):
                opt_code = payload[i]
                if opt_code == 255:
                    break
                if opt_code == 0:
                    i += 1
                    continue
                i += 1
                if i >= len(payload):
                    break
                opt_len = payload[i]
                i += 1
                if i + opt_len > len(payload):
                    break
                if opt_code == 12:
                    return payload[i:i+opt_len].decode('utf-8', errors='ignore').strip()
                i += opt_len
        except Exception:
            pass
        return ''

    @staticmethod
    def _parse_netbios_name(payload: bytes) -> str:
        """NetBIOS Name Service paketinden cihaz adını çıkarır."""
        try:
            if len(payload) < 12:
                return ''
            qcount = _struct.unpack('>H', payload[4:6])[0]
            if qcount == 0:
                return ''
            i = 12
            length = payload[i]
            i += 1
            if length == 32 and i + 32 <= len(payload):
                encoded = payload[i:i+32]
                name_bytes = bytearray()
                for j in range(0, 32, 2):
                    hi = encoded[j]   - ord('A')
                    lo = encoded[j+1] - ord('A')
                    name_bytes.append((hi << 4) | lo)
                decoded = name_bytes.decode('ascii', errors='ignore').rstrip('\x00').strip()
                decoded = decoded[:-1].strip() if decoded else decoded
                return decoded
        except Exception:
            pass
        return ''


# Global sniffer instance
_passive_sniffer = PassiveSnifferEngine()


def _resolve_names_bg(ips: list):
    """
    ARP taramasindan sonra arka planda her IP icin hostname cozer.
    macOS'ta Bonjour/mDNS icerir: 'Omers-iPhone.local' -> 'Omers iPhone'
    Ardından pasif sniffer'ı başlatır.
    """
    state.log(f"[mDNS] {len(ips)} cihaz icin isim arama basliyor...", "info")
    found = 0
    for ip in ips:
        if ip not in state.devices:
            continue
        try:
            raw = _socket.gethostbyaddr(ip)[0]
            if raw and raw != ip and not _is_service_name(raw):
                clean = _clean_mdns_name(raw)
                owner = _extract_owner_from_hostname(raw)
                if not clean:
                    continue
                state.devices[ip]['hostname']      = raw
                state.devices[ip]['friendly_name'] = clean
                state.devices[ip]['owner_name']    = owner
                mac = state.devices[ip]['mac']
                vendor, dtype = get_vendor(mac, raw)
                state.devices[ip]['vendor'] = vendor
                state.devices[ip]['type']   = dtype
                display = f"{owner} / {clean}" if owner else clean
                state.log(f"[mDNS] {ip} \u2192 \"{display}\"", "success")
                found += 1
        except (_socket.herror, _socket.gaierror, OSError):
            pass
        except Exception as e:
            state.log(f"[mDNS] {ip} hata: {e}", "warn")
    state.log(f"[mDNS] \u2713 {found}/{len(ips)} cihazda isim bulundu.", "success" if found else "info")
    # Pasif sniffer'ı başlat (zaten çalışıyorsa yeniden başlatmaz)
    _passive_sniffer.start()


# ── Tarama ────────────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def api_scan():
    if state.scanning:
        return jsonify({"ok": False, "error": "Tarama zaten devam ediyor."}), 409

    data    = request.get_json(silent=True) or {}
    network = data.get("network") or (guess_network_range() if MODULES_OK else "192.168.1.0/24")
    timeout = float(data.get("timeout", 3))

    # ✓ Race condition fix: flag'i thread başlamadan ÖNCE set et
    state.scanning      = True
    state.scan_progress = 8

    def _scan():
        state.log(f"[SCAN] ARP taranıyor: {network}  timeout={timeout}s", "info")
        try:
            state.scan_progress = 20
            nd    = NodeDiscovery()
            state.scan_progress = 30
            # resolve_hostnames=False → daha hızlı tarama
            hosts = nd.scan(network=network, timeout=timeout,
                            resolve_hostnames=False, verbose=False)
            state.scan_progress = 88
            state.devices.clear()
            ips_found = []
            for ip, entry in hosts.items():
                state.devices[ip] = state.device_dict(ip, entry)
                ips_found.append(ip)
            state.scan_progress = 100
            state.log(f"[SCAN] ✓ {len(hosts)} cihaz bulundu.", "success")
            # Arka planda mDNS isim çözümlemesi başlat (taramayı bloklamaz)
            threading.Thread(
                target=_resolve_names_bg,
                args=(ips_found,),
                daemon=True
            ).start()
        except PermissionError:
            state.log("[SCAN] ✗ Root yetkisi gerekli! sudo ile çalıştırın.", "error")
        except Exception as e:
            state.log(f"[SCAN] ✗ Hata: {e}", "error")
        finally:
            state.scanning = False

    threading.Thread(target=_scan, daemon=True).start()
    return jsonify({"ok": True, "network": network})


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify({
        "scanning":  state.scanning,
        "progress":  state.scan_progress,
        "count":     len(state.devices),
    })


@app.route("/api/devices")
def api_devices():
    # İzolasyon durumlarını güncelle
    devices = []
    for ip, d in state.devices.items():
        d = dict(d)
        d["isolated"] = ip in state.isolations
        if d["isolated"] and state.isolations[ip].get("arp"):
            d["pkt_count"] = state.isolations[ip]["arp"].packet_count
        devices.append(d)

    # Gateway önce gelsin
    gw_ip, _ = auto_gateway()
    devices.sort(key=lambda x: (x["ip"] != gw_ip, x["ip"].split(".")[-1].zfill(3)))
    return jsonify(devices)


# ── İzolasyon ─────────────────────────────────────────────────────────────────

@app.route("/api/isolate", methods=["POST"])
def api_isolate():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()
    mac  = data.get("mac", "").strip()

    if not ip or not mac:
        return jsonify({"ok": False, "error": "IP ve MAC gerekli."}), 400
    if ip in state.isolations:
        return jsonify({"ok": False, "error": "Cihaz zaten izole."}), 409

    state.log(f"[ISOLATE] {ip} → izolasyon başlatılıyor...", "warn")

    def _worker():
        _do_isolate(ip, mac)

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/restore", methods=["POST"])
def api_restore():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()

    if not ip:
        return jsonify({"ok": False, "error": "IP gerekli."}), 400
    if ip not in state.isolations:
        return jsonify({"ok": False, "error": "Cihaz izole değil."}), 404

    state.log(f"[RESTORE] {ip} → bağlantı onarılıyor...", "info")

    def _worker():
        _do_restore(ip)

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/restore-all", methods=["POST"])
def api_restore_all():
    ips = list(state.isolations.keys())
    for ip in ips:
        _do_restore(ip)
    return jsonify({"ok": True, "restored": ips})


# ── Expert Mod ────────────────────────────────────────────────────────────────

@app.route("/api/expert/arp-start", methods=["POST"])
def api_arp_start():
    data    = request.get_json(silent=True) or {}
    target  = data.get("target_ip", "").strip()
    gateway = data.get("gateway_ip", "").strip()
    fwd     = data.get("forwarding", False)

    if not target or not gateway:
        return jsonify({"ok": False, "error": "Hedef ve gateway IP gerekli."}), 400

    state.log(f"[ARP] Başlatılıyor → {target}", "warn")

    def _worker():
        try:
            r = TrafficRedirector()
            r.start(target, gateway, enable_forwarding=fwd)
            state.isolations.setdefault(target, {})["arp"] = r
            state.log(f"[ARP] ✓ AKTİF → {target}", "success")
        except Exception as e:
            state.log(f"[ARP] ✗ {e}", "error")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/expert/arp-stop", methods=["POST"])
def api_arp_stop():
    data   = request.get_json(silent=True) or {}
    target = data.get("target_ip", "").strip()
    iso    = state.isolations.get(target, {})
    r      = iso.get("arp")
    if not r:
        return jsonify({"ok": False, "error": "Aktif ARP bulunamadı."}), 404
    r.stop(restore=True)
    iso.pop("arp", None)
    state.log(f"[ARP] ✓ Durduruldu → {target}", "success")
    return jsonify({"ok": True})


@app.route("/api/expert/ndp-start", methods=["POST"])
def api_ndp_start():
    data       = request.get_json(silent=True) or {}
    target_v6  = _strip_zone(data.get("target_v6", "").strip())
    router_v6  = _strip_zone(data.get("router_v6", "").strip())
    target_mac = data.get("target_mac", "").strip() or None

    if not target_v6 or not router_v6:
        return jsonify({"ok": False, "error": "Hedef ve router IPv6 gerekli."}), 400

    state.log(f"[NDP] Başlatılıyor → {target_v6}", "warn")

    def _worker():
        try:
            spoofer = NDPSpoofer(iface=scapy_iface())
            spoofer.start(target_v6, router_v6, target_mac=target_mac)
            state.isolations.setdefault("ndp_" + target_v6, {})["ndp"] = spoofer
            state.log(f"[NDP] ✓ AKTİF → {target_v6}", "success")
        except Exception as e:
            state.log(f"[NDP] ✗ {e}", "error")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/expert/ndp-stop", methods=["POST"])
def api_ndp_stop():
    data      = request.get_json(silent=True) or {}
    target_v6 = _strip_zone(data.get("target_v6", "").strip())
    key       = "ndp_" + target_v6
    iso       = state.isolations.get(key, {})
    spoofer   = iso.get("ndp")
    if not spoofer:
        return jsonify({"ok": False, "error": "Aktif NDP bulunamadı."}), 404
    spoofer.stop(restore=True)
    state.isolations.pop(key, None)
    state.log(f"[NDP] ✓ Durduruldu → {target_v6}", "success")
    return jsonify({"ok": True})


@app.route("/api/expert/flow-start", methods=["POST"])
def api_flow_start():
    data = request.get_json(silent=True) or {}
    mode_str = data.get("mode", "FORWARD").upper()
    bpf      = data.get("bpf", "").strip() or None
    kbps     = float(data.get("kbps", 512))

    mode_map = {"FORWARD": FlowMode.FORWARD, "DROP": FlowMode.DROP,
                "THROTTLE": FlowMode.THROTTLE, "INSPECT": FlowMode.INSPECT}
    mode = mode_map.get(mode_str, FlowMode.FORWARD)

    if state.flow_ctrl and state.flow_ctrl.active:
        return jsonify({"ok": False, "error": "Flow control zaten aktif."}), 409

    def _worker():
        try:
            state.flow_ctrl = PacketFlowController()
            state.flow_ctrl.start(mode=mode, bpf_filter=bpf, throttle_kbps=kbps)
            state.log(f"[FLOW] ✓ AKTİF ({mode_str})", "success")
        except Exception as e:
            state.log(f"[FLOW] ✗ {e}", "error")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/expert/flow-stop", methods=["POST"])
def api_flow_stop():
    if not state.flow_ctrl or not state.flow_ctrl.active:
        return jsonify({"ok": False, "error": "Flow control aktif değil."}), 404
    state.flow_ctrl.stop()
    state.log("[FLOW] ✓ Durduruldu.", "success")
    return jsonify({"ok": True})


# ── Durum ─────────────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    try:
        local_ip = get_local_ip() if MODULES_OK else "N/A"
        local_v6 = get_local_ipv6(scapy_iface()) or "N/A"
    except Exception:
        local_ip = local_v6 = "N/A"

    active_ips = [ip for ip in state.isolations if not ip.startswith("ndp_")]
    gw_ip, _   = auto_gateway()

    return jsonify({
        "local_ip":     local_ip,
        "local_v6":     local_v6,
        "gateway_ip":   gw_ip,
        "scanning":     state.scanning,
        "device_count": len(state.devices),
        "isolated":     active_ips,
        "flow_active":  bool(state.flow_ctrl and state.flow_ctrl.active),
        "flow_mode":    state.flow_ctrl.mode.value if state.flow_ctrl and state.flow_ctrl.active else None,
    })


@app.route("/api/neighbor-cache")
def api_neighbor_cache():
    try:
        r = subprocess.run(["ndp", "-n", "-a"],
                            capture_output=True, text=True, timeout=5)
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        return jsonify({"ok": True, "lines": lines})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── Website Monitor ───────────────────────────────────────────────────────────

def _do_monitor_stop(ip: str):
    """Monitor'ü durdurur, şeffaf MITM'i temizler."""
    mon = state.monitors.pop(ip, {})
    sniffer = mon.get("sniffer")
    if sniffer:
        try:
            sniffer.stop()
        except Exception:
            pass
    mitm = mon.get("mitm")
    if mitm:
        try:
            mitm.stop(restore=True)
        except Exception:
            pass
    # Kapalı olan SSE queue'larını bilgilendir
    for q in mon.get("queues", []):
        try:
            q.put_nowait(None)   # sentinel → stream sonlandır
        except Exception:
            pass
    state.log(f"[MON] {ip} izleme durduruldu.", "info")


@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()
    mac  = data.get("mac", "").strip()

    if not ip:
        return jsonify({"ok": False, "error": "IP gerekli."}), 400
    if ip in state.monitors:
        return jsonify({"ok": True, "already": True, "ip": ip})

    state.log(f"[MON] {ip} için izleme başlatılıyor (şeffaf MITM)...", "info")

    def _worker():
        queues = []
        mitm   = None

        # Şeffaf MITM: IP Forwarding ON → internet kesilmez
        try:
            gw_ip, _ = auto_gateway()
            if gw_ip and ip != gw_ip:
                # Önce forwarding'i aç
                subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                               capture_output=True, timeout=3)
                subprocess.run(["sysctl", "-w", "net.inet6.ip6.forwarding=1"],
                               capture_output=True, timeout=3)
                mitm = TrafficRedirector()
                mitm.start(ip, gw_ip, enable_forwarding=True)
                state.log(f"[MON] ✓ Şeffaf MITM aktif → {ip} (internet kesilmedi)", "success")
            else:
                state.log(f"[MON] Gateway tespit edilemedi, pasif mod.", "warn")
        except Exception as e:
            state.log(f"[MON] MITM başlatılamadı: {e} — pasif modda devam ediliyor.", "warn")
            mitm = None

        def _on_domain(entry):
            """Yeni domain bulununca tüm aktif SSE queue'larına yaz."""
            mon = state.monitors.get(ip, {})
            dead = []
            for q in mon.get("queues", []):
                try:
                    q.put_nowait(entry)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                try:
                    mon["queues"].remove(q)
                except Exception:
                    pass

        sniffer = DnsMonitor(ip, on_domain=_on_domain)
        sniffer.start()

        state.monitors[ip] = {
            "sniffer": sniffer,
            "mitm":    mitm,
            "queues":  queues,
        }
        state.log(f"[MON] ✓ DNS/SNI sniffer başladı → {ip}", "success")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()

    if not ip:
        return jsonify({"ok": False, "error": "IP gerekli."}), 400
    if ip not in state.monitors:
        return jsonify({"ok": False, "error": "Aktif monitor yok."}), 404

    _do_monitor_stop(ip)
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/monitor/stream/<path:ip>")
def api_monitor_stream(ip):
    """SSE stream — hedef IP'nin domain'lerini anlık gönderir."""
    ip = ip.strip()

    if ip not in state.monitors:
        return jsonify({"ok": False, "error": "Monitor aktif değil."}), 404

    client_q: queue.Queue = queue.Queue(maxsize=200)
    state.monitors[ip]["queues"].append(client_q)

    def _gen():
        # Mevcut geçmişi önce gönder
        sniffer = state.monitors.get(ip, {}).get("sniffer")
        if sniffer:
            for entry in sniffer.get_history():
                yield f"data: {json.dumps(entry)}\n\n"

        while True:
            try:
                entry = client_q.get(timeout=25)
                if entry is None:   # sentinel → monitor durduruldu
                    yield f"data: {json.dumps({'type': 'stopped'})}\n\n"
                    break
                yield f"data: {json.dumps(entry)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    resp = Response(
        _gen(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
    return resp


@app.route("/api/monitor/history/<path:ip>")
def api_monitor_history(ip):
    ip = ip.strip()
    mon = state.monitors.get(ip)
    if not mon:
        return jsonify({"ok": False, "error": "Monitor aktif değil."}), 404
    history = mon["sniffer"].get_history()
    return jsonify({"ok": True, "ip": ip, "history": history})


@app.route("/api/monitor/status")
def api_monitor_status():
    result = {}
    for ip, mon in state.monitors.items():
        sniffer = mon.get("sniffer")
        result[ip] = {
            "active":    sniffer.active if sniffer else False,
            "count":     len(sniffer.history) if sniffer else 0,
            "mitm_active": bool(mon.get("mitm") and mon["mitm"].active),
        }
    return jsonify(result)


# ── SSE Log Akışı ─────────────────────────────────────────────────────────────

@app.route("/api/stream")
def api_stream():
    return Response(
        state.log_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


# ── MAC → IPv6 Çevirici ───────────────────────────────────────────────────────

@app.route("/api/mac-to-ipv6")
def api_mac_to_ipv6():
    mac  = request.args.get("mac", "")
    ipv6 = mac_to_ipv6_link_local(mac) if mac else ""
    return jsonify({"ipv6": ipv6})


# ─── Uygulama Başlatma ────────────────────────────────────────────────────────

import atexit
import signal

def _shutdown(signum=None, frame=None):
    print("\n[!] Kapatılıyor, izolasyonlar onarılıyor...")
    state.cleanup()
    sys.exit(0)

atexit.register(state.cleanup)
signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("\n[!] UYARI: Root yetkisi gerekli → sudo python3 web_app.py\n")

    print("\n" + "═" * 60)
    print("   ⬡  AntiGravity Web UI")
    print("   http://localhost:8080")
    print("═" * 60 + "\n")

    import webbrowser
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:8080")).start()

    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
