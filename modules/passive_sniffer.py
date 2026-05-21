"""
AntiGravity — Pasif Sniffer Motoru
====================================
mDNS (Bonjour), DHCP Option 12, LLMNR ve NetBIOS paketlerini
pasif olarak dinleyerek cihaz isimlerini ve sahip adlarını tespit eder.
"""

import re
import struct
import threading
import logging
from typing import Optional, Callable

logger = logging.getLogger("antigravity.passive")


# ─── Yardımcı Fonksiyonlar ─────────────────────────────────────────────────────

def is_service_name(raw: str) -> bool:
    """
    Bonjour/mDNS servis kayıtlarını cihaz isimlerinden ayırt eder.
    '_spotify-connect._tcp.local', 'lb._dns-sd._udp.local' gibi
    servis yayınları cihaz adı değildir, filtrele.

    Args:
        raw: Kontrol edilecek isim string'i.

    Returns:
        bool: Servis adı ise True.
    """
    parts = raw.split('.')
    for part in parts:
        if part.startswith('_'):
            return True
    # Sadece 'lb' gibi bilinen DNS-SD sorguları
    if raw.lower().startswith('lb.'):
        return True
    return False


def clean_mdns_name(raw: str) -> str:
    """
    mDNS hostname'den servis eklerini, .local/.lan uzantısını ve tireleri temizler.

    Args:
        raw: Ham hostname string'i.

    Returns:
        str: Temizlenmiş cihaz adı.
    """
    name = raw
    # Servis tipi eklerini temizle: '._device-info._tcp', '._tcp.local' vb.
    name = re.sub(r'\._[^.]+\._(tcp|udp)(?:\.local)?$', '', name, flags=re.IGNORECASE)
    name = re.sub(r'\._(tcp|udp)(?:\.local)?$', '', name, flags=re.IGNORECASE)
    # .local / .lan uzantısını temizle
    name = re.sub(r'\.(local|lan|home|localdomain)$', '', name, flags=re.IGNORECASE)
    # Tireleri boşlukla değiştir
    name = name.replace('-', ' ').strip()
    return name


def extract_owner_from_hostname(hostname: str) -> str:
    """
    Cihaz adından sahip adını çıkarır.

    Örnekler:
        'Omers-iPhone.local'  -> 'Omers'
        'Efe-s-iPad'          -> 'Efe'
        'DESKTOP-ABC123'      -> ''

    Args:
        hostname: Ham cihaz adı.

    Returns:
        str: Sahip adı veya boş string.
    """
    clean = re.sub(r'\.(local|lan|home|localdomain)$', '', hostname, flags=re.IGNORECASE)
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
            prefix = re.sub(r'-s$', '', prefix, flags=re.IGNORECASE).strip('-').strip()
            if prefix:
                return ' '.join(w.capitalize() for w in prefix.replace('-', ' ').split())
    return ''


def parse_mdns_name_from_payload(payload: bytes) -> list[str]:
    """
    mDNS/DNS binary paketten sorgu/yanıt isimlerini okur.

    Args:
        payload: Ham paket payload'u.

    Returns:
        list: Çözümlenen isim string'leri listesi.
    """
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


# ─── Pasif Sniffer Motoru ──────────────────────────────────────────────────────

class PassiveSnifferEngine:
    """
    Arka planda mDNS (Bonjour), DHCP Opt-12, LLMNR ve NetBIOS paketlerini
    pasif olarak dinler; cihaz isimlerini ve sahip adlarını tespit eder.

    Bu sınıf, bir state nesnesi ile birlikte çalışır ve bulunan isimleri
    state.devices dict'ine yazar.

    Attributes:
        _thread: Arka plan dinleme thread'i.
        _stop:   Durdurma sinyali.
    """

    def __init__(self, state=None, vendor_fn=None, log_fn=None):
        """
        Args:
            state:     AppState nesnesi (devices dict'ine erişim için).
            vendor_fn: get_vendor(mac, hostname) fonksiyonu.
            log_fn:    state.log(msg, level) fonksiyonu.
        """
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._state = state
        self._vendor_fn = vendor_fn
        self._log_fn = log_fn or (lambda msg, lvl="info": None)

    def start(self):
        """Pasif dinlemeyi başlatır."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name='PassiveSniffer')
        self._thread.start()
        self._log_fn("[SNIFF] Pasif dinleyici başlatıldı (mDNS/DHCP/LLMNR/NetBIOS)", "info")

    def stop(self):
        """Pasif dinlemeyi durdurur."""
        self._stop.set()

    def _update_device(self, ip: str, hostname: str, source: str):
        """Keşfedilen ismi state'e yazar."""
        if not ip or not hostname:
            return
        if self._state is None:
            return

        devices = self._state.get_devices() if hasattr(self._state, 'get_devices') else getattr(self._state, 'devices', {})
        if ip not in devices:
            return

        # Bonjour servis yayınlarını filtrele
        if is_service_name(hostname):
            return

        old = devices[ip].get('friendly_name', '')
        clean = clean_mdns_name(hostname)
        owner = extract_owner_from_hostname(hostname)

        if not clean or clean == old:
            return

        # State güncelleme
        update = {
            'hostname':      hostname,
            'friendly_name': clean,
            'owner_name':    owner,
        }

        if self._vendor_fn:
            mac = devices[ip].get('mac', '')
            vendor, dtype = self._vendor_fn(mac, hostname)
            update['vendor'] = vendor
            update['type'] = dtype

        if hasattr(self._state, 'update_device'):
            self._state.update_device(ip, update)
        else:
            devices[ip].update(update)

        display = f"{owner} / {clean}" if owner else clean
        self._log_fn(f"[{source}] {ip} → {display}", "success")

    def _run(self):
        """Scapy sniff — sadece ilgili portları dinler."""
        try:
            from scapy.all import sniff, DNS, UDP, IP, Raw  # noqa: F811
        except ImportError:
            self._log_fn("[SNIFF] Scapy yok, pasif dinleyici devre dışı.", "warn")
            return

        def _pkt_handler(pkt):
            if self._stop.is_set():
                return
            try:
                self._process(pkt)
            except Exception as e:
                logger.debug("Pasif sniffer paket hatası: %s", e)

        bpf = "udp and (port 5353 or port 67 or port 68 or port 5355 or port 137)"
        try:
            sniff(filter=bpf, prn=_pkt_handler, store=False,
                  stop_filter=lambda _: self._stop.is_set(),
                  timeout=None)
        except Exception as e:
            self._log_fn(f"[SNIFF] Hata: {e}", "warn")

    def _process(self, pkt):
        """Gelen paketi protokolüne göre işler."""
        from scapy.all import DNS, UDP, IP, Raw

        if not pkt.haslayer(IP):
            return
        src_ip = pkt[IP].src
        dport = pkt[UDP].dport if pkt.haslayer(UDP) else 0
        sport = pkt[UDP].sport if pkt.haslayer(UDP) else 0

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
                names = parse_mdns_name_from_payload(payload)
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
            qcount = struct.unpack('>H', payload[4:6])[0]
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
