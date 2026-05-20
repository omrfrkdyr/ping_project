"""
AntiGravity — DNS & TLS SNI Monitor
=====================================
Seçilen bir hedef IP'nin ziyaret ettiği web sitelerini,
internet bağlantısını kesmeden (şeffaf MITM) izler.

Nasıl çalışır:
  1. ARP spoofing + IP Forwarding ON  → şeffaf MITM, internet kesilmez
  2. Scapy ile DNS sorguları dinlenir  → UDP port 53
  3. TLS ClientHello SNI alanı okunur → TCP port 443
  4. Sonuçlar thread-safe queue'ya yazılır, SSE ile frontend'e akar

⚠️  UYARI: Yalnızca kendi ağınızda, izinli cihazlarda kullanın.
"""

import time
import threading
import struct
from collections import deque
from datetime import datetime
from typing import Optional, Callable

try:
    from scapy.all import sniff, DNS, UDP, TCP, IP, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


MAX_HISTORY = 300   # Hafızada tutulacak maksimum domain sayısı


def _now_str() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _parse_tls_sni(payload: bytes) -> Optional[str]:
    """
    TLS ClientHello paketinden SNI (Server Name Indication) alanını çıkarır.
    HTTPS bağlantıları şifreli olsa da TLS el sıkışmasının bu kısmı plaintext'tir.

    TLS record yapısı:
      [0]    = Content Type (22 = Handshake)
      [1:3]  = TLS Version
      [3:5]  = Length
      [5]    = Handshake Type (1 = ClientHello)
      ...
      SNI Extension Type = 0x0000
    """
    try:
        if len(payload) < 6:
            return None
        # TLS Handshake kontrolü
        if payload[0] != 0x16:   # Content Type: Handshake
            return None
        if payload[5] != 0x01:   # Handshake Type: ClientHello
            return None

        # Session ID'yi atla
        offset = 43
        if offset >= len(payload):
            return None

        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(payload):
            return None

        # Cipher Suites'i atla
        cipher_len = struct.unpack(">H", payload[offset:offset+2])[0]
        offset += 2 + cipher_len
        if offset + 1 > len(payload):
            return None

        # Compression Methods'u atla
        comp_len = payload[offset]
        offset += 1 + comp_len
        if offset + 2 > len(payload):
            return None

        # Extensions uzunluğu
        ext_total = struct.unpack(">H", payload[offset:offset+2])[0]
        offset += 2
        ext_end = offset + ext_total

        while offset + 4 <= ext_end and offset + 4 <= len(payload):
            ext_type = struct.unpack(">H", payload[offset:offset+2])[0]
            ext_len  = struct.unpack(">H", payload[offset+2:offset+4])[0]
            offset  += 4

            if ext_type == 0x0000:  # SNI extension
                # SNI List Length (2 bytes) + SNI Type (1 byte) + Name Length (2 bytes)
                if offset + 5 > len(payload):
                    break
                name_len = struct.unpack(">H", payload[offset+3:offset+5])[0]
                name_start = offset + 5
                if name_start + name_len > len(payload):
                    break
                sni = payload[name_start:name_start+name_len].decode("utf-8", errors="ignore")
                return sni if sni else None

            offset += ext_len

    except Exception:
        pass
    return None


def _is_cdn_or_tracker(domain: str) -> bool:
    """Anlamsız CDN/tracker domain'lerini filtrele (opsiyonel)."""
    noise = [
        "googlevideo.com", "gstatic.com", "doubleclick.net", "googletagmanager.com",
        "akamaiedge.net", "cloudflare.com", "fastly.net", "cdn77.com",
        "akadns.net", "akamai.net",
    ]
    d = domain.lower()
    return any(d.endswith(n) for n in noise)


class DnsMonitor:
    """
    Hedef bir IP adresinin DNS sorguları ve TLS SNI'larını izler.
    Thread-safe, başlatılıp durdurulabilir.
    """

    def __init__(self, target_ip: str, on_domain: Optional[Callable] = None):
        """
        Args:
            target_ip:  İzlenecek cihazın IP adresi.
            on_domain:  Yeni domain bulunduğunda çağrılacak callback(domain_entry).
        """
        self.target_ip   = target_ip
        self.on_domain   = on_domain
        self.history     = deque(maxlen=MAX_HISTORY)
        self.active      = False
        self._stop_evt   = threading.Event()
        self._thread     = None
        self._seen       = set()        # tekrar filtreleme (aynı domain'i tekrar ekleme)
        self._lock       = threading.Lock()

    def start(self):
        if self.active and self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name=f"DnsMonitor-{self.target_ip}"
        )
        self._thread.start()
        self.active = True

    def stop(self):
        self._stop_evt.set()
        self.active = False

    def get_history(self) -> list:
        with self._lock:
            return list(self.history)

    def _add_domain(self, domain: str, proto: str):
        """Yeni domain kaydı oluştur, history'e ekle, callback çağır."""
        domain = domain.lower().strip().lstrip("www.")
        if not domain or len(domain) < 3:
            return
        # Basit filtre: sadece geçerli domain gibi görünenler
        if "." not in domain:
            return
        # Tekrar filtresi — aynı domain'i son 60 saniyede tekrar ekleme
        key = domain
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)

            entry = {
                "domain":    domain,
                "proto":     proto,
                "ts":        _now_str(),
                "timestamp": time.time(),
            }
            self.history.appendleft(entry)   # En yeni üste

        # 60 saniye sonra seen'den çıkar (aynı site tekrar görünebilsin)
        def _unsee():
            time.sleep(60)
            with self._lock:
                self._seen.discard(key)
        threading.Thread(target=_unsee, daemon=True).start()

        if self.on_domain:
            try:
                self.on_domain(entry)
            except Exception:
                pass

    def _run(self):
        if not SCAPY_OK:
            return

        def _handler(pkt):
            if self._stop_evt.is_set():
                return
            try:
                self._process(pkt)
            except Exception:
                pass

        # BPF filtresi: sadece hedef IP'nin DNS ve HTTPS trafiği
        bpf = (
            f"host {self.target_ip} and "
            f"(udp port 53 or tcp port 443)"
        )

        try:
            sniff(
                filter=bpf,
                prn=_handler,
                store=False,
                stop_filter=lambda _: self._stop_evt.is_set(),
            )
        except Exception:
            pass

    def _process(self, pkt):
        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        dst = pkt[IP].dst

        # Sadece hedef cihazdan GELEN paketler (outbound DNS/HTTPS sorguları)
        if src != self.target_ip:
            return

        # ── DNS (UDP 53) ──────────────────────────────────────────────
        if pkt.haslayer(UDP) and pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0:  # Query (sorgu), Response değil
                for i in range(dns.qdcount):
                    try:
                        qname = dns.qd[i].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="ignore")
                        domain = qname.rstrip(".")
                        if domain:
                            self._add_domain(domain, "DNS")
                    except Exception:
                        pass

        # ── TLS SNI (TCP 443) ─────────────────────────────────────────
        elif pkt.haslayer(TCP) and pkt[TCP].dport == 443 and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            sni = _parse_tls_sni(payload)
            if sni:
                self._add_domain(sni, "HTTPS")
