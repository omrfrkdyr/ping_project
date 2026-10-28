"""
AntiGravity - Modül 1: Node Discovery (Düğüm Keşfi)
=====================================================
ARP istekleri kullanarak yerel ağdaki aktif hostları tespit eder
ve sonuçları IP/MAC tablosu halinde sunar.

Çalışma Prensibi (Layer 2):
  - Broadcast ARP isteği gönderilir: "X.X.X.X IP'si kimin?"
  - Ağdaki aktif düğümler ARP yanıtı ile MAC adreslerini bildirir.
  - Yanıtlar toplanarak bir host tablosu oluşturulur.

Gereksinimler:
  - sudo / root yetkisi (ham soket açmak için)
  - pip install scapy
"""

import time
import threading
from typing import Optional

try:
    from scapy.all import (
        ARP, Ether, srp, conf, get_if_hwaddr, get_if_addr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from modules.utils import (
    cprint, Colors, separator, print_table,
    validate_network, guess_network_range, timestamp
)


# ─── Veri Yapısı ──────────────────────────────────────────────────────────────

class HostEntry:
    """Keşfedilen bir ağ düğümünü temsil eder."""

    def __init__(self, ip: str, mac: str, hostname: str = "N/A"):
        self.ip       = ip
        self.mac      = mac
        self.hostname = hostname
        self.first_seen = timestamp()
        self.last_seen  = timestamp()

    def update(self):
        self.last_seen = timestamp()

    def __repr__(self):
        return f"HostEntry(ip={self.ip}, mac={self.mac})"


# ─── Ana Sınıf ────────────────────────────────────────────────────────────────

class NodeDiscovery:
    """
    ARP tabanlı ağ düğümü keşif motoru.

    Attributes:
        hosts (dict): {ip: HostEntry} haritalama sözlüğü.
        iface (str):  Kullanılan ağ arayüzü.
    """

    def __init__(self, iface: Optional[str] = None):
        """
        Args:
            iface: Ağ arayüzü adı. None ise Scapy varsayılanı kullanılır.
        """
        self.hosts: dict[str, HostEntry] = {}
        # Scapy 2.5+ conf.iface NetworkInterface nesnesi döndürür,
        # subprocess ve BPF soketlerinde sorun yaratır — str'e çevir
        self.iface = iface or (str(conf.iface) if SCAPY_AVAILABLE else "eth0")
        self._scan_lock = threading.Lock()

    # ── Yardımcı Metodlar ────────────────────────────────────────────────────

    def _resolve_hostname(self, ip: str) -> str:
        """
        IP adresinden hostname çözümlemeye çalışır (opsiyonel, DNS bağımlı).

        Args:
            ip: Çözümlenecek IP adresi.

        Returns:
            str: Hostname veya "N/A".
        """
        import socket
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return "N/A"

    def _build_arp_request(self, target: str) -> tuple:
        """
        Hedef IP/ağ için ARP istek paketi oluşturur.

        Args:
            target: IP adresi veya CIDR ağı (örn. "192.168.1.0/24").

        Returns:
            tuple: (Ether katmanı, ARP katmanı) paketi.

        Eğitim Notu:
            - Ether(dst="ff:ff:ff:ff:ff:ff"): Layer 2 broadcast frame
            - ARP(pdst=target): Layer 3 ARP who-has isteği
            - Birleşimi / operatörü ile yapılır (Scapy'nin paket zincirleme söz dizimi)
        """
        # Ethernet katmanı: ff:ff:ff:ff:ff:ff = broadcast adres
        ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff")

        # ARP katmanı: op=1 (who-has / istek), pdst hedef IP
        arp_layer = ARP(pdst=target, op=1)

        return ether_layer, arp_layer

    # ── Temel Tarama ─────────────────────────────────────────────────────────

    def scan(
        self,
        network: Optional[str] = None,
        timeout: float = 2.0,
        retry: int = 1,
        resolve_hostnames: bool = False,
        verbose: bool = False
    ) -> dict[str, HostEntry]:
        """
        Belirtilen ağ aralığında ARP taraması gerçekleştirir.

        Args:
            network:          CIDR formatında ağ aralığı. None ise otomatik tespit.
            timeout:          Her paket için bekleme süresi (saniye).
            retry:            Yanıtsız paketler için tekrar deneme sayısı.
            resolve_hostnames: Her IP için DNS çözümlemesi yapılsın mı?
            verbose:          Scapy ham çıktısı gösterilsin mi?

        Returns:
            dict: {ip: HostEntry} keşfedilen hostların sözlüğü.

        Raises:
            PermissionError: Root yetkisi yoksa.
            ImportError:     Scapy yüklü değilse.
            ValueError:      Geçersiz ağ formatı girilmişse.
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy yüklü değil. Lütfen 'pip install scapy' çalıştırın.")

        # Ağ aralığı belirleme
        if network is None:
            network = guess_network_range()
            cprint(f"  [*] Ağ aralığı otomatik tespit edildi: {network}", Colors.CYAN)

        if not validate_network(network):
            raise ValueError(f"Geçersiz ağ formatı: '{network}'. Örnek: 192.168.1.0/24")

        cprint(f"\n  [+] ARP taraması başlıyor...", Colors.GREEN, bold=True)
        cprint(f"  [*] Hedef Ağ  : {network}", Colors.WHITE)
        cprint(f"  [*] Arayüz    : {self.iface}", Colors.WHITE)
        cprint(f"  [*] Zaman Aşımı: {timeout}s | Tekrar: {retry}", Colors.WHITE)
        separator()

        start_time = time.time()

        try:
            import ipaddress as _ipa
            _net = _ipa.IPv4Network(network, strict=False)

            answered_all = []

            # Büyük ağlarda (/22+) BPF soket limiti aşılabilir.
            # /24 parçalara bölerek tarama yapılır.
            if _net.prefixlen < 24:
                subnets = list(_net.subnets(new_prefix=24))
                cprint(f"  [*] Büyük ağ — {len(subnets)} parça (/24) olarak taranıyor...", Colors.CYAN)
                for i, subnet in enumerate(subnets):
                    try:
                        ether_layer, arp_layer = self._build_arp_request(str(subnet))
                        packet = ether_layer / arp_layer
                        ans, _ = srp(
                            packet,
                            iface=self.iface,
                            timeout=timeout,
                            retry=retry,
                            verbose=verbose
                        )
                        answered_all.extend(ans)
                    except Exception:
                        pass  # Tek parça hata verirse diğerlerine devam et
            else:
                ether_layer, arp_layer = self._build_arp_request(network)
                packet = ether_layer / arp_layer
                ans, _ = srp(
                    packet,
                    iface=self.iface,
                    timeout=timeout,
                    retry=retry,
                    verbose=verbose
                )
                answered_all = ans

        except PermissionError:
            raise PermissionError(
                "Ham soket açmak için root/sudo yetkisi gereklidir.\n"
                "  → sudo python3 main.py"
            )
        except Exception as e:
            # BPF soket hataları dahil tüm hataları yakala,
            # fallback stratejilerine geçiş yapılabilsin
            cprint(f"  [!] ARP tarama hatası: {e}", Colors.YELLOW)
            answered_all = []

        elapsed = time.time() - start_time

        # Yanıtları işle
        with self._scan_lock:
            new_hosts = 0
            for sent_pkt, received_pkt in answered_all:
                # ARP yanıtından IP ve MAC adreslerini çıkar
                ip  = received_pkt[ARP].psrc   # Protokol kaynak IP
                mac = received_pkt[ARP].hwsrc  # Donanım kaynak MAC

                if ip in self.hosts:
                    self.hosts[ip].update()
                else:
                    hostname = self._resolve_hostname(ip) if resolve_hostnames else "N/A"
                    self.hosts[ip] = HostEntry(ip, mac, hostname)
                    new_hosts += 1

        # ARP taraması yeterli sonuç vermediyse çoklu strateji fallback uygula
        # (≤1 = sadece gateway bulundu veya hiç bulunamadı)
        if len(self.hosts) <= 1:
            cprint(f"\n  [!] ARP yetersiz sonuç ({len(self.hosts)} host) — alternatif keşif başlıyor...",
                   Colors.YELLOW, bold=True)
            self._multi_strategy_fallback(network, timeout, resolve_hostnames)

        cprint(f"\n  [✓] Tarama tamamlandı!", Colors.GREEN, bold=True)
        cprint(f"  [*] Süre: {elapsed:.2f}s | Toplam: {len(self.hosts)} host | Yeni: {new_hosts}", Colors.WHITE)

        return self.hosts

    # ── Çoklu Strateji Fallback ──────────────────────────────────────────────

    def _multi_strategy_fallback(
        self,
        network: str,
        timeout: float = 2.0,
        resolve_hostnames: bool = False
    ):
        """
        ARP taraması başarısız olduğunda çoklu strateji ile cihaz keşfi yapar.

        Enterprise / üniversite ağlarında switch'ler ARP broadcast'ı
        engelleyebilir (DAI, client isolation). Bu durumda alternatif
        yöntemlerle cihaz keşfedilir:

          1. OS ARP/NDP cache okuma (önceki iletişimlerden bilinen cihazlar)
          2. IPv6 multicast ping (ff02::1 — bazı switch'ler multicast'e izin verir)
          3. Pasif dinleme (mDNS, DHCP, SSDP, ARP sızıntıları)
          4. ICMP ping sweep (son çare — routing üzerinden ulaşılabilir cihazlar)

        Args:
            network:           CIDR formatında ağ aralığı.
            timeout:           İşlem timeout'u (saniye).
            resolve_hostnames: Hostname çözümlemesi yapılsın mı?
        """
        import ipaddress

        try:
            net = ipaddress.IPv4Network(network, strict=False)
        except (ipaddress.AddressValueError, ValueError):
            return

        before = len(self.hosts)

        # ── Strateji 1: OS Cache Okuma ───────────────────────────────────────
        cprint(f"  [1/4] OS ARP/NDP cache okunuyor...", Colors.CYAN)
        try:
            self._read_os_caches(net, resolve_hostnames)
        except Exception as e:
            cprint(f"        [!] Cache okuma hatası: {e}", Colors.YELLOW)
        cprint(f"        → {len(self.hosts) - before} yeni cihaz bulundu", Colors.WHITE)

        # ── Strateji 2: IPv6 Multicast Ping ──────────────────────────────────
        mid = len(self.hosts)
        cprint(f"  [2/4] IPv6 multicast keşif (ff02::1)...", Colors.CYAN)
        try:
            self._ipv6_multicast_discover(net, resolve_hostnames)
        except Exception as e:
            cprint(f"        [!] IPv6 multicast hatası: {e}", Colors.YELLOW)
        cprint(f"        → {len(self.hosts) - mid} yeni cihaz bulundu", Colors.WHITE)

        # ── Strateji 3: Pasif Broadcast/Multicast Dinleme ────────────────────
        mid2 = len(self.hosts)
        cprint(f"  [3/4] Pasif ağ dinleme (8s — mDNS/DHCP/SSDP/ARP)...", Colors.CYAN)
        try:
            self._passive_broadcast_sniff(net, resolve_hostnames, duration=8)
        except Exception as e:
            cprint(f"        [!] Pasif dinleme hatası: {e}", Colors.YELLOW)
        cprint(f"        → {len(self.hosts) - mid2} yeni cihaz bulundu", Colors.WHITE)

        # ── Strateji 4: ICMP Ping Sweep ──────────────────────────────────────
        mid3 = len(self.hosts)
        cprint(f"  [4/4] ICMP ping sweep...", Colors.CYAN)
        try:
            self._ping_sweep(net, timeout, resolve_hostnames)
        except Exception as e:
            cprint(f"        [!] Ping sweep hatası: {e}", Colors.YELLOW)
        cprint(f"        → {len(self.hosts) - mid3} yeni cihaz bulundu", Colors.WHITE)

        total_new = len(self.hosts) - before
        if total_new == 0:
            cprint(f"\n  [!] Client isolation algılandı — ağda diğer cihazlara erişim engellenmiş.",
                   Colors.YELLOW)
            cprint(f"  [!] Pasif dinleyici arka planda çalışmaya devam edecek.",
                   Colors.YELLOW)

    # ── Strateji 1: OS Cache ─────────────────────────────────────────────────

    def _read_os_caches(self, net, resolve_hostnames: bool = False):
        """OS ARP ve NDP (IPv6) cache'lerini okuyarak bilinen cihazları ekler."""
        import subprocess
        import re
        import ipaddress

        # ARP cache: arp -a
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                m = re.search(
                    r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})',
                    line
                )
                if m:
                    ip, mac = m.group(1), m.group(2).lower()
                    try:
                        if (ipaddress.IPv4Address(ip) in net
                                and ip not in self.hosts
                                and mac != "ff:ff:ff:ff:ff:ff"
                                and not mac.startswith("01:00:5e")):
                            hostname = self._resolve_hostname(ip) if resolve_hostnames else "N/A"
                            with self._scan_lock:
                                self.hosts[ip] = HostEntry(ip, mac, hostname)
                    except (ipaddress.AddressValueError, ValueError):
                        continue
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        # NDP cache: ndp -a (macOS) veya ip -6 neigh (Linux)
        try:
            result = subprocess.run(
                ["ndp", "-a"], capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                # Linux fallback
                result = subprocess.run(
                    ["ip", "-6", "neigh", "show"],
                    capture_output=True, text=True, timeout=5
                )
            # NDP'den gelen link-local MAC'leri topla
            for line in result.stdout.splitlines():
                m = re.search(r'([0-9a-fA-F:]{17})\s+\w+', line)
                if m:
                    mac = m.group(1).lower()
                    if mac and not mac.startswith("01:00:5e") and mac != "(incomplete)":
                        # MAC'ten IPv4 eşleşmesi ARP cache'ten gelir
                        pass  # NDP sonuçları IPv6, ARP cache'den IPv4 zaten okundu
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    # ── Strateji 2: IPv6 Multicast ───────────────────────────────────────────

    def _ipv6_multicast_discover(self, net, resolve_hostnames: bool = False):
        """
        IPv6 all-nodes multicast (ff02::1) ping göndererek
        yanıt veren cihazların MAC adreslerini toplar.

        Bazı switch'ler IPv6 multicast'e L2 client isolation uygulamaz
        çünkü NDP (Neighbor Discovery) ağ çalışması için gereklidir.
        """
        import subprocess
        import re
        import ipaddress

        iface = self.iface
        try:
            # ping6 ff02::1 — tüm IPv6 cihazlara multicast
            result = subprocess.run(
                ["ping6", "-c", "3", "-W", "2000", "-I", iface, "ff02::1"],
                capture_output=True, text=True, timeout=10
            )

            # Yanıtlardaki benzersiz link-local adreslerini topla
            seen_macs = set()
            for line in result.stdout.splitlines():
                # "16 bytes from fe80::xxxx%en0, icmp_seq=0 ..."
                m = re.search(r'from\s+(fe80::[0-9a-fA-F:]+)', line)
                if m:
                    v6_addr = m.group(1)
                    # Link-local'den MAC çıkar (EUI-64 formatı)
                    mac = self._linklocal_to_mac(v6_addr)
                    if mac and mac not in seen_macs:
                        seen_macs.add(mac)

            # ARP cache'ten bu MAC'lere ait IPv4 adreslerini bul
            arp_cache = self._get_arp_cache_dict()
            mac_to_ip = {mac: ip for ip, mac in arp_cache.items()}

            for mac in seen_macs:
                ip = mac_to_ip.get(mac)
                if ip and ip not in self.hosts:
                    try:
                        if ipaddress.IPv4Address(ip) in net:
                            hostname = self._resolve_hostname(ip) if resolve_hostnames else "N/A"
                            with self._scan_lock:
                                self.hosts[ip] = HostEntry(ip, mac, hostname)
                    except (ipaddress.AddressValueError, ValueError):
                        continue

            # Ayrıca ping6 sonrası NDP cache'i tekrar oku
            self._read_os_caches(net, resolve_hostnames)

        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    @staticmethod
    def _linklocal_to_mac(v6_addr: str) -> str:
        """
        IPv6 link-local adresinden MAC adresi çıkarır (EUI-64 formatı).

        Örn: fe80::6f4:1cff:fe49:2859 → 04:f4:1c:49:28:59

        Not: Tüm link-local adresler EUI-64 formatında değildir
        (privacy extensions veya randomized), bu durumda None döner.
        """
        import ipaddress
        try:
            addr = ipaddress.IPv6Address(v6_addr)
            # Son 8 byte'ı al
            packed = addr.packed
            iid = packed[8:]  # Interface ID (8 bytes)

            # EUI-64 formatı kontrolü: byte[3:5] == ff:fe olmalı
            if iid[3] != 0xff or iid[4] != 0xfe:
                return None

            # MAC adresini oluştur
            mac_bytes = [
                iid[0] ^ 0x02,  # Universal/Local bit'i geri çevir
                iid[1],
                iid[2],
                iid[5],
                iid[6],
                iid[7],
            ]
            return ":".join(f"{b:02x}" for b in mac_bytes)
        except (ValueError, IndexError):
            return None

    # ── Strateji 3: Pasif Dinleme ────────────────────────────────────────────

    def _passive_broadcast_sniff(self, net, resolve_hostnames: bool = False, duration: int = 8):
        """
        Belirli süre boyunca ağdaki broadcast/multicast paketleri
        pasif olarak dinler ve kaynak cihazları tespit eder.

        Dinlenen protokoller:
          - ARP (who-has/is-at)
          - mDNS (224.0.0.251 / ff02::fb, port 5353)
          - DHCP (port 67/68)
          - SSDP (239.255.255.250, port 1900)
          - LLMNR (224.0.0.252, port 5355)
          - NetBIOS (port 137/138)
        """
        if not SCAPY_AVAILABLE:
            return

        import ipaddress
        from scapy.all import sniff, IP, IPv6

        discovered = {}  # {mac: ip}

        def _handle_packet(pkt):
            try:
                src_mac = pkt.src if hasattr(pkt, 'src') else None
                src_ip = None

                if pkt.haslayer(ARP):
                    src_ip = pkt[ARP].psrc
                    src_mac = pkt[ARP].hwsrc
                elif pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                elif pkt.haslayer(IPv6):
                    # IPv6 link-local'den MAC çıkar
                    v6_src = pkt[IPv6].src
                    if v6_src.startswith("fe80::"):
                        mac_from_v6 = self._linklocal_to_mac(v6_src)
                        if mac_from_v6:
                            src_mac = mac_from_v6

                if not src_mac or not src_ip:
                    return
                if src_ip in ("0.0.0.0", "255.255.255.255"):
                    return

                try:
                    if ipaddress.IPv4Address(src_ip) not in net:
                        return
                except (ipaddress.AddressValueError, ValueError):
                    return

                # Multicast/broadcast MAC'leri filtrele
                if (src_mac.startswith("01:00:5e") or
                        src_mac.startswith("33:33:") or
                        src_mac == "ff:ff:ff:ff:ff:ff"):
                    return

                if src_ip not in discovered:
                    discovered[src_ip] = src_mac.lower()
            except Exception:
                pass

        try:
            # BPF filtresi: broadcast, multicast veya ARP paketleri
            bpf = (
                "arp or "
                "udp port 5353 or "     # mDNS
                "udp port 67 or "       # DHCP server
                "udp port 68 or "       # DHCP client
                "udp port 1900 or "     # SSDP
                "udp port 5355 or "     # LLMNR
                "udp port 137 or "      # NetBIOS-NS
                "udp port 138"          # NetBIOS-DGM
            )
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=_handle_packet,
                timeout=duration,
                store=False
            )
        except Exception:
            pass

        # Keşfedilenleri ekle
        with self._scan_lock:
            for ip, mac in discovered.items():
                if ip not in self.hosts:
                    hostname = self._resolve_hostname(ip) if resolve_hostnames else "N/A"
                    self.hosts[ip] = HostEntry(ip, mac, hostname)

    # ── Strateji 4: Ping Sweep ───────────────────────────────────────────────

    def _ping_sweep(self, net, timeout: float = 1.0, resolve_hostnames: bool = False):
        """
        ICMP ping sweep ile cihaz keşfi.
        Büyük ağlarda (/22+) sadece kendi /24 subnet'ini tarar.
        """
        import subprocess
        import ipaddress
        import platform
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Büyük ağlarda sadece kendi /24'ünü tara (performans)
        local_ip = get_if_addr(self.iface) if SCAPY_AVAILABLE else "0.0.0.0"
        if net.prefixlen < 24 and local_ip != "0.0.0.0":
            try:
                scan_net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
                cprint(f"        Büyük ağ — sadece {scan_net} taranıyor", Colors.GRAY)
            except (ipaddress.AddressValueError, ValueError):
                scan_net = net
        else:
            scan_net = net

        hosts_list = [str(ip) for ip in scan_net.hosts()]
        total = len(hosts_list)
        system = platform.system()

        def _ping_one(ip: str) -> bool:
            try:
                if system == "Darwin":
                    cmd = ["ping", "-c", "1", "-W", "300", "-q", ip]
                elif system == "Windows":
                    cmd = ["ping", "-n", "1", "-w", "300", ip]
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", "-q", ip]
                result = subprocess.run(cmd, capture_output=True, timeout=3)
                return result.returncode == 0
            except (subprocess.TimeoutExpired, OSError):
                return False

        responded = []
        max_workers = min(80, total)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_ping_one, ip): ip for ip in hosts_list}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        responded.append(ip)
                except Exception:
                    pass

        cprint(f"        Ping yanıtı: {len(responded)} / {total}", Colors.GRAY)

        # Ping sonrası ARP cache oku
        arp_cache = self._get_arp_cache_dict()
        with self._scan_lock:
            for ip in responded:
                if ip not in self.hosts:
                    mac = arp_cache.get(ip, "00:00:00:00:00:00")
                    hostname = self._resolve_hostname(ip) if resolve_hostnames else "N/A"
                    self.hosts[ip] = HostEntry(ip, mac, hostname)

    # ── Yardımcı: ARP Cache Sözlüğü ─────────────────────────────────────────

    @staticmethod
    def _get_arp_cache_dict() -> dict:
        """OS ARP cache'ini {ip: mac} sözlüğü olarak döndürür."""
        import subprocess
        import re

        cache = {}
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                m = re.search(
                    r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})',
                    line
                )
                if m:
                    cache[m.group(1)] = m.group(2).lower()
                    continue
                m = re.search(
                    r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})',
                    line
                )
                if m:
                    cache[m.group(1)] = m.group(2).replace('-', ':').lower()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return cache

    # ── Görüntüleme ──────────────────────────────────────────────────────────

    def display_table(self, hosts: Optional[dict] = None):
        """
        Keşfedilen hostları biçimlendirilmiş tablo olarak gösterir.

        Args:
            hosts: Gösterilecek host sözlüğü. None ise self.hosts kullanılır.
        """
        target_hosts = hosts or self.hosts

        if not target_hosts:
            cprint("\n  [!] Henüz hiç host keşfedilmedi. Önce tarama yapın.", Colors.YELLOW)
            return

        cprint(f"\n  ═══  KEŞFEDİLEN AĞ DÜĞÜMLERİ  ═══", Colors.CYAN, bold=True)
        cprint(f"  Zaman: {timestamp()}", Colors.GRAY)
        separator()

        headers = ["#", "IP Adresi", "MAC Adresi", "Hostname", "İlk Görülme"]
        rows = []
        row_colors = []

        # Satırları IP'ye göre sırala
        sorted_hosts = sorted(target_hosts.values(), key=lambda h: [int(x) for x in h.ip.split(".")])

        for idx, host in enumerate(sorted_hosts, start=1):
            rows.append([str(idx), host.ip, host.mac, host.hostname, host.first_seen])
            # Birinci host (genellikle gateway) farklı renkle göster
            row_colors.append(Colors.YELLOW if idx == 1 else Colors.WHITE)

        print_table(headers, rows, row_colors)
        cprint(f"\n  Toplam {len(rows)} aktif düğüm tespit edildi.", Colors.GREEN)

    # ── İnteraktif Menü ──────────────────────────────────────────────────────

    def interactive_scan(self):
        """
        Kullanıcıdan parametreleri alarak interaktif tarama başlatır.
        """
        cprint("\n  ┌─ NODE DISCOVERY MODÜLÜ ───────────────────────────────┐", Colors.CYAN, bold=True)
        cprint("  │  ARP taraması ile aktif hostları tespit eder          │", Colors.CYAN)
        cprint("  └────────────────────────────────────────────────────────┘\n", Colors.CYAN)

        # Ağ aralığı
        suggested = guess_network_range()
        cprint(f"  Taranacak ağ aralığı [{suggested}]: ", Colors.WHITE, end="")
        raw = input().strip()
        network = raw if raw else suggested

        # Zaman aşımı
        cprint("  Zaman aşımı süresi saniye [2]: ", Colors.WHITE, end="")
        raw_timeout = input().strip()
        try:
            timeout = float(raw_timeout) if raw_timeout else 2.0
            if timeout <= 0:
                raise ValueError
        except ValueError:
            cprint("  [!] Geçersiz değer, varsayılan (2s) kullanılıyor.", Colors.YELLOW)
            timeout = 2.0

        # Hostname çözümleme
        cprint("  Hostname çözümlemesi yapılsın mı? (y/N): ", Colors.WHITE, end="")
        resolve = input().strip().lower() in ("y", "yes", "evet")

        try:
            hosts = self.scan(
                network=network,
                timeout=timeout,
                resolve_hostnames=resolve
            )
            self.display_table(hosts)
        except (PermissionError, ImportError, ValueError, OSError) as e:
            cprint(f"\n  [✗] HATA: {e}", Colors.RED, bold=True)

        return self.hosts
