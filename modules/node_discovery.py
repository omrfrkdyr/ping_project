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
        self.iface = iface or (conf.iface if SCAPY_AVAILABLE else "eth0")
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
            ether_layer, arp_layer = self._build_arp_request(network)
            packet = ether_layer / arp_layer

            # srp = Send & Receive at Layer 2 (ham Ethernet frame gönderir)
            # answered  : yanıt alınan paket çiftleri
            # unanswered: yanıt alınamayan paketler
            answered, unanswered = srp(
                packet,
                iface=self.iface,
                timeout=timeout,
                retry=retry,
                verbose=verbose
            )

        except PermissionError:
            raise PermissionError(
                "Ham soket açmak için root/sudo yetkisi gereklidir.\n"
                "  → sudo python3 main.py"
            )
        except OSError as e:
            raise OSError(f"Ağ arayüzü hatası [{self.iface}]: {e}")

        elapsed = time.time() - start_time

        # Yanıtları işle
        with self._scan_lock:
            new_hosts = 0
            for sent_pkt, received_pkt in answered:
                # ARP yanıtından IP ve MAC adreslerini çıkar
                ip  = received_pkt[ARP].psrc   # Protokol kaynak IP
                mac = received_pkt[ARP].hwsrc  # Donanım kaynak MAC

                if ip in self.hosts:
                    self.hosts[ip].update()
                else:
                    hostname = self._resolve_hostname(ip) if resolve_hostnames else "N/A"
                    self.hosts[ip] = HostEntry(ip, mac, hostname)
                    new_hosts += 1

        sep_count = 66
        cprint(f"\n  [✓] Tarama tamamlandı!", Colors.GREEN, bold=True)
        cprint(f"  [*] Süre: {elapsed:.2f}s | Toplam: {len(self.hosts)} host | Yeni: {new_hosts}", Colors.WHITE)

        return self.hosts

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
