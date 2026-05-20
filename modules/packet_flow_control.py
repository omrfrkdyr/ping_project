"""
AntiGravity - Modül 3: Packet Flow Control (Akış Kontrolü)
===========================================================
Yönlendirilen trafiğin iletilmesini (forwarding) manuel olarak
durdurabilen veya bant genişliğini simüle edebilen kontrol katmanı.

Özellikler:
  1. FORWARD modu  : Paketleri filtresiz ilet (şeffaf geçiş).
  2. DROP modu     : Tüm paketleri düşür (bağlantı kesme simülasyonu).
  3. THROTTLE modu : Belirli bant genişliği (kbps) ile iletim.
  4. INSPECT modu  : Paketleri filtrele ve terminale dökümle.

Çalışma Prensibi:
  Scapy'nin sniff() fonksiyonu ile yönlendirilen trafik yakalanır.
  Her paket için seçilen mod'a göre işlem yapılır:
    - FORWARD  → sendp() ile Layer 2'den ilet
    - DROP     → paketi yok say
    - THROTTLE → gecikme ekleyerek ilet
    - INSPECT  → içeriği göster, opsiyonel ilet

Gereksinimler:
  - sudo / root yetkisi
  - pip install scapy
  - IP Forwarding aktif (traffic_redirection modülü ile birlikte kullanın)
"""

import time
import threading
import queue
from enum import Enum
from typing import Optional, Callable

try:
    from scapy.all import (
        sniff, sendp, Ether, IP, TCP, UDP, ICMP,
        DNS, Raw, conf, get_if_hwaddr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# HTTPRequest opsiyonel — scapy.layers.http modülünde (her ortamda yüklü olmayabilir)
try:
    from scapy.layers.http import HTTPRequest  # noqa: F401
except Exception:
    HTTPRequest = None

from modules.utils import cprint, Colors, separator, timestamp


# ─── Mod Tanımları ────────────────────────────────────────────────────────────

class FlowMode(Enum):
    """Paket akış kontrol modları."""
    FORWARD  = "forward"    # Tüm paketleri şeffaf ilet
    DROP     = "drop"       # Tüm paketleri düşür
    THROTTLE = "throttle"   # Bant genişliği sınırlı iletim
    INSPECT  = "inspect"    # Paketleri göster + ilet


# ─── İstatistik Sayacı ────────────────────────────────────────────────────────

class FlowStats:
    """Anlık akış istatistiklerini takip eder."""

    def __init__(self):
        self.total_captured  = 0   # Toplam yakalanan paket
        self.total_forwarded = 0   # İletilen paket sayısı
        self.total_dropped   = 0   # Düşürülen paket sayısı
        self.total_bytes     = 0   # İşlenen toplam bayt
        self.start_time      = time.time()
        self._lock = threading.Lock()

    def record(self, forwarded: bool, size: int = 0):
        with self._lock:
            self.total_captured += 1
            self.total_bytes    += size
            if forwarded:
                self.total_forwarded += 1
            else:
                self.total_dropped   += 1

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def throughput_kbps(self) -> float:
        """Anlık işleme hızı (kbps)."""
        t = self.elapsed
        return (self.total_bytes * 8 / 1024 / t) if t > 0 else 0.0

    def display(self):
        cprint(f"\n  ─── Akış İstatistikleri ───────────────────────────────", Colors.CYAN)
        cprint(f"  Çalışma Süresi  : {self.elapsed:.1f}s", Colors.WHITE)
        cprint(f"  Toplam Yakalanan: {self.total_captured} paket", Colors.WHITE)
        cprint(f"  İletilen        : {self.total_forwarded} paket", Colors.GREEN)
        cprint(f"  Düşürülen       : {self.total_dropped} paket", Colors.RED)
        cprint(f"  Toplam Bayt     : {self.total_bytes / 1024:.2f} KB", Colors.WHITE)
        cprint(f"  Verim           : {self.throughput_kbps:.2f} kbps", Colors.CYAN)
        separator()


# ─── Ana Sınıf ────────────────────────────────────────────────────────────────

class PacketFlowController:
    """
    Yönlendirilmiş trafik üzerinde akış kontrolü sağlar.

    Bu sınıf, TrafficRedirector ile birlikte kullanılmak üzere tasarlanmıştır.
    Yakalanan paketler seçilen moda göre işlenir.

    Attributes:
        mode        (FlowMode): Aktif akış kontrolü modu.
        throttle_kbps (float): THROTTLE modunda maksimum hız (kbps).
        stats  (FlowStats): Anlık istatistikler.
        active       (bool): Kontrol sistemi çalışıyor mu?
        iface         (str): Dinleme arayüzü.
    """

    def __init__(self, iface: Optional[str] = None):
        """
        Args:
            iface: Ağ arayüzü. None ise Scapy varsayılanı kullanılır.
        """
        self.mode = FlowMode.FORWARD
        self.throttle_kbps = 512.0          # Varsayılan: 512 kbps
        self.stats = FlowStats()
        self.active = False
        self.iface = iface or (conf.iface if SCAPY_AVAILABLE else "eth0")
        self._stop_event  = threading.Event()
        self._sniff_thread: Optional[threading.Thread] = None
        self._filter: Optional[str] = None  # BPF filtresi
        self._inspect_callback: Optional[Callable] = None

    # ── Mod Değişikliği ───────────────────────────────────────────────────────

    def set_mode(self, mode: FlowMode, throttle_kbps: float = 512.0):
        """
        Aktif akış kontrol modunu değiştirir.

        Args:
            mode: Yeni FlowMode.
            throttle_kbps: THROTTLE modunda kbps sınırı.
        """
        self.mode = mode
        self.throttle_kbps = throttle_kbps
        cprint(f"\n  [✓] Akış modu değiştirildi → {mode.value.upper()}", Colors.CYAN, bold=True)

        if mode == FlowMode.DROP:
            cprint("  [!] Tüm paketler DÜŞÜRÜLÜYOR. Bağlantı kesilecek.", Colors.RED)
        elif mode == FlowMode.THROTTLE:
            cprint(f"  [*] Bant genişliği sınırı: {throttle_kbps:.0f} kbps", Colors.YELLOW)
        elif mode == FlowMode.INSPECT:
            cprint("  [*] Paketler terminale yazdırılacak ve iletilecek.", Colors.CYAN)

    # ── Paket İşleyiciler ─────────────────────────────────────────────────────

    def _forward_packet(self, pkt) -> bool:
        """
        Paketi Layer 2'den iletir.

        Eğitim Notu:
            sendp() → Layer 2 (Ethernet frame) gönderimi.
            send()  → Layer 3 (IP datagram) gönderimi.
            Şeffaf tünelleme için Ethernet başlığını korumak istediğimizden
            sendp() kullanırız.
        """
        try:
            sendp(pkt, iface=self.iface, verbose=False)
            return True
        except OSError:
            return False

    def _process_forward(self, pkt):
        """FORWARD modu: doğrudan ilet."""
        size = len(pkt)
        ok = self._forward_packet(pkt)
        self.stats.record(forwarded=ok, size=size)

    def _process_drop(self, pkt):
        """DROP modu: paketi yok say."""
        self.stats.record(forwarded=False, size=len(pkt))

    def _process_throttle(self, pkt):
        """
        THROTTLE modu: bant genişliği sınırlı iletim.

        Hesap:
            Paket boyutu (bit) / hedef bant genişliği (bps) = gecikme (s)
            Bu gecikme eklenerek sanki bant genişliği düşük bir bağlantıdaymış gibi davranılır.
        """
        size_bits = len(pkt) * 8
        target_bps = self.throttle_kbps * 1024
        delay = size_bits / target_bps  # saniye cinsinden gecikme

        time.sleep(delay)               # bant genişliği simülasyonu

        ok = self._forward_packet(pkt)
        self.stats.record(forwarded=ok, size=len(pkt))

    def _process_inspect(self, pkt):
        """
        INSPECT modu: paket içeriğini analiz ederek göster ve ilet.

        Katman bazlı inceleme:
          - Ether  : Kaynak/Hedef MAC
          - IP     : Kaynak/Hedef IP, TTL, Protokol
          - TCP    : Port, Flags, Sequence
          - UDP    : Port, Payload boyutu
          - DNS    : Sorgu adı
          - Raw    : Hammadde (payload) içeriği
        """
        lines = [f"\n  ┌─ PAKET  [{timestamp()}]  ({'%d' % len(pkt)} B) ────────────────"]

        # Layer 2 - Ethernet
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            lines.append(f"  │ [ETH]  {eth.src}  →  {eth.dst}  (type={hex(eth.type)})")

        # Layer 3 - IP
        if pkt.haslayer(IP):
            ip = pkt[IP]
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(ip.proto, str(ip.proto))
            lines.append(f"  │ [IP]   {ip.src}  →  {ip.dst}  TTL={ip.ttl}  Proto={proto_name}")

        # Layer 4 - TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = tcp.flags
            lines.append(f"  │ [TCP]  Sport={tcp.sport}  Dport={tcp.dport}  Flags={flags}  Seq={tcp.seq}")

        # Layer 4 - UDP
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            lines.append(f"  │ [UDP]  Sport={udp.sport}  Dport={udp.dport}  Len={udp.len}")

        # Layer 4 - ICMP
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            type_map = {0: "Echo-Reply", 8: "Echo-Request", 3: "Unreachable"}
            lines.append(f"  │ [ICMP] Type={type_map.get(icmp.type, icmp.type)}")

        # DNS sorgulama
        if pkt.haslayer(DNS):
            try:
                qname = pkt[DNS].qd.qname.decode(errors="ignore")
                lines.append(f"  │ [DNS]  Sorgu: {qname}")
            except Exception:
                pass

        # Payload (ilk 64 bayt)
        if pkt.haslayer(Raw):
            raw_data = bytes(pkt[Raw])[:64]
            try:
                text = raw_data.decode("utf-8", errors="replace").replace("\n", "↵").replace("\r", "")
                lines.append(f"  │ [RAW]  {text[:80]}")
            except Exception:
                lines.append(f"  │ [RAW]  {raw_data.hex()[:80]}")

        lines.append("  └" + "─" * 60)

        cprint("\n".join(lines), Colors.GRAY)

        # İnceleme sonrası ilet
        ok = self._forward_packet(pkt)
        self.stats.record(forwarded=ok, size=len(pkt))

        # Opsiyonel harici callback
        if self._inspect_callback:
            self._inspect_callback(pkt)

    # ── Paket Dağıtıcı ────────────────────────────────────────────────────────

    def _packet_handler(self, pkt):
        """
        Her yakalanan paket için çağrılan merkezi işleyici.
        Aktif moda göre doğru işleme fonksiyonuna yönlendirir.
        """
        if self._stop_event.is_set():
            return

        dispatch = {
            FlowMode.FORWARD:  self._process_forward,
            FlowMode.DROP:     self._process_drop,
            FlowMode.THROTTLE: self._process_throttle,
            FlowMode.INSPECT:  self._process_inspect,
        }

        handler_fn = dispatch.get(self.mode)
        if handler_fn:
            try:
                handler_fn(pkt)
            except Exception as e:
                cprint(f"  [!] Paket işleme hatası: {e}", Colors.YELLOW)

    # ── Başlat / Durdur ───────────────────────────────────────────────────────

    def start(
        self,
        mode: FlowMode = FlowMode.FORWARD,
        bpf_filter: Optional[str] = None,
        throttle_kbps: float = 512.0,
        inspect_callback: Optional[Callable] = None
    ) -> bool:
        """
        Paket akış kontrolünü başlatır.

        Args:
            mode:             Başlangıç FlowMode.
            bpf_filter:       BPF (Berkeley Packet Filter) filtre ifadesi.
                              Örn: "tcp", "udp port 53", "host 192.168.1.5"
            throttle_kbps:    THROTTLE modunda kbps sınırı.
            inspect_callback: INSPECT modunda ek işlem yapacak fonksiyon.

        Returns:
            bool: Başarılı ise True.

        Raises:
            ImportError: Scapy yüklü değilse.
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy yüklü değil. → pip install scapy")

        if self.active:
            cprint("  [!] Akış kontrolü zaten çalışıyor!", Colors.YELLOW)
            return False

        self.mode = mode
        self.throttle_kbps = throttle_kbps
        self._filter = bpf_filter
        self._inspect_callback = inspect_callback
        self.stats = FlowStats()    # İstatistikleri sıfırla
        self._stop_event.clear()

        cprint(f"\n  [+] Paket Akış Kontrolü başlatılıyor...", Colors.GREEN, bold=True)
        cprint(f"  [*] Mod    : {mode.value.upper()}", Colors.WHITE)
        cprint(f"  [*] Arayüz: {self.iface}", Colors.WHITE)
        if bpf_filter:
            cprint(f"  [*] BPF Filtresi: {bpf_filter}", Colors.WHITE)
        separator()

        def _sniff_target():
            """sniff() blocking çağrısı ayrı thread'de çalışır."""
            try:
                sniff(
                    iface=self.iface,
                    prn=self._packet_handler,
                    filter=self._filter,
                    store=False,                         # Belleğe kaydetme
                    stop_filter=lambda _: self._stop_event.is_set()
                )
            except PermissionError:
                cprint("\n  [✗] Root yetkisi gerekli! → sudo python3 main.py", Colors.RED, bold=True)
            except OSError as e:
                cprint(f"\n  [✗] Arayüz hatası: {e}", Colors.RED, bold=True)

        self._sniff_thread = threading.Thread(
            target=_sniff_target,
            name="PacketSniffer-Thread",
            daemon=True
        )
        self._sniff_thread.start()
        self.active = True

        cprint(f"  [✓] Akış kontrolü AKTİF (mod={mode.value.upper()})", Colors.GREEN, bold=True)
        return True

    def stop(self) -> FlowStats:
        """
        Akış kontrolünü durdurur ve istatistikleri döndürür.

        Returns:
            FlowStats: Toplanan istatistikler.
        """
        if not self.active:
            cprint("  [!] Aktif akış kontrolü bulunamadı.", Colors.YELLOW)
            return self.stats

        cprint("\n  [*] Akış kontrolü durduruluyor...", Colors.YELLOW)
        self._stop_event.set()

        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=5)

        self.active = False
        self.stats.display()
        cprint("  [✓] Akış kontrolü durduruldu.", Colors.GREEN)
        return self.stats

    # ── Canlı Gösterge ────────────────────────────────────────────────────────

    def live_status(self, refresh_sec: float = 3.0):
        """
        Akış kontrolü çalışırken interaktif canlı istatistik döngüsü.
        'q' + Enter ile çıkılır.

        Args:
            refresh_sec: İstatistik yenileme aralığı (saniye).
        """
        if not self.active:
            cprint("  [!] Önce akış kontrolünü başlatın.", Colors.YELLOW)
            return

        cprint("\n  [Canlı İzleme] Çıkmak için Enter'a basın...\n", Colors.CYAN)
        try:
            while self.active:
                self.stats.display()
                cprint(f"  Mod: {self.mode.value.upper()}  │  "
                       f"Yakalanan: {self.stats.total_captured}  │  "
                       f"İletilen: {self.stats.total_forwarded}  │  "
                       f"Düşürülen: {self.stats.total_dropped}", Colors.WHITE)
                time.sleep(refresh_sec)
        except KeyboardInterrupt:
            pass

    # ── BPF Filtre Yardımcısı ─────────────────────────────────────────────────

    @staticmethod
    def build_bpf_filter(
        target_ip: Optional[str] = None,
        protocol:  Optional[str] = None,
        port:      Optional[int] = None
    ) -> str:
        """
        BPF filtre ifadesi oluşturmak için kolaylık metodu.

        Args:
            target_ip: Yalnızca bu IP'nin trafiğini filtrele.
            protocol:  "tcp", "udp", "icmp" vb.
            port:      Port numarası (yalnızca tcp/udp için anlamlı).

        Returns:
            str: BPF filtre ifadesi.

        Örnekler:
            build_bpf_filter("192.168.1.5", "tcp", 80)   → "host 192.168.1.5 and tcp port 80"
            build_bpf_filter(protocol="dns")              → "udp port 53"
            build_bpf_filter("10.0.0.1")                  → "host 10.0.0.1"

        Eğitim Notu:
            BPF, ağ arayüz sürücüsü seviyesinde paket filtrelemeyi sağlar.
            Kernel'da çalışır → kullanıcı alanına yalnızca eşleşen paketler gelir.
            Bu, performansı önemli ölçüde artırır.
        """
        parts = []

        if target_ip:
            parts.append(f"host {target_ip}")

        # Özel protokol kısayolları
        if protocol == "dns":
            parts.append("udp port 53")
        elif protocol == "http":
            parts.append("tcp port 80")
        elif protocol == "https":
            parts.append("tcp port 443")
        elif protocol and port:
            parts.append(f"{protocol} port {port}")
        elif protocol:
            parts.append(protocol)
        elif port:
            parts.append(f"port {port}")

        bpf = " and ".join(parts) if parts else ""
        return bpf

    # ── İnteraktif Menü ──────────────────────────────────────────────────────

    def interactive_flow_control(self):
        """
        Kullanıcıdan mod ve parametreleri alarak akış kontrolü başlatır.
        """
        cprint("\n  ┌─ PACKET FLOW CONTROL MODÜLÜ ──────────────────────────┐", Colors.YELLOW, bold=True)
        cprint("  │  Yönlendirilen trafiğin akışını kontrol eder          │", Colors.YELLOW)
        cprint("  └────────────────────────────────────────────────────────┘\n", Colors.YELLOW)

        # Mod seçimi
        cprint("  Akış Modları:", Colors.CYAN)
        cprint("    [1] FORWARD  - Tüm trafiği şeffaf ilet", Colors.WHITE)
        cprint("    [2] DROP     - Tüm trafiği düşür (bağlantıyı kes)", Colors.WHITE)
        cprint("    [3] THROTTLE - Bant genişliği sınırlı iletim", Colors.WHITE)
        cprint("    [4] INSPECT  - Paketleri analiz et ve ilet\n", Colors.WHITE)

        cprint("  Mod seçin [1-4]: ", Colors.WHITE, end="")
        choice = input().strip()

        mode_map = {
            "1": FlowMode.FORWARD,
            "2": FlowMode.DROP,
            "3": FlowMode.THROTTLE,
            "4": FlowMode.INSPECT,
        }
        mode = mode_map.get(choice, FlowMode.FORWARD)

        # THROTTLE kbps
        throttle_kbps = 512.0
        if mode == FlowMode.THROTTLE:
            cprint("  Bant genişliği sınırı kbps [512]: ", Colors.WHITE, end="")
            raw = input().strip()
            try:
                throttle_kbps = float(raw) if raw else 512.0
            except ValueError:
                throttle_kbps = 512.0

        # BPF filtresi
        cprint("  BPF filtresi (boş bırakın = tüm trafik): ", Colors.WHITE, end="")
        bpf = input().strip() or None

        # Hedef IP filtresi (kısayol)
        if not bpf:
            cprint("  Belirli bir IP'yi filtrele (boş = tümü): ", Colors.WHITE, end="")
            ip = input().strip()
            if ip:
                bpf = self.build_bpf_filter(target_ip=ip)
                cprint(f"  [*] BPF oluşturuldu: {bpf}", Colors.GRAY)

        try:
            self.start(mode=mode, bpf_filter=bpf, throttle_kbps=throttle_kbps)
        except (ImportError, PermissionError, OSError) as e:
            cprint(f"\n  [✗] HATA: {e}", Colors.RED, bold=True)
