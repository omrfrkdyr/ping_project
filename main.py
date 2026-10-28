"""
AntiGravity - Ana Giriş Noktası
================================
Ağ Trafiği Yönetimi ve Topoloji Analizi Eğitim Modülü

Kullanım:
    sudo python3 main.py

Modüller:
  1. Node Discovery      → ARP tabanlı host keşfi
  2. Traffic Redirection → Çift taraflı ARP güncelleme (yönlendirme)
  3. Packet Flow Control → Trafik akış kontrolü (drop/throttle/inspect)

⚠️  YASAL UYARI:
    Bu araç yalnızca kendi kontrolündeki, izole test ortamlarında
    eğitim amaçlı kullanım için tasarlanmıştır.
    İzinsiz ağlarda kullanmak yasaldışıdır.

Gereksinimler:
    pip install scapy
    sudo python3 main.py  (root/Administrator yetkisi)
"""

import sys
import os
import signal
import atexit

# ─── Bağımlılık Ön Kontrolleri ────────────────────────────────────────────────
# Modülleri yüklemeden önce gerekli kütüphaneleri kontrol et

def _preflight_checks() -> bool:
    """Ön kontroller: Python sürümü, Scapy, yetki."""
    # Python >= 3.8 kontrolü
    if sys.version_info < (3, 8):
        print("[✗] Python 3.8 veya üzeri gereklidir.")
        print(f"    Mevcut sürüm: {sys.version}")
        return False

    # Scapy kontrolü
    try:
        import scapy  # noqa: F401
    except ImportError:
        print("[✗] Scapy kütüphanesi bulunamadı!")
        print("    Yüklemek için: pip install scapy")
        return False

    return True


if not _preflight_checks():
    sys.exit(1)


# ─── Proje Modülleri ──────────────────────────────────────────────────────────

from modules.utils import (
    cprint, Colors, separator, print_banner,
    check_root, timestamp, get_local_ip, validate_ip,
    get_default_iface_name, get_default_gateway_v4, get_default_gateway_v6
)
from modules.node_discovery     import NodeDiscovery
from modules.traffic_redirection import TrafficRedirector
from modules.packet_flow_control import PacketFlowController, FlowMode
from modules.ipv6_ndp import (
    IPv6Discovery, NDPSpoofer, mac_helper_menu,
    mac_to_ipv6_link_local, get_local_ipv6
)
from modules.dns_monitor import DnsMonitor


def _get_default_iface() -> str:
    """Sistem varsayılan ağ arayüzünü döndürür."""
    return get_default_iface_name()


# ─── Global Durum ─────────────────────────────────────────────────────────────

discovered_hosts    = {}   # {ip: HostEntry} en son ARP tarama sonuçları
discovered_v6_hosts = {}   # {ipv6: dict}   en son IPv6 tarama sonuçları
redirector  = None      # TrafficRedirector örneği (global, temizlik için)
flow_ctrl   = None      # PacketFlowController örneği
ndp_spoofer = None      # NDPSpoofer örneği (IPv6)


# ─── Temizlik (atexit / signal) ───────────────────────────────────────────────

def _cleanup_on_exit():
    """
    Program kapanırken ARP tablolarını ve IP Forwarding'i temizler.
    atexit kaydı ile Python normal çıkışlarda otomatik tetikler.
    """
    global redirector, flow_ctrl

    print()  # Temiz satır

    if flow_ctrl and flow_ctrl.active:
        cprint("  [*] Akış kontrolü kapatılıyor...", Colors.YELLOW)
        flow_ctrl.stop()

    if redirector and redirector.active:
        cprint("  [!] ARP tabloları onarılıyor (temizlik)...", Colors.YELLOW)
        redirector.stop(restore=True)

    if ndp_spoofer and ndp_spoofer.active:
        cprint("  [!] IPv6 Neighbor Cache onarılıyor (temizlik)...", Colors.YELLOW)
        ndp_spoofer.stop(restore=True)

    cprint("  [✓] AntiGravity kapatıldı. Güvenli çıkış.", Colors.GREEN)


atexit.register(_cleanup_on_exit)


def _signal_handler(sig, frame):
    """Ctrl+C yakalandığında düzenli çıkış yapar."""
    cprint(f"\n\n  [!] Ctrl+C algılandı. Çıkış yapılıyor...", Colors.YELLOW, bold=True)
    sys.exit(0)   # atexit tetiklenir


signal.signal(signal.SIGINT,  _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ─── Menü Yardımcıları ────────────────────────────────────────────────────────

def _print_main_menu():
    """Ana menüyü terminale yazdırır."""
    cprint("\n  ╔══════════════════════════════════════════════╗", Colors.CYAN)
    cprint("  ║           ANA MENÜ                           ║", Colors.CYAN, bold=True)
    cprint("  ╠══════════════════════════════════════════════╣", Colors.CYAN)
    cprint("  ║  [1]  Node Discovery      (ARP Keşfi)       ║", Colors.WHITE)
    cprint("  ║  [2]  Traffic Redirection (ARP Yönl.)       ║", Colors.WHITE)
    cprint("  ║  [3]  Packet Flow Control (Akış Kontrolü)   ║", Colors.WHITE)
    cprint("  ╠══════════════════════════════════════════════╣", Colors.CYAN)
    cprint("  ║  [4]  Sistem Durumu                          ║", Colors.WHITE)
    cprint("  ║  [5]  Yönlendirmeyi Durdur + ARP Onar       ║", Colors.YELLOW)
    cprint("  ║  [6]  Akış Kontrolünü Durdur                 ║", Colors.YELLOW)
    cprint("  ╠══════════════════════════════════════════════╣", Colors.CYAN)
    cprint("  ║  ── IPv6 & İleri İzolasyon ──                ║", Colors.MAGENTA, bold=True)
    cprint("  ║  [7]  IPv6 Node Discovery  (ICMPv6 Keşfi)  ║", Colors.MAGENTA)
    cprint("  ║  [8]  IPv6 NDP Spoofing    (NA Zehirleme)  ║", Colors.MAGENTA)
    cprint("  ║  [9]  IPv6 Durdur + Cache Onar             ║", Colors.YELLOW)
    cprint("  ║  [W]  DNS / Website Monitor (Canlı İzleme)  ║", Colors.GREEN)
    cprint("  ║  [I]  Tam İzolasyon Modu   (ARP + NDP)      ║", Colors.RED)
    cprint("  ║  [M]  MAC / IPv6 Yardımcı Araçlar          ║", Colors.CYAN)
    cprint("  ╠══════════════════════════════════════════════╣", Colors.CYAN)
    cprint("  ║  [0]  Çıkış                                  ║", Colors.RED)
    cprint("  ╚══════════════════════════════════════════════╝", Colors.CYAN)

    local_v6 = get_local_ipv6(_get_default_iface()) or 'N/A'
    cprint(f"\n  [{timestamp()}]  IPv4: {get_local_ip()}  │  IPv6: {local_v6}", Colors.GRAY)


def _print_system_status():
    """Tüm modüllerin mevcut durumunu gösterir."""
    cprint("\n  ═══  SİSTEM DURUMU  ═══════════════════════════════", Colors.CYAN, bold=True)

    cprint(f"  Yerel IPv4    : {get_local_ip()}", Colors.WHITE)
    local_v6 = get_local_ipv6(_get_default_iface()) or 'N/A'
    cprint(f"  Yerel IPv6    : {local_v6}", Colors.WHITE)
    cprint(f"  Python        : {sys.version.split()[0]}", Colors.WHITE)

    try:
        import scapy
        cprint(f"  Scapy         : {scapy.__version__}", Colors.WHITE)
    except Exception:
        cprint("  Scapy         : yüklü değil", Colors.RED)

    separator()

    cprint(f"  [ARP] Keşfedilen Host: {len(discovered_hosts)}", Colors.CYAN)
    if discovered_hosts:
        for ip, entry in list(discovered_hosts.items())[:5]:
            cprint(f"    {ip}  →  {entry.mac}", Colors.GRAY)
        if len(discovered_hosts) > 5:
            cprint(f"    ... ve {len(discovered_hosts)-5} host daha", Colors.GRAY)

    cprint(f"  [IPv6] Keşfedilen Host: {len(discovered_v6_hosts)}", Colors.MAGENTA)
    if discovered_v6_hosts:
        for ipv6, info in list(discovered_v6_hosts.items())[:3]:
            cprint(f"    {ipv6[:38]}  →  {info['mac']}", Colors.GRAY)
        if len(discovered_v6_hosts) > 3:
            cprint(f"    ... ve {len(discovered_v6_hosts)-3} host daha", Colors.GRAY)

    separator()

    if redirector:
        redirector.status()
    else:
        cprint("  [ARP Redirection] Henüz başlatılmadı.", Colors.GRAY)

    if ndp_spoofer:
        ndp_spoofer.status()
    else:
        cprint("  [NDP Spoofing] Henüz başlatılmadı.", Colors.GRAY)

    if flow_ctrl and flow_ctrl.active:
        cprint(f"  [Flow Control] AKTİF  Mod: {flow_ctrl.mode.value.upper()}", Colors.GREEN)
        flow_ctrl.stats.display()
    else:
        cprint("  [Flow Control] Devre dışı.", Colors.GRAY)

    separator()


# ─── Menü Aksiyonları ─────────────────────────────────────────────────────────

def _action_node_discovery():
    """Menü [1]: Node Discovery modülünü çalıştırır."""
    global discovered_hosts
    nd = NodeDiscovery()
    discovered_hosts = nd.interactive_scan()


def _action_traffic_redirection():
    """Menü [2]: Traffic Redirection modülünü başlatır."""
    global redirector
    if redirector and redirector.active:
        cprint("\n  [!] Yönlendirme zaten aktif.", Colors.YELLOW)
        cprint("  [!] Önce menü [5] ile durdurun.", Colors.YELLOW)
        return
    redirector = TrafficRedirector()
    redirector.interactive_redirect(known_hosts=discovered_hosts)


def _action_flow_control():
    """Menü [3]: Packet Flow Control modülünü başlatır."""
    global flow_ctrl
    if flow_ctrl and flow_ctrl.active:
        cprint("\n  [!] Akış kontrolü zaten aktif.", Colors.YELLOW)
        cprint("  [!] Önce menü [6] ile durdurun.", Colors.YELLOW)
        return
    flow_ctrl = PacketFlowController()
    flow_ctrl.interactive_flow_control()

    if flow_ctrl.active:
        cprint("\n  [*] Canlı istatistik izleme başlatılıyor...", Colors.CYAN)
        cprint("  [*] Ana menüye dönmek için Ctrl+C basın.", Colors.GRAY)
        try:
            flow_ctrl.live_status()
        except KeyboardInterrupt:
            pass


def _action_stop_redirection():
    """Menü [5]: Yönlendirmeyi durdurur, ARP tablolarını onarır."""
    global redirector
    if not redirector or not redirector.active:
        cprint("\n  [!] Aktif yönlendirme bulunamadı.", Colors.YELLOW)
        return
    total = redirector.stop(restore=True)
    cprint(f"\n  [✓] {total} sahte ARP paketi gönderilmişti.", Colors.GREEN)


def _action_stop_flow_control():
    """Menü [6]: Akış kontrolünü durdurur."""
    global flow_ctrl
    if not flow_ctrl or not flow_ctrl.active:
        cprint("\n  [!] Aktif akış kontrolü bulunamadı.", Colors.YELLOW)
        return
    flow_ctrl.stop()


def _action_ipv6_discovery():
    """Menü [7]: IPv6 ICMPv6 multicast host keşfi."""
    global discovered_v6_hosts
    ipv6disc = IPv6Discovery()
    discovered_v6_hosts = ipv6disc.interactive_scan()


def _action_ndp_spoof():
    """Menü [8]: IPv6 NDP Spoofing başlatır."""
    global ndp_spoofer
    if ndp_spoofer and ndp_spoofer.active:
        cprint("\n  [!] NDP Spoofing zaten aktif!", Colors.YELLOW)
        cprint("  [!] Önce menü [9] ile durdurun.", Colors.YELLOW)
        return
    ndp_spoofer = NDPSpoofer()
    ndp_spoofer.interactive_spoof(known_hosts=discovered_v6_hosts)


def _action_stop_ndp():
    """Menü [9]: NDP Spoofing'i durdurur ve Neighbor Cache onarır."""
    global ndp_spoofer
    if not ndp_spoofer or not ndp_spoofer.active:
        cprint("\n  [!] Aktif NDP Spoofing bulunamadı.", Colors.YELLOW)
        return
    total = ndp_spoofer.stop(restore=True)
    cprint(f"\n  [✓] {total} sahte NA paketi gönderilmişti.", Colors.GREEN)


def _action_dns_monitor():
    """Menü [W]: Gerçek zamanlı DNS ve TLS SNI izleyici."""
    import time
    cprint("\n  ┌─ DNS & TLS SNI WEBSITE MONITOR ────────────────────────┐", Colors.CYAN, bold=True)
    cprint("  │  Hedef cihazın ziyaret ettiği siteleri canlı izler    │", Colors.CYAN)
    cprint("  └────────────────────────────────────────────────────────┘\n", Colors.CYAN)

    if not discovered_hosts:
        cprint("  [!] Önce [1] ile ağ taraması yapmanız önerilir.", Colors.YELLOW)

    cprint("  İzlenecek Hedef IP: ", Colors.WHITE, end="")
    target_ip = input().strip()
    if not validate_ip(target_ip):
        cprint("  [✗] Geçersiz IP adresi!", Colors.RED)
        return

    cprint(f"\n  [*] {target_ip} için DNS/SNI izleyici başlatılıyor...", Colors.CYAN)
    cprint("  [*] Durdurmak ve ana menüye dönmek için Ctrl+C basın.\n", Colors.GRAY)

    def on_domain(entry):
        cprint(f"  [{entry.get('ts')}] ({entry.get('proto')}) {entry.get('domain')}", Colors.GREEN)

    monitor = DnsMonitor(target_ip, on_domain=on_domain)
    monitor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        cprint("\n  [✓] Website izleme durduruldu.", Colors.GREEN)


def _action_full_isolation():
    """Menü [I]: Seçili cihazı hem ARP hem NDP ile izole eder."""
    cprint("\n  ┌─ TAM İZOLASYON MODU (ARP + NDP) ───────────────────────┐", Colors.RED, bold=True)
    cprint("  │  Seçilen cihazın hem IPv4 hem IPv6 erişimini keser     │", Colors.RED)
    cprint("  └────────────────────────────────────────────────────────┘\n", Colors.RED)

    cprint("  İzole Edilecek Hedef IPv4: ", Colors.WHITE, end="")
    target_ip = input().strip()
    if not validate_ip(target_ip):
        cprint("  [✗] Geçersiz IP!", Colors.RED)
        return

    gw_ip, gw_mac = get_default_gateway_v4()
    cprint(f"  Ağ Geçidi IPv4 [{gw_ip}]: ", Colors.WHITE, end="")
    user_gw = input().strip()
    if user_gw:
        gw_ip = user_gw

    global redirector, ndp_spoofer
    target_entry = discovered_hosts.get(target_ip)
    target_mac = target_entry.mac if target_entry else None

    cprint("\n  [*] ARP İzolasyonu başlatılıyor...", Colors.CYAN)
    redirector = TrafficRedirector(iface=_get_default_iface())
    redirector.start(target_ip, gw_ip, target_mac=target_mac, gateway_mac=gw_mac, enable_forwarding=False)

    gw_v6, _ = get_default_gateway_v6()
    cprint("  Hedef IPv6 (Opsiyonel / link-local, boşsa atlar): ", Colors.WHITE, end="")
    target_v6 = input().strip()
    if target_v6:
        ndp_spoofer = NDPSpoofer(iface=_get_default_iface())
        ndp_spoofer.start(target_v6, gw_v6, target_mac=target_mac)

    cprint(f"\n  [✓] {target_ip} izolasyona alındı. İnternet erişimi kesildi.", Colors.GREEN, bold=True)
    cprint("  [*] İzolasyonu kaldırmak için menüden [5] ve [9] kullanın.", Colors.YELLOW)


# ─── Ana Döngü ────────────────────────────────────────────────────────────────

def main():
    """Program giriş noktası."""
    # Banner
    print_banner()

    # Root yetkisi kontrolü
    if not check_root():
        cprint("\n  [!] Root yetkisi olmadan bazı özellikler çalışmayabilir.", Colors.YELLOW)
        cprint("  [!] Devam etmek istiyor musunuz? (y/N): ", Colors.YELLOW, end="")
        yn = input().strip().lower()
        if yn not in ("y", "yes", "evet"):
            cprint("  Çıkılıyor...", Colors.GRAY)
            sys.exit(0)

    # Menü döngüsü
    action_map = {
        "1": _action_node_discovery,
        "2": _action_traffic_redirection,
        "3": _action_flow_control,
        "4": _print_system_status,
        "5": _action_stop_redirection,
        "6": _action_stop_flow_control,
        "7": _action_ipv6_discovery,
        "8": _action_ndp_spoof,
        "9": _action_stop_ndp,
        "w": _action_dns_monitor,
        "W": _action_dns_monitor,
        "i": _action_full_isolation,
        "I": _action_full_isolation,
        "m": mac_helper_menu,
        "M": mac_helper_menu,
    }

    while True:
        _print_main_menu()
        cprint("\n  Seçiminiz: ", Colors.WHITE, bold=True, end="")

        try:
            choice = input().strip()
        except EOFError:
            break

        if choice == "0":
            cprint("\n  AntiGravity kapatılıyor...", Colors.CYAN)
            break
        elif choice in action_map:
            try:
                action_map[choice]()
            except KeyboardInterrupt:
                cprint("\n  [!] İşlem iptal edildi.", Colors.YELLOW)
            except PermissionError as e:
                cprint(f"\n  [✗] YETKİ HATASI: {e}", Colors.RED, bold=True)
                cprint("  [!] Lütfen sudo ile çalıştırın: sudo python3 main.py", Colors.YELLOW)
            except ImportError as e:
                cprint(f"\n  [✗] KÜTÜPHANE HATASI: {e}", Colors.RED, bold=True)
            except Exception as e:
                cprint(f"\n  [✗] HATA: {type(e).__name__}: {e}", Colors.RED, bold=True)
        else:
            cprint("  [!] Geçersiz seçim. 0-9 veya M girin.", Colors.YELLOW)

    # Çıkış (atexit tetiklenir)
    sys.exit(0)


if __name__ == "__main__":
    main()
