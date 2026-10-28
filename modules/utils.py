"""
AntiGravity - Utility Functions
================================
Ortak yardımcı fonksiyonlar: renk çıktısı, yetki kontrolü, logo.
"""

import os
import sys
import socket
import platform
import logging
import ipaddress
from datetime import datetime
from typing import Optional


# ─── ANSI Renk Kodları ────────────────────────────────────────────────────────

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_BLUE   = "\033[44m"
    BG_YELLOW = "\033[43m"





def cprint(text: str, color: str = Colors.WHITE, bold: bool = False, end: str = "\n"):
    """Renkli terminal çıktısı."""
    prefix = Colors.BOLD if bold else ""
    print(f"{prefix}{color}{text}{Colors.RESET}", end=end)


def print_banner():
    """AntiGravity ASCII banner'ını yazdırır."""
    banner = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    █████╗ ███╗   ██╗████████╗██╗ ██████╗ ██████╗  █████╗   ║
    ║   ██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝ ██╔══██╗██╔══██╗  ║
    ║   ███████║██╔██╗ ██║   ██║   ██║██║  ███╗██████╔╝███████║  ║
    ║   ██╔══██║██║╚██╗██║   ██║   ██║██║   ██║██╔══██╗██╔══██║  ║
    ║   ██║  ██║██║ ╚████║   ██║   ██║╚██████╔╝██║  ██║██║  ██║  ║
    ║   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ║
    ║                                                              ║
    ║        Network Traffic Management & Topology Analysis        ║
    ║              ★  E Ğ İ T İ M   M O D Ü L Ü  ★               ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    cprint(banner, Colors.CYAN, bold=True)
    cprint(f"    [!] Bu araç YALNIZCA izole test ortamlarında kullanılmalıdır.",
           Colors.YELLOW, bold=True)
    cprint(f"    [!] İzinsiz kullanım yasaldışıdır.\n", Colors.RED)


def check_root() -> bool:
    """
    Root/Administrator yetkisi kontrolü yapar.

    Returns:
        bool: Yeterli yetki varsa True, yoksa False.

    Raises:
        PermissionError: Root yetkisi yoksa uyarı verir.
    """
    system = platform.system()
    try:
        if system == "Windows":
            import ctypes
            has_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            has_admin = (os.geteuid() == 0)

        if not has_admin:
            cprint("\n  [✗] HATA: Bu modül root/administrator yetkisi gerektirir!", Colors.RED, bold=True)
            cprint("  [!] Lütfen şu şekilde çalıştırın:", Colors.YELLOW)
            if system == "Windows":
                cprint("      → PowerShell/CMD uygulamasını 'Yönetici olarak çalıştır' ile açın.", Colors.WHITE)
            else:
                cprint("      → sudo python3 main.py", Colors.WHITE)
            return False
        return True
    except AttributeError:
        # Windows olmayan sistemlerde ctypes.windll yoktur
        return (os.geteuid() == 0)


def check_scapy() -> bool:
    """
    Scapy kütüphanesinin yüklü olup olmadığını kontrol eder.

    Returns:
        bool: Scapy yüklüyse True, değilse False.
    """
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        cprint("\n  [✗] HATA: Scapy kütüphanesi bulunamadı!", Colors.RED, bold=True)
        cprint("  [!] Yüklemek için:", Colors.YELLOW)
        cprint("      pip install scapy", Colors.WHITE)
        cprint("      veya: pip3 install scapy\n", Colors.WHITE)
        return False


def validate_ip(ip: str) -> bool:
    """
    Verilen IP adresinin geçerli bir IPv4 adresi olup olmadığını kontrol eder.

    Args:
        ip: Kontrol edilecek IP adresi string'i.

    Returns:
        bool: Geçerliyse True.
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ipv6(ip: str) -> bool:
    """
    Verilen IP adresinin geçerli bir IPv6 adresi olup olmadığını kontrol eder.

    Args:
        ip: Kontrol edilecek IPv6 adresi string'i.

    Returns:
        bool: Geçerliyse True.
    """
    try:
        ipaddress.IPv6Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_mac(mac: str) -> bool:
    """
    Verilen string'in geçerli bir MAC adresi formatında olup olmadığını kontrol eder.

    Args:
        mac: "aa:bb:cc:dd:ee:ff" formatında kontrol edilecek MAC adresi.

    Returns:
        bool: Geçerliyse True.
    """
    import re
    return bool(re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac))


def validate_network(network: str) -> bool:
    """
    Verilen string'in geçerli bir CIDR ağ adresi olup olmadığını kontrol eder.

    Args:
        network: Örn. "192.168.1.0/24"

    Returns:
        bool: Geçerliyse True.
    """
    try:
        ipaddress.IPv4Network(network, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def get_local_ip() -> str:
    """
    Makinenin yerel ağ IP adresini döndürür.

    Returns:
        str: Yerel IP adresi veya '127.0.0.1'.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _detect_prefix_length(local_ip: str) -> int:
    """
    İşletim sisteminden gerçek subnet prefix uzunluğunu algılar.

    Önce ifconfig (macOS/BSD), sonra ip addr (Linux) çıktısını parse eder.
    Başarısız olursa /24 varsayılanına döner.

    Args:
        local_ip: Yerel IP adresi (doğru arayüzü bulmak için).

    Returns:
        int: Prefix uzunluğu (örn. 22, 24).
    """
    import subprocess
    import re

    # ── macOS / BSD: ifconfig ──────────────────────────────────────────
    try:
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # ifconfig çıktısında IP'mizi bulup aynı satırdaki netmask'i al
            for line in result.stdout.splitlines():
                if local_ip in line:
                    # macOS formatı: "inet 192.168.1.5 netmask 0xffffff00 ..."
                    hex_match = re.search(r'netmask\s+(0x[0-9a-fA-F]+)', line)
                    if hex_match:
                        mask_int = int(hex_match.group(1), 16)
                        return bin(mask_int).count('1')
                    # Linux formatı: "inet 192.168.1.5 netmask 255.255.255.0 ..."
                    dot_match = re.search(r'netmask\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if dot_match:
                        octets = dot_match.group(1).split('.')
                        mask_int = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(octets))
                        return bin(mask_int).count('1')
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # ── Linux: ip addr ─────────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if local_ip in line:
                    # Formatı: "2: eth0  inet 192.168.1.5/24 ..."
                    cidr_match = re.search(rf'{re.escape(local_ip)}/(\d+)', line)
                    if cidr_match:
                        return int(cidr_match.group(1))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # ── Fallback ───────────────────────────────────────────────────────
    return 24


def guess_network_range() -> str:
    """
    Yerel IP ve gerçek subnet maskesine göre ağ aralığını tespit eder.

    İşletim sisteminden gerçek prefix uzunluğunu okuyarak doğru CIDR
    aralığını döndürür. Algılama başarısız olursa /24'e düşer.

    Returns:
        str: Örn. "139.179.232.0/22" veya "192.168.1.0/24"
    """
    local_ip = get_local_ip()
    prefix = _detect_prefix_length(local_ip)
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
        return str(network)
    except (ipaddress.AddressValueError, ValueError):
        # Son çare: eski /24 davranışı
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def timestamp() -> str:
    """Anlık zaman damgası string'i döndürür."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def separator(char: str = "─", width: int = 66, color: str = Colors.GRAY):
    """Terminal ayırıcı çizgi yazdırır."""
    cprint(f"  {char * width}", color)


def print_table(headers: list, rows: list, colors: list = None):
    """
    Basit, hizalanmış bir tablo yazdırır.

    Args:
        headers: Sütun başlıkları listesi.
        rows:    Her biri bir satır olan liste listesi.
        colors:  Her satır için opsiyonel renk listesi.
    """
    if not rows:
        cprint("  [!] Gösterilecek veri yok.", Colors.YELLOW)
        return

    # Sütun genişliklerini hesapla
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    # Üst çizgi
    top = "  ┌" + "┬".join("─" * (w + 2) for w in col_widths) + "┐"
    cprint(top, Colors.GRAY)

    # Başlık satırı
    header_row = "  │" + "│".join(
        f" {Colors.BOLD}{Colors.CYAN}{h.center(w)}{Colors.RESET} "
        for h, w in zip(headers, col_widths)
    ) + "│"
    print(header_row)

    # Başlık ayırıcı
    mid = "  ├" + "┼".join("─" * (w + 2) for w in col_widths) + "┤"
    cprint(mid, Colors.GRAY)

    # Veri satırları
    for idx, row in enumerate(rows):
        row_color = (colors[idx] if colors and idx < len(colors) else Colors.WHITE)
        cells = "  │" + "│".join(
            f" {row_color}{str(cell).ljust(w)}{Colors.RESET} "
            for cell, w in zip(row, col_widths)
        ) + "│"
        print(cells)

    # Alt çizgi
    bottom = "  └" + "┴".join("─" * (w + 2) for w in col_widths) + "┘"
    cprint(bottom, Colors.GRAY)


# ─── IPv6 Yardımcıları ────────────────────────────────────────────────────────

def strip_zone(ipv6: str) -> str:
    """
    IPv6 adresinden '%iface' zone ID'yi temizler.
    Örn: 'fe80::1%en0' → 'fe80::1'
    Scapy ve socket kütüphaneleri zone ID'yi kabul etmez.

    Args:
        ipv6: Temizlenecek IPv6 adresi string'i.

    Returns:
        str: Zone ID olmadan IPv6 adresi.
    """
    if ipv6 and '%' in ipv6:
        return ipv6.split('%')[0]
    return ipv6 or ""


# ─── Cross-Platform Ağ ve Sistem Yardımcıları ─────────────────────────────────

def get_default_iface_name() -> str:
    """Sistem varsayılan ağ arayüzü adını döndürür (Cross-Platform)."""
    try:
        from scapy.all import conf as scapy_conf
        iface = str(scapy_conf.iface)
        if iface:
            return iface
    except Exception:
        pass

    import subprocess
    import re
    sys_name = platform.system()
    if sys_name == "Linux":
        try:
            r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
            m = re.search(r"dev\s+([^\s]+)", r.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "eth0"
    elif sys_name == "Darwin":
        return "en0"
    return "eth0"


def get_default_gateway_v4() -> tuple[Optional[str], Optional[str]]:
    """Varsayılan IPv4 gateway IP ve MAC adresini döndürür (Cross-Platform)."""
    import subprocess
    import re
    sys_name = platform.system()
    gw_ip = None

    if sys_name == "Darwin":
        try:
            r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                if "gateway:" in line:
                    gw_ip = line.split(":")[1].strip()
                    break
        except Exception:
            pass
        if not gw_ip:
            try:
                r2 = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True, timeout=3)
                for line in r2.stdout.splitlines():
                    if line.startswith("default"):
                        gw_ip = line.split()[1]
                        break
            except Exception:
                pass
    elif sys_name == "Linux":
        try:
            r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
            m = re.search(r"default\s+via\s+([0-9.]+)", r.stdout)
            if m:
                gw_ip = m.group(1)
        except Exception:
            pass
        if not gw_ip:
            try:
                r2 = subprocess.run(["route", "-n"], capture_output=True, text=True, timeout=3)
                for line in r2.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "default") and parts[1] != "0.0.0.0":
                        gw_ip = parts[1]
                        break
            except Exception:
                pass

    return gw_ip or "192.168.1.1", None


def get_default_gateway_v6() -> tuple[Optional[str], Optional[str]]:
    """Varsayılan IPv6 gateway IP'sini döndürür (Cross-Platform)."""
    import subprocess
    import re
    sys_name = platform.system()
    if sys_name == "Darwin":
        try:
            r = subprocess.run(["netstat", "-rn", "-f", "inet6"], capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                if line.strip().startswith("default"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return strip_zone(parts[1]), None
        except Exception:
            pass
    elif sys_name == "Linux":
        try:
            r = subprocess.run(["ip", "-6", "route", "show", "default"], capture_output=True, text=True, timeout=3)
            m = re.search(r"default\s+via\s+([a-fA-F0-9:]+)", r.stdout)
            if m:
                return strip_zone(m.group(1)), None
        except Exception:
            pass

    return "fe80::1", None


def get_neighbor_cache_entries() -> list[str]:
    """Sistem IPv6/IPv4 neighbor/ARP önbellek çıktı satırlarını döndürür (Cross-Platform)."""
    import subprocess
    sys_name = platform.system()
    if sys_name == "Darwin":
        try:
            r = subprocess.run(["ndp", "-n", "-a"], capture_output=True, text=True, timeout=5)
            return [l for l in r.stdout.splitlines() if l.strip()]
        except Exception:
            pass
    elif sys_name == "Linux":
        try:
            r = subprocess.run(["ip", "-6", "neigh", "show"], capture_output=True, text=True, timeout=5)
            lines = [l for l in r.stdout.splitlines() if l.strip()]
            if not lines:
                r2 = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
                lines = [l for l in r2.stdout.splitlines() if l.strip()]
            return lines
        except Exception:
            pass

    return []


def set_ip_forwarding(enable: bool, ipv6: bool = True) -> bool:
    """
    İşletim sisteminde IPv4 ve opsiyonel IPv6 paket iletimini (forwarding)
    etkinleştirir veya devre dışı bırakır (Cross-Platform: Linux & macOS).
    """
    import subprocess
    sys_name = platform.system()
    val = "1" if enable else "0"
    success = True

    if sys_name == "Linux":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(val)
        except Exception:
            try:
                subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"], capture_output=True, timeout=3)
            except Exception:
                success = False

        if ipv6:
            try:
                with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as f:
                    f.write(val)
            except Exception:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv6.conf.all.forwarding={val}"], capture_output=True, timeout=3)
                except Exception:
                    pass
    elif sys_name == "Darwin":
        try:
            subprocess.run(["sysctl", "-w", f"net.inet.ip.forwarding={val}"], capture_output=True, timeout=3)
            if ipv6:
                subprocess.run(["sysctl", "-w", f"net.inet6.ip6.forwarding={val}"], capture_output=True, timeout=3)
        except Exception:
            success = False

    return success


# ─── Logging Altyapısı ────────────────────────────────────────────────────────

def setup_logging(level: str = "INFO", log_file: str = "") -> logging.Logger:
    """
    Proje genelinde kullanılacak logging altyapısını kurar.

    Args:
        level:    Log seviyesi (DEBUG, INFO, WARNING, ERROR).
        log_file: Log dosyası yolu. Boşsa sadece console'a yazar.

    Returns:
        logging.Logger: Kök logger.
    """
    root = logging.getLogger("antigravity")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler
    if not root.handlers:
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S"
        )
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        root.addHandler(ch)

        # Dosya handler (opsiyonel)
        if log_file:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)

    return root
