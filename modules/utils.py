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


def guess_network_range() -> str:
    """
    Yerel IP'ye göre /24 ağ aralığını tahmin eder.

    Returns:
        str: Örn. "192.168.1.0/24"
    """
    local_ip = get_local_ip()
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
