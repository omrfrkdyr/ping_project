"""
AntiGravity — Merkezi Konfigürasyon
=====================================
Projede dağınık olan tüm sabit değerleri toplar.
Ortam değişkenleri ile geçersiz kılınabilir.

Kullanım:
    from config import cfg
    cfg.WEB_PORT        # → 8080
    cfg.PACKET_INTERVAL # → 1.5
"""

import os
import logging


def _env_float(key: str, default: float) -> float:
    """Ortam değişkeninden float okur; yoksa default döner."""
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_int(key: str, default: int) -> int:
    """Ortam değişkeninden int okur; yoksa default döner."""
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


# ─── Konfigürasyon Sınıfı ─────────────────────────────────────────────────────

class _Config:
    """Proje genelinde kullanılan sabitler."""

    # ── Ağ Sabitleri ────────────────────────────────────────────────────
    PACKET_INTERVAL: float = _env_float("AG_PACKET_INTERVAL", 1.5)
    """Sahte ARP/NA paketi gönderme aralığı (saniye)."""

    RESTORE_COUNT: int = _env_int("AG_RESTORE_COUNT", 5)
    """Onarma sırasında gönderilecek gerçek ARP paketi sayısı."""

    NDP_INTERVAL: float = _env_float("AG_NDP_INTERVAL", 1.5)
    """Sahte NA gönderme aralığı (saniye)."""

    NDP_RESTORE_CNT: int = _env_int("AG_NDP_RESTORE_CNT", 5)
    """Onarma sırasında gönderilecek gerçek NA sayısı."""

    DEFAULT_SCAN_TIMEOUT: float = _env_float("AG_SCAN_TIMEOUT", 2.0)
    """ARP tarama zaman aşımı (saniye)."""

    # ── DNS Monitor ─────────────────────────────────────────────────────
    MAX_HISTORY: int = _env_int("AG_MAX_HISTORY", 300)
    """DNS monitor hafızasında tutulacak maksimum domain sayısı."""

    DOMAIN_DEDUP_SECONDS: int = _env_int("AG_DOMAIN_DEDUP", 60)
    """Aynı domain'in tekrar görünmeden önce bekleme süresi (saniye)."""

    # ── Web Sunucu ──────────────────────────────────────────────────────
    WEB_HOST: str = _env_str("AG_WEB_HOST", "127.0.0.1")
    """Flask dinleme adresi. Güvenlik: varsayılan sadece localhost."""

    WEB_PORT: int = _env_int("AG_WEB_PORT", 8080)
    """Flask dinleme portu."""

    # ── Logging ─────────────────────────────────────────────────────────
    LOG_LEVEL: str = _env_str("AG_LOG_LEVEL", "INFO").upper()
    """Python logging seviyesi: DEBUG, INFO, WARNING, ERROR."""

    LOG_FILE: str = _env_str("AG_LOG_FILE", "")
    """Log dosyası yolu. Boşsa sadece console'a yazar."""

    # ── IPv6 Multicast Sabitleri ────────────────────────────────────────
    IPV6_ALL_NODES: str = "ff02::1"
    IPV6_ALL_ROUTERS: str = "ff02::2"
    ETH_IPV6_MCAST: str = "33:33:00:00:00:01"

    # ── Pasif Sniffer ───────────────────────────────────────────────────
    NAME_POLL_DURATION_MS: int = _env_int("AG_NAME_POLL_MS", 180000)
    """İsim polling süresi (ms)."""

    NAME_POLL_INTERVAL_MS: int = _env_int("AG_NAME_POLL_INTERVAL", 2000)
    """İsim polling aralığı (ms)."""


cfg = _Config()
