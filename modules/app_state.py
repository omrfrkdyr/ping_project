"""
AntiGravity — Thread-Safe Uygulama Durumu
===========================================
Flask web uygulaması için thread-safe global state yöneticisi.
Tüm paylaşılan veriler (devices, isolations, monitors) RLock koruması altındadır.
"""

import json
import time
import queue
import threading
import logging
from typing import Optional
from datetime import datetime

from modules.oui_table import get_vendor

logger = logging.getLogger("antigravity.state")


def _ts() -> str:
    """Kısa zaman damgası."""
    return datetime.now().strftime("%H:%M:%S")


class AppState:
    """
    Flask web uygulaması için thread-safe global state.

    Tüm shared dictionary'ler (devices, isolations, monitors) bir RLock
    ile korunur. Erişim mutlaka accessor metodları üzerinden yapılmalıdır.
    """

    def __init__(self):
        self._lock = threading.RLock()

        # Keşif
        self._devices: dict = {}       # {ip: DeviceInfo dict}
        self.scanning: bool = False
        self.scan_progress: int = 0

        # Aktif izolasyonlar: {ip: {"arp": redirector, "ndp": spoofer}}
        self._isolations: dict = {}

        # Aktif monitörler: {ip: {"mitm": redirector|None, "sniffer": DnsMonitor, "queues": [queue,...]}}
        self._monitors: dict = {}

        # Flow Control
        self.flow_ctrl = None

        # Log kuyruğu (SSE) — per-client queues
        self._log_clients: list[queue.Queue] = []
        self._log_clients_lock = threading.Lock()

    # ── Logging ───────────────────────────────────────────────────────────────

    def log(self, msg: str, level: str = "info"):
        """Log mesajı gönderir. Tüm SSE client'lara dağıtılır."""
        entry = {"ts": _ts(), "msg": msg, "level": level}
        try:
            logger.info("[%s] %s", level.upper(), msg)
        except Exception:
            pass

        with self._log_clients_lock:
            dead = []
            for client_q in self._log_clients:
                try:
                    client_q.put_nowait(entry)
                except queue.Full:
                    dead.append(client_q)
            for d in dead:
                try:
                    self._log_clients.remove(d)
                except ValueError:
                    pass

    def add_log_client(self) -> queue.Queue:
        """Yeni SSE client için queue oluşturur ve kayıt eder."""
        client_q: queue.Queue = queue.Queue(maxsize=500)
        with self._log_clients_lock:
            self._log_clients.append(client_q)
        return client_q

    def remove_log_client(self, client_q: queue.Queue):
        """SSE client queue'sunu kaldırır."""
        with self._log_clients_lock:
            try:
                self._log_clients.remove(client_q)
            except ValueError:
                pass

    def log_stream(self):
        """SSE generator: per-client queue ile log akışı."""
        client_q = self.add_log_client()
        try:
            while True:
                try:
                    entry = client_q.get(timeout=30)
                    yield f"data: {json.dumps(entry)}\n\n"
                except queue.Empty:
                    yield f"data: {json.dumps({'ts': _ts(), 'msg': '', 'level': 'ping'})}\n\n"
        finally:
            self.remove_log_client(client_q)

    # ── Devices (Thread-Safe) ──────────────────────────────────────────────────

    @property
    def devices(self) -> dict:
        """Geriye dönük uyumluluk için property. Dikkatli kullanın."""
        return self._devices

    def get_devices(self) -> dict:
        """Tüm cihazları döndürür (kopyasız, lock tutulmaz — okuma amaçlı)."""
        with self._lock:
            return dict(self._devices)

    def get_device(self, ip: str) -> Optional[dict]:
        """Tek bir cihaz bilgisi döndürür."""
        with self._lock:
            return self._devices.get(ip)

    def set_device(self, ip: str, data: dict):
        """Bir cihazı ekler veya günceller."""
        with self._lock:
            self._devices[ip] = data

    def update_device(self, ip: str, updates: dict):
        """Mevcut cihaz verisini kısmi günceller."""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].update(updates)

    def clear_devices(self):
        """Tüm cihaz listesini temizler."""
        with self._lock:
            self._devices.clear()

    def device_ips(self) -> list[str]:
        """Cihaz IP listesi döndürür."""
        with self._lock:
            return list(self._devices.keys())

    # ── Isolations (Thread-Safe) ───────────────────────────────────────────────

    @property
    def isolations(self) -> dict:
        """Geriye dönük uyumluluk."""
        return self._isolations

    def is_isolated(self, ip: str) -> bool:
        """Cihaz izole mi?"""
        with self._lock:
            return ip in self._isolations

    def get_isolation(self, ip: str) -> dict:
        """İzolasyon bilgisi döndürür."""
        with self._lock:
            return self._isolations.get(ip, {})

    def add_isolation(self, ip: str, key: str, obj):
        """İzolasyon nesnesi ekler."""
        with self._lock:
            self._isolations.setdefault(ip, {})[key] = obj

    def remove_isolation(self, ip: str) -> dict:
        """İzolasyonu kaldırır, eski veriyi döndürür."""
        with self._lock:
            return self._isolations.pop(ip, {})

    def isolation_keys(self) -> list[str]:
        """Aktif izolasyon IP listesi."""
        with self._lock:
            return list(self._isolations.keys())

    def has_isolations(self) -> bool:
        """Aktif izolasyon var mı?"""
        with self._lock:
            return bool(self._isolations)

    # ── Monitors (Thread-Safe) ─────────────────────────────────────────────────

    @property
    def monitors(self) -> dict:
        """Geriye dönük uyumluluk."""
        return self._monitors

    def get_monitor(self, ip: str) -> Optional[dict]:
        """Monitor bilgisi döndürür."""
        with self._lock:
            return self._monitors.get(ip)

    def add_monitor(self, ip: str, data: dict):
        """Monitor ekler."""
        with self._lock:
            self._monitors[ip] = data

    def remove_monitor(self, ip: str) -> dict:
        """Monitor kaldırır."""
        with self._lock:
            return self._monitors.pop(ip, {})

    def has_monitor(self, ip: str) -> bool:
        """Aktif monitor var mı?"""
        with self._lock:
            return ip in self._monitors

    def monitor_items(self) -> list:
        """Monitor öğelerini döndürür."""
        with self._lock:
            return list(self._monitors.items())

    # ── Device Dict Builder ────────────────────────────────────────────────────

    def device_dict(self, ip: str, entry) -> dict:
        """HostEntry nesnesini JSON-serialize edilebilir dict'e çevirir."""
        mac = entry.mac if hasattr(entry, "mac") else str(entry.get("mac", ""))
        hostname_val = entry.hostname if hasattr(entry, "hostname") else str(entry.get("hostname", ""))
        vendor, dev_type = get_vendor(mac, hostname_val)
        isolated = self.is_isolated(ip)
        iso_data = self.get_isolation(ip) if isolated else {}
        return {
            "ip":           ip,
            "mac":          mac,
            "hostname":     entry.hostname if hasattr(entry, "hostname") else str(entry.get("hostname", "")),
            "first_seen":   entry.first_seen if hasattr(entry, "first_seen") else str(entry.get("first_seen", "")),
            "vendor":       vendor,
            "type":         dev_type,
            "isolated":     isolated,
            "pkt_count":    iso_data.get("arp", None) and iso_data["arp"].packet_count or 0 if isolated else 0,
            "friendly_name": "",
            "owner_name":   "",
        }

    # ── Temizlik ───────────────────────────────────────────────────────────────

    def cleanup(self):
        """Tüm aktif izolasyonları ve monitörleri onarır."""
        if not self.has_isolations() and not self._monitors and not (self.flow_ctrl and self.flow_ctrl.active):
            return
        self.log("Temizlik: tüm izolasyonlar onarılıyor...", "warn")
        for ip in self.isolation_keys():
            iso = self.remove_isolation(ip)
            if iso.get("arp"):
                try:
                    iso["arp"].stop(restore=True)
                except Exception as e:
                    logger.error("ARP onarım hatası: %s", e)
            if iso.get("ndp"):
                try:
                    iso["ndp"].stop(restore=True)
                except Exception as e:
                    logger.error("NDP onarım hatası: %s", e)

        for ip in list(self._monitors.keys()):
            mon = self.remove_monitor(ip)
            sniffer = mon.get("sniffer")
            if sniffer:
                try:
                    sniffer.stop()
                except Exception:
                    pass
            mitm = mon.get("mitm")
            if mitm:
                try:
                    mitm.stop(restore=True)
                except Exception:
                    pass

        if self.flow_ctrl and self.flow_ctrl.active:
            try:
                self.flow_ctrl.stop()
            except Exception:
                pass
