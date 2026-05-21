"""
AntiGravity — Web Application Backend
======================================
Flask tabanlı REST API + Server-Sent Events.

Çalıştırma:
    sudo python3 web_app.py

Adres:
    http://localhost:8080
"""

import os
import sys
import json
import time
import queue
import threading
import subprocess
import socket as _socket
import logging
from typing import Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, request, Response, send_from_directory

# ─── Proje Modülleri ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from config import cfg
from modules.utils import (
    get_local_ip, guess_network_range, validate_ip, validate_mac,
    strip_zone, setup_logging
)

try:
    from modules.node_discovery      import NodeDiscovery
    from modules.traffic_redirection import TrafficRedirector
    from modules.packet_flow_control import PacketFlowController, FlowMode
    from modules.ipv6_ndp import (
        IPv6Discovery, NDPSpoofer,
        mac_to_ipv6_link_local, get_local_ipv6
    )
    from modules.dns_monitor import DnsMonitor
    from modules.oui_table import get_vendor
    from modules.passive_sniffer import (
        PassiveSnifferEngine, is_service_name, clean_mdns_name,
        extract_owner_from_hostname
    )
    from modules.app_state import AppState
    MODULES_OK = True
except ImportError as e:
    MODULES_OK = False
    print(f"[!] Modül uyarısı: {e}")

# ─── Logging ──────────────────────────────────────────────────────────────────
setup_logging(level=cfg.LOG_LEVEL, log_file=cfg.LOG_FILE)
logger = logging.getLogger("antigravity.web")

# ─── Flask ────────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_STATIC = os.path.join(_HERE, "static")

app = Flask(__name__, static_folder=_STATIC, static_url_path="/static")
app.config["JSON_SORT_KEYS"] = False


def scapy_iface():
    try:
        from scapy.all import conf as sc
        return sc.iface
    except Exception:
        return "en0"


def ts():
    return datetime.now().strftime("%H:%M:%S")


# ─── Global Uygulama Durumu ───────────────────────────────────────────────────

state = AppState()


# ─── Yardımcı: Otomatik Gateway Bul ──────────────────────────────────────────

def auto_gateway() -> tuple:
    """Sistemdeki varsayılan gateway IP ve MAC'i döndürür."""
    try:
        r = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=3
        )
        gw_ip = None
        for line in r.stdout.splitlines():
            if "gateway:" in line:
                gw_ip = line.split(":")[1].strip()
                break

        if not gw_ip:
            # macOS netstat
            r2 = subprocess.run(
                ["netstat", "-rn", "-f", "inet"],
                capture_output=True, text=True, timeout=3
            )
            for line in r2.stdout.splitlines():
                if line.startswith("default"):
                    gw_ip = line.split()[1]
                    break

        devices = state.get_devices()
        if gw_ip and gw_ip in devices:
            gw_mac = devices[gw_ip]["mac"]
        else:
            gw_mac = None

        return gw_ip, gw_mac

    except Exception:
        return "192.168.1.1", None


def auto_gateway_ipv6() -> tuple:
    """Varsayılan IPv6 gateway'i döndürür."""
    try:
        r = subprocess.run(
            ["netstat", "-rn", "-f", "inet6"],
            capture_output=True, text=True, timeout=3
        )
        for line in r.stdout.splitlines():
            if line.strip().startswith("default"):
                parts = line.split()
                if len(parts) >= 2:
                    gw = strip_zone(parts[1])
                    return gw, None
    except Exception:
        pass
    return "fe80::1", None


# ─── Yardımcı: İzolasyon ─────────────────────────────────────────────────────

def _do_isolate(ip: str, target_mac: str) -> dict:
    """Bir cihazı hem ARP hem NDP ile izole eder."""
    gw_ip, gw_mac = auto_gateway()
    result = {"arp": False, "ndp": False, "errors": []}

    # ── ARP Spoofing ──
    try:
        r = TrafficRedirector()
        r.start(ip, gw_ip, enable_forwarding=False)
        state.add_isolation(ip, "arp", r)
        result["arp"] = True
        state.log(f"[ARP] ✓ {ip} izole edildi (ARP)", "success")
    except Exception as e:
        result["errors"].append(f"ARP: {e}")
        state.log(f"[ARP] ✗ {ip}: {e}", "error")

    # ── IP Forwarding kapat ──
    try:
        subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"],
                       capture_output=True, timeout=3)
        subprocess.run(["sysctl", "-w", "net.inet6.ip6.forwarding=0"],
                       capture_output=True, timeout=3)
        state.log("[SYS] IP Forwarding kapatıldı.", "warn")
    except Exception:
        pass

    # ── NDP Spoofing ─── (IPv6 adresi biliniyorsa)
    try:
        iface = scapy_iface()
        ndp_out = subprocess.run(["ndp", "-n", "-a"],
                                  capture_output=True, text=True, timeout=3).stdout
        target_v6 = None
        for line in ndp_out.splitlines():
            if target_mac.lower() in line.lower():
                parts = line.split()
                if parts:
                    target_v6 = strip_zone(parts[0])
                    break

        if target_v6:
            gw_v6, _ = auto_gateway_ipv6()
            spoofer = NDPSpoofer(iface=iface)
            spoofer.start(target_v6, gw_v6)
            state.add_isolation(ip, "ndp", spoofer)
            result["ndp"] = True
            state.log(f"[NDP] ✓ {ip} izole edildi (IPv6: {target_v6})", "success")
        else:
            state.log(f"[NDP] IPv6 adresi bulunamadı ({ip}), sadece ARP aktif.", "warn")
    except Exception as e:
        result["errors"].append(f"NDP: {e}")
        state.log(f"[NDP] ✗ {ip}: {e}", "warn")

    return result


def _do_restore(ip: str) -> bool:
    """Bir cihazın izolasyonunu kaldırır, bağlantısını onarır."""
    iso = state.remove_isolation(ip)
    ok = False

    if iso.get("arp"):
        try:
            iso["arp"].stop(restore=True)
            state.log(f"[ARP] ✓ {ip} ARP onarıldı.", "success")
            ok = True
        except Exception as e:
            state.log(f"[ARP] Onarım hatası: {e}", "error")

    if iso.get("ndp"):
        try:
            iso["ndp"].stop(restore=True)
            state.log(f"[NDP] ✓ {ip} NDP onarıldı.", "success")
        except Exception as e:
            state.log(f"[NDP] Onarım hatası: {e}", "error")

    # Başka aktif izolasyon yoksa forwarding'i geri aç
    if not state.has_isolations():
        try:
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                           capture_output=True, timeout=3)
            subprocess.run(["sysctl", "-w", "net.inet6.ip6.forwarding=1"],
                           capture_output=True, timeout=3)
            state.log("[SYS] IP Forwarding yeniden açıldı.", "info")
        except Exception:
            pass

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# API ENDPOINT'LERİ
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory(_STATIC, "index.html")


# ── Pasif Sniffer ─────────────────────────────────────────────────────────────

# Global sniffer instance
_passive_sniffer = PassiveSnifferEngine(
    state=state,
    vendor_fn=get_vendor,
    log_fn=state.log
) if MODULES_OK else None


def _resolve_names_bg(ips: list):
    """
    ARP taramasından sonra arka planda her IP için hostname çözer.
    ThreadPoolExecutor ile paralel çözümleme yapar.
    Ardından pasif sniffer'ı başlatır.
    """
    state.log(f"[mDNS] {len(ips)} cihaz için isim arama başlıyor...", "info")
    found = 0

    def _resolve_single(ip):
        nonlocal found
        dev = state.get_device(ip)
        if dev is None:
            return
        try:
            raw = _socket.gethostbyaddr(ip)[0]
            if raw and raw != ip and not is_service_name(raw):
                clean = clean_mdns_name(raw)
                owner = extract_owner_from_hostname(raw)
                if not clean:
                    return
                mac = dev['mac']
                vendor, dtype = get_vendor(mac, raw)
                state.update_device(ip, {
                    'hostname':      raw,
                    'friendly_name': clean,
                    'owner_name':    owner,
                    'vendor':        vendor,
                    'type':          dtype,
                })
                display = f"{owner} / {clean}" if owner else clean
                state.log(f'[mDNS] {ip} → "{display}"', "success")
                found += 1
        except (_socket.herror, _socket.gaierror, OSError):
            pass
        except Exception as e:
            state.log(f"[mDNS] {ip} hata: {e}", "warn")

    # Paralel çözümleme (max 8 thread)
    with ThreadPoolExecutor(max_workers=8) as pool:
        pool.map(_resolve_single, ips)

    state.log(f"[mDNS] ✓ {found}/{len(ips)} cihazda isim bulundu.", "success" if found else "info")
    # Pasif sniffer'ı başlat
    if _passive_sniffer:
        _passive_sniffer.start()


# ── Tarama ────────────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def api_scan():
    if state.scanning:
        return jsonify({"ok": False, "error": "Tarama zaten devam ediyor."}), 409

    data    = request.get_json(silent=True) or {}
    network = data.get("network") or (guess_network_range() if MODULES_OK else "192.168.1.0/24")
    timeout = float(data.get("timeout", 3))

    # ✓ Race condition fix: flag'i thread başlamadan ÖNCE set et
    state.scanning      = True
    state.scan_progress = 8

    def _scan():
        state.log(f"[SCAN] ARP taranıyor: {network}  timeout={timeout}s", "info")
        try:
            state.scan_progress = 20
            nd    = NodeDiscovery()
            state.scan_progress = 30
            hosts = nd.scan(network=network, timeout=timeout,
                            resolve_hostnames=False, verbose=False)
            state.scan_progress = 88
            state.clear_devices()
            ips_found = []
            for ip, entry in hosts.items():
                state.set_device(ip, state.device_dict(ip, entry))
                ips_found.append(ip)
            state.scan_progress = 100
            state.log(f"[SCAN] ✓ {len(hosts)} cihaz bulundu.", "success")
            # Arka planda mDNS isim çözümlemesi başlat
            threading.Thread(
                target=_resolve_names_bg,
                args=(ips_found,),
                daemon=True
            ).start()
        except PermissionError:
            state.log("[SCAN] ✗ Root yetkisi gerekli! sudo ile çalıştırın.", "error")
        except Exception as e:
            state.log(f"[SCAN] ✗ Hata: {e}", "error")
            logger.exception("Tarama hatası")
        finally:
            state.scanning = False

    threading.Thread(target=_scan, daemon=True).start()
    return jsonify({"ok": True, "network": network})


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify({
        "scanning":  state.scanning,
        "progress":  state.scan_progress,
        "count":     len(state.devices),
    })


@app.route("/api/devices")
def api_devices():
    devices = []
    all_devs = state.get_devices()
    for ip, d in all_devs.items():
        d = dict(d)
        d["isolated"] = state.is_isolated(ip)
        if d["isolated"]:
            iso = state.get_isolation(ip)
            if iso.get("arp"):
                d["pkt_count"] = iso["arp"].packet_count
        devices.append(d)

    # Gateway önce gelsin
    gw_ip, _ = auto_gateway()
    devices.sort(key=lambda x: (x["ip"] != gw_ip, x["ip"].split(".")[-1].zfill(3)))
    return jsonify(devices)


# ── İzolasyon ─────────────────────────────────────────────────────────────────

@app.route("/api/isolate", methods=["POST"])
def api_isolate():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()
    mac  = data.get("mac", "").strip()

    if not ip or not mac:
        return jsonify({"ok": False, "error": "IP ve MAC gerekli."}), 400
    if not validate_ip(ip):
        return jsonify({"ok": False, "error": f"Geçersiz IP adresi: {ip}"}), 400
    if not validate_mac(mac):
        return jsonify({"ok": False, "error": f"Geçersiz MAC adresi: {mac}"}), 400
    if state.is_isolated(ip):
        return jsonify({"ok": False, "error": "Cihaz zaten izole."}), 409

    state.log(f"[ISOLATE] {ip} → izolasyon başlatılıyor...", "warn")

    def _worker():
        _do_isolate(ip, mac)

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/restore", methods=["POST"])
def api_restore():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()

    if not ip:
        return jsonify({"ok": False, "error": "IP gerekli."}), 400
    if not state.is_isolated(ip):
        return jsonify({"ok": False, "error": "Cihaz izole değil."}), 404

    state.log(f"[RESTORE] {ip} → bağlantı onarılıyor...", "info")

    def _worker():
        _do_restore(ip)

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/restore-all", methods=["POST"])
def api_restore_all():
    ips = state.isolation_keys()
    for ip in ips:
        _do_restore(ip)
    return jsonify({"ok": True, "restored": ips})


# ── Expert Mod ────────────────────────────────────────────────────────────────

@app.route("/api/expert/arp-start", methods=["POST"])
def api_arp_start():
    data    = request.get_json(silent=True) or {}
    target  = data.get("target_ip", "").strip()
    gateway = data.get("gateway_ip", "").strip()
    fwd     = data.get("forwarding", False)

    if not target or not gateway:
        return jsonify({"ok": False, "error": "Hedef ve gateway IP gerekli."}), 400
    if not validate_ip(target):
        return jsonify({"ok": False, "error": f"Geçersiz hedef IP: {target}"}), 400
    if not validate_ip(gateway):
        return jsonify({"ok": False, "error": f"Geçersiz gateway IP: {gateway}"}), 400

    state.log(f"[ARP] Başlatılıyor → {target}", "warn")

    def _worker():
        try:
            r = TrafficRedirector()
            r.start(target, gateway, enable_forwarding=fwd)
            state.add_isolation(target, "arp", r)
            state.log(f"[ARP] ✓ AKTİF → {target}", "success")
        except Exception as e:
            state.log(f"[ARP] ✗ {e}", "error")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/expert/arp-stop", methods=["POST"])
def api_arp_stop():
    data   = request.get_json(silent=True) or {}
    target = data.get("target_ip", "").strip()
    iso    = state.get_isolation(target)
    r      = iso.get("arp")
    if not r:
        return jsonify({"ok": False, "error": "Aktif ARP bulunamadı."}), 404
    r.stop(restore=True)
    # Remove arp from isolation
    iso.pop("arp", None)
    state.log(f"[ARP] ✓ Durduruldu → {target}", "success")
    return jsonify({"ok": True})


@app.route("/api/expert/ndp-start", methods=["POST"])
def api_ndp_start():
    data       = request.get_json(silent=True) or {}
    target_v6  = strip_zone(data.get("target_v6", "").strip())
    router_v6  = strip_zone(data.get("router_v6", "").strip())
    target_mac = data.get("target_mac", "").strip() or None

    if not target_v6 or not router_v6:
        return jsonify({"ok": False, "error": "Hedef ve router IPv6 gerekli."}), 400

    state.log(f"[NDP] Başlatılıyor → {target_v6}", "warn")

    def _worker():
        try:
            spoofer = NDPSpoofer(iface=scapy_iface())
            spoofer.start(target_v6, router_v6, target_mac=target_mac)
            state.add_isolation("ndp_" + target_v6, "ndp", spoofer)
            state.log(f"[NDP] ✓ AKTİF → {target_v6}", "success")
        except Exception as e:
            state.log(f"[NDP] ✗ {e}", "error")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/expert/ndp-stop", methods=["POST"])
def api_ndp_stop():
    data      = request.get_json(silent=True) or {}
    target_v6 = strip_zone(data.get("target_v6", "").strip())
    key       = "ndp_" + target_v6
    iso       = state.get_isolation(key)
    spoofer   = iso.get("ndp")
    if not spoofer:
        return jsonify({"ok": False, "error": "Aktif NDP bulunamadı."}), 404
    spoofer.stop(restore=True)
    state.remove_isolation(key)
    state.log(f"[NDP] ✓ Durduruldu → {target_v6}", "success")
    return jsonify({"ok": True})


@app.route("/api/expert/flow-start", methods=["POST"])
def api_flow_start():
    data = request.get_json(silent=True) or {}
    mode_str = data.get("mode", "FORWARD").upper()
    bpf      = data.get("bpf", "").strip() or None
    kbps     = float(data.get("kbps", 512))

    mode_map = {"FORWARD": FlowMode.FORWARD, "DROP": FlowMode.DROP,
                "THROTTLE": FlowMode.THROTTLE, "INSPECT": FlowMode.INSPECT}
    mode = mode_map.get(mode_str, FlowMode.FORWARD)

    if state.flow_ctrl and state.flow_ctrl.active:
        return jsonify({"ok": False, "error": "Flow control zaten aktif."}), 409

    def _worker():
        try:
            state.flow_ctrl = PacketFlowController()
            state.flow_ctrl.start(mode=mode, bpf_filter=bpf, throttle_kbps=kbps)
            state.log(f"[FLOW] ✓ AKTİF ({mode_str})", "success")
        except Exception as e:
            state.log(f"[FLOW] ✗ {e}", "error")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/expert/flow-stop", methods=["POST"])
def api_flow_stop():
    if not state.flow_ctrl or not state.flow_ctrl.active:
        return jsonify({"ok": False, "error": "Flow control aktif değil."}), 404
    state.flow_ctrl.stop()
    state.log("[FLOW] ✓ Durduruldu.", "success")
    return jsonify({"ok": True})


# ── Durum ─────────────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    try:
        local_ip = get_local_ip() if MODULES_OK else "N/A"
        local_v6 = get_local_ipv6(scapy_iface()) or "N/A"
    except Exception:
        local_ip = local_v6 = "N/A"

    active_ips = [ip for ip in state.isolation_keys() if not ip.startswith("ndp_")]
    gw_ip, _   = auto_gateway()

    return jsonify({
        "local_ip":     local_ip,
        "local_v6":     local_v6,
        "gateway_ip":   gw_ip,
        "scanning":     state.scanning,
        "device_count": len(state.devices),
        "isolated":     active_ips,
        "flow_active":  bool(state.flow_ctrl and state.flow_ctrl.active),
        "flow_mode":    state.flow_ctrl.mode.value if state.flow_ctrl and state.flow_ctrl.active else None,
    })


@app.route("/api/neighbor-cache")
def api_neighbor_cache():
    try:
        r = subprocess.run(["ndp", "-n", "-a"],
                            capture_output=True, text=True, timeout=5)
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        return jsonify({"ok": True, "lines": lines})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── Website Monitor ───────────────────────────────────────────────────────────

def _do_monitor_stop(ip: str):
    """Monitor'ü durdurur, şeffaf MITM'i temizler."""
    mon = state.remove_monitor(ip)
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
    # Kapalı olan SSE queue'larını bilgilendir
    for q in mon.get("queues", []):
        try:
            q.put_nowait(None)   # sentinel → stream sonlandır
        except Exception:
            pass
    state.log(f"[MON] {ip} izleme durduruldu.", "info")


@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()
    mac  = data.get("mac", "").strip()

    if not ip:
        return jsonify({"ok": False, "error": "IP gerekli."}), 400
    if state.has_monitor(ip):
        return jsonify({"ok": True, "already": True, "ip": ip})

    state.log(f"[MON] {ip} için izleme başlatılıyor (şeffaf MITM)...", "info")

    def _worker():
        queues = []
        mitm   = None

        # Şeffaf MITM: IP Forwarding ON → internet kesilmez
        try:
            gw_ip, _ = auto_gateway()
            if gw_ip and ip != gw_ip:
                subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                               capture_output=True, timeout=3)
                subprocess.run(["sysctl", "-w", "net.inet6.ip6.forwarding=1"],
                               capture_output=True, timeout=3)
                mitm = TrafficRedirector()
                mitm.start(ip, gw_ip, enable_forwarding=True)
                state.log(f"[MON] ✓ Şeffaf MITM aktif → {ip} (internet kesilmedi)", "success")
            else:
                state.log(f"[MON] Gateway tespit edilemedi, pasif mod.", "warn")
        except Exception as e:
            state.log(f"[MON] MITM başlatılamadı: {e} — pasif modda devam ediliyor.", "warn")
            mitm = None

        def _on_domain(entry):
            """Yeni domain bulununca tüm aktif SSE queue'larına yaz."""
            mon = state.get_monitor(ip)
            if not mon:
                return
            dead = []
            for q in mon.get("queues", []):
                try:
                    q.put_nowait(entry)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                try:
                    mon["queues"].remove(q)
                except Exception:
                    pass

        sniffer = DnsMonitor(ip, on_domain=_on_domain)
        sniffer.start()

        state.add_monitor(ip, {
            "sniffer": sniffer,
            "mitm":    mitm,
            "queues":  queues,
        })
        state.log(f"[MON] ✓ DNS/SNI sniffer başladı → {ip}", "success")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()

    if not ip:
        return jsonify({"ok": False, "error": "IP gerekli."}), 400
    if not state.has_monitor(ip):
        return jsonify({"ok": False, "error": "Aktif monitor yok."}), 404

    _do_monitor_stop(ip)
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/monitor/stream/<path:ip>")
def api_monitor_stream(ip):
    """SSE stream — hedef IP'nin domain'lerini anlık gönderir."""
    ip = ip.strip()

    if not state.has_monitor(ip):
        return jsonify({"ok": False, "error": "Monitor aktif değil."}), 404

    client_q: queue.Queue = queue.Queue(maxsize=200)
    mon = state.get_monitor(ip)
    if mon:
        mon["queues"].append(client_q)

    def _gen():
        # Mevcut geçmişi önce gönder
        mon_data = state.get_monitor(ip)
        sniffer = mon_data.get("sniffer") if mon_data else None
        if sniffer:
            for entry in sniffer.get_history():
                yield f"data: {json.dumps(entry)}\n\n"

        while True:
            try:
                entry = client_q.get(timeout=25)
                if entry is None:   # sentinel → monitor durduruldu
                    yield f"data: {json.dumps({'type': 'stopped'})}\n\n"
                    break
                yield f"data: {json.dumps(entry)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    resp = Response(
        _gen(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
    return resp


@app.route("/api/monitor/history/<path:ip>")
def api_monitor_history(ip):
    ip = ip.strip()
    mon = state.get_monitor(ip)
    if not mon:
        return jsonify({"ok": False, "error": "Monitor aktif değil."}), 404
    history = mon["sniffer"].get_history()
    return jsonify({"ok": True, "ip": ip, "history": history})


@app.route("/api/monitor/status")
def api_monitor_status():
    result = {}
    for ip, mon in state.monitor_items():
        sniffer = mon.get("sniffer")
        result[ip] = {
            "active":    sniffer.active if sniffer else False,
            "count":     len(sniffer.history) if sniffer else 0,
            "mitm_active": bool(mon.get("mitm") and mon["mitm"].active),
        }
    return jsonify(result)


# ── SSE Log Akışı ─────────────────────────────────────────────────────────────

@app.route("/api/stream")
def api_stream():
    return Response(
        state.log_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


# ── MAC → IPv6 Çevirici ───────────────────────────────────────────────────────

@app.route("/api/mac-to-ipv6")
def api_mac_to_ipv6():
    mac  = request.args.get("mac", "")
    ipv6 = mac_to_ipv6_link_local(mac) if mac else ""
    return jsonify({"ipv6": ipv6})


# ─── Uygulama Başlatma ────────────────────────────────────────────────────────

import atexit
import signal

def _shutdown(signum=None, frame=None):
    print("\n[!] Kapatılıyor, izolasyonlar onarılıyor...")
    state.cleanup()
    sys.exit(0)

atexit.register(state.cleanup)
signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("\n[!] UYARI: Root yetkisi gerekli → sudo python3 web_app.py\n")

    print("\n" + "═" * 60)
    print("   ⬡  AntiGravity Web UI")
    print(f"   http://localhost:{cfg.WEB_PORT}")
    print("═" * 60 + "\n")

    import webbrowser
    threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{cfg.WEB_PORT}")).start()

    app.run(host=cfg.WEB_HOST, port=cfg.WEB_PORT, debug=False, threaded=True)
