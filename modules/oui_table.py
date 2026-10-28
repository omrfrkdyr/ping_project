"""
AntiGravity — OUI Vendor Tablosu & Cihaz Tanıma
=================================================
MAC OUI prefix'inden cihaz üreticisini ve türünü çözer.
iOS 14+ rastgele MAC (locally-administered) desteği dahil.
"""

from typing import Tuple


# ─── OUI Vendor Tablosu ───────────────────────────────────────────────────────

OUI_TABLE: dict[str, Tuple[str, str]] = {
    # ── Router / Gateway ───────────────────────────────────────────
    "20:e8:82": ("Router",    "router"), "d8:07:b6": ("Router",    "router"),
    "c8:d7:19": ("Router",    "router"), "a8:6b:d9": ("Router",    "router"),
    "74:da:38": ("Router",    "router"), "c0:4a:00": ("Router",    "router"),
    "b0:be:76": ("Router",    "router"), "e4:ab:89": ("Router",    "router"),
    "f8:1a:67": ("Router",    "router"), "00:1a:2b": ("Router",    "router"),

    # ── Apple (iPhone/iPad/MacBook) ────────────────────────────────
    "84:90:0a": ("Apple",     "phone"),  "a4:c3:61": ("Apple",     "phone"),
    "3c:22:fb": ("Apple",     "phone"),  "f0:b3:ec": ("Apple",     "phone"),
    "40:cb:c0": ("Apple",     "phone"),  "bc:92:6b": ("Apple",     "phone"),
    "dc:2b:61": ("Apple",     "phone"),  "f4:d4:88": ("Apple",     "phone"),
    "34:c0:59": ("Apple",     "phone"),  "70:3c:69": ("Apple",     "phone"),
    "f0:18:98": ("Apple",     "phone"),  "28:6a:b8": ("Apple",     "phone"),
    "d8:bb:c1": ("Apple",     "phone"),  "14:99:e2": ("Apple",     "phone"),
    "60:f8:1d": ("Apple",     "phone"),  "e0:b9:ba": ("Apple",     "phone"),
    "a8:51:ab": ("Apple",     "phone"),  "70:56:81": ("Apple",     "phone"),
    "dc:a9:04": ("Apple",     "phone"),  "f0:d1:a9": ("Apple",     "phone"),
    "9c:f4:8e": ("Apple",     "phone"),  "bc:d0:74": ("Apple",     "phone"),
    "b8:09:8a": ("Apple",     "phone"),  "4c:57:ca": ("Apple",     "phone"),
    "94:e9:6a": ("Apple",     "phone"),  "d8:1d:72": ("Apple",     "phone"),
    "f4:f1:5a": ("Apple",     "phone"),  "00:cd:fe": ("Apple",     "phone"),
    "d8:f8:83": ("Apple",     "phone"),  "20:7d:74": ("Apple",     "phone"),
    "78:4f:43": ("Apple",     "phone"),  "68:96:7b": ("Apple",     "phone"),
    "18:af:61": ("Apple",     "phone"),  "74:1b:b2": ("Apple",     "phone"),
    "90:72:40": ("Apple",     "phone"),  "e8:8d:28": ("Apple",     "phone"),
    "d4:61:9d": ("Apple",     "phone"),  "b8:53:ac": ("Apple",     "phone"),
    "48:bf:6b": ("Apple",     "phone"),  "ac:37:43": ("Apple",     "phone"),
    "68:fb:7e": ("Apple",     "phone"),  "a0:56:f3": ("Apple",     "phone"),
    "24:18:c6": ("Apple",     "laptop"), "8c:85:90": ("Apple",     "laptop"),
    "ac:bc:32": ("Apple",     "laptop"), "a4:83:e7": ("Apple",     "laptop"),
    "f0:9f:c2": ("Apple",     "laptop"), "3c:07:54": ("Apple",     "laptop"),
    "88:66:5a": ("Apple",     "laptop"),
    "f8:27:93": ("Apple",     "laptop"), "64:76:ba": ("Apple",     "laptop"),
    "78:7b:8a": ("Apple",     "laptop"), "a4:5e:60": ("Apple",     "laptop"),
    "84:a1:34": ("Apple",     "laptop"), "34:36:3b": ("Apple",     "laptop"),

    # ── Samsung ────────────────────────────────────────────────────
    "8c:c8:4b": ("Samsung",   "phone"),  "2c:f0:ee": ("Samsung",   "phone"),
    "f4:42:8f": ("Samsung",   "phone"),  "70:f9:27": ("Samsung",   "phone"),
    "94:35:0a": ("Samsung",   "phone"),  "cc:07:ab": ("Samsung",   "phone"),
    "5c:49:7d": ("Samsung",   "phone"),  "b4:3a:28": ("Samsung",   "phone"),
    "b0:72:bf": ("Samsung",   "phone"),  "3c:8b:fe": ("Samsung",   "phone"),
    "7c:1c:4e": ("Samsung TV","tv"),     "f4:7b:5e": ("Samsung TV","tv"),
    "14:49:bc": ("Samsung TV","tv"),     "8c:71:f8": ("Samsung TV","tv"),

    # ── Xiaomi ─────────────────────────────────────────────────────
    "28:6c:07": ("Xiaomi",    "phone"),  "64:cc:2e": ("Xiaomi",    "phone"),
    "00:9e:c8": ("Xiaomi",    "phone"),  "ac:c1:ee": ("Xiaomi",    "phone"),
    "f8:a4:5f": ("Xiaomi",    "phone"),  "34:80:b3": ("Xiaomi",    "phone"),

    # ── Huawei ─────────────────────────────────────────────────────
    "b4:cd:27": ("Huawei",    "phone"),  "04:f9:38": ("Huawei",    "phone"),
    "6c:b7:f4": ("Huawei",    "phone"),  "00:9a:cd": ("Huawei",    "phone"),

    # ── Smart TV / LG ─────────────────────────────────────────────
    "a8:23:fe": ("LG TV",     "tv"),     "c4:36:6c": ("LG TV",     "tv"),
    "48:59:29": ("LG TV",     "tv"),     "cc:2d:8c": ("LG TV",     "tv"),
    "b8:ad:3e": ("LG TV",     "tv"),     "78:5d:c8": ("LG TV",     "tv"),
    "00:1c:62": ("LG TV",     "tv"),     "00:1e:75": ("LG TV",     "tv"),
    "10:f9:ee": ("LG TV",     "tv"),     "20:3d:b2": ("LG TV",     "tv"),
    "34:fc:ef": ("LG TV",     "tv"),     "58:a2:b5": ("LG TV",     "tv"),
    "64:99:5d": ("LG TV",     "tv"),     "70:05:14": ("LG TV",     "tv"),
    "7c:1c:f1": ("LG TV",     "tv"),     "88:36:6c": ("LG TV",     "tv"),
    "a8:16:b2": ("LG TV",     "tv"),     "b4:e6:2d": ("LG TV",     "tv"),
    "c8:08:e9": ("LG TV",     "tv"),     "e8:5b:5b": ("LG TV",     "tv"),
    "00:26:e2": ("LG TV",     "tv"),     "50:56:bf": ("LG TV",     "tv"),
    "68:94:23": ("LG TV",     "tv"),     "dc:0b:34": ("LG TV",     "tv"),
    "e4:b3:18": ("LG TV",     "tv"),     "ec:9b:f3": ("LG TV",     "tv"),
    "08:d4:6a": ("LG TV",     "tv"),
    "ac:9b:0a": ("Sony TV",   "tv"),     "04:5d:4b": ("Sony TV",   "tv"),
    "f4:f5:24": ("Sony TV",   "tv"),     "7c:c3:a1": ("Sony TV",   "tv"),
    "90:e7:c4": ("Hisense",   "tv"),     "f4:43:02": ("Hisense",   "tv"),
    "00:17:88": ("Philips",   "tv"),     "78:84:e1": ("Philips",   "tv"),

    # ── Ev Aletleri (Siemens / Bosch / BSH) ─────────────────────────
    "94:27:70": ("Siemens / Bosch", "iot"), "68:a4:0e": ("Siemens / Bosch", "iot"),
    "38:b4:d3": ("Siemens / Bosch", "iot"), "c8:d7:78": ("Siemens / Bosch", "iot"),
    "74:5d:43": ("Siemens / Bosch", "iot"), "e4:67:a6": ("Siemens / Bosch", "iot"),
    "40:0a:e7": ("Siemens / Bosch", "iot"), "00:21:4f": ("BSH Hausgeräte",  "iot"),
    "00:1c:06": ("Siemens",         "iot"), "00:0e:8c": ("Siemens",         "iot"),
    "00:1f:f8": ("Siemens",         "iot"), "18:87:96": ("Siemens",         "iot"),
    "80:34:28": ("Siemens",         "iot"),

    # ── IoT / Diğer ───────────────────────────────────────────────
    "8c:79:67": ("ZTE",       "router"),
    "b4:75:0e": ("IoT",       "iot"),    "18:fe:34": ("IoT",       "iot"),
    "50:02:91": ("IoT",       "iot"),    "a0:20:a6": ("IoT",       "iot"),
    "ac:cf:23": ("IoT",       "iot"),

    # ── VM ─────────────────────────────────────────────────────────
    "00:50:56": ("VMware",    "laptop"), "00:0c:29": ("VMware",    "laptop"),
    "08:00:27": ("VBox",      "laptop"),
}


# ─── Hostname İpuçları ─────────────────────────────────────────────────────────

HOSTNAME_HINTS: dict[str, Tuple[str, str]] = {
    # ── LG & Smart TV ──────────────────────────────────────────────
    "lgwebostv":    ("LG TV",          "tv"),
    "webostv":      ("LG TV",          "tv"),
    "webos":        ("LG TV",          "tv"),
    "lg-tv":        ("LG TV",          "tv"),
    "lg tv":        ("LG TV",          "tv"),
    "lgtv":         ("LG TV",          "tv"),
    "[lg]":         ("LG TV",          "tv"),
    "smarttv":      ("Smart TV",       "tv"),
    "smart-tv":     ("Smart TV",       "tv"),
    "smart tv":     ("Smart TV",       "tv"),
    "appletv":      ("Apple TV",       "tv"),
    "apple tv":     ("Apple TV",       "tv"),
    "firetv":       ("Amazon Fire TV", "tv"),
    "firestick":    ("Amazon Fire TV", "tv"),
    "roku":         ("Roku TV",        "tv"),
    "bravia":       ("Sony Bravia",    "tv"),
    "tizen":        ("Samsung TV",     "tv"),
    "chromecast":   ("Chromecast",     "tv"),
    "mibox":        ("Mi Box",         "tv"),
    "shield":       ("Nvidia Shield",  "tv"),

    # ── Ev Aletleri / IoT (Siemens, Bosch vb.) ──────────────────────
    "siemens dryer": ("Siemens Dryer", "iot"),
    "siemens-dryer": ("Siemens Dryer", "iot"),
    "siemens_dryer": ("Siemens Dryer", "iot"),
    "dryer":        ("Siemens Dryer",  "iot"),
    "kurutma":      ("Kurutma Makinesi", "iot"),
    "washer":       ("Çamaşır Makinesi", "iot"),
    "camasir":      ("Çamaşır Makinesi", "iot"),
    "dishwasher":   ("Bulaşık Makinesi", "iot"),
    "bulasik":      ("Bulaşık Makinesi", "iot"),
    "siemens":      ("Siemens",        "iot"),
    "bosch":        ("Bosch",          "iot"),
    "homeconnect":  ("Home Connect",   "iot"),
    "home-connect": ("Home Connect",   "iot"),
    "bsh":          ("BSH Appliance",  "iot"),

    # ── Apple (iPhone/iPad/MacBook) ────────────────────────────────
    "iphone":       ("iPhone",         "phone"),
    "ipad":         ("iPad",           "phone"),
    "macbook":      ("MacBook",        "laptop"),
    "mac-":         ("MacBook",        "laptop"),

    # ── Diğer Telefonlar / Cihazlar ────────────────────────────────
    "android":      ("Android",        "phone"),
    "samsung":      ("Samsung",        "phone"),
    "xiaomi":       ("Xiaomi",         "phone"),
    "huawei":       ("Huawei",         "phone"),
    "xbox":         ("Xbox",           "laptop"),
    "playstation":  ("PlayStation",    "laptop"),
    "ps4":          ("PlayStation",    "laptop"),
    "ps5":          ("PlayStation",    "laptop"),
}


# ─── Yardımcı Fonksiyonlar ─────────────────────────────────────────────────────

def is_locally_administered(mac: str) -> bool:
    """
    MAC adresinin yerel olarak atanmış (locally-administered) olup olmadığını kontrol eder.
    iOS 14+ Private Wi-Fi Address özelliği bu bit'i 1 yapar.
    İlk oktetin bit 1 (LSB+1) = 1 ise locally-administered.

    Args:
        mac: "aa:bb:cc:dd:ee:ff" formatında MAC adresi.

    Returns:
        bool: Locally-administered ise True.
    """
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False


def get_vendor(mac: str, hostname: str = "") -> Tuple[str, str]:
    """
    MAC OUI + hostname + locally-administered flag'inden vendor ve cihaz türünü çözer.

    iOS 14+ rastgele MAC kullanır — OUI tablosu çalışmaz, ama LA bit tespit edilebilir.

    Args:
        mac:      "aa:bb:cc:dd:ee:ff" formatında MAC adresi.
        hostname: Cihaz adı (opsiyonel, en güvenilir bilgi kaynağı).

    Returns:
        Tuple[str, str]: (vendor_adı, cihaz_türü)
    """
    # 1. Hostname ipucu (en güvenilir)
    hn = (hostname or "").lower()
    hn_normalized = hn.replace("-", " ").replace("_", " ")
    hn_compact = hn.replace(" ", "").replace("-", "").replace("_", "")

    for kw, (vendor, dtype) in HOSTNAME_HINTS.items():
        kw_lower = kw.lower()
        kw_compact = kw_lower.replace(" ", "").replace("-", "").replace("_", "")
        if (kw_lower in hn or
            kw_lower in hn_normalized or
            (kw_compact and kw_compact in hn_compact)):
            return vendor, dtype

    # 2. OUI tablosu
    prefix = mac.lower()[:8]
    if prefix in OUI_TABLE:
        return OUI_TABLE[prefix]

    # 3. Locally-administered MAC → büyük ihtimalle iPhone/Android (iOS 14+ / Android 10+)
    if is_locally_administered(mac):
        return ("iPhone?", "phone")

    return ("Bilinmiyor", "unknown")
