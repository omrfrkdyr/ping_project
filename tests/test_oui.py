"""
AntiGravity — oui_table.py Birim Testleri
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.oui_table import get_vendor, is_locally_administered, HOSTNAME_HINTS


class TestIsLocallyAdministered:
    def test_la_bit_set(self):
        # 0x02 bit set → locally administered
        assert is_locally_administered("02:00:00:00:00:00") is True
        assert is_locally_administered("0a:11:22:33:44:55") is True
        assert is_locally_administered("36:6f:9b:00:00:00") is True

    def test_la_bit_not_set(self):
        assert is_locally_administered("00:00:00:00:00:00") is False
        assert is_locally_administered("84:90:0a:11:22:33") is False
        assert is_locally_administered("20:e8:82:00:00:00") is False

    def test_invalid_mac(self):
        assert is_locally_administered("") is False
        assert is_locally_administered("invalid") is False
        assert is_locally_administered("zz:zz:zz:zz:zz:zz") is False


class TestGetVendor:
    def test_known_oui_apple(self):
        vendor, dtype = get_vendor("84:90:0a:11:22:33")
        assert vendor == "Apple"
        assert dtype == "phone"

    def test_known_oui_router(self):
        vendor, dtype = get_vendor("20:e8:82:ab:cd:ef")
        assert vendor == "Router"
        assert dtype == "router"

    def test_known_oui_samsung_tv(self):
        vendor, dtype = get_vendor("7c:1c:4e:ab:cd:ef")
        assert vendor == "Samsung TV"
        assert dtype == "tv"

    def test_unknown_mac(self):
        # ff:ff:ff:ff:ff:ff has LA bit set, so it returns 'iPhone?'
        vendor, dtype = get_vendor("00:11:22:33:44:55")
        assert vendor == "Bilinmiyor"
        assert dtype == "unknown"

    def test_locally_administered(self):
        # LA bit set, no OUI match → iPhone?
        vendor, dtype = get_vendor("36:6f:9b:ab:cd:ef")
        assert vendor == "iPhone?"
        assert dtype == "phone"

    def test_hostname_overrides_oui(self):
        # Hostname hint should take priority
        vendor, dtype = get_vendor("ff:ff:ff:ff:ff:ff", hostname="Omers-iPhone")
        assert vendor == "iPhone"
        assert dtype == "phone"

    def test_hostname_macbook(self):
        vendor, dtype = get_vendor("ff:ff:ff:ff:ff:ff", hostname="MacBook-Pro.local")
        assert vendor == "MacBook"
        assert dtype == "laptop"

    def test_hostname_samsung(self):
        vendor, dtype = get_vendor("ff:ff:ff:ff:ff:ff", hostname="samsung-galaxy-s21")
        assert vendor == "Samsung"
        assert dtype == "phone"

    def test_hostname_android(self):
        vendor, dtype = get_vendor("ff:ff:ff:ff:ff:ff", hostname="android-abc123")
        assert vendor == "Android"
        assert dtype == "phone"


class TestHostnameHints:
    def test_all_hints_have_tuple(self):
        for kw, (vendor, dtype) in HOSTNAME_HINTS.items():
            assert isinstance(kw, str)
            assert isinstance(vendor, str)
            assert dtype in ("phone", "laptop", "tv")
