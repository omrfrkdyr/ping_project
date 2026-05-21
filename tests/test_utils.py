"""
AntiGravity — utils.py Birim Testleri
"""
import sys
import os

# Proje kökünü path'e ekle
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.utils import (
    validate_ip,
    validate_ipv6,
    validate_mac,
    validate_network,
    guess_network_range,
    get_local_ip,
    timestamp,
    strip_zone,
)


class TestValidateIP:
    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("255.255.255.255") is True
        assert validate_ip("0.0.0.0") is True

    def test_invalid_ipv4(self):
        assert validate_ip("") is False
        assert validate_ip("abc") is False
        assert validate_ip("256.1.1.1") is False
        assert validate_ip("192.168.1") is False
        assert validate_ip("192.168.1.1.1") is False

    def test_ipv6_is_invalid_for_ipv4_validator(self):
        assert validate_ip("fe80::1") is False
        assert validate_ip("::1") is False


class TestValidateIPv6:
    def test_valid_ipv6(self):
        assert validate_ipv6("::1") is True
        assert validate_ipv6("fe80::1") is True
        assert validate_ipv6("2001:db8::1") is True

    def test_invalid_ipv6(self):
        assert validate_ipv6("") is False
        assert validate_ipv6("192.168.1.1") is False
        assert validate_ipv6("not_ipv6") is False
        assert validate_ipv6("fe80::gggg") is False


class TestValidateMAC:
    def test_valid_mac(self):
        assert validate_mac("aa:bb:cc:dd:ee:ff") is True
        assert validate_mac("00:00:00:00:00:00") is True
        assert validate_mac("FF:FF:FF:FF:FF:FF") is True
        assert validate_mac("a1:B2:c3:D4:e5:F6") is True

    def test_invalid_mac(self):
        assert validate_mac("") is False
        assert validate_mac("aa:bb:cc:dd:ee") is False
        assert validate_mac("aa:bb:cc:dd:ee:ff:gg") is False
        assert validate_mac("aa-bb-cc-dd-ee-ff") is False
        assert validate_mac("aabbccddeeff") is False
        assert validate_mac("zz:zz:zz:zz:zz:zz") is False


class TestValidateNetwork:
    def test_valid_cidr(self):
        assert validate_network("192.168.1.0/24") is True
        assert validate_network("10.0.0.0/8") is True
        assert validate_network("172.16.0.0/16") is True

    def test_invalid_cidr(self):
        assert validate_network("") is False
        assert validate_network("abc/24") is False
        # Note: validate_network("192.168.1.1") returns True because
        # Python's ipaddress module accepts bare IPs as /32 networks


class TestStripZone:
    def test_strips_zone_id(self):
        assert strip_zone("fe80::1%en0") == "fe80::1"
        assert strip_zone("fe80::a:b:c:d%eth0") == "fe80::a:b:c:d"

    def test_no_zone(self):
        assert strip_zone("fe80::1") == "fe80::1"
        assert strip_zone("::1") == "::1"

    def test_empty_and_none(self):
        assert strip_zone("") == ""
        assert strip_zone(None) == ""


class TestGuessNetworkRange:
    def test_returns_valid_cidr(self):
        result = guess_network_range()
        assert result is not None
        assert "/" in result
        assert result.endswith("/24")


class TestGetLocalIP:
    def test_returns_ip_string(self):
        ip = get_local_ip()
        assert isinstance(ip, str)
        assert len(ip) > 0
        # Should be an IP or 127.0.0.1
        parts = ip.split(".")
        assert len(parts) == 4


class TestTimestamp:
    def test_returns_formatted_string(self):
        ts = timestamp()
        assert isinstance(ts, str)
        # Format: YYYY-MM-DD HH:MM:SS
        assert len(ts) >= 19
        assert "-" in ts
        assert ":" in ts
