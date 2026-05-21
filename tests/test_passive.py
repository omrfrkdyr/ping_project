"""
AntiGravity — passive_sniffer.py Birim Testleri
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.passive_sniffer import (
    is_service_name,
    clean_mdns_name,
    extract_owner_from_hostname,
    parse_mdns_name_from_payload,
)


class TestIsServiceName:
    def test_service_names(self):
        assert is_service_name("_spotify-connect._tcp.local") is True
        assert is_service_name("_http._tcp.local") is True
        assert is_service_name("lb._dns-sd._udp.local") is True
        assert is_service_name("_airplay._tcp") is True

    def test_not_service_names(self):
        assert is_service_name("Omers-iPhone.local") is False
        assert is_service_name("MacBook-Pro.local") is False
        assert is_service_name("my-device") is False

    def test_edge_cases(self):
        assert is_service_name("") is False
        assert is_service_name("simple") is False


class TestCleanMdnsName:
    def test_removes_local(self):
        assert clean_mdns_name("MacBook-Pro.local") == "MacBook Pro"
        assert clean_mdns_name("Omers-iPhone.local") == "Omers iPhone"

    def test_removes_lan(self):
        assert clean_mdns_name("my-device.lan") == "my device"

    def test_removes_home(self):
        assert clean_mdns_name("desktop.home") == "desktop"

    def test_removes_service_suffixes(self):
        assert clean_mdns_name("My-Device._device-info._tcp.local") == "My Device"
        assert clean_mdns_name("printer._tcp.local") == "printer"

    def test_replaces_hyphens(self):
        assert clean_mdns_name("my-cool-device") == "my cool device"

    def test_empty_string(self):
        assert clean_mdns_name("") == ""


class TestExtractOwnerFromHostname:
    def test_iphone_owner(self):
        assert extract_owner_from_hostname("Omers-iPhone.local") == "Omers"

    def test_ipad_owner(self):
        assert extract_owner_from_hostname("Efe-s-iPad") == "Efe"

    def test_macbook_owner(self):
        assert extract_owner_from_hostname("John-MacBook-Pro.local") == "John"

    def test_galaxy_owner(self):
        assert extract_owner_from_hostname("Ali-Galaxy-S21") == "Ali"

    def test_no_owner(self):
        # Generic device names without owner prefix
        assert extract_owner_from_hostname("DESKTOP-ABC123") == ""
        assert extract_owner_from_hostname("printer") == ""
        assert extract_owner_from_hostname("") == ""

    def test_possessive_forms(self):
        assert extract_owner_from_hostname("Omer's-iPhone") == "Omer"


class TestParseMdnsNameFromPayload:
    def test_empty_payload(self):
        assert parse_mdns_name_from_payload(b"") == []

    def test_too_short(self):
        assert parse_mdns_name_from_payload(b"\x00" * 5) == []

    def test_basic_dns_query(self):
        """Minimal DNS query for 'test.local'."""
        # DNS header (12 bytes): ID=0, QD=1, AN=0, NS=0, AR=0
        header = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        # Query: 4test5local0 + QTYPE(A)=1 + QCLASS(IN)=1
        query = b'\x04test\x05local\x00\x00\x01\x00\x01'
        payload = header + query

        names = parse_mdns_name_from_payload(payload)
        assert len(names) >= 1
        assert "test.local" in names
