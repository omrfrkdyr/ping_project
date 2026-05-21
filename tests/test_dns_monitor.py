"""
AntiGravity — dns_monitor.py Birim Testleri
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.dns_monitor import _parse_tls_sni, _is_cdn_or_tracker, _now_str


class TestParseTlsSni:
    def test_valid_client_hello(self):
        """El ile oluşturulmuş minimal TLS ClientHello SNI payload'u."""
        # TLS Record: ContentType=22 (Handshake)
        # Version: TLS 1.0 (0x0301)
        # Handshake Type: ClientHello (1)
        # SNI Extension (type=0x0000) with hostname "example.com"
        hostname = b"example.com"
        sni_entry = (
            b'\x00'          # Name type: host_name (0)
            + len(hostname).to_bytes(2, 'big')
            + hostname
        )
        sni_list = len(sni_entry).to_bytes(2, 'big') + sni_entry
        sni_ext = (
            b'\x00\x00'     # Extension type: server_name (0)
            + len(sni_list).to_bytes(2, 'big')
            + sni_list
        )
        extensions = len(sni_ext).to_bytes(2, 'big') + sni_ext

        # Minimal ClientHello fields
        client_hello_body = (
            b'\x03\x03'     # Client version: TLS 1.2
            + b'\x00' * 32  # Random (32 bytes)
            + b'\x00'       # Session ID length: 0
            + b'\x00\x02\x00\xff'  # Cipher suites
            + b'\x01\x00'   # Compression methods
            + extensions
        )

        handshake = (
            b'\x01'          # Handshake type: ClientHello
            + len(client_hello_body).to_bytes(3, 'big')
            + client_hello_body
        )

        tls_record = (
            b'\x16'          # ContentType: Handshake
            + b'\x03\x01'   # Version: TLS 1.0
            + len(handshake).to_bytes(2, 'big')
            + handshake
        )

        result = _parse_tls_sni(tls_record)
        assert result == "example.com"

    def test_not_tls(self):
        """TLS olmayan payload → None."""
        assert _parse_tls_sni(b"GET / HTTP/1.1\r\n") is None
        assert _parse_tls_sni(b"") is None
        assert _parse_tls_sni(b"\x00\x00\x00") is None

    def test_too_short(self):
        """Çok kısa payload → None."""
        assert _parse_tls_sni(b"\x16\x03\x01") is None


class TestIsCdnOrTracker:
    def test_cdn_domains(self):
        # Function uses endswith matching on known CDN domain suffixes
        assert _is_cdn_or_tracker("ads.doubleclick.net") is True
        assert _is_cdn_or_tracker("fonts.gstatic.com") is True
        assert _is_cdn_or_tracker("example.akamaiedge.net") is True
        assert _is_cdn_or_tracker("something.cloudflare.com") is True

    def test_normal_domains(self):
        assert _is_cdn_or_tracker("www.google.com") is False
        assert _is_cdn_or_tracker("github.com") is False
        assert _is_cdn_or_tracker("example.com") is False

    def test_edge_cases(self):
        assert _is_cdn_or_tracker("") is False
        assert _is_cdn_or_tracker("a") is False


class TestNowStr:
    def test_returns_string(self):
        result = _now_str()
        assert isinstance(result, str)
        assert ":" in result
