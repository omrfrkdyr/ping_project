"""
AntiGravity — web_app.py API Endpoint Testleri
"""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from web_app import app, state


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestWebAPI:
    def test_status_endpoint(self, client):
        res = client.get("/api/status")
        assert res.status_code == 200
        data = res.get_json()
        assert "local_ip" in data
        assert "scanning" in data
        assert "device_count" in data
        assert "isolated" in data

    def test_devices_endpoint(self, client):
        state.clear_devices()
        state.set_device("192.168.1.10", {
            "ip": "192.168.1.10",
            "mac": "24:18:c6:11:22:33",
            "hostname": "Test-MacBook",
            "friendly_name": "Test MacBook",
            "vendor": "Apple",
            "type": "laptop",
        })
        res = client.get("/api/devices")
        assert res.status_code == 200
        devices = res.get_json()
        assert len(devices) >= 1
        assert any(d["ip"] == "192.168.1.10" for d in devices)

    def test_mac_to_ipv6_endpoint(self, client):
        res = client.get("/api/mac-to-ipv6?mac=24:18:c6:d2:1c:e6")
        assert res.status_code == 200
        data = res.get_json()
        assert "ipv6" in data
        assert data["ipv6"].startswith("fe80::")

    def test_neighbor_cache_endpoint(self, client):
        res = client.get("/api/neighbor-cache")
        assert res.status_code == 200
        data = res.get_json()
        assert "ok" in data
        assert data["ok"] is True
        assert "lines" in data

    def test_isolate_validation(self, client):
        # Missing parameters
        res = client.post("/api/isolate", json={})
        assert res.status_code == 400

        # Invalid IP
        res = client.post("/api/isolate", json={"ip": "999.999.999.999", "mac": "aa:bb:cc:dd:ee:ff"})
        assert res.status_code == 400

        # Invalid MAC
        res = client.post("/api/isolate", json={"ip": "192.168.1.55", "mac": "invalid-mac"})
        assert res.status_code == 400

    def test_ndp_start_validation(self, client):
        # Missing fields
        res = client.post("/api/expert/ndp-start", json={})
        assert res.status_code == 400
