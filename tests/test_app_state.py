"""
AntiGravity — app_state.py Birim Testleri
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.app_state import AppState


class TestAppState:
    def test_init_state(self):
        state = AppState()
        assert state.get_devices() == {}
        assert state.scanning is False
        assert state.has_isolations() is False
        assert state.has_monitor("192.168.1.5") is False

    def test_device_crud(self):
        state = AppState()
        dev_data = {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "TestDevice"}
        state.set_device("192.168.1.100", dev_data)
        
        assert state.get_device("192.168.1.100") == dev_data
        assert "192.168.1.100" in state.device_ips()

        # Update
        state.update_device("192.168.1.100", {"friendly_name": "My iPhone"})
        updated = state.get_device("192.168.1.100")
        assert updated["friendly_name"] == "My iPhone"
        assert updated["mac"] == "aa:bb:cc:dd:ee:ff"

        # Clear
        state.clear_devices()
        assert state.get_devices() == {}

    def test_isolation_crud(self):
        state = AppState()
        dummy_redirector = object()
        
        state.add_isolation("192.168.1.50", "arp", dummy_redirector)
        assert state.is_isolated("192.168.1.50") is True
        assert state.has_isolations() is True
        assert "192.168.1.50" in state.isolation_keys()

        iso = state.get_isolation("192.168.1.50")
        assert iso.get("arp") is dummy_redirector

        removed = state.remove_isolation("192.168.1.50")
        assert removed.get("arp") is dummy_redirector
        assert state.is_isolated("192.168.1.50") is False
        assert state.has_isolations() is False

    def test_monitor_crud(self):
        state = AppState()
        mon_data = {"sniffer": None, "mitm": None, "queues": []}
        state.add_monitor("192.168.1.60", mon_data)

        assert state.has_monitor("192.168.1.60") is True
        assert state.get_monitor("192.168.1.60") == mon_data
        assert len(state.monitor_items()) == 1

        state.remove_monitor("192.168.1.60")
        assert state.has_monitor("192.168.1.60") is False

    def test_device_dict_builder(self):
        state = AppState()
        entry_mock = type("MockEntry", (), {
            "mac": "84:90:0a:11:22:33",
            "hostname": "Omers-iPhone.local",
            "first_seen": "12:00:00"
        })()
        d = state.device_dict("192.168.1.75", entry_mock)
        assert d["ip"] == "192.168.1.75"
        assert d["mac"] == "84:90:0a:11:22:33"
        assert d["vendor"] in ("Apple", "iPhone")
        assert d["type"] == "phone"
