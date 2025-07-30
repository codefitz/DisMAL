import os
import sys
import types

sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import core.api as api_mod

class DummySearch:
    def search(self, query, format="object", limit=500):
        return types.SimpleNamespace(json=lambda: [])


def test_missing_vms_calls_completage(monkeypatch):
    results = [
        {"Guest_Full_Name": "h1"},
        {"Guest_Full_Name": "h2"},
    ]

    monkeypatch.setattr(api_mod, "search_results", lambda *a, **k: results)
    monkeypatch.setattr(api_mod.access, "ping", lambda host: 0)
    monkeypatch.setattr(api_mod.socket, "gethostbyname", lambda host: "1.2.3.4")
    monkeypatch.setattr(api_mod, "output", types.SimpleNamespace(define_csv=lambda *a, **k: None))

    calls = {"n": 0}

    def fake_completage(msg, count, timer):
        calls["n"] += 1
        return timer + 1

    monkeypatch.setattr(api_mod.tools, "completage", fake_completage)

    args = types.SimpleNamespace(resolve_hostnames=True, output_file=None, target="t", output_csv=None)

    api_mod.missing_vms(DummySearch(), args, "")

    assert calls["n"] == len(results)


def test_missing_vms_enriches_from_devices(monkeypatch):
    missing = [{"Guest_Full_Name": "h1"}]

    device_info = [{
        "DA_Endpoint": "1.2.3.4",
        "Device_Hostname": "id1",
        "DA_Start": "2024-01-01 10:00:00",
        "DA_Result": "OK",
    }]

    def fake_search_results(search, query):
        if query == api_mod.queries.missing_vms:
            return missing
        if query == api_mod.queries.deviceInfo:
            return device_info
        return []

    captured = {}

    def fake_define_csv(args, header, data, *a, **k):
        captured["header"] = header
        captured["data"] = data

    monkeypatch.setattr(api_mod, "search_results", fake_search_results)
    monkeypatch.setattr(api_mod.access, "ping", lambda host: 0)
    monkeypatch.setattr(api_mod.socket, "gethostbyname", lambda host: "1.2.3.4")
    monkeypatch.setattr(api_mod, "output", types.SimpleNamespace(define_csv=fake_define_csv))
    monkeypatch.setattr(api_mod.tools, "completage", lambda *a, **k: 0)

    args = types.SimpleNamespace(resolve_hostnames=True, output_file=None, target="t", output_csv=None)

    api_mod.missing_vms(DummySearch(), args, "")

    assert captured["header"][-3:] == ["last_identity", "last_scanned", "last_result"]
    assert captured["data"][0][-3:] == ["id1", "2024-01-01 10:00:00", "OK"]
