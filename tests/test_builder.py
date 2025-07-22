import os
import sys
import types

sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import core.builder as builder


class DummyResponse:
    status_code = 401
    ok = False
    reason = "Unauthorized"
    url = "http://x"

    def json(self):
        return {}


class DummySearch:
    def search(self, query, format="object", limit=500):
        return DummyResponse()


def test_overlapping_handles_bad_api(monkeypatch):
    called = {}

    def fake_report(data, headers, args):
        called["ran"] = True

    monkeypatch.setattr(builder, "output", types.SimpleNamespace(report=fake_report))
    args = types.SimpleNamespace(output_csv=False, output_file=None)

    # Should not raise even though API call fails
    builder.overlapping(DummySearch(), args)

    # If the function returned early, fake_report won't be called
    assert "ran" not in called

