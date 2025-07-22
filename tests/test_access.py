import os
import sys
import types

sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import core.access as access

class DummyResponse:
    def __init__(self, ok=True, reason="OK"):
        self.ok = ok
        self.reason = reason
    def json(self):
        return {"api_versions": ["v1"]}

class DummyTW:
    def __init__(self, resp):
        self._resp = resp
    def about(self):
        return self._resp

def test_api_version_returns_none_on_failure(caplog):
    tw = DummyTW(DummyResponse(ok=False, reason="fail"))
    about, version = access.api_version(tw)
    assert about is None
    assert version is None
    assert "fail" in caplog.text


def test_api_target_handles_missing_about(monkeypatch):
    class DummySwagger:
        ok = True
        url = "http://x"
    class DummyAppliance:
        def swagger(self):
            return DummySwagger()
    dummy_app = DummyAppliance()
    args = types.SimpleNamespace(target="t", token="tok", f_token=None)
    monkeypatch.setattr(access, "api_version", lambda x: (None, None))
    monkeypatch.setattr(access.tideway, "appliance", lambda *a, **k: dummy_app, raising=False)
    result = access.api_target(args)
    assert result is dummy_app
