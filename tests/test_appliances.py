import sys
import types
import argparse
import importlib

# Stub external dependencies before importing dismal
sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())


def test_run_appliance_list_handles_mixed_credentials(monkeypatch):
    sys.argv = ["dismal"]
    dismal = importlib.reload(importlib.import_module("dismal"))

    calls = []

    def fake_run(args):
        calls.append(args)

    monkeypatch.setattr(dismal, "run_for_args", fake_run)

    base_args = argparse.Namespace(
        target=None,
        username="base",
        password=None,
        token=None,
        f_token=None,
        f_passwd=None,
    )

    appliance_list = [
        {"target": "a1", "username": "u1", "token_file": "tok.txt"},
        {"target": "a2", "username": "u2", "password_file": "pw.txt"},
        "a3",
    ]

    dismal.run_appliance_list(appliance_list, base_args)

    assert [c.target for c in calls] == ["a1", "a2", "a3"]
    assert calls[0].f_token == "tok.txt"
    assert calls[1].f_passwd == "pw.txt"
    assert calls[2].username == "base"
