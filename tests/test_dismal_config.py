import importlib
import sys


def test_dismal_iterates_over_config(monkeypatch, multi_appliance_config):
    config_path, token_file_path = multi_appliance_config
    # Ensure dismal loads our temporary config
    monkeypatch.setattr(sys, "argv", ["dismal.py", "--config", str(config_path)])
    dismal = importlib.reload(importlib.import_module("dismal"))

    captured = []

    def fake_run(args):
        captured.append(args)

    monkeypatch.setattr(dismal, "run_for_args", fake_run)
    dismal.main()

    assert len(captured) == 2

    first, second = captured

    assert first.target == "app1"
    assert first.token == "tok1"
    assert getattr(first, "f_token", None) is None
    assert getattr(first, "password", None) is None

    assert second.target == "app2"
    assert second.token is None
    assert second.f_token == token_file_path
    assert second.password == "pw2"
