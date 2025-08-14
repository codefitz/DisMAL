import os
import sys
import types

# Stub modules that may not be installed
sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import core.api as api_mod
import core.cli as cli_mod


class DummySearch:
    def search(self, query, format="object", limit=500):
        return types.SimpleNamespace(json=lambda: [])


def test_api_orphan_vms_includes_os_type(monkeypatch):
    captured = {}

    def fake_search_results(search, query):
        captured["query"] = query
        return [
            {
                "hostname": "h1",
                "os": "Linux",
                "OS_Type": "Unix",
                "virtual": True,
                "cloud": False,
                "endpoint": "ep",
                "vendor": "v",
                "vm_class": "class",
            }
        ]

    def fake_csv_file(data, header, filename):
        captured["header"] = header
        captured["data"] = data

    monkeypatch.setattr(api_mod, "search_results", fake_search_results)
    monkeypatch.setattr(api_mod.output, "csv_file", fake_csv_file)

    args = types.SimpleNamespace(
        output_file=None,
        output_csv=None,
        output_null=False,
        output_cli=False,
        target="t",
    )

    api_mod.orphan_vms(DummySearch(), args, "")

    assert "DeviceInfo.os_type" in captured["query"]
    assert "OS_Type" in captured["header"]


def test_cli_orphan_vms_includes_os_type(monkeypatch):
    captured = {}

    def fake_run_query(client, user, passwd, query):
        captured["query"] = query
        return (
            "hostname,os,OS_Type,virtual,cloud,endpoint,vendor,vm_class\n"
            "h1,Linux,Unix,true,false,ep,v,class"
        )

    def fake_save2csv(clidata, filename, appliance):
        header = clidata.split("\n", 1)[0].split(",")
        captured["header"] = header

    monkeypatch.setattr(cli_mod, "run_query", fake_run_query)
    monkeypatch.setattr(cli_mod.output, "save2csv", fake_save2csv)

    args = types.SimpleNamespace(
        output_file=None,
        output_csv=None,
        output_null=False,
        output_cli=False,
        target="t",
    )

    cli_mod.orphan_vms(object(), args, "u", "p", "")

    assert "DeviceInfo.os_type" in captured["query"]
    assert "OS_Type" in captured["header"]

