import os
import sys
import types
import json

# Stub external modules before importing project modules
sys.modules.setdefault("pandas", types.SimpleNamespace())
sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("tideway", types.SimpleNamespace())
sys.modules.setdefault("paramiko", types.SimpleNamespace())
sys.modules.setdefault("core.tools", types.SimpleNamespace(dequote=lambda x: x))

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core import api, output, defaults


class DummyResponse:
    def __init__(self, status_code=200, data="{}", reason="OK", url="http://x"):
        self.status_code = status_code
        self._data = data
        self.reason = reason
        self.url = url
        self.ok = status_code == 200
        self.text = data

    def json(self):
        return json.loads(self._data)


class DummyKnowledge:
    def __init__(self, response):
        self._response = response

    @property
    def get_knowledge(self):
        return self._response


def test_api_tku_creates_csv_columns(tmp_path):
    resp = DummyResponse(
        200,
        json.dumps(
            {
                "latest_tku": {"name": "TKU-1"},
                "latest_edp": {"name": "EDP-1"},
                "latest_storage": {"name": "STOR-1"},
            }
        ),
    )
    args = types.SimpleNamespace(
        target="appl",
        output_file=None,
        output_csv=False,
        output_null=False,
        output_cli=False,
    )
    api.tku(DummyKnowledge(resp), args, str(tmp_path))
    csv_path = tmp_path / defaults.tku_filename.strip("/")
    lines = csv_path.read_text().splitlines()
    assert lines[0].split(",") == ["Discovery Instance", "TKU"]
    first = lines[1].split(",")
    assert first[0] == "appl"
    assert first[1] == "TKU-1"


def test_define_csv_adds_tku_column(tmp_path):
    clidata = "name\npattern1"
    filename = tmp_path / "out.csv"
    args = types.SimpleNamespace(
        output_file=False,
        output_csv=False,
        output_null=False,
        output_cli=False,
    )
    output.define_csv(args, None, clidata, str(filename), None, "appl", "csv", "TKU-1")
    lines = filename.read_text().splitlines()
    header = lines[0].split(",")
    assert header[0] == "Discovery Instance"
    assert header[1] == "TKU"
    row = lines[1].split(",")
    assert row[0] == "appl"
    assert row[1] == "TKU-1"
