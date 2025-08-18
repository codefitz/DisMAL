import os
import csv
import sys
import types

sys.modules.setdefault("tabulate", types.SimpleNamespace(tabulate=lambda *a, **k: ""))
sys.modules.setdefault("core.api", types.SimpleNamespace())
sys.modules.setdefault("core.tools", types.SimpleNamespace(dequote=lambda s: s.strip('"')))

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import core.output as output

@output._timer
def decorated_plain():
    return "ok"

@output._timer()
def decorated_called():
    return "ok"

@output._timer("Report Name")
def decorated_positional():
    return "ok"

@output._timer(name="Report Name")
def decorated_keyword():
    return "ok"


def test_timer_variants(capsys, monkeypatch):
    def run(func, expected_name):
        times = [0, 1]
        monkeypatch.setattr(output.time, "time", lambda: times.pop(0))
        assert func() == "ok"
        out = capsys.readouterr().out
        assert f"Running report {expected_name}..." in out
        assert "Report completed in 1.00 seconds" in out

    run(decorated_plain, "decorated_plain")
    run(decorated_called, "decorated_called")
    run(decorated_positional, "Report Name")
    run(decorated_keyword, "Report Name")


def test_format_duration_units():
    assert output.format_duration(45) == "45.00 seconds"
    assert output.format_duration(120) == "2.00 minutes"
    assert output.format_duration(7200) == "2.00 hours"


def test_save2csv_numeric(tmp_path):
    clidata = "Consecutive Scan Failures\n-5\r\n"
    filename = tmp_path / "out.csv"
    output.save2csv(clidata, str(filename), "appliance")
    with open(filename, newline="") as fh:
        row = next(csv.DictReader(fh))
    assert int(row["Consecutive Scan Failures"]) == -5
