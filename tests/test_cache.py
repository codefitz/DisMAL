import types
from core import api, cache, queries, reporting


def test_run_queries_populates_cache(tmp_path):
    cache.configure(tmp_path)

    class Search:
        def search_bulk(self, query, format="object", limit=500, offset=0):
            return [{"col": "val"}]

    args = types.SimpleNamespace(
        excavate=["credential_success"],
        output_cli=False,
        output_csv=False,
        output_file=None,
        output_null=False,
        target="app",
    )

    api.run_queries(Search(), args, tmp_path)
    assert any(p.name.startswith("credential_success_") for p in tmp_path.iterdir())


def test_successful_uses_cache(tmp_path, monkeypatch):
    cache.configure(tmp_path)
    qnames = [
        "credential_success",
        "deviceinfo_success",
        "credential_failure",
        "credential_success_7d",
        "deviceinfo_success_7d",
        "credential_failure_7d",
        "outpost_credentials",
        "scanrange",
        "excludes",
    ]
    for name in qnames:
        query = getattr(queries, name)
        cache.save(name, query, 0, [])

    monkeypatch.setattr(reporting.api, "get_json", lambda *a, **k: [])

    class Creds:
        def get_vault_credentials(self):
            return []

    class Search:
        def search_bulk(self, *a, **k):
            raise AssertionError("API should not be called when cached data is available")

    args = types.SimpleNamespace(
        target=None,
        output_cli=False,
        output_csv=False,
        output_file=None,
        output_null=False,
        reporting_dir=str(tmp_path),
        excavate=None,
    )

    reporting.successful(Creds(), Search(), args)
