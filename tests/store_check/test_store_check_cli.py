import json

import builders as B
from narvy.store_check.cli import main


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_exit_codes(tmp_path, capsys):
    ok = _write(tmp_path, "ok.apk", B.apk(B.manifest(target=36)))
    bad = _write(tmp_path, "bad.apk", B.apk(B.manifest(target=36, app_attrs={"android:debuggable": True})))
    warn = _write(tmp_path, "warn.apk", B.apk(B.manifest(target=36, app_attrs={"android:usesCleartextTraffic": True})))
    junk = _write(tmp_path, "junk.apk", b"junk")
    assert main([ok, "--as-of", "2026-10-04"]) == 0
    assert main([bad, "--as-of", "2026-10-04"]) == 1
    assert main([warn, "--as-of", "2026-10-04"]) == 0
    assert main([warn, "--as-of", "2026-10-04", "--fail-on", "warning"]) == 1
    assert main([junk]) == 2
    capsys.readouterr()


def test_json_has_both_languages_and_doc_links(tmp_path, capsys):
    p = _write(tmp_path, "a.apk", B.apk(B.manifest(target=30)))
    main([p, "--json", "--as-of", "2026-10-04"])
    d = json.loads(capsys.readouterr().out)
    assert d["platform"] == "android" and d["as_of"] == "2026-10-04"
    assert len(d["input"]["sha256"]) == 64
    for r in d["results"]:
        assert r["message"]["en"] and r["message"]["fr"] and r["title"]["fr"]
        assert r["doc_url"].startswith("https://")
        assert r["status"] in ("fail", "pass", "not_determined", "not_applicable")
        assert r["severity"] in ("blocker", "warning", "info")


def test_human_output_fr(tmp_path, capsys):
    p = _write(tmp_path, "a.ipa", B.ipa(info={"MinimumOSVersion": "12.0"}))
    main([p, "--lang", "fr", "--as-of", "2026-10-04"])
    out = capsys.readouterr().out
    assert "BLOQUANT" in out and "APPSTORE-MIN-OS" in out and "PAS PRÊT" in out


def test_json_error(tmp_path, capsys):
    p = _write(tmp_path, "x.zip", B.split_set({"readme.txt": b"hi"}))
    assert main([p, "--json"]) == 2
    assert "error" in json.loads(capsys.readouterr().out)


def test_french_messages_have_no_em_dash():
    """House style: no em dash in French text."""
    import inspect

    from narvy.store_check import cli
    from narvy.store_check.android import checks as ac
    from narvy.store_check.ios import checks as ic
    for mod in (ac, ic, cli):
        assert "\u2014" not in inspect.getsource(mod)


# --------------------------------------------------------------- summary plurals (1.2.2)
import pytest as _pytest  # noqa: E402

from narvy.store_check.cli import count_label  # noqa: E402


@_pytest.mark.parametrize("lang,key,n,text", [
    ("en", "blocker", 0, "0 blockers"), ("en", "blocker", 1, "1 blocker"), ("en", "blocker", 2, "2 blockers"),
    ("en", "warning", 1, "1 warning"), ("en", "warning", 3, "3 warnings"), ("en", "info", 2, "2 info"),
    ("en", "not_determined", 2, "2 not determined"),
    ("fr", "blocker", 0, "0 bloquant"), ("fr", "blocker", 1, "1 bloquant"), ("fr", "blocker", 2, "2 bloquants"),
    ("fr", "warning", 1, "1 avertissement"), ("fr", "warning", 2, "2 avertissements"),
    ("fr", "info", 1, "1 information"), ("fr", "info", 4, "4 informations"),
    ("fr", "not_determined", 1, "1 non déterminé"), ("fr", "not_determined", 2, "2 non déterminés"),
])
def test_summary_counts_use_real_plurals(lang, key, n, text):
    assert count_label(lang, key, n) == text


def test_summary_line_has_no_parenthesised_plural():
    from narvy.store_check import cli as C
    from narvy.store_check.model import Report
    rep = Report("x", "a.apk", "0" * 64, "android", "apk", "2026-10-09", {"id": "a"}, [])
    for lang in ("en", "fr"):
        out = C.render_text(rep, lang)
        assert "(s)" not in out, out
    assert "Résumé : 0 bloquant, 0 avertissement, 0 information, 0 non déterminé" in C.render_text(rep, "fr")
    assert "Summary: 0 blockers, 0 warnings, 0 info, 0 not determined" in C.render_text(rep, "en")
