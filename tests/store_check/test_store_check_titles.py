"""Status titles: a failure is titled as a failure, citing the value read.

Engine 0.1.0 used one title per check, phrased as the passing state, for every
status ("[BLOCKER] PLAY-TARGET-SDK: Target API level meets Google Play's current
requirement"). Since 0.2.0 ``title`` is status-specific and ``requirement``
keeps the rule text."""
import json

import builders as B
from narvy.store_check.cli import main, render_text

REQ_TARGET_EN = "Target API level meets Google Play's current requirement"


def test_target_sdk_fail_and_pass_titles(run):
    res, _ = run(B.apk(B.manifest(target=33)))
    r = res["PLAY-TARGET-SDK"]
    assert r.status == "fail"
    assert r.title == {"en": "Target API 33 is below Google Play's requirement (API 36)",
                       "fr": "API cible 33 inférieure à l'exigence de Google Play (API 36)"}
    assert r.requirement["en"] == REQ_TARGET_EN
    res, _ = run(B.apk(B.manifest(target=36)))
    r = res["PLAY-TARGET-SDK"]
    assert r.status == "pass"
    assert r.title["en"] == "Target API 36 meets Google Play's requirement (API 36)"


def test_debuggable_titles(run):
    res, _ = run(B.apk(B.manifest(target=36, app_attrs={"android:debuggable": True})))
    assert res["PLAY-DEBUGGABLE"].title["en"] == "Build is debuggable (android:debuggable=true)"
    res, _ = run(B.apk(B.manifest(target=36)))
    assert res["PLAY-DEBUGGABLE"].title["en"] == "Build is not debuggable"


def test_min_os_fail_title_cites_the_value(run):
    res, _ = run(B.ipa(info={"MinimumOSVersion": "12.0"}), suffix=".ipa")
    r = res["APPSTORE-MIN-OS"]
    assert r.status == "fail"
    assert r.title["en"] == "Minimum iOS 12.0 is below App Store Connect's requirement (iOS 13)"
    assert r.title["fr"] == "iOS minimum 12.0 inférieur à l'exigence d'App Store Connect (iOS 13)"


def test_human_output_never_prints_the_requirement_as_a_failure_title(tmp_path, capsys):
    p = tmp_path / "a.apk"
    p.write_bytes(B.apk(B.manifest(target=30, app_attrs={"android:debuggable": True})))
    assert main([str(p), "--as-of", "2026-10-04"]) == 1
    out = capsys.readouterr().out
    assert "[BLOCKER] PLAY-TARGET-SDK: Target API 30 is below Google Play's requirement (API 36)" in out
    assert REQ_TARGET_EN not in out
    assert main([str(p), "--as-of", "2026-10-04", "--lang", "fr"]) == 1
    out = capsys.readouterr().out
    assert "[BLOQUANT] PLAY-TARGET-SDK: API cible 30 inférieure à l'exigence de Google Play (API 36)" in out


def test_json_keeps_title_shape_and_adds_requirement(tmp_path, capsys):
    p = tmp_path / "a.apk"
    p.write_bytes(B.apk(B.manifest(target=30)))
    main([str(p), "--json", "--as-of", "2026-10-04"])
    d = json.loads(capsys.readouterr().out)
    assert d["tool_version"] == "0.2.0"
    for r in d["results"]:
        assert set(r["title"]) == {"en", "fr"} and set(r["requirement"]) == {"en", "fr"}
        assert r["title"]["en"] != r["requirement"]["en"]
    t = next(r for r in d["results"] if r["id"] == "PLAY-TARGET-SDK")
    assert t["requirement"]["en"] == REQ_TARGET_EN
    assert t["title"]["en"].startswith("Target API 30 is below")
