"""`narvy store-check`: wiring into the narvy command, exit codes, no telemetry,
and the engine kept byte-identical to the copy the hosted service runs."""
import hashlib
import json
import os
import subprocess
import sys

import pytest

import builders as B
import narvy.store_check as engine
from narvy import telemetry

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HOSTED_COPY = os.path.join(os.environ.get("NARVY_HOSTED_ENGINE_DIR", os.path.join(os.path.expanduser("~"), "titanshield")),
                           "src", "store_check")


def _narvy(*args):
    env = dict(os.environ, NARVY_TELEMETRY="0", PYTHONPATH=REPO)
    return subprocess.run([sys.executable, "-m", "narvy", "store-check", *args],
                          cwd=REPO, env=env, capture_output=True, text=True, timeout=120)


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_exit_codes(tmp_path):
    ok = _write(tmp_path, "ok.apk", B.apk(B.manifest(target=36)))
    bad = _write(tmp_path, "bad.apk", B.apk(B.manifest(target=36, app_attrs={"android:debuggable": True})))
    warn = _write(tmp_path, "warn.apk", B.apk(B.manifest(target=36, app_attrs={"android:usesCleartextTraffic": True})))
    junk = _write(tmp_path, "junk.ipa", b"junk")
    assert _narvy(ok, "--as-of", "2026-10-04").returncode == 0
    assert _narvy(bad, "--as-of", "2026-10-04").returncode == 1
    assert _narvy(warn, "--as-of", "2026-10-04").returncode == 0
    assert _narvy(warn, "--as-of", "2026-10-04", "--fail-on", "warning").returncode == 1
    r = _narvy(junk)
    assert r.returncode == 3 and "store-check: error:" in r.stderr
    assert _narvy(str(tmp_path / "missing.apk")).returncode == 3
    assert _narvy(ok, "--as-of", "2026-13-01").returncode == 3
    assert _narvy(ok, "--lang", "de").returncode == 3


def test_json_and_french_output(tmp_path):
    bad = _write(tmp_path, "bad.apk", B.apk(B.manifest(target=30)))
    r = _narvy(bad, "--json", "--as-of", "2026-10-04")
    d = json.loads(r.stdout)
    assert d["tool"] == "narvy-store-check" and d["platform"] == "android"
    by = {x["id"]: x for x in d["results"]}
    assert by["PLAY-TARGET-SDK"]["status"] == "fail" and by["PLAY-TARGET-SDK"]["severity"] == "blocker"
    assert by["PLAY-TARGET-SDK"]["message"]["fr"]
    r = _narvy(bad, "--lang", "fr", "--as-of", "2026-10-04")
    assert "[BLOQUANT] PLAY-TARGET-SDK" in r.stdout and "PAS PRÊT" in r.stdout and "Résumé : " in r.stdout


def test_listed_in_top_level_help():
    env = dict(os.environ, NARVY_TELEMETRY="0", PYTHONPATH=REPO)
    r = subprocess.run([sys.executable, "-m", "narvy", "--help"], cwd=REPO, env=env,
                       capture_output=True, text=True, timeout=60)
    assert "store-check" in r.stdout


def test_store_check_sends_no_telemetry():
    assert "store-check" not in telemetry.COMMANDS


def _tree_digest(root):
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for n in sorted(f for f in filenames if f.endswith(".py")):
            p = os.path.join(dirpath, n)
            h.update(os.path.relpath(p, root).replace(os.sep, "/").encode() + b"\0")
            with open(p, "rb") as fh:
                h.update(fh.read() + b"\0")
    return h.hexdigest()


def test_engine_is_byte_identical_to_the_hosted_copy():
    if not os.path.isdir(HOSTED_COPY):
        pytest.skip("hosted engine checkout not present on this machine")
    cli = os.path.dirname(os.path.abspath(engine.__file__))
    assert _tree_digest(cli) == _tree_digest(HOSTED_COPY), f"narvy/store_check drifted from {HOSTED_COPY}"
