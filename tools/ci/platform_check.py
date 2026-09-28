"""Cross-platform install check for the built wheel (used by .github/workflows/platform.yml).

Runs the installed CLI the way a new user does (`python -m narvy`, and the
`narvy` launcher by its full path since a user install is off PATH), on:
  - a web source repo with known issues, a non-cp1252 character in a flagged
    line, a berry yarn.lock and two versions of one package;
  - a real APK whose file name and directory contain spaces;
and asserts on the SARIF/JSON content, not just the exit code.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import urllib.request

APK_URL = "https://github.com/dineshshetty/Android-InsecureBankv2/raw/master/InsecureBankv2.apk"
APK_SHA256 = "b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4"

FAILURES = []


def check(cond, what):
    print(("PASS " if cond else "FAIL ") + what, flush=True)
    if not cond:
        FAILURES.append(what)


def run(args, **kw):
    print("$ " + " ".join(args), flush=True)
    env = dict(os.environ, NARVY_TELEMETRY="0", **kw.pop("env", {}))
    # Decode as the real user console would NOT: bytes, so a crash is visible here.
    p = subprocess.run(args, capture_output=True, env=env, timeout=kw.pop("timeout", 1800), **kw)
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    if p.returncode not in (0,):
        print(out[-3000:])
        print(err[-6000:])
    return p.returncode, out, err


def make_source_repo(root):
    os.makedirs(os.path.join(root, "api"), exist_ok=True)
    with open(os.path.join(root, "api", "app.py"), "w", encoding="utf-8") as f:
        f.write(
            "import sqlite3, subprocess\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "@app.route('/q')\n"
            "def q():\n"
            "    name = request.args.get('name')\n"
            "    conn = sqlite3.connect('x.db')\n"
            "    conn.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")  # Łódź ✓\n"
            "    subprocess.call('ping ' + request.args.get('h'), shell=True)\n"
            "    return 'ok'\n"
        )
    with open(os.path.join(root, "requirements.txt"), "w", encoding="utf-8") as f:
        f.write("flask==0.12\n")
    with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as f:
        f.write('{"name": "app", "dependencies": {"minimist": "^1.2.0"}}\n')
    # yarn berry lockfile, CRLF like a Windows checkout with autocrlf.
    berry = (
        "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
        '"minimist@npm:0.0.8":\n  version: 0.0.8\n  resolution: "minimist@npm:0.0.8"\n'
        "  languageName: node\n  linkType: hard\n\n"
        '"minimist@npm:^1.2.0":\n  version: 1.2.5\n  resolution: "minimist@npm:1.2.5"\n'
        "  languageName: node\n  linkType: hard\n\n"
        '"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n'
        "  languageName: unknown\n  linkType: soft\n"
    )
    with open(os.path.join(root, "yarn.lock"), "wb") as f:
        f.write(berry.replace("\n", "\r\n").encode())


def launcher_path():
    """The `narvy` launcher pip wrote for a --user install (not on PATH on purpose)."""
    name = "narvy.exe" if os.name == "nt" else "narvy"
    for scheme in (sysconfig.get_preferred_scheme("user"), None):
        d = sysconfig.get_path("scripts", scheme) if scheme else sysconfig.get_path("scripts")
        cand = os.path.join(d, name)
        if os.path.isfile(cand):
            return cand
    return None


def main():
    work = tempfile.mkdtemp(prefix="narvy ci ")  # a space in every path below
    py = sys.executable

    rc, out, _ = run([py, "-m", "narvy", "--version"])
    check(rc == 0 and out.strip().startswith("narvy "), "python -m narvy --version")

    exe = launcher_path()
    check(exe is not None, f"narvy launcher installed ({exe})")
    if exe:
        rc, out, _ = run([exe, "--version"])
        check(rc == 0, "narvy launcher by full path runs")
    check(shutil.which("narvy") is None or os.environ.get("NARVY_CI_ON_PATH") == "1",
          "user Scripts dir is off PATH (the new-user situation)")

    rc, out, err = run([py, "-m", "narvy", "doctor"])
    print(err[-3000:])

    # --- source repo ------------------------------------------------------
    src = os.path.join(work, "my repo")
    make_source_repo(src)
    sarif_path = os.path.join(work, "out dir", "results file.sarif")
    os.makedirs(os.path.dirname(sarif_path), exist_ok=True)
    rc, out, err = run([py, "-m", "narvy", "scan", src, "--output", "sarif", "--file", sarif_path])
    check(rc == 0, "source scan exit 0")
    check("execvp" not in err and "semgrep not found" not in err.lower(), "semgrep pass ran (not skipped)")
    rules = set()
    if os.path.isfile(sarif_path):
        with open(sarif_path, encoding="utf-8") as f:
            sarif = json.load(f)
        results = sarif["runs"][0]["results"]
        rules = {r["ruleId"] for r in results}
        print("source rules:", sorted(rules))
    check("formatted-sql-string-to-execute" in rules, "source: SQL injection found (semgrep)")
    check("subprocess-shell-true-with-var" in rules, "source: shell=True injection found (semgrep)")

    json_path = os.path.join(work, "out dir", "results.json")
    rc, out, err = run([py, "-m", "narvy", "scan", src, "-o", "json", "-f", json_path])
    check(rc == 0, "source scan json exit 0")
    sca = set()
    if os.path.isfile(json_path):
        with open(json_path, encoding="utf-8") as f:
            findings = json.load(f).get("findings", [])
        for x in findings:
            text = json.dumps(x)
            if "minimist@0.0.8" in text:
                sca.add("0.0.8")
            if "minimist@1.2.5" in text:
                sca.add("1.2.5")
    check(sca == {"0.0.8", "1.2.5"}, f"SCA: both minimist versions from the berry lock reported ({sorted(sca)})")

    # Console output through a pipe: the Windows cp1252 path, with a non-cp1252 snippet.
    rc, out, err = run([py, "-m", "narvy", "scan", src])
    check(rc == 0 and "Unexpected error" not in err and "UnicodeEncodeError" not in err,
          "console output through a pipe does not crash on a non-cp1252 snippet")

    # --- APK with spaces --------------------------------------------------
    apk_dir = os.path.join(work, "My Apps")
    os.makedirs(apk_dir, exist_ok=True)
    apk = os.path.join(apk_dir, "Insecure Bank v1.3.7.apk")
    urllib.request.urlretrieve(APK_URL, apk)
    with open(apk, "rb") as f:
        check(hashlib.sha256(f.read()).hexdigest() == APK_SHA256, "APK download checksum")
    # jadx and the JRE go to ~/.narvy/tools: on Windows put that home under a
    # path with a space, the case where `cmd /c jadx.bat` used to break.
    # (Windows only: on POSIX, HOME also moves the pip --user site.)
    home_env = {}
    if os.name == "nt":
        home = os.path.join(work, "Jean Dupont")
        os.makedirs(home, exist_ok=True)
        home_env = {"USERPROFILE": home}
    apk_sarif = os.path.join(work, "out dir", "apk results.sarif")
    rc, out, err = run([py, "-m", "narvy", "scan", apk, "--max-mem", "3g", "--output", "sarif",
                        "--file", apk_sarif], env=home_env, timeout=3000)
    check(rc == 0, "APK scan exit 0")
    apk_rules = set()
    n = 0
    if os.path.isfile(apk_sarif):
        with open(apk_sarif, encoding="utf-8") as f:
            res = json.load(f)["runs"][0]["results"]
        n = len(res)
        apk_rules = {r["ruleId"] for r in res}
        print("apk rules:", sorted(apk_rules))
    check(n >= 15, f"APK: >= 15 findings (Linux baseline 20), got {n}")
    check("AND-CONF-001" in apk_rules, "APK: manifest check ran")
    check("android-webview-js-enabled" in apk_rules, "APK: semgrep pass over jadx output ran")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed:")
        for f_ in FAILURES:
            print("  - " + f_)
        sys.exit(1)
    print("all platform checks passed")


if __name__ == "__main__":
    main()
