"""Proof that an analysis writes nothing to disk and opens no network connection.

The CLI runs in a child interpreter with a PEP 578 audit hook installed before
the package is imported. The hook records every file open with a write/create
flag, every filesystem mutation and every socket operation. The test also
compares the content of the temp directory and the working directory before
and after the run. The interpreter runs with -B so that Python's own bytecode
cache is not mistaken for a write by the tool.
"""
import json
import os
import subprocess
import sys
import tempfile

import pytest

import builders as B
import narvy.store_check as _pkg

# Directory to put on PYTHONPATH so the child interpreter imports this package.
IMPORT_ROOT = os.path.dirname(os.path.abspath(_pkg.__file__))
for _ in range(_pkg.__name__.count(".") + 1):
    IMPORT_ROOT = os.path.dirname(IMPORT_ROOT)

HOOK = r"""
import os, sys, json
events = []
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
MUTATING = {"os.mkdir", "os.rmdir", "os.remove", "os.rename", "os.replace", "os.symlink", "os.link",
            "os.truncate", "os.chmod", "os.chown", "os.utime", "shutil.copyfile", "shutil.copytree",
            "shutil.move", "shutil.rmtree", "shutil.make_archive", "shutil.unpack_archive",
            "tempfile.mkstemp", "tempfile.mkdtemp", "zipfile.ZipFile.extract"}
NETWORK_PREFIXES = ("socket.", "urllib.", "http.client.", "ftplib.", "smtplib.", "ssl.")
def hook(event, args):
    if event == "open":
        path, mode, flags = args
        if isinstance(path, int):
            return
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & WRITE_FLAGS):
            events.append(["write-open", str(path), str(mode), flags])
    elif event in MUTATING:
        events.append(["fs", event, repr(args)[:200]])
    elif event.startswith(NETWORK_PREFIXES):
        events.append(["net", event, repr(args)[:200]])
sys.addaudithook(hook)
from narvy.store_check.cli import main
import contextlib, io
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    code = main(sys.argv[1:])
sys.stderr.write(json.dumps({"code": code, "events": events}))
"""


def _snapshot(*dirs):
    out = set()
    for d in dirs:
        for root, dnames, fnames in os.walk(d):
            for n in dnames + fnames:
                p = os.path.join(root, n)
                try:
                    st = os.stat(p)
                    out.add((p, st.st_size, st.st_mtime_ns))
                except OSError:
                    pass
    return out


def _run_isolated(path, extra_args=()):
    tmp = tempfile.gettempdir()
    cwd = tempfile.mkdtemp(prefix="nsc-cwd-")
    before = _snapshot(tmp)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    env["PYTHONPATH"] = IMPORT_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-B", "-c", HOOK, path, "--json", *extra_args],
                          cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    after = _snapshot(tmp)
    report = json.loads(proc.stderr.strip().splitlines()[-1])
    new_in_cwd = os.listdir(cwd)
    os.rmdir(cwd)
    return report, before, after, new_in_cwd


def _fixtures(tmp_path):
    files = {}
    files["apk"] = B.apk(B.manifest(app_attrs={"android:networkSecurityConfig": ("ref", 0x7F010000)}),
                         files={"resources.arsc": B.arsc({0x7F010000: ("file", "res/xml/n.xml")}),
                                "res/xml/n.xml": B.axml(B.E("network-security-config")),
                                "lib/arm64-v8a/libx.so": B.elf64([0x1000])})
    files["aab"] = B.aab(B.manifest(), files={"base/lib/arm64-v8a/libx.so": B.elf64([0x4000])})
    files["xapk"] = B.split_set({"base.apk": B.apk(B.manifest())})
    files["ipa"] = B.ipa(files=B.framework("Alamofire", B.macho(imports=["_stat"], selectors=["systemUptime"])))
    paths = []
    for ext, data in files.items():
        p = tmp_path / f"in.{ext}"
        p.write_bytes(data)
        paths.append(str(p))
    return paths


def _assert_clean(report, before, after, new_in_cwd):
    writes = [e for e in report["events"] if e[0] in ("write-open", "fs")]
    net = [e for e in report["events"] if e[0] == "net"]
    assert writes == [], writes
    assert net == [], net
    # The temp dir may change because of other processes on the machine; only
    # entries that look like ours would matter, and there must be none.
    created = {p for p, _s, _m in after} - {p for p, _s, _m in before}
    assert not [p for p in created if "narvy" in p.lower() or "nsc" in os.path.basename(p).lower()], created
    assert new_in_cwd == []


def test_no_writes_no_network_synthetic(tmp_path):
    for p in _fixtures(tmp_path):
        report, before, after, new_in_cwd = _run_isolated(p)
        assert report["code"] in (0, 1)
        _assert_clean(report, before, after, new_in_cwd)


CORPUS = os.environ.get("NARVY_STORE_CHECK_CORPUS", "/nonexistent")
REAL = [p for p in (os.path.join(CORPUS, n) for n in ("com.whatsapp.xapk", "DVIA-v2.ipa", "aabs/fcc.aab"))
        if os.path.exists(p)]


@pytest.mark.real
@pytest.mark.skipif(not REAL, reason="real binaries not present on this machine")
@pytest.mark.parametrize("path", REAL)
def test_no_writes_no_network_real(path):
    report, before, after, new_in_cwd = _run_isolated(path)
    assert report["code"] in (0, 1)
    _assert_clean(report, before, after, new_in_cwd)


def test_hook_detects_writes(tmp_path):
    """Guard against a hook that silently records nothing."""
    code = HOOK.replace("from narvy.store_check.cli import main",
                        "open(%r, 'w').write('x')\nimport tempfile; tempfile.mkdtemp()\nfrom narvy.store_check.cli import main"
                        % str(tmp_path / "probe.txt"))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    env["PYTHONPATH"] = IMPORT_ROOT
    p = tmp_path / "in.apk"
    p.write_bytes(B.apk(B.manifest()))
    proc = subprocess.run([sys.executable, "-B", "-c", code, str(p), "--json"], capture_output=True, text=True)
    report = json.loads(proc.stderr.strip().splitlines()[-1])
    kinds = {e[0] for e in report["events"]}
    assert "write-open" in kinds and "fs" in kinds
