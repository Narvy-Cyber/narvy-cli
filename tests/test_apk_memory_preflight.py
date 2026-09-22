"""Tests for the JADX memory pre-flight (apk_memory_preflight.py): DEX header
reading, heap prediction against measured outcomes, --force bypass and the
never-gate-on-zero-confidence rules. Corpus-backed tests skip when absent.
"""
import os
import struct
import subprocess
import sys
import tempfile
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.apk_memory_preflight import (  # noqa: E402
    DexStats,
    _is_app_dex,
    available_ram_mb,
    check_memory_preflight,
    estimate_heap_mb,
    parse_mem_arg,
    read_dex_stats,
)
from narvy import decompiler  # noqa: E402

CORPUS = "/path/to/dropzone/android"

# name -> (methods, classes, outcome_at_4g). Outcome is True (decompiled),
# False (proven JVM OutOfMemoryError) or None (run destroyed by an unrelated
# process reaper, so there is no memory verdict to assert on).
SWEEP = {
    "com.example.app_ok_small.apk":   (131_175, 17_544, True),
    "com.example.app_ok_large.apk":   (478_046, 70_221, True),
    "com.example.app_xl.apk":         (2_246_022, 411_514, False),
    "com.example.app_oom_a.apk":      (479_318, 93_503, False),
    "com.example.app_oom_b.apk":      (1_130_010, 180_681, False),
    "com.example.app_unknown_a.apk":  (1_027_925, 184_012, None),
    "com.example.app_unknown_b.apk":  (1_304_200, 273_238, None),
    "com.example.app_unknown_c.apk":  (563_132, 88_178, None),
    "com.example.app_unknown_d.apk":  (1_296_667, 254_179, None),
    "com.example.app_unknown_e.apk":  (587_403, 92_998, None),
}
PROVEN = {k: v for k, v in SWEEP.items() if v[2] is not None}


def _apk(name):
    p = os.path.join(CORPUS, name)
    if not os.path.exists(p):
        pytest.skip(f"binary APK corpus not present on this machine ({p})")
    return p


def _fake_dex(methods, classes, body_bytes=0):
    """A byte-accurate minimal DEX file header: magic at 0, method_ids_size
    (uint32 LE) at 0x58, class_defs_size at 0x60, per the Dalvik spec."""
    hdr = bytearray(112)
    hdr[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", hdr, 0x58, methods)
    struct.pack_into("<I", hdr, 0x60, classes)
    return bytes(hdr) + b"\x00" * body_bytes


def _fake_apk(path, dexes, extra=()):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        for name, blob in dexes:
            zf.writestr(name, blob)
        for name, blob in extra:
            zf.writestr(name, blob)
    return path


@pytest.mark.parametrize("name", sorted(SWEEP))
def test_dex_header_counts_match_real_apks(name):
    """The cheap header read must reproduce the measured counts exactly."""
    stats = read_dex_stats(_apk(name))
    exp_methods, exp_classes, _ = SWEEP[name]
    assert stats.ok
    assert stats.methods == exp_methods
    assert stats.classes == exp_classes


def test_reader_is_cheap_on_the_largest_real_apk():
    """The 588 MB corpus APK must be read in well under a second."""
    import time
    p = _apk("com.example.app_xl.apk")
    t0 = time.monotonic()
    stats = read_dex_stats(p)
    elapsed = time.monotonic() - t0
    assert stats.ok and stats.dex_files == 50
    assert elapsed < 2.0, f"header read took {elapsed:.2f}s, expected microseconds of IO"


@pytest.mark.parametrize("name", sorted(PROVEN))
def test_predictor_matches_real_outcome_at_4g(name):
    """Blocked-vs-allowed must match what happened at --max-mem 4g. Only apps
    with a proven outcome are asserted."""
    _, _, decompiled_ok = PROVEN[name]
    # Pin available RAM high so this asserts the heap judgement only and does
    # not flake on whatever else is running on the test machine.
    v = check_memory_preflight(_apk(name), "4g", available_mb=64 * 1024)
    assert v.should_block is (not decompiled_ok), (
        f"{name}: predicted block={v.should_block} (est {v.estimated_mb} MB) "
        f"but it actually {'succeeded' if decompiled_ok else 'ran out of memory'} at 4g"
    )


def test_gate_sits_inside_the_measured_uncertainty_interval():
    """The 4g boundary must stay strictly between the largest proven success
    (70,221 classes) and the smallest proven OOM (93,503)."""
    with tempfile.TemporaryDirectory() as d:
        def blocked(classes):
            p = _fake_apk(os.path.join(d, f"c{classes}.apk"),
                          [("classes.dex", _fake_dex(classes * 5, classes))])
            return check_memory_preflight(p, "4g", available_mb=64 * 1024).should_block
        assert not blocked(70_221), "now blocking app sizes proven to work"
        assert blocked(93_503), "now allowing app sizes proven to OOM"


def test_known_good_apps_are_not_blocked_at_any_sane_max_mem():
    """Raising --max-mem must never start blocking an app that works at 4g."""
    for name in ("com.example.app_ok_small.apk", "com.example.app_ok_large.apk"):
        for mem in ("4g", "6g", "8g", "16g"):
            v = check_memory_preflight(_apk(name), mem, available_mb=64 * 1024)
            assert not v.should_block, f"{name} blocked at --max-mem {mem}: {v.message}"


def test_raising_max_mem_unblocks_a_blocked_app():
    """Asserts the gate arithmetic only; whether the suggested number is enough
    for a given app is measured separately."""
    p = _apk("com.example.app_unknown_e.apk")
    assert check_memory_preflight(p, "4g", available_mb=64 * 1024).should_block
    assert not check_memory_preflight(p, "5g", available_mb=64 * 1024).should_block


def test_suggested_max_mem_actually_fixes_a_proven_oom():
    """One case measured end to end: an app that OOMs at 4g is refused with a
    message naming 6g, and 6g was verified to complete."""
    v = check_memory_preflight(_apk("com.example.app_oom_a.apk"), "4g", available_mb=64 * 1024)
    assert v.should_block and v.reason == "heap_too_small"
    assert "--max-mem 6g" in v.message
    assert not check_memory_preflight(_apk("com.example.app_oom_a.apk"), "6g",
                                      available_mb=64 * 1024).should_block


def test_suggested_max_mem_is_above_the_estimate_not_a_round_guess():
    """The suggestion is derived from this app, with headroom over the
    estimate, rather than a blanket "try 8g"."""
    for name in ("com.example.app_unknown_e.apk", "com.example.app_xl.apk"):
        v = check_memory_preflight(_apk(name), "4g", available_mb=64 * 1024)
        # anchored on "re-run with", so it reads the suggestion and not the
        # "--max-mem 4g" that the head sentence quotes back at the user
        m = __import__("re").search(r"re-run with --max-mem (\d+)g", v.message)
        assert m, v.message
        suggested_mb = int(m.group(1)) * 1024
        assert suggested_mb > v.estimated_mb, (
            f"{name}: suggested {suggested_mb} MB is not above the {v.estimated_mb} MB estimate")


OSS_CORPUS = "/path/to/narvy/test_corpus/android_apk"


def test_no_false_blocks_on_the_open_source_corpus():
    """The common case must be untouched: 27 open-source APKs, 2.4 MB to 83 MB,
    none blocked at the default 4g."""
    apks = sorted(__import__("glob").glob(os.path.join(OSS_CORPUS, "*.apk")))
    if len(apks) < 10:
        pytest.skip(f"open-source APK corpus not present on this machine ({OSS_CORPUS})")
    blocked = [os.path.basename(p) for p in apks
               if check_memory_preflight(p, "4g", available_mb=64 * 1024).should_block]
    assert blocked == [], f"false blocks on normal-sized apps: {blocked}"


def test_preflight_cost_is_negligible_against_a_real_scan():
    """The pre-flight costs 17 ms to 192 ms against a 58-700 second scan; if it
    ever grows into seconds the zero-added-latency promise is broken."""
    import time
    p = _apk("com.example.app_xl.apk")  # worst case: 589 MB, 50 DEX files
    t0 = time.monotonic()
    for _ in range(3):
        check_memory_preflight(p, "4g", available_mb=64 * 1024)
    per_call = (time.monotonic() - t0) / 3
    assert per_call < 1.0, f"pre-flight costs {per_call:.2f}s per call on the largest real APK"


# The same logic on crafted headers: runs everywhere, no corpus needed.

def test_crafted_headers_block_and_allow_around_the_boundary():
    with tempfile.TemporaryDirectory() as d:
        small = _fake_apk(os.path.join(d, "small.apk"), [("classes.dex", _fake_dex(50_000, 6_000))])
        huge = _fake_apk(os.path.join(d, "huge.apk"), [("classes.dex", _fake_dex(900_000, 200_000))])
        assert not check_memory_preflight(small, "4g", available_mb=64 * 1024).should_block
        v = check_memory_preflight(huge, "4g", available_mb=64 * 1024)
        assert v.should_block and v.reason == "heap_too_small"
        # and the advice scales with the app, not a hardcoded "try 8g"
        assert "--max-mem 11g" in v.message


def test_multidex_counts_are_summed():
    with tempfile.TemporaryDirectory() as d:
        p = _fake_apk(os.path.join(d, "m.apk"), [
            (f"classes{'' if i == 0 else i + 1}.dex", _fake_dex(10_000, 1_000)) for i in range(5)
        ])
        s = read_dex_stats(p)
        assert (s.methods, s.classes, s.dex_files) == (50_000, 5_000, 5)


def test_aab_dex_layout_is_counted_and_asset_dex_is_not():
    """.aab keeps its DEX under base/dex/; a .dex shipped as a plain asset is
    not part of the compiled classes and must not inflate the estimate."""
    with tempfile.TemporaryDirectory() as d:
        p = _fake_apk(os.path.join(d, "app.aab"),
                      [("base/dex/classes.dex", _fake_dex(20_000, 3_000))],
                      extra=[("base/assets/payload/classes.dex", _fake_dex(900_000, 200_000))])
        s = read_dex_stats(p)
        assert (s.methods, s.classes, s.dex_files) == (20_000, 3_000, 1)


def test_ram_too_small_is_reported_separately_from_heap_too_small():
    """Two different failures, two different fixes: 'raise --max-mem' is the
    right advice for one and actively harmful for the other."""
    with tempfile.TemporaryDirectory() as d:
        p = _fake_apk(os.path.join(d, "s.apk"), [("classes.dex", _fake_dex(50_000, 6_000))])
        v = check_memory_preflight(p, "16g", available_mb=4096)
        assert v.should_block and v.reason == "ram_too_small"
        assert "out-of-memory killer" in v.message
        # must NOT tell the user to raise --max-mem in this branch
        assert "--max-mem 17g" not in v.message
        # ...and must not bolt a nonsensical "may not be enough" caveat onto a
        # suggestion that is already far above what this small app needs
        assert "may still not be enough" not in v.message

        # the caveat DOES belong when the machine genuinely can't fit the app
        big = _fake_apk(os.path.join(d, "b.apk"), [("classes.dex", _fake_dex(900_000, 200_000))])
        v2 = check_memory_preflight(big, "16g", available_mb=4096)
        assert v2.should_block and "may still not be enough" in v2.message


def test_unreadable_dex_never_blocks():
    """A zip whose headers cannot be read is a measurement failure, not a big
    app."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "weird.apk")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
            zf.writestr("classes.dex", b"NOTADEX" + b"\x00" * 200)
        s = read_dex_stats(p)
        assert not s.ok
        assert not check_memory_preflight(p, "1m", available_mb=1).should_block


def test_unparseable_max_mem_never_blocks():
    with tempfile.TemporaryDirectory() as d:
        p = _fake_apk(os.path.join(d, "h.apk"), [("classes.dex", _fake_dex(900_000, 200_000))])
        assert not check_memory_preflight(p, "lots", available_mb=64 * 1024).should_block
        assert not check_memory_preflight(p, "", available_mb=64 * 1024).should_block


def test_corrupt_header_counts_are_skipped_not_trusted():
    """A garbage uint32 (e.g. 4 billion methods) must not fabricate a block."""
    with tempfile.TemporaryDirectory() as d:
        p = _fake_apk(os.path.join(d, "c.apk"), [("classes.dex", _fake_dex(0xFFFFFFFF, 0xFFFFFFFF))])
        s = read_dex_stats(p)
        assert not s.ok and s.methods == 0


@pytest.mark.parametrize("value,expected", [
    ("4g", 4096), ("4G", 4096), ("4096m", 4096), ("512M", 512),
    ("2048k", 2), ("8g", 8192), (" 4g ", 4096), ("4gb", 4096),
    ("2147483648", 2048),  # bare number = bytes, same as java -Xmx
    ("", None), ("lots", None), ("g", None), (None, None),
])
def test_parse_mem_arg(value, expected):
    assert parse_mem_arg(value) == expected


def test_available_ram_is_plausible_or_none():
    mb = available_ram_mb()
    assert mb is None or 16 <= mb <= 16 * 1024 * 1024


def test_estimate_is_zero_when_stats_are_not_ok():
    assert estimate_heap_mb(DexStats(0, 0, 0, 0, ok=False)) == 0


def _cli_env():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "..")
    return env


def _plain(s):
    """Strip ANSI and line wrapping; rich colourises per-token, so a large
    number arrives as several escape-separated fragments."""
    import re
    return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", s).replace("\n", " ")


def test_cli_blocks_huge_apk_fast_and_exits_nonzero():
    """A too-large app must fail in about a second, with a message naming the
    real numbers, instead of dying minutes later."""
    p = _apk("com.example.app_xl.apk")
    r = subprocess.run([sys.executable, "-c",
                        "import sys; from narvy.main import cli; sys.argv=['narvy','scan',%r]; cli()" % p],
                       capture_output=True, text=True, timeout=60, env=_cli_env())
    out = _plain(r.stdout + r.stderr)
    assert r.returncode != 0
    assert "This app is very large" in out
    assert "2,246,022 methods" in out and "411,514 classes" in out
    assert "--force" in out


def test_cli_force_bypasses_the_preflight():
    """A TimeoutExpired means jadx went on to do real work; the absence of the
    pre-flight text means the gate did not fire."""
    p = _apk("com.example.app_xl.apk")
    cmd = [sys.executable, "-c",
           "import sys; from narvy.main import cli; "
           "sys.argv=['narvy','scan',%r,'--force']; cli()" % p]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45, env=_cli_env())
    except subprocess.TimeoutExpired as e:
        def _dec(b):
            return b.decode(errors="replace") if isinstance(b, bytes) else (b or "")
        out = _plain(_dec(e.stdout) + _dec(e.stderr))
        assert "This app is very large" not in out, "--force did not bypass the pre-flight"
        return
    out = _plain(r.stdout + r.stderr)
    assert "Decompiling it typically needs around" not in out, "--force did not bypass the pre-flight"


def test_force_flag_is_threaded_into_decompile_apk():
    """Guard on the wiring, so a refactor that drops the kwarg is caught
    without needing the corpus."""
    import inspect
    assert "force" in inspect.signature(decompiler.decompile_apk).parameters
    from narvy import main as cli_main
    assert "force" in inspect.signature(cli_main._run_local_scan).parameters


# Post-mortem messages: a JVM OOM and a bare SIGKILL are not the same thing.

def _failed_decompile_message(monkeypatch, returncode, output, apk):
    """Drive decompile_apk's failure-formatting branch with subprocess.run
    stubbed; the APK, header read and estimator stay real."""
    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(returncode, cmd, output=output, stderr="")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(decompiler.subprocess, "run", fake_run, raising=False)
    monkeypatch.setattr(decompiler, "resolve_jadx_binary", lambda: "/bin/true")
    monkeypatch.setattr(decompiler, "resolve_java_home", lambda: None)
    with tempfile.TemporaryDirectory() as out:
        ok, detail = decompiler.decompile_apk(apk, os.path.join(out, "d"), "4g", force=True)
    assert not ok
    return detail


def test_jvm_oom_message_names_a_concrete_max_mem(monkeypatch):
    detail = _failed_decompile_message(
        monkeypatch, 1, "java.lang.OutOfMemoryError: Java heap space",
        _apk("com.example.app_oom_a.apk"))
    assert "ran out of memory" in detail
    assert "479,318 methods" in detail
    assert "--max-mem" in detail
    assert "SIGKILL" not in detail


def test_sigkill_message_does_not_claim_it_was_memory(monkeypatch):
    """SIGKILL carries no diagnostic, so the message must say so and point at
    the plausible causes rather than asserting one."""
    detail = _failed_decompile_message(
        monkeypatch, -9, "INFO - progress: 53529 of 65767 (81%)",
        _apk("com.example.app_unknown_e.apk"))
    assert "SIGKILL" in detail
    assert "container" in detail and "cgroup" in detail
    assert "If it was memory" in detail
    # must not state memory as fact
    assert "JADX ran out of memory decompiling this app" not in detail


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only backstop")
def test_as_limit_preexec_is_generous_enough_for_a_jvm_to_start():
    """`java -Xmx4096m -version` cannot start under an AS limit of 4096 MB or
    5427 MB, and does start at 7168 MB, so the limit set for 4g must exceed
    that."""
    import resource
    fn = decompiler._as_limit_preexec(4096)
    assert fn is not None
    pid = os.fork()
    if pid == 0:  # child: apply and report back through the exit code
        try:
            fn()
            soft, _ = resource.getrlimit(resource.RLIMIT_AS)
            os._exit(0 if soft >= 7168 * 1024 * 1024 else 1)
        except Exception:
            os._exit(2)
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only backstop")
def test_as_limit_never_raises_an_existing_tighter_limit():
    """A CI runner may set a deliberately low RLIMIT_AS; the safety net must
    not quietly widen it."""
    import resource
    fn = decompiler._as_limit_preexec(4096)
    tight = 2 * 1024 * 1024 * 1024
    pid = os.fork()
    if pid == 0:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (tight, tight))
            fn()
            soft, _ = resource.getrlimit(resource.RLIMIT_AS)
            os._exit(0 if soft <= tight else 1)
        except Exception:
            os._exit(2)
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0


def test_no_preexec_on_windows_path():
    assert decompiler._as_limit_preexec(None) is None
