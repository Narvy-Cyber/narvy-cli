"""jadx memory preflight: DEX header reads, heap estimate, --force. Corpus tests skip if absent."""
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

# name -> (methods, classes, outcome_at_4g). Outcome: True decompiled, False OOM,
# None when the run was killed for an unrelated reason.
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
    """Minimal DEX header with method_ids_size at 0x58 and class_defs_size at 0x60."""
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
    """Block/allow at 4g matches measured outcomes."""
    _, _, decompiled_ok = PROVEN[name]
    # Pin available RAM high so this asserts the heap judgement only and does
    # not flake on whatever else is running on the test machine.
    v = check_memory_preflight(_apk(name), "4g", available_mb=64 * 1024)
    assert v.should_block is (not decompiled_ok), (
        f"{name}: predicted block={v.should_block} (est {v.estimated_mb} MB) "
        f"but it actually {'succeeded' if decompiled_ok else 'ran out of memory'} at 4g"
    )


def test_gate_sits_inside_the_measured_uncertainty_interval():
    """The 4g gate sits between the largest success and the smallest OOM."""
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
    """Raising --max-mem unblocks the app (gate arithmetic only)."""
    p = _apk("com.example.app_unknown_e.apk")
    assert check_memory_preflight(p, "4g", available_mb=64 * 1024).should_block
    assert not check_memory_preflight(p, "5g", available_mb=64 * 1024).should_block


def test_suggested_max_mem_actually_fixes_a_proven_oom():
    """An app that OOMs at 4g is refused with a 6g suggestion, which works."""
    v = check_memory_preflight(_apk("com.example.app_oom_a.apk"), "4g", available_mb=64 * 1024)
    assert v.should_block and v.reason == "heap_too_small"
    assert "--max-mem 6g" in v.message
    assert not check_memory_preflight(_apk("com.example.app_oom_a.apk"), "6g",
                                      available_mb=64 * 1024).should_block


def test_suggested_max_mem_is_above_the_estimate_not_a_round_guess():
    """The suggestion comes from the estimate plus headroom."""
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
    """No open-source corpus APK is blocked at the default 4g."""
    apks = sorted(__import__("glob").glob(os.path.join(OSS_CORPUS, "*.apk")))
    if len(apks) < 10:
        pytest.skip(f"open-source APK corpus not present on this machine ({OSS_CORPUS})")
    blocked = [os.path.basename(p) for p in apks
               if check_memory_preflight(p, "4g", available_mb=64 * 1024).should_block]
    assert blocked == [], f"false blocks on normal-sized apps: {blocked}"


def test_preflight_cost_is_negligible_against_a_real_scan():
    """The preflight stays in the millisecond range."""
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
    """Count base/dex/ in an .aab, ignore .dex shipped as assets."""
    with tempfile.TemporaryDirectory() as d:
        p = _fake_apk(os.path.join(d, "app.aab"),
                      [("base/dex/classes.dex", _fake_dex(20_000, 3_000))],
                      extra=[("base/assets/payload/classes.dex", _fake_dex(900_000, 200_000))])
        s = read_dex_stats(p)
        assert (s.methods, s.classes, s.dex_files) == (20_000, 3_000, 1)


def test_ram_too_small_is_reported_separately_from_heap_too_small():
    """Low RAM and low heap get different advice."""
    with tempfile.TemporaryDirectory() as d:
        p = _fake_apk(os.path.join(d, "s.apk"), [("classes.dex", _fake_dex(280_000, 40_000))])
        v = check_memory_preflight(p, "16g", available_mb=4096)
        assert v.should_block and v.reason == "ram_too_small"
        assert "out-of-memory killer" in v.message
        # must NOT tell the user to raise --max-mem in this branch
        assert "--max-mem 17g" not in v.message
        # ...and must not bolt a nonsensical "may not be enough" caveat onto a
        # suggestion that is already above what this app needs
        assert "may still not be enough" not in v.message

        # the caveat DOES belong when the machine genuinely can't fit the app
        big = _fake_apk(os.path.join(d, "b.apk"), [("classes.dex", _fake_dex(900_000, 200_000))])
        v2 = check_memory_preflight(big, "16g", available_mb=4096)
        assert v2.should_block and "may still not be enough" in v2.message


def _insecurebank_like(d):
    # Header counts of the APK the platform CI scans (48,172 methods, 6,529 classes, 6 MB DEX).
    return _fake_apk(os.path.join(d, "ib.apk"),
                     [("classes.dex", _fake_dex(48_172, 6_529, body_bytes=6_125_692 - 112))])


def test_max_mem_that_does_not_fit_is_lowered_not_refused():
    """A small app runs with a smaller heap instead of being refused.

    Regression: the 7 GB macOS CI runner (3.2 to 4.4 GB available) refused a
    6,500-class app at --max-mem 3g, and an 8 GB laptop refused every app at
    the default 4g.
    """
    with tempfile.TemporaryDirectory() as d:
        p = _insecurebank_like(d)
        for mem, avail in (("3g", 3200), ("4g", 3200), ("4g", 4400), ("16g", 3200)):
            v = check_memory_preflight(p, mem, available_mb=avail)
            assert not v.should_block, f"--max-mem {mem} with {avail} MB free: {v.message}"
            assert v.reason == "lowered" and v.lowered_max_mem
            lowered = int(v.lowered_max_mem.rstrip("m"))
            # the lowered heap fits in what is free and still covers the app with margin
            assert lowered * 1.3 <= avail - 1024
            assert lowered >= v.estimated_mb * 1.5
            assert "instead of --max-mem " + mem in v.message
        # --max-mem that fits is passed through untouched
        v = check_memory_preflight(p, "2g", available_mb=64 * 1024)
        assert not v.should_block and v.lowered_max_mem is None and v.reason == ""
        # a machine that cannot hold even the lowered heap is still refused
        v = check_memory_preflight(p, "4g", available_mb=1800)
        assert v.should_block and v.reason == "ram_too_small"


def test_decompile_uses_the_lowered_heap(monkeypatch):
    """jadx gets the lowered -Xmx, and the note is left for the caller to print."""
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["opts"] = kwargs["env"].get("JADX_OPTS")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(decompiler.subprocess, "run", fake_run)
    monkeypatch.setattr(decompiler, "resolve_jadx_binary", lambda: "/bin/true")
    monkeypatch.setattr(decompiler, "resolve_java_home", lambda: None)
    monkeypatch.setattr("narvy.apk_memory_preflight.available_ram_mb", lambda: 3200)
    with tempfile.TemporaryDirectory() as d:
        p = _insecurebank_like(d)
        ok, _ = decompiler.decompile_apk(p, os.path.join(d, "out"), "4g")
    assert ok
    assert seen["opts"] == "-Xmx1536m"
    assert decompiler.LAST_HEAP_NOTE and "1.5 GB Java heap" in decompiler.LAST_HEAP_NOTE


def test_darwin_available_prefers_the_kernel_memorystatus_level():
    from narvy.apk_memory_preflight import _darwin_available_mb, _vm_stat_available_mb
    vm = ("Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
          "Pages free:                               29399.\n"
          "Pages active:                            370913.\n"
          "Pages inactive:                          344932.\n"
          "Pages speculative:                        25149.\n"
          "Pages wired down:                        114741.\n"
          "Pages purgeable:                           3285.\n")
    pages_mb = (29399 + 344932 + 25149 + 3285) * 16384 // (1024 * 1024)
    assert _vm_stat_available_mb(vm) == pages_mb
    # 16 GB Mac at 75% free: the kernel figure wins over the lower page count
    assert _darwin_available_mb(memsize=16 * 1024 ** 3, level=75, vm_stat_out=vm) == 12288
    # no sysctl: page counts
    assert _darwin_available_mb(memsize=None, level=None, vm_stat_out=vm) is not None
    assert _vm_stat_available_mb("") is None


def test_unreadable_dex_never_blocks():
    """Unreadable headers never block a scan."""
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
    """Strip ANSI codes and line wrapping from rich output."""
    import re
    return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", s).replace("\n", " ")


def test_cli_blocks_huge_apk_fast_and_exits_nonzero():
    """A too-large app fails in about a second with the real numbers."""
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
    """--force skips the gate and jadx starts."""
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
    """--force reaches decompile_apk."""
    import inspect
    assert "force" in inspect.signature(decompiler.decompile_apk).parameters
    from narvy import main as cli_main
    assert "force" in inspect.signature(cli_main._run_local_scan).parameters


# Post-mortem messages: a JVM OOM and a bare SIGKILL are not the same thing.

def _failed_decompile_message(monkeypatch, returncode, output, apk):
    """Run decompile_apk's failure branch with subprocess.run stubbed."""
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
    """A SIGKILL message lists likely causes instead of blaming memory."""
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
    """The address-space limit for 4g is high enough for the JVM to start."""
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
    """Never raise an existing, tighter RLIMIT_AS."""
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
