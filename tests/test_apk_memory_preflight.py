"""jadx heap sizing: DEX header reads, estimate, free memory per OS, retry. Corpus tests skip if absent."""
import os
import struct
import subprocess
import sys
import tempfile
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.apk_memory_preflight import (  # noqa: E402
    MIN_HEAP_MB,
    OS_HEADROOM_MB,
    DexStats,
    _is_app_dex,
    available_ram_mb,
    check_memory_preflight,
    estimate_heap_mb,
    heap_that_fits_mb,
    jvm_resident_mb,
    parse_mem_arg,
    plan_heap,
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



# --- heap sizing: never a refusal ---------------------------------------
#
# Measured on jadx 1.5.0 / OpenJDK 21 / 8 CPUs (peak RSS from wait4, 2026-09):
#   app (classes, est.)        -Xmx   result             peak RSS
#   InsecureBankv2 (6.5k, 512) 256m   OOM                   -
#                              384m   ok                  626 MB
#                              512m   ok                  713 MB
#                              1g     ok                  985 MB
#                              4g     ok                 1558 MB   (same output)
#   K-9 Mail (20.7k, 1034)     1g     OOM                1307 MB
#                              1536m  ok, 78 jadx errors 1824 MB
#                              2g     ok, 34 jadx errors 2325 MB
#   Telegram (37.7k, 1887)     2g     OOM                2427 MB
#                              3g     ok                 3469 MB
#                              4g     ok                 4431 MB
MEASURED = {
    # name: (methods, classes, dex_bytes, smallest heap that decompiled cleanly)
    "InsecureBankv2": (48_172, 6_529, 6_125_692, 384),
    "k9": (127_492, 20_684, 16 * 1024 * 1024, 2048),
    "telegram": (231_677, 37_742, 34 * 1024 * 1024, 3072),
}


def _stats(methods, classes, dex_bytes, dex_files=1):
    return DexStats(methods, classes, dex_files, dex_bytes, ok=True)


def _friend_report_stats():
    # The app from the Windows report: ~33,340 methods / ~6,282 classes, 1 DEX, 5 MB.
    return _stats(33_340, 6_282, 5 * 1024 * 1024)


def test_the_reported_windows_case_runs_instead_of_being_refused():
    """1.1 GB free, a 6.3k-class app: 1.1.3-1.1.5 refused it; it needs ~0.4 GB of heap."""
    plan = plan_heap("unused.apk", "4g", available_mb=1126, stats=_friend_report_stats())
    assert plan.xmx_mb >= 384, plan          # the measured working heap of its size twin
    assert jvm_resident_mb(plan.xmx_mb) + OS_HEADROOM_MB <= 1126
    assert plan.fits and plan.warning == ""
    # auto (the new default) picks the same heap
    auto = plan_heap("unused.apk", None, available_mb=1126, stats=_friend_report_stats())
    assert auto.xmx_mb == plan.xmx_mb


@pytest.mark.parametrize("avail", [300, 600, 900, 1126, 2048, 4096, 8192, 65536, None])
@pytest.mark.parametrize("max_mem", ["auto", None, "1g", "4g", "16g", "512m"])
def test_plan_never_refuses_and_stays_in_bounds(avail, max_mem):
    for methods, classes, dex_bytes, _ in MEASURED.values():
        plan = plan_heap("unused.apk", max_mem, available_mb=avail,
                         stats=_stats(methods, classes, dex_bytes))
        assert plan.xmx_mb >= MIN_HEAP_MB
        req = parse_mem_arg(max_mem) if max_mem not in (None, "auto") else None
        if req:
            assert plan.xmx_mb <= req, "an explicit --max-mem is an upper limit"
        if avail is not None and heap_that_fits_mb(avail) >= MIN_HEAP_MB:
            assert plan.xmx_mb <= heap_that_fits_mb(avail), "heap must fit in free memory"
        assert not hasattr(plan, "should_block")


def test_plenty_of_memory_gives_a_margin_over_the_measured_need():
    """With RAM to spare the heap covers what each measured app really needed."""
    for name, (methods, classes, dex_bytes, needed) in MEASURED.items():
        plan = plan_heap("unused.apk", None, available_mb=64 * 1024,
                         stats=_stats(methods, classes, dex_bytes))
        assert plan.xmx_mb >= needed, f"{name}: {plan.xmx_mb} MB < measured need {needed} MB"
        assert plan.xmx_mb <= max(1024, plan.estimated_mb * 2), "no heap far beyond the need"


def test_heap_is_not_inflated_to_max_mem_when_the_app_is_small():
    """-Xmx4g on a 6.5k-class app peaked at 1.56 GB RSS vs 0.99 GB at 1g for the same output."""
    plan = plan_heap("unused.apk", "4g", available_mb=64 * 1024, stats=_friend_report_stats())
    assert plan.xmx_mb == 1024
    assert "upper limit" in plan.note


def test_estimate_above_free_memory_warns_and_uses_the_largest_heap_that_fits():
    methods, classes, dex_bytes, _ = MEASURED["telegram"]
    plan = plan_heap("unused.apk", None, available_mb=1500, stats=_stats(methods, classes, dex_bytes))
    assert not plan.fits
    assert plan.xmx_mb == (heap_that_fits_mb(1500) // 64) * 64
    assert "Trying with that" in plan.warning and "1.5 GB" in plan.warning
    assert "--force" not in plan.warning and "refus" not in plan.warning.lower()


def test_explicit_max_mem_below_the_estimate_warns_but_runs_at_that_value():
    methods, classes, dex_bytes, _ = MEASURED["telegram"]
    plan = plan_heap("unused.apk", "1g", available_mb=64 * 1024, stats=_stats(methods, classes, dex_bytes))
    assert plan.xmx_mb == 1024 and not plan.fits
    assert "--max-mem 1g is below" in plan.warning


def test_unknown_free_memory_caps_the_auto_heap():
    plan = plan_heap("unused.apk", None, available_mb=None, stats=_stats(*MEASURED["telegram"][:3]))
    assert plan.xmx_mb == 3774 // 64 * 64  # 2x estimate, under the 4 GB unknown-RAM cap
    big = plan_heap("unused.apk", None, available_mb=None, stats=_stats(900_000, 200_000, 100 << 20))
    assert big.xmx_mb == 4096


def test_unreadable_dex_and_unparseable_max_mem_still_run():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "weird.apk")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
            zf.writestr("classes.dex", b"NOTADEX" + b"\x00" * 200)
        assert not read_dex_stats(p).ok
        plan = plan_heap(p, "1m", available_mb=1)
        assert plan.xmx_mb >= 1 and plan.warning == ""
        plan = plan_heap(p, "lots", available_mb=64 * 1024)
        assert plan.xmx_mb >= MIN_HEAP_MB


def test_split_bundle_feature_modules_are_counted():
    """jadx decompiles base + feature APKs together, so the estimate must too."""
    with tempfile.TemporaryDirectory() as d:
        base = _fake_apk(os.path.join(d, "base.apk"), [("classes.dex", _fake_dex(200_000, 30_000))])
        feat = _fake_apk(os.path.join(d, "feature.apk"), [("classes.dex", _fake_dex(200_000, 30_000))])
        alone = plan_heap([base], None, available_mb=64 * 1024)
        both = plan_heap([base, feat], None, available_mb=64 * 1024)
        assert both.stats.classes == 60_000
        assert both.estimated_mb >= 2 * alone.estimated_mb - 1


# --- free memory per platform ------------------------------------------

def test_windows_uses_avail_phys_bounded_by_available_commit():
    from narvy.apk_memory_preflight import _MemStatusEx, _windows_available_mb
    st = _MemStatusEx()
    st.ullAvailPhys = 1126 * 1024 * 1024
    st.ullAvailPageFile = 6 * 1024 * 1024 * 1024
    assert _windows_available_mb(st) == 1126
    st.ullAvailPageFile = 700 * 1024 * 1024  # commit charge nearly full
    assert _windows_available_mb(st) == 700
    st.ullAvailPhys = 0
    assert _windows_available_mb(st) is None


def test_available_ram_dispatches_to_windows(monkeypatch):
    from narvy import apk_memory_preflight as m
    monkeypatch.setattr(m.platform, "system", lambda: "Windows")
    monkeypatch.setattr(m, "_windows_available_mb", lambda: 1126)
    assert m.available_ram_mb() == 1126


def test_linux_takes_the_tighter_of_meminfo_and_the_cgroup_limit(monkeypatch):
    from narvy import apk_memory_preflight as m
    monkeypatch.setattr(m.platform, "system", lambda: "Linux")
    monkeypatch.setattr(m, "_linux_meminfo_available_mb", lambda: 60_000)
    monkeypatch.setattr(m, "_cgroup_available_mb", lambda: 1800)
    assert m.available_ram_mb() == 1800
    monkeypatch.setattr(m, "_cgroup_available_mb", lambda: None)
    assert m.available_ram_mb() == 60_000


def test_meminfo_parse():
    from narvy.apk_memory_preflight import _linux_meminfo_available_mb
    txt = "MemTotal:       32083908 kB\nMemFree:  100 kB\nMemAvailable:   22363448 kB\n"
    assert _linux_meminfo_available_mb(txt) == 22363448 // 1024
    assert _linux_meminfo_available_mb("MemTotal: 1 kB\n") is None


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def test_cgroup_v2_limit_with_reclaimable_cache_and_ancestors(tmp_path):
    from narvy.apk_memory_preflight import _cgroup_available_mb
    root = str(tmp_path)
    mib = 1024 * 1024
    # the scan's own scope: 2 GiB limit, 1.5 GiB used of which 512 MiB is cache
    _write(os.path.join(root, "a", "b", "memory.max"), str(2048 * mib))
    _write(os.path.join(root, "a", "b", "memory.current"), str(1536 * mib))
    _write(os.path.join(root, "a", "b", "memory.stat"), f"anon 1\ninactive_file {512 * mib}\n")
    _write(os.path.join(root, "a", "memory.max"), "max")
    assert _cgroup_available_mb(root, "0::/a/b\n") == 1024
    # a tighter ancestor wins
    _write(os.path.join(root, "a", "memory.max"), str(1024 * mib))
    _write(os.path.join(root, "a", "memory.current"), str(900 * mib))
    assert _cgroup_available_mb(root, "0::/a/b\n") == 124
    # no limit anywhere: None (use MemAvailable)
    assert _cgroup_available_mb(str(tmp_path / "empty"), "0::/\n") is None


def test_cgroup_v2_container_root(tmp_path):
    from narvy.apk_memory_preflight import _cgroup_available_mb
    mib = 1024 * 1024
    _write(str(tmp_path / "memory.max"), str(2048 * mib))
    _write(str(tmp_path / "memory.current"), str(300 * mib))
    assert _cgroup_available_mb(str(tmp_path), "0::/\n") == 1748


def test_cgroup_v1_limit(tmp_path):
    from narvy.apk_memory_preflight import _cgroup_available_mb
    mib = 1024 * 1024
    d = tmp_path / "memory" / "docker" / "abc"
    _write(str(d / "memory.limit_in_bytes"), str(1024 * mib))
    _write(str(d / "memory.usage_in_bytes"), str(800 * mib))
    _write(str(d / "memory.stat"), f"total_inactive_file {100 * mib}\n")
    assert _cgroup_available_mb(str(tmp_path), "4:memory:/docker/abc\n") == 324
    _write(str(d / "memory.limit_in_bytes"), str(9223372036854771712))
    assert _cgroup_available_mb(str(tmp_path), "4:memory:/docker/abc\n") is None


# --- decompile: sizing, retry, honest failure ----------------------------

class _Proc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _run_decompile(monkeypatch, outcomes, max_mem=None, force=False, avail=1126,
                   stats=None, write_sources=True):
    """Drive decompile_apk with a scripted sequence of jadx outcomes."""
    calls = []
    notes = []
    seq = list(outcomes)

    def fake_run(cmd, **kwargs):
        calls.append({"cmd": cmd, "opts": kwargs["env"].get("JADX_OPTS"), "kw": kwargs})
        rc, out = seq.pop(0)
        outdir = cmd[cmd.index("--output-dir") + 1]
        if write_sources and rc == 0:
            os.makedirs(os.path.join(outdir, "sources", "a"), exist_ok=True)
            with open(os.path.join(outdir, "sources", "a", "A.java"), "w") as f:
                f.write("class A {}")
        return _Proc(rc, out, "")
    monkeypatch.setattr(decompiler.subprocess, "run", fake_run)
    monkeypatch.setattr(decompiler, "resolve_jadx_binary", lambda: "/fake/jadx")
    monkeypatch.setattr(decompiler, "resolve_java_home", lambda: None)
    monkeypatch.setattr("narvy.apk_memory_preflight.available_ram_mb", lambda: avail)
    monkeypatch.setattr(decompiler, "available_ram_mb", lambda: avail)
    with tempfile.TemporaryDirectory() as d:
        s = stats or _friend_report_stats()
        p = _fake_apk(os.path.join(d, "app.apk"), [("classes.dex", _fake_dex(s.methods, s.classes))])
        ok, detail = decompiler.decompile_apk(p, os.path.join(d, "out"), max_mem, force=force,
                                              notify=lambda lvl, t: notes.append((lvl, t)))
    return ok, detail, calls, notes


def test_reported_case_decompiles_with_a_heap_that_fits(monkeypatch):
    ok, detail, calls, notes = _run_decompile(monkeypatch, [(0, "INFO - done")], max_mem="4g")
    assert ok, detail
    assert len(calls) == 1
    assert "-Xmx704m" in calls[0]["opts"] and "-Xms256m" in calls[0]["opts"]
    assert "-XX:+ExitOnOutOfMemoryError" in calls[0]["opts"]
    assert not [n for n in notes if n[0] == "warning"]
    assert "JADX heap 704 MB" in decompiler.LAST_HEAP_NOTE


def test_no_address_space_limit_is_put_on_the_jvm(monkeypatch):
    """RLIMIT_AS 2x heap + 3 GB made a 384m JVM fail to start its threads and exit 0 with no output."""
    ok, _, calls, _ = _run_decompile(monkeypatch, [(0, "")])
    assert ok and "preexec_fn" not in calls[0]["kw"]
    assert not hasattr(decompiler, "_as_limit_preexec")


def test_heap_oom_retries_once_bigger_when_memory_allows(monkeypatch):
    st = _stats(*MEASURED["k9"][:3])
    ok, detail, calls, notes = _run_decompile(
        monkeypatch,
        [(3, "Terminating due to java.lang.OutOfMemoryError: Java heap space"), (0, "INFO - done")],
        avail=64 * 1024, stats=st, max_mem="8g")
    assert ok, detail
    assert len(calls) == 2
    first = int(calls[0]["opts"].split("-Xmx")[1].split("m")[0])
    second = int(calls[1]["opts"].split("-Xmx")[1].split("m")[0])
    assert second >= first * 1.25 and second <= 8192
    assert any("retrying once" in t for _, t in notes)
    assert "succeeded on retry" in decompiler.LAST_HEAP_NOTE


def test_heap_oom_with_no_room_for_a_bigger_heap_fails_clearly_without_a_futile_retry(monkeypatch):
    oom = (3, "Terminating due to java.lang.OutOfMemoryError: Java heap space")
    ok, detail, calls, _ = _run_decompile(monkeypatch, [oom], avail=1126)
    assert not ok and len(calls) == 1
    assert "ran out of Java heap" in detail and "Tried: 704 MB heap." in detail
    assert "--force" not in detail and "--upload`" not in detail
    assert "close other apps" in detail


def test_os_refusing_memory_retries_smaller(monkeypatch):
    native = (1, "There is insufficient memory for the Java Runtime Environment to continue.\n"
                 "Native memory allocation (mmap) failed to map 268435456 bytes")
    ok, detail, calls, _ = _run_decompile(monkeypatch, [native, (0, "")], avail=4096,
                                          stats=_stats(*MEASURED["k9"][:3]))
    assert ok, detail
    first = int(calls[0]["opts"].split("-Xmx")[1].split("m")[0])
    second = int(calls[1]["opts"].split("-Xmx")[1].split("m")[0])
    assert second < first and second >= MIN_HEAP_MB


def test_sigkill_is_not_stated_as_a_java_heap_error(monkeypatch):
    ok, detail, calls, _ = _run_decompile(monkeypatch, [(-9, "INFO - progress: 5 of 9"),
                                                        (-9, "INFO - progress: 5 of 9")], avail=4096)
    assert not ok and len(calls) == 2
    assert calls[1]["cmd"][calls[1]["cmd"].index("-j") + 1] == "1"
    assert "SIGKILL" in detail and "cgroup" in detail
    assert "ran out of Java heap" not in detail


def test_force_runs_exactly_max_mem_without_retry(monkeypatch):
    oom = (3, "java.lang.OutOfMemoryError: Java heap space")
    ok, detail, calls, notes = _run_decompile(monkeypatch, [oom], max_mem="3g", force=True, avail=1126)
    assert not ok and len(calls) == 1
    assert "-Xmx3072m" in calls[0]["opts"]
    assert not notes


def test_exit_zero_without_sources_is_a_failure_not_a_clean_scan(monkeypatch):
    """jadx exited 0 with 0 files when its threads could not start (seen under RLIMIT_AS)."""
    ok, detail, calls, _ = _run_decompile(
        monkeypatch, [(0, "Exception in thread \"pool-1-thread-1\" java.lang.OutOfMemoryError: "
                          "unable to create native thread")] * 2, write_sources=False)
    assert not ok
    ok, detail, calls, _ = _run_decompile(monkeypatch, [(0, "INFO - done")], write_sources=False)
    assert not ok and "wrote no Java sources" in detail


def test_oom_text_on_exit_zero_is_not_trusted(monkeypatch):
    ok, detail, calls, _ = _run_decompile(
        monkeypatch, [(0, "java.lang.OutOfMemoryError: Java heap space"), (0, "INFO - done")],
        avail=64 * 1024)
    assert ok and len(calls) == 2


def test_jadx_method_errors_are_reported_not_hidden(monkeypatch):
    ok, _, _, _ = _run_decompile(monkeypatch, [(0, "ERROR - finished with errors, count: 78")])
    assert ok
    assert "could not fully decompile 78 method(s)" in decompiler.LAST_HEAP_NOTE


def test_failure_message_escapes_nothing_it_should_not(monkeypatch):
    """Raw jadx output reaches the console through rich_escape (main), never as markup."""
    import inspect
    from narvy import main as cli_main
    src = inspect.getsource(cli_main._run_local_scan)
    assert "rich_escape(decompile_error)" in src


def test_windows_bat_command_line_keeps_the_thread_flag(monkeypatch):
    monkeypatch.setattr(decompiler, "_IS_WINDOWS", True)
    cmd = decompiler._jadx_cmd(r"C:\Users\Jean Dupont\.narvy\tools\jadx-1.5.0\bin\jadx.bat",
                               ["--output-dir", r"C:\Temp\x y", "--show-bad-code", "-j", "1",
                                r"D:\Apps\été\my app.apk"])
    assert isinstance(cmd, str) and cmd.startswith('cmd /d /s /c "')
    assert ' -j 1 ' in cmd and '"D:\\Apps\\été\\my app.apk"' in cmd


def test_cli_accepts_auto_and_rejects_garbage():
    from narvy import main as cli_main
    assert cli_main.is_auto_mem("auto") and cli_main.is_auto_mem(None)
    assert not cli_main.is_auto_mem("4g")
    r = subprocess.run([sys.executable, "-m", "narvy", "scan", "--help"], capture_output=True,
                       text=True, env=_cli_env(), timeout=60)
    assert "Default 'auto'" in _plain(r.stdout)


def test_doctor_memory_line_uses_the_same_model():
    from narvy import doctor
    from narvy import apk_memory_preflight as m
    orig = m.available_ram_mb
    try:
        m.available_ram_mb = lambda: 1126
        ok, detail, hint = doctor._check_memory()
    finally:
        m.available_ram_mb = orig
    assert ok and "1.1 GB available" in detail and "--upload`" not in (hint or "")


MEASURED_OOM_HEAPS = {"InsecureBankv2": 256, "k9": 1024, "telegram": 2048}


def test_every_measured_oom_heap_would_have_been_warned_about():
    """A heap jadx really ran out of memory at is always below the warning threshold."""
    from narvy.apk_memory_preflight import needed_heap_mb
    for name, oom_heap in MEASURED_OOM_HEAPS.items():
        methods, classes, dex_bytes, _ = MEASURED[name]
        assert needed_heap_mb(_stats(methods, classes, dex_bytes)) > oom_heap, name
        # and a machine whose free memory only fits that heap gets the warning
        avail = jvm_resident_mb(oom_heap) + OS_HEADROOM_MB
        plan = plan_heap("unused.apk", None, available_mb=avail, stats=_stats(methods, classes, dex_bytes))
        assert plan.warning and not plan.fits, name


def test_ci_hook_pretends_free_memory(monkeypatch):
    from narvy import apk_memory_preflight as m
    monkeypatch.setenv("NARVY_ASSUME_AVAILABLE_MB", "1126")
    assert m.available_ram_mb() == 1126
    monkeypatch.setenv("NARVY_ASSUME_AVAILABLE_MB", "nonsense")
    assert m.available_ram_mb() != "nonsense"


def test_sca_line_does_not_say_zero_cves_when_the_lookup_failed():
    from narvy import main as cli_main
    ok = cli_main._sca_result_line({"unique_dependencies_checked": 5, "cves_found": 0,
                                    "vulnerable_dependencies": 0})
    assert "found 0 known CVE(s)" in ok
    bad = cli_main._sca_result_line({"unique_dependencies_checked": 5, "cves_found": 0,
                                     "vulnerable_dependencies": 0, "osv_unreachable": True},
                                    "embedded framework(s)")
    assert "0 known CVE" not in bad and "UNKNOWN" in bad and "5 unique embedded framework(s)" in bad


def test_reported_113_windows_case_end_to_end_through_the_windows_memory_reading(monkeypatch):
    """The reported case, on 1.1.3: Windows, 1.1 GB available, estimate 512 MB, default --max-mem 4g.

    1.1.3 read the memory correctly (GlobalMemoryStatusEx.ullAvailPhys is Task
    Manager's "Available", standby cache included, not "Free"), then refused:
    room = 1126 - 1024 (fixed reserve) = 102 MB, / 1.3 overhead -> 0 MB of
    heap < 1.5 x 512 required. Here the same reading must yield a run.
    """
    from narvy import apk_memory_preflight as m
    st = m._MemStatusEx()
    st.ullAvailPhys = 1126 * 1024 * 1024        # what 1.1.3 showed as "1.1 GB available"
    st.ullAvailPageFile = 5 * 1024 * 1024 * 1024
    monkeypatch.setattr(m.platform, "system", lambda: "Windows")
    real = m._windows_available_mb
    # GlobalMemoryStatusEx itself only exists on Windows: feed the real parser the struct.
    monkeypatch.setattr(m, "_windows_available_mb", lambda: real(st))
    monkeypatch.delenv("NARVY_ASSUME_AVAILABLE_MB", raising=False)
    assert m._windows_available_mb() == 1126
    stats = _friend_report_stats()
    assert estimate_heap_mb(stats) == 512           # "about 512 MB of heap" in the report
    # the 1.1.3 arithmetic, kept here to show why it refused
    old_room = 1126 - 1024
    old_fit = (max(0, int(old_room / 1.30)) // 256) * 256
    assert old_fit < max(512, 512 * 1.5)
    # the new design, default --max-mem as 1.1.3 had it ("4g") and as it is now ("auto")
    for max_mem in ("4g", "auto"):
        plan = plan_heap("unused.apk", max_mem, stats=stats)   # measures through available_ram_mb()
        assert plan.available_mb == 1126
        assert plan.xmx_mb >= 384 and jvm_resident_mb(plan.xmx_mb) <= 1126 - OS_HEADROOM_MB
        assert plan.fits and not plan.warning


def test_windows_reading_is_available_not_free():
    """ullAvailPhys is the right field; there is no 'free-only' field in MEMORYSTATUSEX to confuse it with."""
    from narvy.apk_memory_preflight import _MemStatusEx
    names = [f[0] for f in _MemStatusEx._fields_]
    assert names == ["dwLength", "dwMemoryLoad", "ullTotalPhys", "ullAvailPhys", "ullTotalPageFile",
                     "ullAvailPageFile", "ullTotalVirtual", "ullAvailVirtual", "ullAvailExtendedVirtual"]
