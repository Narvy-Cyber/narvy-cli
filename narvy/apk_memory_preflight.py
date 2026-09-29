"""Size the jadx Java heap from the app's DEX header counts and the memory free right now.

A scan is never refused on memory grounds. The heap is

    min(--max-mem if given, what fits in free memory, a generous margin over the estimate)

and when even the estimate does not fit, jadx still runs with the largest heap
that does, with a warning. decompiler.decompile_apk retries once when jadx
really runs out of memory, then fails with the numbers.

Calibration (jadx 1.5.0, OpenJDK 17/21, G1, 8 CPUs; peak RSS from wait4):
  - the JVM's resident memory above -Xmx is ~250 MB plus ~5% of the heap
    (metaspace, code cache, GC tables, thread stacks), not a 30% multiplier;
  - -Xmx is a ceiling G1 grows into: a 6.5k-class app peaks at 0.7 GB RSS
    with -Xmx512m and at 1.5 GB with -Xmx4g, for the same output. Capping
    the heap near the need is what keeps a laptop out of swap;
  - see tests/test_apk_memory_preflight.py for the measured table.
"""

import ctypes
import logging
import os
import platform
import re
import struct
import zipfile
from typing import Iterable, NamedTuple, Optional, Sequence, Union

logger = logging.getLogger(__name__)

# Class count is the discriminating estimator; the other two add caution under max().
HEAP_MB_PER_CLASS = 0.050
HEAP_MB_PER_METHOD = 0.0073
HEAP_MB_PER_DEX_MB = 45.0

MIN_ESTIMATE_MB = 512

# Resident memory the JVM uses on top of the heap at peak: a fixed part plus a
# small share of the heap (GC tables). Measured +200..+400 MB from -Xmx384m to -Xmx4g.
JVM_NONHEAP_FIXED_MB = 256
JVM_NONHEAP_PER_HEAP = 0.05
# Left free for the OS and whatever else is open. "Available" already counts
# reclaimable cache (Linux MemAvailable, Windows standby list, macOS compressor).
OS_HEADROOM_MB = 128

# Smallest heap worth starting jadx with (its launcher's own -Xms is 256M).
MIN_HEAP_MB = 256
# With free memory to spare, the heap is this multiple of the estimate (at least
# DEFAULT_MIN_HEAP_MB). More than that buys nothing but a bigger resident set.
HEAP_MARGIN = 2.0
DEFAULT_MIN_HEAP_MB = 1024
# Heap used when the free memory cannot be read and no --max-mem was given.
UNKNOWN_RAM_CAP_MB = 4096


class DexStats(NamedTuple):
    methods: int
    classes: int
    dex_files: int
    dex_bytes: int
    ok: bool  # False => header read failed, callers must not gate on this


class HeapPlan(NamedTuple):
    xmx_mb: int                  # -Xmx for the first jadx run
    estimated_mb: int            # estimate_heap_mb(): the app's size in heap terms (0 = unknown)
    available_mb: Optional[int]  # free memory right now (None = unknown)
    requested_mb: Optional[int]  # --max-mem as a cap, None when sized automatically
    fit_mb: Optional[int]        # largest heap that fits in free memory (None = unknown)
    stats: DexStats
    fits: bool                   # False when the estimate is above the heap used
    note: str                    # informational line ("" when nothing to say)
    warning: str                 # shown before jadx starts when the estimate does not fit

    @property
    def xmx(self) -> str:
        return f"{self.xmx_mb}m"


def parse_mem_arg(value: str) -> Optional[int]:
    """Parse a JVM-style memory string ('4g', '4096m', '512k') to MB, or None."""
    if not value:
        return None
    m = re.fullmatch(r"\s*(\d+)\s*([kmgKMG]?)[bB]?\s*", str(value))
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2).lower()
    if unit == "g":
        return n * 1024
    if unit == "m":
        return n
    if unit == "k":
        return max(1, n // 1024)
    return max(1, n // (1024 * 1024))  # bare number = bytes, per java -Xmx


def is_auto(value) -> bool:
    return value is None or str(value).strip().lower() in ("", "auto")


# --- free memory ----------------------------------------------------------

def _linux_meminfo_available_mb(text: Optional[str] = None) -> Optional[int]:
    if text is None:
        try:
            with open("/proc/meminfo", "r") as f:
                text = f.read()
        except OSError:
            return None
    m = re.search(r"^MemAvailable:\s+(\d+)\s*kB", text, re.M)
    return int(m.group(1)) // 1024 if m else None


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except OSError:
        return None


def _cgroup_available_mb(root: str = "/sys/fs/cgroup",
                         proc_cgroup: Optional[str] = None) -> Optional[int]:
    """Memory left under this process's cgroup limit (Docker --memory, CI caps,
    systemd MemoryMax), or None when there is no limit.

    /proc/meminfo shows the whole host inside a container, so a 2 GB container
    on a 64 GB host would otherwise size the heap for 60 GB and be OOM-killed.
    Reclaimable page cache (inactive_file) is counted as free, like MemAvailable.
    """
    if proc_cgroup is None:
        proc_cgroup = _read("/proc/self/cgroup") or ""
    best = None
    # cgroup v2: "0::/path". Every ancestor's limit applies too.
    m = re.search(r"^0::(\S*)", proc_cgroup, re.M)
    if m:
        rel = m.group(1).strip("/")
        parts = rel.split("/") if rel else []
        for depth in range(len(parts), -1, -1):
            d = os.path.join(root, *parts[:depth]) if depth else root
            limit = _read(os.path.join(d, "memory.max"))
            if not limit or limit == "max" or not limit.isdigit():
                continue
            current = _read(os.path.join(d, "memory.current"))
            if not current or not current.isdigit():
                continue
            stat = _read(os.path.join(d, "memory.stat")) or ""
            im = re.search(r"^inactive_file (\d+)", stat, re.M)
            reclaimable = int(im.group(1)) if im else 0
            free = int(limit) - int(current) + reclaimable
            free_mb = max(0, min(free, int(limit)) // (1024 * 1024))
            best = free_mb if best is None else min(best, free_mb)
        return best
    # cgroup v1 memory controller.
    for line in proc_cgroup.splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and "memory" in fields[1].split(","):
            rel = fields[2].strip("/")
            for d in (os.path.join(root, "memory", rel), os.path.join(root, "memory")):
                limit = _read(os.path.join(d, "memory.limit_in_bytes"))
                usage = _read(os.path.join(d, "memory.usage_in_bytes"))
                if not (limit and usage and limit.isdigit() and usage.isdigit()):
                    continue
                if int(limit) >= (1 << 60):  # "unlimited" is a huge page-aligned number
                    return None
                stat = _read(os.path.join(d, "memory.stat")) or ""
                im = re.search(r"^total_inactive_file (\d+)", stat, re.M)
                reclaimable = int(im.group(1)) if im else 0
                return max(0, int(limit) - int(usage) + reclaimable) // (1024 * 1024)
    return None


class _MemStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _windows_available_mb(stat: Optional[_MemStatusEx] = None) -> Optional[int]:
    """Windows: ullAvailPhys, the "Available" figure of Task Manager.

    It already includes the standby list (file cache Windows hands back on
    demand), so it is not the pessimistic "Free" number. Bounded by the commit
    still available (ullAvailPageFile): the JVM commits its heap as it grows,
    and a full commit charge fails the allocation even with RAM free.
    """
    if stat is None:
        stat = _MemStatusEx()
        stat.dwLength = ctypes.sizeof(_MemStatusEx)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return None
    phys = int(stat.ullAvailPhys) // (1024 * 1024)
    commit = int(stat.ullAvailPageFile) // (1024 * 1024)
    if phys <= 0:
        return None
    return min(phys, commit) if commit > 0 else phys


def available_ram_mb() -> Optional[int]:
    """Best-effort memory a new process can use right now, in MB, or None if unknown."""
    # Test hook (platform CI): pretend this much is free, to run the low-memory
    # path end to end on a runner that has plenty.
    forced = os.environ.get("NARVY_ASSUME_AVAILABLE_MB", "").strip()
    if forced.isdigit():
        return int(forced)
    system = platform.system()
    try:
        if system == "Linux":
            host = _linux_meminfo_available_mb()
            cg = _cgroup_available_mb()
            known = [v for v in (host, cg) if v is not None]
            if known:
                return min(known)
        elif system == "Darwin":
            return _darwin_available_mb()
        elif system == "Windows":
            return _windows_available_mb()
        # Generic POSIX fallback, also covers Linux if /proc is unreadable.
        if hasattr(os, "sysconf") and "SC_AVPHYS_PAGES" in os.sysconf_names:
            return (os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")) // (1024 * 1024)
    except Exception as e:  # noqa: BLE001
        logger.debug(f"available_ram_mb() failed on {system}: {e}")
    return None


def _sysctl_int(name: str) -> Optional[int]:
    import subprocess
    try:
        out = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return int(out) if out.isdigit() else None


def _vm_stat_available_mb(out: str) -> Optional[int]:
    """free + inactive + speculative + purgeable pages from `vm_stat` output, in MB."""
    page = 4096
    pm = re.search(r"page size of (\d+) bytes", out)
    if pm:
        page = int(pm.group(1))
    counts = dict(re.findall(r"^(.+?):\s+(\d+)\.", out, re.M))
    pages = sum(int(counts.get(k, 0)) for k in
                ("Pages free", "Pages inactive", "Pages speculative", "Pages purgeable"))
    if not pages:
        return None
    return (pages * page) // (1024 * 1024)


def _darwin_available_mb(memsize: Optional[int] = None, level: Optional[int] = None,
                         vm_stat_out: Optional[str] = None) -> Optional[int]:
    """Available memory on macOS.

    The kernel's own figure is kern.memorystatus_level (the "free percentage"
    `memory_pressure` prints), which counts memory the compressor can reclaim.
    Page counts from vm_stat miss that and read a few GB low on a machine that
    is not under pressure at all, so they are only the fallback.
    """
    import subprocess
    if memsize is None:
        memsize = _sysctl_int("hw.memsize")
    if level is None:
        level = _sysctl_int("kern.memorystatus_level")
    from_level = None
    if memsize and level is not None and 0 < level <= 100:
        from_level = (memsize * level // 100) // (1024 * 1024)
    if vm_stat_out is None:
        try:
            vm_stat_out = subprocess.run(["vm_stat"], capture_output=True, text=True,
                                         encoding="utf-8", errors="replace", timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            vm_stat_out = ""
    from_pages = _vm_stat_available_mb(vm_stat_out or "")
    known = [v for v in (from_level, from_pages) if v is not None]
    return max(known) if known else None


# --- app size -------------------------------------------------------------

def _is_app_dex(name: str) -> bool:
    """True for app-code DEX (APK `classes*.dex` or App Bundle `<module>/dex/classes*.dex`), not asset .dex."""
    base = name.rsplit("/", 1)[-1]
    if not (base.startswith("classes") and base.endswith(".dex")):
        return False
    depth = name.count("/")
    if depth == 0:
        return True
    return re.fullmatch(r"[^/]+/dex/classes\d*\.dex", name) is not None


def read_dex_stats(apk_path: str) -> DexStats:
    """Read method/class counts from DEX headers (Dalvik spec: method_ids_size @0x58, class_defs_size @0x60, uint32 LE)."""
    methods = classes = count = 0
    dex_bytes = 0
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for zi in zf.infolist():
                if not _is_app_dex(zi.filename):
                    continue
                try:
                    with zf.open(zi) as f:
                        hdr = f.read(112)
                except Exception:
                    continue
                if len(hdr) < 0x70 or hdr[:3] != b"dex":
                    continue
                m = struct.unpack_from("<I", hdr, 0x58)[0]
                c = struct.unpack_from("<I", hdr, 0x60)[0]
                # Corrupt-header guard: no real DEX holds these counts.
                if m > 5_000_000 or c > 1_000_000:
                    continue
                methods += m
                classes += c
                dex_bytes += zi.file_size
                count += 1
    except Exception as e:  # noqa: BLE001
        logger.debug(f"read_dex_stats({apk_path}) failed: {e}")
        return DexStats(0, 0, 0, 0, ok=False)
    return DexStats(methods, classes, count, dex_bytes, ok=count > 0)


def read_dex_stats_all(paths: Iterable[str]) -> DexStats:
    """Summed DEX stats over every input jadx gets (base APK plus split feature modules)."""
    total = DexStats(0, 0, 0, 0, ok=False)
    for p in paths:
        s = read_dex_stats(p)
        if s.ok:
            total = DexStats(total.methods + s.methods, total.classes + s.classes,
                             total.dex_files + s.dex_files, total.dex_bytes + s.dex_bytes, ok=True)
    return total


def _raw_estimate_mb(stats: DexStats) -> int:
    if not stats.ok:
        return 0
    return int(max(
        stats.classes * HEAP_MB_PER_CLASS,
        stats.methods * HEAP_MB_PER_METHOD,
        (stats.dex_bytes / (1024 * 1024)) * HEAP_MB_PER_DEX_MB,
    ))


def estimate_heap_mb(stats: DexStats) -> int:
    """Estimated -Xmx (MB) jadx needs to decompile an app of this size."""
    if not stats.ok:
        return 0
    return max(MIN_ESTIMATE_MB, _raw_estimate_mb(stats))


# Smallest heap that decompiled cleanly, over the raw estimate: 1.1x (6.5k
# classes), 1.5-2.0x (20.7k), 1.6x (37.7k). Below NEED_FACTOR x raw the scan
# still runs, with a warning.
NEED_FACTOR = 1.5


def needed_heap_mb(stats: DexStats) -> int:
    """Heap below which jadx is likely to run out of memory on this app (0 = unknown)."""
    raw = _raw_estimate_mb(stats)
    return max(MIN_HEAP_MB, int(raw * NEED_FACTOR)) if raw else 0


def fmt_mb(mb: Optional[int]) -> str:
    if mb is None:
        return "unknown"
    if mb >= 1024:
        return f"{mb / 1024:.1f} GB"
    return f"{mb} MB"


_fmt_mb = fmt_mb


def jvm_resident_mb(xmx_mb: int) -> int:
    """Expected peak resident memory of a jadx JVM running with -Xmx{xmx_mb}m."""
    return int(xmx_mb * (1 + JVM_NONHEAP_PER_HEAP) + JVM_NONHEAP_FIXED_MB)


def heap_that_fits_mb(available_mb: Optional[int]) -> Optional[int]:
    """Largest -Xmx whose JVM (heap + non-heap) fits in `available_mb`, keeping OS headroom."""
    if available_mb is None:
        return None
    room = available_mb - OS_HEADROOM_MB - JVM_NONHEAP_FIXED_MB
    return max(0, int(room / (1 + JVM_NONHEAP_PER_HEAP)))


def _round_down(mb: int, step: int = 64) -> int:
    return max(step, (mb // step) * step)


def app_scale(stats: DexStats) -> str:
    return (f"~{stats.methods:,} methods / ~{stats.classes:,} classes across "
            f"{stats.dex_files} DEX file(s), {stats.dex_bytes / (1024 * 1024):.0f} MB of bytecode")


_MEASURE = object()


def plan_heap(apk_paths: Union[str, Sequence[str]], max_mem: Optional[str] = None,
              available_mb=_MEASURE, stats: Optional[DexStats] = None) -> HeapPlan:
    """Pick the jadx heap. Never refuses: the worst case is a warning plus the largest heap that fits."""
    if isinstance(apk_paths, str):
        apk_paths = [apk_paths]
    if stats is None:
        stats = read_dex_stats_all(apk_paths)
    requested = None if is_auto(max_mem) else parse_mem_arg(max_mem)
    if available_mb is _MEASURE:
        available_mb = available_ram_mb()
    est = estimate_heap_mb(stats)
    fit = heap_that_fits_mb(available_mb)

    target = max(DEFAULT_MIN_HEAP_MB, int(est * HEAP_MARGIN)) if est else UNKNOWN_RAM_CAP_MB
    caps = [target]
    if requested:
        caps.append(requested)
    if fit is not None:
        caps.append(fit)
    elif not requested:
        caps.append(UNKNOWN_RAM_CAP_MB)
    xmx = min(caps)
    # Never below the floor, and never above an explicit --max-mem.
    xmx = max(MIN_HEAP_MB, _round_down(xmx))
    if requested and requested < MIN_HEAP_MB:
        xmx = requested

    need = needed_heap_mb(stats)
    fits = not need or xmx >= need
    note = ""
    warning = ""
    if need and not fits:
        if requested and requested == xmx and (fit is None or fit >= need):
            warning = (
                f"--max-mem {max_mem} is below the ~{fmt_mb(need)} of Java heap this app is "
                f"estimated to need ({app_scale(stats)}). Trying anyway; if JADX runs out of "
                f"memory, re-run without --max-mem so Narvy sizes the heap itself."
            )
        else:
            warning = (
                f"This app is estimated to need ~{fmt_mb(need)} of Java heap ({app_scale(stats)}), "
                f"but only {fmt_mb(available_mb)} of memory is free right now, which leaves room "
                f"for a {fmt_mb(xmx)} heap. Trying with that; closing other apps (browsers, IDEs) "
                f"before the scan gives it more room."
            )
    elif requested and xmx < requested:
        why = ("free memory" if fit is not None and fit <= target else "the app's size")
        note = (f"JADX heap: {fmt_mb(xmx)} (sized to {why}; this app needs about {fmt_mb(need or est)}, "
                f"--max-mem {max_mem} is the upper limit).")
    return HeapPlan(xmx, est, available_mb, requested, fit, stats, fits, note, warning)


def check_memory_preflight(apk_path, max_mem=None, available_mb=_MEASURE) -> HeapPlan:
    """Backward-compatible name for plan_heap()."""
    return plan_heap(apk_path, max_mem, available_mb=available_mb)
