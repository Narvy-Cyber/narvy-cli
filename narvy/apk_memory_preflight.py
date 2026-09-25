"""Estimate the jadx heap from DEX header counts and warn before an OOM. `--force` skips it."""

import ctypes
import logging
import math
import os
import platform
import re
import struct
import zipfile
from typing import NamedTuple, Optional

logger = logging.getLogger(__name__)

# Class count is the discriminating estimator; the other two add caution under max().
HEAP_MB_PER_CLASS = 0.050
HEAP_MB_PER_METHOD = 0.0073
HEAP_MB_PER_DEX_MB = 45.0

MIN_ESTIMATE_MB = 512

# JVM resident set = heap plus metaspace, stacks, GC, JIT cache, mapped DEX.
JVM_RSS_OVERHEAD = 1.30

RAM_SAFETY_RESERVE_MB = 1024


class DexStats(NamedTuple):
    methods: int
    classes: int
    dex_files: int
    dex_bytes: int
    ok: bool  # False => header read failed, callers must not gate on this


class PreflightVerdict(NamedTuple):
    should_block: bool
    reason: str          # "" | "heap_too_small" | "ram_too_small"
    message: str
    estimated_mb: int
    max_mem_mb: int
    available_mb: Optional[int]
    stats: DexStats


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


def available_ram_mb() -> Optional[int]:
    """Best-effort free memory in MB for this machine, or None if unknown."""
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) // 1024
        elif system == "Darwin":
            # vm_stat exposes reclaimable inactive+purgeable pools that SC_AVPHYS_PAGES omits.
            import subprocess
            out = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=10).stdout
            page = 4096
            pm = re.search(r"page size of (\d+) bytes", out)
            if pm:
                page = int(pm.group(1))
            counts = dict(re.findall(r"^(.+?):\s+(\d+)\.", out, re.M))
            free = int(counts.get("Pages free", 0))
            inactive = int(counts.get("Pages inactive", 0))
            purgeable = int(counts.get("Pages purgeable", 0))
            if free or inactive:
                return ((free + inactive + purgeable) * page) // (1024 * 1024)
        elif system == "Windows":
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
            stat = _MemStatusEx()
            stat.dwLength = ctypes.sizeof(_MemStatusEx)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return int(stat.ullAvailPhys) // (1024 * 1024)
        # Generic POSIX fallback, also covers Linux if /proc is unreadable.
        if hasattr(os, "sysconf") and "SC_AVPHYS_PAGES" in os.sysconf_names:
            return (os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")) // (1024 * 1024)
    except Exception as e:  # noqa: BLE001
        logger.debug(f"available_ram_mb() failed on {system}: {e}")
    return None


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


def estimate_heap_mb(stats: DexStats) -> int:
    """Estimated -Xmx (MB) jadx needs to decompile an app of this size."""
    if not stats.ok:
        return 0
    estimates = (
        stats.classes * HEAP_MB_PER_CLASS,
        stats.methods * HEAP_MB_PER_METHOD,
        (stats.dex_bytes / (1024 * 1024)) * HEAP_MB_PER_DEX_MB,
    )
    return max(MIN_ESTIMATE_MB, int(max(estimates)))


def _fmt_mb(mb: Optional[int]) -> str:
    if mb is None:
        return "unknown"
    if mb >= 1024:
        return f"{mb / 1024:.1f} GB"
    return f"{mb} MB"


def _round_up_gb(mb: int) -> int:
    return max(1, math.ceil(mb / 1024))


def check_memory_preflight(apk_path: str, max_mem: str,
                           available_mb: Optional[int] = None) -> PreflightVerdict:
    """Decide before spending jadx time whether this scan can work; never blocks on a low-confidence estimate."""
    stats = read_dex_stats(apk_path)
    max_mem_mb = parse_mem_arg(max_mem)
    if available_mb is None:
        available_mb = available_ram_mb()

    no_block = PreflightVerdict(False, "", "", estimate_heap_mb(stats),
                                max_mem_mb or 0, available_mb, stats)
    if not stats.ok or not max_mem_mb:
        return no_block

    need_mb = estimate_heap_mb(stats)
    scale = (
        f"~{stats.methods:,} methods / ~{stats.classes:,} classes across "
        f"{stats.dex_files} DEX file(s), {stats.dex_bytes / (1024 * 1024):.0f} MB of bytecode"
    )

    if need_mb > max_mem_mb:
        suggest_gb = _round_up_gb(int(need_mb * 1.1))
        need_rss_mb = int(suggest_gb * 1024 * JVM_RSS_OVERHEAD)
        head = (
            f"This app is very large: {scale}. Decompiling it typically needs around "
            f"{_fmt_mb(need_mb)} of Java heap, but this scan is limited to "
            f"{_fmt_mb(max_mem_mb)} (--max-mem {max_mem}). JADX will most likely run out "
            f"of memory partway through, after several minutes of work."
        )
        if available_mb is not None and need_rss_mb > (available_mb - RAM_SAFETY_RESERVE_MB):
            body = (
                f"\n\nRaising --max-mem on its own will not be enough: {suggest_gb}g of heap needs "
                f"roughly {_fmt_mb(need_rss_mb)} of real memory, and this machine only has "
                f"{_fmt_mb(available_mb)} available right now. Options:\n"
                f"  - use the hosted scan (`--upload`): the platform decompiles any app size with no local memory ceiling\n"
                f"  - or free up that much memory (close other apps) and re-run with --max-mem {suggest_gb}g\n"
                f"  - or run it anyway with --force if your setup can take it"
            )
        else:
            avail_note = (f" (this machine has {_fmt_mb(available_mb)} available)"
                          if available_mb is not None else "")
            body = (
                f"\n\nOptions:\n"
                f"  - re-run with --max-mem {suggest_gb}g{avail_note}\n"
                f"  - run it anyway at {max_mem} with --force"
            )
        return PreflightVerdict(True, "heap_too_small", head + body,
                                need_mb, max_mem_mb, available_mb, stats)

    if available_mb is not None:
        needed_rss = int(max_mem_mb * JVM_RSS_OVERHEAD)
        if needed_rss > (available_mb - RAM_SAFETY_RESERVE_MB):
            safe_gb = max(1, int((available_mb - RAM_SAFETY_RESERVE_MB) / JVM_RSS_OVERHEAD / 1024))
            lower_line = f"  - lower to --max-mem {safe_gb}g, which fits in what's free"
            if safe_gb * 1024 < need_mb:
                lower_line += (f" (though this app looks like it needs about {_fmt_mb(need_mb)}, "
                               f"so it may still not be enough)")
            msg = (
                f"--max-mem {max_mem} asks JADX for {_fmt_mb(max_mem_mb)} of Java heap, which needs "
                f"about {_fmt_mb(needed_rss)} of real memory once JVM overhead is counted. This "
                f"machine only has {_fmt_mb(available_mb)} available right now.\n\n"
                f"Running this would push the machine into swap and most likely get JADX killed by "
                f"the OS out-of-memory killer (and may take other apps down with it). Options:\n"
                f"  - free up memory and try again\n"
                f"{lower_line}\n"
                f"  - run it anyway with --force"
            )
            return PreflightVerdict(True, "ram_too_small", msg,
                                    need_mb, max_mem_mb, available_mb, stats)

    return no_block
