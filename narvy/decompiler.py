import subprocess
import os
import platform
import re
import shutil
import stat
import tarfile
import zipfile
import logging

import requests

from .apk_memory_preflight import (
    MIN_HEAP_MB,
    app_scale,
    available_ram_mb,
    check_memory_preflight,
    fmt_mb,
    heap_that_fits_mb,
    is_auto,
    needed_heap_mb,
    parse_mem_arg,
    plan_heap,
)

logger = logging.getLogger(__name__)

JADX_VERSION = "1.5.0"
JADX_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"
TOOLS_DIR = os.path.expanduser("~/.narvy/tools")
JADX_HOME = os.path.join(TOOLS_DIR, f"jadx-{JADX_VERSION}")
_IS_WINDOWS = platform.system() == "Windows"
_IS_MAC = platform.system() == "Darwin"
# jadx ships a Unix shell script and a Windows .bat; the .bat avoids WinError 193.
JADX_BIN = os.path.join(JADX_HOME, "bin", "jadx.bat" if _IS_WINDOWS else "jadx")

# jadx 1.5.0 needs Java 11+; a JRE is fetched when the system has none.
_JRE_MAJOR = "17"
_JRE_ADOPTIUM_OS = "windows" if _IS_WINDOWS else ("mac" if _IS_MAC else "linux")
# Apple Silicon and ARM Linux get the native aarch64 build (an x64 JRE needs
# Rosetta on a Mac and does not run at all on ARM Linux). Windows stays x64:
# Temurin 17 has no Windows ARM JRE, and Windows on ARM emulates x64.
_JRE_ADOPTIUM_ARCH = (
    "aarch64"
    if not _IS_WINDOWS and platform.machine().lower() in ("arm64", "aarch64")
    else "x64"
)
JRE_URL = (
    f"https://api.adoptium.net/v3/binary/latest/{_JRE_MAJOR}/ga/"
    f"{_JRE_ADOPTIUM_OS}/{_JRE_ADOPTIUM_ARCH}/jre/hotspot/normal/eclipse"
)
JRE_HOME = os.path.join(TOOLS_DIR, f"jre-{_JRE_MAJOR}")


def _download_jadx():
    os.makedirs(TOOLS_DIR, exist_ok=True)
    zip_path = os.path.join(TOOLS_DIR, f"jadx-{JADX_VERSION}.zip")
    logger.info(f"jadx not found on PATH - downloading {JADX_URL}")
    resp = requests.get(JADX_URL, stream=True, timeout=120)
    resp.raise_for_status()
    with open(zip_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1 << 20):
            f.write(chunk)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(JADX_HOME)
    os.remove(zip_path)
    if not _IS_WINDOWS:
        st = os.stat(JADX_BIN)
        os.chmod(JADX_BIN, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    logger.info(f"jadx {JADX_VERSION} installed to {JADX_HOME}")


def resolve_jadx_binary():
    on_path = shutil.which("jadx")
    if on_path:
        return on_path
    if os.path.exists(JADX_BIN):
        return JADX_BIN
    _download_jadx()
    return JADX_BIN


def _java_major_version(java_bin):
    try:
        result = subprocess.run([java_bin, "-version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
    except Exception:
        return None
    out = result.stderr or result.stdout or ""
    m = re.search(r'version "(\d+)(?:\.(\d+))?', out)
    if not m:
        return None
    major = int(m.group(1))
    if major == 1 and m.group(2):  # old "1.x" scheme: the real major is second
        major = int(m.group(2))
    return major


def _jre_bin_dir():
    """The bin/ dir inside the downloaded JRE, once extracted."""
    # Discovered, not hardcoded: the Adoptium top-level dir carries the patch version.
    if not os.path.isdir(JRE_HOME):
        return None
    for entry in sorted(os.listdir(JRE_HOME)):
        # Linux/Windows: <jdk-17...-jre>/bin. macOS: <jdk-17...-jre>/Contents/Home/bin.
        for sub in (("bin",), ("Contents", "Home", "bin")):
            candidate = os.path.join(JRE_HOME, entry, *sub)
            if os.path.isdir(candidate):
                return candidate
    return None


def _download_jre():
    os.makedirs(TOOLS_DIR, exist_ok=True)
    is_zip = _IS_WINDOWS
    archive_path = os.path.join(TOOLS_DIR, f"jre-{_JRE_MAJOR}.{'zip' if is_zip else 'tar.gz'}")
    logger.info(f"No usable Java 11+ found - downloading a JRE ourselves from {JRE_URL}")
    resp = requests.get(JRE_URL, stream=True, timeout=180, allow_redirects=True)
    resp.raise_for_status()
    with open(archive_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1 << 20):
            f.write(chunk)
    if os.path.exists(JRE_HOME):
        shutil.rmtree(JRE_HOME)
    os.makedirs(JRE_HOME, exist_ok=True)
    if is_zip:
        with zipfile.ZipFile(archive_path) as z:
            z.extractall(JRE_HOME)
    else:
        with tarfile.open(archive_path) as t:
            t.extractall(JRE_HOME)
    os.remove(archive_path)
    bin_dir = _jre_bin_dir()
    if not bin_dir:
        raise RuntimeError(f"JRE archive extracted to {JRE_HOME} but no bin/ dir found inside - bad archive or unexpected layout")
    if not _IS_WINDOWS:
        java_bin = os.path.join(bin_dir, "java")
        st = os.stat(java_bin)
        os.chmod(java_bin, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    logger.info(f"JRE {_JRE_MAJOR} installed to {bin_dir}")
    return bin_dir


def resolve_java_home():
    """Return a bin/ dir for jadx (None if system java is 11+); downloads a JRE if needed."""
    system_java = shutil.which("java")
    if system_java and (_java_major_version(system_java) or 0) >= 11:
        return None

    bin_dir = _jre_bin_dir()
    if bin_dir:
        java = os.path.join(bin_dir, "java.exe" if _IS_WINDOWS else "java")
        # A JRE left by an older narvy can be the wrong architecture (x64 on
        # Apple Silicon without Rosetta): it must actually run, or it is replaced.
        if (_java_major_version(java) or 0) >= 11:
            return bin_dir
        logger.warning(f"The cached JRE in {JRE_HOME} does not run here - downloading a fresh one")

    return _download_jre()


def _jadx_cmd(jadx_bin, extra_args):
    """argv for jadx. On Windows a .bat goes through cmd.exe as ONE string.

    A list like ["cmd", "/c", bat, ...] breaks as soon as the .bat path is quoted
    (a space in the user name, or C:\\Program Files): cmd /c strips the first
    and the last quote of the line and runs `C:\\Users\\Jean`. With /s and the
    whole line wrapped in one extra pair of quotes, cmd strips exactly that pair.
    """
    if _IS_WINDOWS and jadx_bin.lower().endswith((".bat", ".cmd")):
        return 'cmd /d /s /c "' + subprocess.list2cmdline([jadx_bin] + list(extra_args)) + '"'
    return [jadx_bin] + list(extra_args)


def _cmd_text(cmd):
    return cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd)


def _validate_apk_zip(apk_path: str):
    """Return None if the file looks like Android build output, else an error (jadx exits 0 on an empty/non-Android zip). Never raises."""
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
    except zipfile.BadZipFile as e:
        return f"Could not open {apk_path} as a zip archive: {e}. Not a valid APK/AAB?"
    except OSError as e:
        return f"Could not read {apk_path}: {e}"

    if not names:
        return f"{apk_path} is an empty archive (0 entries) - not a valid APK/AAB."

    has_manifest_or_dex = any(
        n.endswith("AndroidManifest.xml") or n.endswith(".dex") for n in names
    )
    if not has_manifest_or_dex:
        return (
            f"{apk_path} doesn't look like a valid APK/AAB - no AndroidManifest.xml "
            f"or .dex file found anywhere in the archive (found {len(names)} other "
            f"entries). If this is meant to be an Android app, check the file wasn't "
            f"truncated or is the wrong file."
        )
    return None


# Set by decompile_apk: the heap line(s) the caller prints after decompilation.
LAST_HEAP_NOTE = None
# What the last decompile_apk did, for tests and the JSON report: list of attempts.
LAST_ATTEMPTS = []

_HEAP_OOM_MARKERS = (
    "java.lang.OutOfMemoryError: Java heap space",
    "java.lang.OutOfMemoryError: GC overhead limit exceeded",
    "Terminating due to java.lang.OutOfMemoryError",
    "OutOfMemoryError: Java heap space",
)
# The OS would not give the JVM memory (commit charge full on Windows, a
# container limit, the OOM killer): a smaller heap is what can still work.
_NATIVE_OOM_MARKERS = (
    "There is insufficient memory for the Java Runtime Environment",
    "Native memory allocation (mmap) failed",
    "Native memory allocation (malloc) failed",
    "Could not reserve enough space for",
    "unable to create native thread",
    "Cannot allocate memory",
    "Error occurred during initialization of VM",
)


def _count_sources(output_dir):
    n = 0
    for _root, _dirs, files in os.walk(output_dir):
        n += sum(1 for f in files if f.endswith((".java", ".kt")))
    return n


def _classify_failure(returncode, output):
    """'heap' (Java heap too small), 'native' (the OS refused memory), or 'other'."""
    if any(m in output for m in _NATIVE_OOM_MARKERS):
        return "native"
    if any(m in output for m in _HEAP_OOM_MARKERS) or "OutOfMemoryError" in output:
        return "heap"
    # SIGKILL: POSIX -9, or 137 when a shell in between reports it.
    if returncode in (-9, 137):
        return "native"
    return "other"


def _jadx_env(xmx_mb, jre_bin_dir):
    env = os.environ.copy()
    # -Xms: the launcher's own -Xms256M would stop a smaller -Xmx from starting.
    # ExitOnOutOfMemoryError: stop at the first heap exhaustion instead of
    # grinding on for minutes, so the retry starts sooner.
    env['JADX_OPTS'] = (f'-Xms{min(256, xmx_mb)}m -Xmx{xmx_mb}m '
                        f'-XX:+ExitOnOutOfMemoryError')
    if jre_bin_dir:
        # jadx.bat reads JAVA_HOME, the Unix launcher just calls `java`.
        env['JAVA_HOME'] = os.path.dirname(jre_bin_dir)
        env['PATH'] = jre_bin_dir + os.pathsep + env.get('PATH', '')
    else:
        # jadx.bat prefers JAVA_HOME over PATH; drop a stale one for this subprocess only.
        java_home = env.get('JAVA_HOME')
        if java_home:
            candidate = os.path.join(java_home, 'bin', 'java.exe' if _IS_WINDOWS else 'java')
            if not os.path.isfile(candidate) or (_java_major_version(candidate) or 0) < 11:
                logger.warning(f"JAVA_HOME ({java_home}) is broken or too old - ignoring it for this scan only, falling back to PATH java")
                del env['JAVA_HOME']
    return env


def _run_jadx_once(jadx_bin, jre_bin_dir, apk_path, output_dir, extra_inputs, xmx_mb, threads):
    """One jadx run. Returns dict(ok, kind, returncode, output, cmd, sources, timed_out)."""
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir, ignore_errors=True)
    os.makedirs(output_dir, exist_ok=True)
    args = ['--output-dir', output_dir, '--show-bad-code']
    if threads:
        args += ['-j', str(threads)]
    cmd = _jadx_cmd(jadx_bin, args + [apk_path] + list(extra_inputs or []))
    rec = {"xmx_mb": xmx_mb, "threads": threads, "cmd": cmd, "timed_out": False}
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=900, env=_jadx_env(xmx_mb, jre_bin_dir),
        )
    except subprocess.TimeoutExpired:
        rec.update(ok=False, kind="timeout", returncode=None, output="", sources=0, timed_out=True)
        return rec
    rc = getattr(proc, "returncode", 0) or 0
    output = (getattr(proc, "stdout", "") or "") + (getattr(proc, "stderr", "") or "")
    rec.update(returncode=rc, output=output, stdout=getattr(proc, "stdout", "") or "",
               stderr=getattr(proc, "stderr", "") or "")
    rec["sources"] = _count_sources(output_dir)
    kind = _classify_failure(rc, output) if rc != 0 or "OutOfMemoryError" in output else None
    if kind is None and "unable to create native thread" in output:
        kind = "native"
    rec["kind"] = kind
    rec["ok"] = rc == 0 and kind is None
    return rec


def _retry_heap(first, plan, requested_mb):
    """(xmx_mb, threads) for the single retry, or None when no retry can help."""
    xmx = first["xmx_mb"]
    if first["kind"] == "heap":
        fit_now = heap_that_fits_mb(available_ram_mb())
        caps = [c for c in (requested_mb, fit_now) if c]
        bigger = min(caps) if caps else None
        if bigger and (bigger // 64) * 64 >= int(xmx * 1.25):
            return (bigger // 64) * 64, None
        # No room for a bigger heap. The same heap with fewer worker threads was
        # measured and does not rescue it (K-9 Mail at 1g: OOM with 4, 2 and 1
        # threads), so no retry: minutes saved, and the message says why.
        return None
    if first["kind"] == "native":
        smaller = max(MIN_HEAP_MB, ((int(xmx * 0.6)) // 64) * 64)
        if smaller < xmx:
            return smaller, 1
        return xmx, 1
    return None


def _failure_message(apk_path, attempts, plan):
    last = attempts[-1]
    cmd = last["cmd"]
    if last.get("timed_out"):
        return (
            f"JADX timed out after 900s decompiling {apk_path}. Large/obfuscated "
            "APKs can take longer - this is a hard ceiling, not currently configurable."
        )
    tried = ", then ".join(
        f"{fmt_mb(a['xmx_mb'])} heap" + (f" with {a['threads']} thread" if a.get("threads") else "")
        for a in attempts)
    if last["kind"] in ("heap", "native"):
        st = plan.stats
        size = f" ({app_scale(st)})" if st.ok else ""
        avail = available_ram_mb()
        if last["kind"] == "heap":
            head = f"JADX ran out of Java heap decompiling this app{size}. Tried: {tried}."
        else:
            head = (f"The operating system could not give JADX the memory it asked for{size}. "
                    f"Tried: {tried}.")
            if last["returncode"] in (-9, 137):
                head += (" (The process was killed with SIGKILL: the OS out-of-memory killer, a "
                         "container/cgroup memory limit or a CI runner's cap. Check "
                         "`dmesg -T | grep -i oom` and your container/CI limits.)")
        lines = [head]
        need = needed_heap_mb(plan.stats)
        if need:
            lines.append(f"This app is estimated to need about {fmt_mb(need)} of Java heap; "
                         f"{fmt_mb(avail)} of memory is free right now.")
        lines.append("Options:")
        lines.append("  - close other apps (browsers, IDEs, emulators) and re-run: the heap is sized "
                     "from the memory free at the start of the scan")
        if plan.requested_mb:
            lines.append(f"  - drop --max-mem {fmt_mb(plan.requested_mb)} (or raise it) so the heap "
                         f"can grow to what is free")
        lines.append("  - scan on a machine with more free memory, or upload the app from your "
                     "Narvy dashboard for a hosted scan")
        lines.append(f"Command run: {_cmd_text(cmd)}")
        return "\n".join(lines)
    parts = [f"JADX failed (exit code {last['returncode']})", f"Command run: {_cmd_text(cmd)}"]
    if last.get("stdout"):
        parts.append(f"JADX stdout:\n{last['stdout'][-4000:]}")
    if last.get("stderr"):
        parts.append(f"JADX stderr:\n{last['stderr'][-4000:]}")
    if not last.get("stdout") and not last.get("stderr"):
        parts.append(
            "No output captured on either stdout or stderr. Run "
            "`narvy doctor` to check your Java/jadx setup, or try "
            f"running this exact command yourself to see the raw error: {_cmd_text(cmd)}"
        )
    if last["returncode"] == 0 and last.get("sources", 0) == 0:
        parts.insert(0, "JADX exited without error but wrote no Java sources, so there is "
                        "nothing to analyse (reported as a failure, not as a clean scan).")
    return "\n".join(parts)


def decompile_apk(apk_path: str, output_dir: str, max_mem: str = None, force: bool = False,
                  extra_inputs=None, notify=None):
    """Decompile an APK with jadx; returns (success, error_detail).

    The Java heap is sized by apk_memory_preflight.plan_heap (never a refusal).
    If jadx runs out of Java heap it is retried once with a bigger heap when free
    memory allows; when the OS refused memory outright (commit limit, OOM killer,
    no native thread) it is retried once with a smaller heap and one thread. `--force` runs exactly --max-mem, no sizing and
    no retry. jadx keeps the FIRST input's manifest, so apk_path stays first;
    `extra_inputs` merge into one tree. `notify(level, text)` receives the heap
    warning before jadx starts (level "warning") and progress notes ("note").
    """
    validation_error = _validate_apk_zip(apk_path)
    if validation_error:
        return False, validation_error

    global LAST_HEAP_NOTE, LAST_ATTEMPTS
    LAST_HEAP_NOTE = None
    LAST_ATTEMPTS = []

    def _say(level, text):
        if notify and text:
            try:
                notify(level, text)
            except Exception:  # noqa: BLE001 - a display hiccup must not fail the scan
                logger.debug("notify failed", exc_info=True)

    inputs = [apk_path] + list(extra_inputs or [])
    plan = plan_heap(inputs, max_mem)
    requested_mb = plan.requested_mb
    if force and requested_mb:
        xmx = requested_mb
    else:
        xmx = plan.xmx_mb
        _say("warning", plan.warning)

    try:
        jadx_bin = resolve_jadx_binary()
    except Exception as e:
        return False, f"Could not obtain jadx: {e}. Run `narvy doctor` to check your setup."

    try:
        jre_bin_dir = resolve_java_home()
    except Exception as e:
        return False, (
            f"No usable Java found, and auto-downloading one failed: {e}. "
            "Check your internet connection can reach api.adoptium.net and "
            "github.com, or install a JRE 11+ yourself (https://adoptium.net) "
            "and put it on PATH. Run `narvy doctor` to check your setup."
        )

    try:
        first = _run_jadx_once(jadx_bin, jre_bin_dir, apk_path, output_dir, extra_inputs, xmx, None)
    except FileNotFoundError as e:
        return False, (
            f"Could not launch jadx ({jadx_bin}): {e}. Run `narvy doctor` "
            "to check your setup, or delete ~/.narvy/tools and re-run "
            "to force a clean re-download."
        )
    attempts = [first]
    if not first["ok"] and not force:
        retry = _retry_heap(first, plan, requested_mb)
        if retry:
            r_xmx, r_threads = retry
            what = "ran out of Java heap" if first["kind"] == "heap" else "was refused memory by the OS"
            _say("warning", f"JADX {what} at a {fmt_mb(xmx)} heap; retrying once with "
                            f"{fmt_mb(r_xmx)}" + (f" and {r_threads} worker thread" if r_threads else "")
                            + ".")
            attempts.append(_run_jadx_once(jadx_bin, jre_bin_dir, apk_path, output_dir,
                                           extra_inputs, r_xmx, r_threads))
    LAST_ATTEMPTS = [{k: a.get(k) for k in ("xmx_mb", "threads", "returncode", "kind", "sources", "ok")}
                     for a in attempts]
    final = attempts[-1]
    if final["ok"] and plan.stats.ok and plan.stats.classes > 0 and final.get("sources", 0) == 0:
        final["ok"] = False
        final["kind"] = "other"
    if not final["ok"]:
        return False, _failure_message(apk_path, attempts, plan)

    used = final["xmx_mb"]
    bits = [f"JADX heap {fmt_mb(used)}"]
    if needed_heap_mb(plan.stats):
        bits.append(f"app needs ~{fmt_mb(needed_heap_mb(plan.stats))}")
    if plan.available_mb is not None:
        bits.append(f"{fmt_mb(plan.available_mb)} free at start")
    if requested_mb and used < requested_mb:
        bits.append(f"--max-mem {fmt_mb(requested_mb)} is the upper limit")
    if len(attempts) > 1:
        bits.append(f"succeeded on retry after the {fmt_mb(attempts[0]['xmx_mb'])} run failed")
    note = "; ".join(bits) + "."
    m = re.search(r"finished with errors, count: (\d+)", final.get("output") or "")
    if m and int(m.group(1)):
        note += (f" JADX could not fully decompile {int(m.group(1))} method(s); they are kept "
                 f"as low-level code, so findings inside them may be missed.")
    LAST_HEAP_NOTE = note
    return True, ""
