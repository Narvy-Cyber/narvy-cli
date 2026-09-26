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
    JVM_RSS_OVERHEAD,
    check_memory_preflight,
    parse_mem_arg,
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
# x64 only: ARM Linux is unsupported and fails loudly on the archive.
_JRE_ADOPTIUM_ARCH = "x64"
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
        result = subprocess.run([java_bin, "-version"], capture_output=True, text=True, timeout=10)
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
    for entry in os.listdir(JRE_HOME):
        candidate = os.path.join(JRE_HOME, entry, "bin")
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
        return bin_dir

    return _download_jre()


def _jadx_cmd(jadx_bin, extra_args):
    # A .bat needs `cmd /c`; shell=True would mis-quote paths.
    if _IS_WINDOWS and jadx_bin.lower().endswith(".bat"):
        return ["cmd", "/c", jadx_bin] + extra_args
    return [jadx_bin] + extra_args


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


def _as_limit_preexec(max_mem_mb):
    """Return a preexec_fn capping the jadx child's address space, or None. POSIX only."""
    # Cap is 2x heap + 3 GB: a JVM reserves far more address space than its heap.
    if _IS_WINDOWS or not max_mem_mb:
        return None
    try:
        import resource
    except ImportError:
        return None

    limit_bytes = int((max_mem_mb * 2 + 3072) * 1024 * 1024)

    def _set_limits():
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            # Never raise an existing limit: a CI runner may have set a tighter one.
            target = limit_bytes
            if hard != resource.RLIM_INFINITY:
                target = min(target, hard)
            if soft != resource.RLIM_INFINITY:
                target = min(target, soft)
            resource.setrlimit(resource.RLIMIT_AS, (target, hard))
        except Exception:
            pass

    return _set_limits


def decompile_apk(apk_path: str, output_dir: str, max_mem: str = "4g", force: bool = False,
                  extra_inputs=None):
    """Decompile an APK with jadx; returns (success, error_detail). jadx keeps the FIRST input's manifest, so apk_path stays first; `extra_inputs` merge into one tree."""
    validation_error = _validate_apk_zip(apk_path)
    if validation_error:
        return False, validation_error

    if not force:
        verdict = check_memory_preflight(apk_path, max_mem)
        if verdict.should_block:
            return False, verdict.message

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

    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    jadx_env = os.environ.copy()
    jadx_env['JADX_OPTS'] = f'-Xmx{max_mem}'

    if jre_bin_dir:
        # jadx.bat reads JAVA_HOME, the Unix launcher just calls `java`.
        jadx_env['JAVA_HOME'] = os.path.dirname(jre_bin_dir)
        jadx_env['PATH'] = jre_bin_dir + os.pathsep + jadx_env.get('PATH', '')
    else:
        # jadx.bat prefers JAVA_HOME over PATH; drop a stale one for this subprocess only.
        java_home = jadx_env.get('JAVA_HOME')
        if java_home:
            candidate = os.path.join(java_home, 'bin', 'java.exe' if _IS_WINDOWS else 'java')
            if not os.path.isfile(candidate) or (_java_major_version(candidate) or 0) < 11:
                logger.warning(f"JAVA_HOME ({java_home}) is broken or too old - ignoring it for this scan only, falling back to PATH java")
                del jadx_env['JAVA_HOME']

    cmd = _jadx_cmd(
        jadx_bin,
        ['--output-dir', output_dir, '--show-bad-code', apk_path] + list(extra_inputs or []),
    )

    run_kwargs = {}
    preexec = _as_limit_preexec(parse_mem_arg(max_mem))
    if preexec is not None:
        run_kwargs["preexec_fn"] = preexec

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=900,
            env=jadx_env,
            **run_kwargs
        )
        return True, ""
    except subprocess.CalledProcessError as e:
        # jadx/cmd.exe don't consistently use stderr; report both streams.
        parts = [f"JADX failed (exit code {e.returncode})", f"Command run: {' '.join(str(c) for c in cmd)}"]
        if e.stdout:
            parts.append(f"JADX stdout:\n{e.stdout}")
        if e.stderr:
            parts.append(f"JADX stderr:\n{e.stderr}")
        if not e.stdout and not e.stderr:
            parts.append(
                "No output captured on either stdout or stderr. Run "
                "`narvy doctor` to check your Java/jadx setup, or try "
                f"running this exact command yourself to see the raw error: "
                f"{' '.join(str(c) for c in cmd)}"
            )
        # OOM is unambiguous; a bare -9 (SIGKILL) is ambiguous, so they differ.
        _combined_output = (e.stdout or "") + (e.stderr or "")
        _jvm_oom = "OutOfMemoryError" in _combined_output
        if _jvm_oom or e.returncode == -9:
            if _jvm_oom:
                hint = "\nJADX ran out of memory decompiling this app."
            else:
                hint = (
                    "\nJADX was killed by SIGKILL (exit -9) - killed from outside, with no "
                    "error of its own. There is no way to tell from the exit code alone which "
                    "of these it was: the OS out-of-memory killer, a container/cgroup memory "
                    "limit (Docker `--memory`, a CI runner's cap), a job timeout, or another "
                    "process on this machine. Check `dmesg -T | grep -i oom` and your "
                    "container/CI memory limits."
                )
            try:
                v = check_memory_preflight(apk_path, max_mem)
                suggest_gb = max(1, -(-int(v.estimated_mb * 1.25) // 1024))
                lead = ("Based on" if _jvm_oom else
                        "\n\nIf it was memory: based on")
                hint += (
                    f" {lead} its size (~{v.stats.methods:,} methods / "
                    f"~{v.stats.classes:,} classes), it needs noticeably more than the "
                    f"{max_mem} it was given"
                )
                if v.available_mb is not None:
                    fits = int(suggest_gb * 1024 * JVM_RSS_OVERHEAD) <= v.available_mb
                    hint += (
                        f". Try `--max-mem {suggest_gb}g`"
                        + ("." if fits else
                           f", but note this machine only has ~{v.available_mb // 1024} GB free "
                           f"right now - you would need to free memory first, or run this scan "
                           f"elsewhere (e.g. `--upload` for the hosted scan).")
                    )
                else:
                    hint += f". Try `--max-mem {suggest_gb}g`."
            except Exception:
                hint += (
                    f" Try again with more headroom, e.g. `narvy scan {apk_path} "
                    f"--max-mem 8g`."
                )
            parts.append(hint)
        return False, "\n".join(parts)
    except subprocess.TimeoutExpired:
        return False, (
            f"JADX timed out after 900s decompiling {apk_path}. Large/obfuscated "
            "APKs can take longer - this is a hard ceiling, not currently configurable."
        )
    except FileNotFoundError as e:
        return False, (
            f"Could not launch jadx ({jadx_bin}): {e}. Run `narvy doctor` "
            "to check your setup, or delete ~/.narvy/tools and re-run "
            "to force a clean re-download."
        )
