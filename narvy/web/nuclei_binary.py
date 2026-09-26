"""Resolve a `nuclei` binary, downloading a pinned release if none on PATH."""

import logging
import os
import platform
import shutil
import stat
import subprocess
import zipfile

import requests

logger = logging.getLogger(__name__)

# Pinned by hand: a floating version would change scan behaviour between runs.
NUCLEI_VERSION = "3.5.1"
TOOLS_DIR = os.path.expanduser("~/.narvy/tools")
NUCLEI_HOME = os.path.join(TOOLS_DIR, f"nuclei-{NUCLEI_VERSION}")
_IS_WINDOWS = platform.system() == "Windows"
_IS_MAC = platform.system() == "Darwin"
NUCLEI_BIN = os.path.join(NUCLEI_HOME, "nuclei.exe" if _IS_WINDOWS else "nuclei")


def _release_asset_name() -> str:
    """Release zip filename: nuclei_<version>_<os>_<arch>.zip (os linux/macOS/windows)."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    elif machine in ("armv7l", "armv6l", "arm"):
        arch = "arm"
    elif machine in ("i386", "i686", "x86"):
        arch = "386"
    else:
        raise RuntimeError(
            f"No known nuclei release for CPU architecture {machine!r}. "
            "Install nuclei yourself and put it on PATH: "
            "https://github.com/projectdiscovery/nuclei/releases"
        )

    if _IS_WINDOWS:
        os_name = "windows"
    elif _IS_MAC:
        os_name = "macOS"
    else:
        os_name = "linux"

    return f"nuclei_{NUCLEI_VERSION}_{os_name}_{arch}.zip"


def _download_nuclei():
    os.makedirs(TOOLS_DIR, exist_ok=True)
    asset_name = _release_asset_name()
    url = (
        f"https://github.com/projectdiscovery/nuclei/releases/download/"
        f"v{NUCLEI_VERSION}/{asset_name}"
    )
    zip_path = os.path.join(TOOLS_DIR, asset_name)
    logger.info(f"nuclei not found on PATH - downloading {url}")
    resp = requests.get(url, stream=True, timeout=120, allow_redirects=True)
    resp.raise_for_status()
    with open(zip_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1 << 20):
            f.write(chunk)
    os.makedirs(NUCLEI_HOME, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(NUCLEI_HOME)
    os.remove(zip_path)
    if not os.path.exists(NUCLEI_BIN):
        raise RuntimeError(
            f"nuclei archive extracted to {NUCLEI_HOME} but no binary found "
            f"at the expected path {NUCLEI_BIN} - unexpected archive layout."
        )
    if not _IS_WINDOWS:
        st = os.stat(NUCLEI_BIN)
        os.chmod(NUCLEI_BIN, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    logger.info(f"nuclei {NUCLEI_VERSION} installed to {NUCLEI_BIN}")


def resolve_nuclei_binary() -> str:
    """Prefer nuclei on PATH, else download the pinned release to ~/.narvy/tools."""
    on_path = shutil.which("nuclei")
    if on_path:
        return on_path
    if os.path.exists(NUCLEI_BIN):
        return NUCLEI_BIN
    _download_nuclei()
    return NUCLEI_BIN


def verify_nuclei(nuclei_bin: str) -> str:
    try:
        result = subprocess.run(
            [nuclei_bin, "-version"], capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        raise RuntimeError(f"Could not run nuclei ({nuclei_bin}): {e}")
    # nuclei prints its version banner to stderr and exits 0.
    out = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0 or not out.strip():
        raise RuntimeError(
            f"nuclei ({nuclei_bin}) did not run cleanly (exit {result.returncode}): {out[:300]}"
        )
    return out.strip()
