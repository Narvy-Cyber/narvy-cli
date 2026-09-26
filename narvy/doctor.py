"""`narvy doctor`: check the local environment and print a fix for each failure."""
import os
import platform
import re
import shutil
import subprocess
import sys

from rich.console import Console
from rich.table import Table
from rich.markup import escape as _rich_escape

from . import decompiler
from .ios import binary_analyzer as ios_binary_analyzer

console = Console()


def _java_version(java_bin):
    """Run `java -version` and return (version_line, major_version_int_or_None)."""
    result = subprocess.run([java_bin, "-version"], capture_output=True, text=True, timeout=10)
    out = result.stderr or result.stdout or ""
    version_line = out.splitlines()[0] if out else "unknown version"
    # Handles both the old "1.8.0_501" scheme and the modern "17.0.2" one.
    m = re.search(r'version "(\d+)(?:\.(\d+))?', out)
    if not m:
        return version_line, None
    major = int(m.group(1))
    if major == 1 and m.group(2):
        major = int(m.group(2))
    return version_line, major


def _check_java():
    try:
        jre_bin_dir = decompiler.resolve_java_home()
    except Exception as e:
        return False, f"No usable Java found and auto-download failed: {e}", (
            "Check your internet connection can reach api.adoptium.net and "
            "github.com. If it's not a network issue, install a JRE 11+ "
            "yourself: https://adoptium.net"
        )
    if jre_bin_dir:
        return True, f"Using our own auto-downloaded JRE 17 ({jre_bin_dir}) - your system Java was missing or too old, no action needed", None
    java = shutil.which("java")
    version_line, _ = _java_version(java) if java else ("system java", None)
    return True, version_line, None


def _check_jadx():
    try:
        jadx_bin = decompiler.resolve_jadx_binary()
    except Exception as e:
        return False, "Not found, auto-download failed", (
            f"Download failed: {e}. Check your internet connection can reach "
            "github.com, or manually install jadx and put it on PATH: "
            "https://github.com/skylot/jadx/releases"
        )
    return True, jadx_bin, None


def _check_write_access():
    import os
    test_dir = os.path.expanduser("~/.narvy")
    try:
        os.makedirs(test_dir, exist_ok=True)
        test_file = os.path.join(test_dir, ".doctor_write_test")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        return True, test_dir, None
    except Exception as e:
        return False, f"Cannot write to {test_dir}: {e}", (
            "Check folder permissions, or that no antivirus/sync tool (OneDrive, "
            "Dropbox) is locking files in your home directory."
        )


def _check_icdump():
    """Informational only: iOS binary scans degrade to a LIEF-only Obj-C pass without it."""
    if ios_binary_analyzer.icdump_available():
        return True, "Installed - full Obj-C class/method/property introspection available for iOS binary (.ipa) scans", None
    import platform as _platform
    if _platform.system() == "Windows":
        detail = "Not installed (expected on Windows - no icdump wheel exists for this platform)"
    else:
        detail = "Not installed - iOS binary scans will fall back to symbol-table-only Obj-C detection"
    return True, detail, (
        "Optional: `pip install narvy-cli[ios-full]` (Linux/macOS/WSL only - no Windows wheel exists) "
        "for full Obj-C class/method/property introspection on .ipa scans. Not required - iOS binary "
        "scanning still works without it, just with coarser Obj-C detection (class names only, via LIEF's "
        "symbol table, no methods/properties/protocols)."
    )


def _check_memory():
    """Report how much RAM is free and what size of app that buys."""
    from .apk_memory_preflight import (
        HEAP_MB_PER_CLASS, JVM_RSS_OVERHEAD, RAM_SAFETY_RESERVE_MB, available_ram_mb,
    )
    avail = available_ram_mb()
    if avail is None:
        return True, "Could not determine available memory on this platform", None
    usable_heap_mb = max(0, (avail - RAM_SAFETY_RESERVE_MB) / JVM_RSS_OVERHEAD)
    classes = int(usable_heap_mb / HEAP_MB_PER_CLASS)
    detail = (
        f"{avail / 1024:.1f} GB available - enough Java heap for an app of roughly "
        f"{classes // 1000}k classes (default --max-mem 4g handles ~80k)"
    )
    if avail < 5 * 1024:
        return True, detail, (
            "Large commercial apps need 8-24 GB of free memory to decompile locally. "
            "The hosted scan (`--upload`) removes the local memory ceiling and handles "
            "any app size - use it for large apps, or scan locally within this "
            "machine's memory."
        )
    return True, detail, None


def _check_network():
    import socket
    for host in ("github.com", "api.adoptium.net"):
        try:
            socket.create_connection((host, 443), timeout=5)
        except Exception as e:
            return False, f"Cannot reach {host}: {e}", (
                "Check your internet connection / firewall / proxy settings. "
                f"{host} is needed for jadx/JRE auto-download."
            )
    return True, "github.com + api.adoptium.net reachable (jadx + JRE auto-download)", None


def _check_semgrep():
    """semgrep runs the AST/taint pass; without it `scan` falls back to regex rules only."""
    from . import semgrep_engine
    if semgrep_engine.is_available():
        return True, f"{semgrep_engine.semgrep_bin()}", None
    return True, "Not found - scans fall back to regex-only (reduced coverage)", (
        "semgrep is the deep structural analysis engine for `narvy scan` "
        "(Android/iOS/web source and binary modes). Without it, scans run regex "
        "rules only and miss AST/taint-based findings. Install it: "
        "pip install semgrep==1.152.0 (it ships as a dependency of narvy, "
        "so a missing binary usually means a broken venv - reinstall the CLI)."
    )


def _check_nuclei():
    """Informational: needed by `narvy web-scan` only."""
    from .web import nuclei_binary
    try:
        nuclei_bin = nuclei_binary.resolve_nuclei_binary()
        version = nuclei_binary.verify_nuclei(nuclei_bin)
    except Exception as e:
        return True, f"Not available yet - auto-download failed: {e}", (
            "Needed only for `narvy web-scan`. Check your internet "
            "connection can reach github.com, or install nuclei yourself "
            "and put it on PATH: https://github.com/projectdiscovery/nuclei/releases"
        )
    first = re.sub(r"\x1b\[[0-9;]*m", "", version.splitlines()[0])
    return True, f"{nuclei_bin} ({first[:60]})", None


def _check_ssh_client():
    """Informational: `narvy host-audit` uses the system ssh/scp binaries."""
    ssh_bin = shutil.which("ssh")
    scp_bin = shutil.which("scp")
    if not ssh_bin or not scp_bin:
        missing = "ssh" if not ssh_bin else "scp"
        return True, f"{missing} not found on PATH", (
            "Needed only for `narvy host-audit`. Install an OpenSSH "
            "client (usually pre-installed on Linux/macOS; on Windows, "
            "enable the built-in OpenSSH client or use WSL)."
        )
    return True, f"{ssh_bin}", None


def _check_boto3():
    """Informational: boto3 is an opt-in extra needed by `narvy cloud-scan`."""
    try:
        import boto3  # noqa: F401
        return True, f"Installed ({boto3.__version__})", None
    except ImportError:
        return True, "Not installed", (
            "Needed only for `narvy cloud-scan`. Run: "
            "pip install narvy-cli[cloud]"
        )


def run_doctor():
    console.print(f"\n[bold]Narvy CLI Doctor[/bold] - {platform.system()} {platform.release()}, Python {sys.version.split()[0]}\n")

    checks = [
        ("Java (JRE 11+)", _check_java),
        ("Disk write access (~/.narvy)", _check_write_access),
        ("Available memory (Android decompile)", _check_memory),
        ("Network (github.com, for jadx download)", _check_network),
        ("jadx (decompiler)", _check_jadx),
        ("semgrep (deep SAST engine)", _check_semgrep),
        ("icdump (iOS Obj-C introspection, optional)", _check_icdump),
        ("nuclei (web-scan, optional)", _check_nuclei),
        ("ssh/scp client (host-audit, optional)", _check_ssh_client),
        ("boto3 (cloud-scan, optional)", _check_boto3),
    ]

    table = Table(show_header=True)
    table.add_column("Check")
    table.add_column("Status", justify="center")
    table.add_column("Detail")

    all_ok = True
    fixes = []
    optional_hints = []
    for name, check_fn in checks:
        ok, detail, fix = check_fn()
        if not ok:
            status = "[bold red]FAIL[/bold red]"
        elif fix:
            status = "[bold cyan]INFO[/bold cyan]"
        else:
            status = "[bold green]PASS[/bold green]"
        # Detail text can contain '[...]' (an extras spec, nuclei's [INF]) which
        # Rich would parse as markup and silently drop.
        table.add_row(name, status, _rich_escape(detail))
        if not ok:
            all_ok = False
            fixes.append((name, fix))
        elif fix:
            optional_hints.append((name, fix))

    console.print(table)

    if all_ok:
        console.print("\n[bold green]Everything looks good. `narvy scan <apk|ipa|android-source-dir|ios-source-dir|web-source-dir>` should work.[/bold green]")
    else:
        console.print("\n[bold red]Found problems - fix these before scanning:[/bold red]")
        for name, fix in fixes:
            console.print(f"\n[bold]{name}:[/bold] {_rich_escape(fix)}")

    for name, hint in optional_hints:
        label = name if "optional" in name else f"{name} (optional)"
        console.print(f"\n[bold cyan]{label}:[/bold cyan] {_rich_escape(hint)}")

    if not all_ok:
        sys.exit(1)
