"""The synthetic fixtures are only meaningful if they are valid binaries.
These tests check them with independent tools when available (aapt, llvm-readelf,
llvm-nm, llvm-objdump); they are skipped otherwise."""
import os
import shutil
import subprocess

import pytest

import builders as B

AAPT = os.environ.get("AAPT") or shutil.which("aapt")
READELF = shutil.which("llvm-readelf") or shutil.which("readelf")
NM = shutil.which("llvm-nm")
OBJDUMP = shutil.which("llvm-objdump")


@pytest.mark.skipif(not AAPT, reason="aapt not installed")
def test_axml_is_readable_by_aapt(tmp_path):
    man = B.manifest(target=34, app_attrs={"android:debuggable": True},
                     app_children=[B.E("activity", {"android:name": ".Main", "android:exported": True},
                                       [B.E("intent-filter", {}, [B.E("action", {"android:name": "android.intent.action.MAIN"})])]),
                                   B.E("service", {"android:name": ".S", "android:foregroundServiceType": ("hex", 0x9)})],
                     perms=["android.permission.FOREGROUND_SERVICE"])
    p = tmp_path / "a.apk"
    p.write_bytes(B.apk(man))
    out = subprocess.run([AAPT, "dump", "xmltree", str(p), "AndroidManifest.xml"], capture_output=True, text=True).stdout
    assert "android:targetSdkVersion(0x01010270)=(type 0x10)0x22" in out
    assert "android:debuggable(0x0101000f)=(type 0x12)0xffffffff" in out
    assert "android:foregroundServiceType(0x01010599)=(type 0x11)0x9" in out
    assert "android:exported(0x01010010)=(type 0x12)0xffffffff" in out
    badging = subprocess.run([AAPT, "dump", "badging", str(p)], capture_output=True, text=True).stdout
    assert "targetSdkVersion:'34'" in badging


@pytest.mark.skipif(not AAPT, reason="aapt not installed")
def test_arsc_is_readable_by_aapt(tmp_path):
    man = B.manifest(app_attrs={"android:networkSecurityConfig": ("ref", 0x7F010000)})
    p = tmp_path / "a.apk"
    p.write_bytes(B.apk(man, files={"resources.arsc": B.arsc({0x7F010000: ("file", "res/xml/nsc.xml"),
                                                               0x7F020001: ("bool", True)})}))
    out = subprocess.run([AAPT, "dump", "--values", "resources", str(p)], capture_output=True, text=True).stdout
    assert "0x7f010000" in out and "res/xml/nsc.xml" in out
    assert "0x7f020001" in out


@pytest.mark.skipif(not READELF, reason="readelf not installed")
@pytest.mark.parametrize("align", [0x1000, 0x4000, 0x10000])
def test_elf_is_readable_by_readelf(tmp_path, align):
    p = tmp_path / "x.so"
    p.write_bytes(B.elf64([align, align]))
    out = subprocess.run([READELF, "-lW", str(p)], capture_output=True, text=True).stdout
    loads = [line.split()[-1] for line in out.splitlines() if line.strip().startswith("LOAD")]
    assert len(loads) == 2 and all(int(x, 16) == align for x in loads)


@pytest.mark.skipif(not NM, reason="llvm-nm not installed")
def test_macho_is_readable_by_llvm_nm(tmp_path):
    p = tmp_path / "bin"
    p.write_bytes(B.macho(imports=["_stat", "_OBJC_CLASS_$_NSUserDefaults"], defined=["_main"]))
    out = subprocess.run([NM, "-u", str(p)], capture_output=True, text=True).stdout.split()
    assert set(out) == {"_stat", "_OBJC_CLASS_$_NSUserDefaults"}
    out = subprocess.run([NM, "--defined-only", str(p)], capture_output=True, text=True).stdout
    assert "_main" in out


@pytest.mark.skipif(not OBJDUMP, reason="llvm-objdump not installed")
def test_macho_build_version_readable(tmp_path):
    p = tmp_path / "bin"
    p.write_bytes(B.macho(sdk=(18, 2), minos=(12, 0)))
    out = subprocess.run([OBJDUMP, "--macho", "--private-headers", str(p)], capture_output=True, text=True).stdout
    assert "LC_BUILD_VERSION" in out
    assert "sdk 18.2" in out and "minos 12.0" in out
