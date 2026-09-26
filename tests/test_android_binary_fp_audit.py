"""Android binary FP tests: stack protector, JNI vendor libs, PendingIntent, exported components, API keys."""
import os
import shutil
import struct
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy import native_hardening as nh
from narvy.android_rule_context import apply_gate
from narvy.rule_engine import load_rules_from_dir, run_rules_on_file
from narvy.stack_protector_evidence import (
    _aarch64_takes_stack_address,
    _arm32_takes_stack_address,
    has_instrumentable_stack_code,
)

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "narvy", "rules", "android",
)


def _cc_available():
    return shutil.which("gcc") or shutil.which("clang")


@pytest.mark.skipif(not _cc_available(), reason="no C compiler on this box")
def test_controlled_compile_proves_the_ambiguity():
    """`__stack_chk_fail` only appears when a function has a stack buffer."""
    cc = shutil.which("gcc") or shutil.which("clang")
    nobuf = (
        "#include <stdlib.h>\n"
        "char *decrypt(const char *in, unsigned n) {\n"
        "  char *out = (char *)malloc(n + 1);\n"
        "  for (unsigned i = 0; i < n; i++) out[i] = in[i] ^ 0x5a;\n"
        "  out[n] = 0; return out; }\n"
    )
    withbuf = (
        "#include <string.h>\n"
        "int fmt(const char *in) { char buf[64]; strcpy(buf, in); "
        "return (int)strlen(buf); }\n"
    )

    def build(src, flag, tmp, name):
        c = os.path.join(tmp, name + ".c")
        so = os.path.join(tmp, name + "." + flag.replace("-", "") + ".so")
        open(c, "w").write(src)
        r = subprocess.run([cc, "-O2", "-shared", "-fPIC", flag, "-o", so, c],
                           capture_output=True)
        assert r.returncode == 0, r.stderr.decode()[:400]
        return so

    def has_sym(path):
        out = subprocess.run(["readelf", "-sDW", path],
                             capture_output=True, text=True).stdout
        return "__stack_chk_fail" in out

    with tempfile.TemporaryDirectory() as tmp:
        on = build(nobuf, "-fstack-protector-strong", tmp, "nobuf")
        off = build(nobuf, "-fno-stack-protector", tmp, "nobuf")
        # Protection on, no canary symbol emitted.
        assert not has_sym(on), (
            "compiler emitted a canary for a function with no stack buffer; "
            "the premise of this fix would no longer hold"
        )
        assert not has_sym(off)
        assert os.path.getsize(on) == os.path.getsize(off), (
            "with no stack buffer, -fstack-protector-strong and "
            "-fno-stack-protector must produce identical output"
        )
        # Control: a real stack buffer DOES get instrumented, so the check is
        # not simply always-silent.
        assert has_sym(build(withbuf, "-fstack-protector-strong", tmp, "withbuf"))
        assert not has_sym(build(withbuf, "-fno-stack-protector", tmp, "withbuf"))


def _a64(words):
    return b"".join(struct.pack("<I", w) for w in words)


def test_aarch64_pure_register_spill_frame_is_not_instrumentable():
    """Heap buffer, stack only used to spill registers: nothing to protect."""
    code = _a64([
        0xA9BE7BFD,  # stp  x29, x30, [sp, #-0x20]!
        0xF9000BF3,  # str  x19, [sp, #0x10]
        0x910003FD,  # mov  x29, sp           (== add x29, sp, #0, FP setup)
        0xAA0003F3,  # mov  x19, x0
        0x52800440,  # mov  w0, #0x22
        0x94000029,  # bl   malloc
        0x3828682B,  # strb w11, [x1, x8]     (writes into the HEAP buffer)
        0xF9400BF3,  # ldr  x19, [sp, #0x10]
        0xA8C27BFD,  # ldp  x29, x30, [sp], #0x20
        0xD61F0040,  # br   x2
    ])
    assert _aarch64_takes_stack_address(code) is False


def test_aarch64_escaping_local_address_is_instrumentable():
    """Taking the address of a stack local is instrumentable, so the finding stays."""
    code = _a64([
        0xD10143FF,  # sub  sp, sp, #0x50
        0xA9047BFD,  # stp  x29, x30, [sp, #0x40]
        0x910103FD,  # add  x29, sp, #0x40     (FP setup, must not count)
        0x910063E1,  # add  x1, sp, #0x18      <-- escaping local address
        0xF9000FFF,  # str  xzr, [sp, #0x18]
    ])
    assert _aarch64_takes_stack_address(code) is True


def test_aarch64_frame_pointer_setup_alone_is_not_evidence():
    """Frame setup instructions are not an escaping address."""
    code = _a64([0xD10143FF, 0x910103FD, 0x910003FD])
    assert _aarch64_takes_stack_address(code) is False


def test_arm32_thumb_and_a32_forms_detected():
    assert _arm32_takes_stack_address(struct.pack("<I", 0xE28D1018))  # ADD r1, sp, #24
    assert _arm32_takes_stack_address(struct.pack("<H", 0xA906))      # ADD r1, SP, #24
    assert _arm32_takes_stack_address(struct.pack("<H", 0x466C))      # MOV r4, SP
    # ADD sp, sp, #imm / plain data ops are not evidence
    assert not _arm32_takes_stack_address(struct.pack("<I", 0xE28DD018))


def test_unknown_architecture_returns_none_not_false():
    """No decoder means unknown, not 'nothing instrumentable'."""
    class _Hdr:
        machine_type = object()

    class _Fake:
        header = _Hdr()
        sections = []

    assert has_instrumentable_stack_code(_Fake()) is None
    assert has_instrumentable_stack_code(None) is None


def test_androidx_jni_namespace_is_vendor_whatever_the_filename():
    """JNI entry points identify an AndroidX lib even when the filename doesn't."""
    assert nh._is_vendor_lib("libdatastore_shared_counter.so", [
        "Java_androidx_datastore_core_NativeSharedCounter_nativeCreateSharedCounter",
        "Java_androidx_datastore_core_NativeSharedCounter_nativeGetCounterValue",
        "mmap", "__errno",
    ]) is True
    assert nh._is_vendor_lib("libimage_processing_util_jni.so", [
        "Java_androidx_camera_core_ImageProcessingUtil_nativeShiftPixel",
    ]) is True


def test_app_own_jni_namespace_stays_own_code():
    """First-party native code must not be swept into "vendor"."""
    assert nh._is_vendor_lib("libexample-ndk.so", [
        "Java_com_example_app_crypto_KeyUtil_decryptApiKey",
        "malloc",
    ]) is False


def test_mixed_namespaces_are_not_vendor():
    """A lib exporting the app's own JNI symbols is app code."""
    assert nh._is_vendor_lib("libmixed.so", [
        "Java_androidx_camera_core_Foo_bar",
        "Java_com_example_app_Baz_qux",
    ]) is False


def test_no_jni_exports_falls_back_to_filename_logic():
    assert nh._is_vendor_lib("libc++_shared.so", ["_ZNSt3__1x", "operator_new"]) is True
    assert nh._is_vendor_lib("libmycompany_engine.so", ["_ZN3foo3barEv"]) is False


def _run_rule(tmp_path, filename, content, rule_id):
    p = tmp_path / filename
    p.write_text(content)
    rules = [r for r in load_rules_from_dir(RULES_DIR) if r["id"] == rule_id]
    assert rules, f"{rule_id} missing from the ruleset"
    return run_rules_on_file(str(p), rules)


@pytest.mark.parametrize("flags,label", [
    ("67108864", "FLAG_IMMUTABLE"),
    ("1140850688", "FLAG_ONE_SHOT|FLAG_IMMUTABLE"),
    ("335544320", "FLAG_CANCEL_CURRENT|FLAG_IMMUTABLE"),
    ("201326592", "FLAG_UPDATE_CURRENT|FLAG_IMMUTABLE"),
    ("PendingIntent.FLAG_IMMUTABLE", "symbolic"),
    ("PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE", "symbolic combo"),
])
def test_pending_intent_with_immutable_flag_is_not_reported(tmp_path, flags, label):
    """Flag values are the literals jadx emits at real call sites."""
    src = (
        "class A {\n"
        "  void f(Context c, Intent i) {\n"
        f"    PendingIntent p = PendingIntent.getBroadcast(c, 0, i, {flags});\n"
        "  }\n}\n"
    )
    assert _run_rule(tmp_path, "A.java", src, "AND-CONF-009") == [], label


def test_pending_intent_without_any_mutability_flag_is_still_reported(tmp_path):
    """Android 12+ requires an explicit flag, so the genuine bug must fire."""
    src = (
        "class A {\n"
        "  void f(Context c, Intent i) {\n"
        "    PendingIntent p = PendingIntent.getActivity(c, 0, i, 134217728);\n"
        "  }\n}\n"
    )
    assert len(_run_rule(tmp_path, "A.java", src, "AND-CONF-009")) == 1


def test_pending_intent_with_unresolvable_flags_is_still_reported(tmp_path):
    """"Can't tell" must stay in the report; the gate only drops on proof."""
    src = (
        "class A {\n"
        "  void f(Context c, Intent i, int flags) {\n"
        "    PendingIntent p = PendingIntent.getService(c, 0, i, flags);\n"
        "  }\n}\n"
    )
    assert len(_run_rule(tmp_path, "A.java", src, "AND-CONF-009")) == 1


def test_explicit_mutable_is_kept_and_reworded(tmp_path):
    src = (
        "class A {\n"
        "  void f(Context c, Intent i) {\n"
        "    PendingIntent p = PendingIntent.getBroadcast(c, 0, i, 33554432);\n"
        "  }\n}\n"
    )
    out = _run_rule(tmp_path, "A.java", src, "AND-CONF-009")
    assert len(out) == 1
    assert "Mutable" in out[0]["name"]
    assert "setComponent" in out[0]["details"]["recommendation"]


# A LAUNCHER entry point is not an export vulnerability.

_LAUNCHER_ALIAS = """<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.app">
    <application>
        <activity-alias
            android:name="launcher.alt"
            android:exported="true"
            android:targetActivity="com.example.app.main.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity-alias>
    </application>
</manifest>
"""

_EXPORTED_RECEIVER = """<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.app">
    <application>
        <receiver
            android:name="com.example.app.AdminReceiver"
            android:exported="true"/>
    </application>
</manifest>
"""

_DEEPLINK_ACTIVITY = """<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.app">
    <application>
        <activity android:name="com.example.app.DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


def test_launcher_entry_point_is_not_reported(tmp_path):
    """Android requires a LAUNCHER component to be exported."""
    assert _run_rule(tmp_path, "AndroidManifest.xml", _LAUNCHER_ALIAS,
                     "AND-CONF-004") == []


def test_plain_exported_receiver_is_still_reported(tmp_path):
    assert len(_run_rule(tmp_path, "AndroidManifest.xml", _EXPORTED_RECEIVER,
                         "AND-CONF-004")) == 1


def test_deeplink_activity_is_still_reported(tmp_path):
    """A BROWSABLE deep-link handler is reachable; only launcher entries are exempt."""
    assert len(_run_rule(tmp_path, "AndroidManifest.xml", _DEEPLINK_ACTIVITY,
                         "AND-CONF-004")) == 1


_FIREBASE_STRINGS = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<resources>\n'
    '    <string name="google_api_key">AIzaSyEXAMPLE_NOT_A_REAL_KEY_0000000000</string>\n'
    '    <string name="google_crash_reporting_api_key">'
    'AIzaSyEXAMPLE_NOT_A_REAL_KEY_0000000000</string>\n'
    '</resources>\n'
)


def test_firebase_generated_key_is_medium_not_high(tmp_path):
    """The Firebase config key is an identifier, not a secret."""
    out = _run_rule(tmp_path, "strings.xml", _FIREBASE_STRINGS, "AND-S-005")
    assert len(out) == 2
    for f in out:
        assert f["severity"] == "MEDIUM"
        assert "signing certificate SHA-1" in f["details"]["recommendation"]


def test_google_key_hardcoded_in_source_stays_high(tmp_path):
    """A raw AIza key in code stays HIGH."""
    src = (
        "class A {\n"
        '  static final String K = "AIzaSyEXAMPLE_NOT_A_REAL_KEY_0000000000";\n'
        "}\n"
    )
    out = _run_rule(tmp_path, "A.java", src, "AND-S-005")
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH"


def test_gate_failure_keeps_the_finding():
    """Fail-open contract: a broken gate must never silently suppress."""
    import narvy.android_rule_context as ctx

    original = ctx.RULE_GATES["AND-CONF-004"]
    try:
        ctx.RULE_GATES["AND-CONF-004"] = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        finding = {"rule_id": "AND-CONF-004"}
        import re
        m = re.search("x", "x")
        assert apply_gate("AND-CONF-004", "x", m, finding) is finding
    finally:
        ctx.RULE_GATES["AND-CONF-004"] = original
