"""Tests for android-weak-prng usage-context grading: HIGH when the value
reaches security material, INFO when it demonstrably does not, LOW when there
is no evidence either way, and nothing ever dropped.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import semgrep_engine, weak_prng_context

RULE_ID = "android-weak-prng"


# Security fixtures: must grade `security` / HIGH.

# Fully obfuscated class and field names, so the only evidence left is the
# `nextBytes` sink and the package path.
FIXTURE_FIDO2 = """package com.example.identity.auth.device;

import java.util.Random;

public final class l6 extends xc {
    public static final Random f = new Random();

    public static PublicKeyCredentialCreationOptions a(String str, Promise promise) {
        PublicKeyCredentialCreationOptions.Builder builder = new PublicKeyCredentialCreationOptions.Builder();
        byte[] bArr = new byte[32];
        f.nextBytes(bArr);
        builder.setUser(new PublicKeyCredentialUserEntity(bArr, "Example User", null, "Example User"));
        builder.setChallenge(Base64.decode(str, 3));
        return builder.build();
    }
}
"""

# Canonical shapes MASVS MSTG-CRYPTO-6 / CWE-338 describe.
FIXTURE_TOKEN = """package com.example.app;

import java.util.Random;

public class SessionManager {
    public String newSessionToken() {
        Random r = new Random();
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append(ALPHABET.charAt(r.nextInt(ALPHABET.length())));
        }
        return token.toString();
    }
}
"""

FIXTURE_CRYPTO_IV = """package com.example.app;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class Crypto {
    public byte[] encrypt(byte[] data, javax.crypto.SecretKey k) throws Exception {
        byte[] iv = new byte[16];
        Random rng = new Random();
        for (int i = 0; i < 16; i++) {
            iv[i] = (byte) rng.nextInt(256);
        }
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
        return c.doFinal(data);
    }
}
"""

FIXTURE_OTP = """package com.example.app;

import java.util.Random;

public class PasswordReset {
    public String generateOtp() {
        int otp = 100000 + new Random().nextInt(900000);
        return String.valueOf(otp);
    }
}
"""

# Non-security fixtures: must grade `non_security` / INFO.

# Jitter on a metrics upload alarm.
FIXTURE_JITTER = """package com.example.client.metrics;

public class AlarmUploadScheduler {
    protected int getJitterTimerInMillis() {
        return (int) (Math.random() * 3600000.0d);
    }
}
"""

# Analytics sampling coin flip.
FIXTURE_SAMPLING = """package com.example.reporting;

public class Reporter {
    boolean shouldRecordEvent(double rate) {
        return Math.random() < rate;
    }
}
"""

# Retry backoff sleep.
FIXTURE_BACKOFF = """package com.example.net;

public class ImageFetcher {
    public void retrySending(int attempt) {
        if (attempt == 0) {
            try {
                Thread.sleep(((int) (Math.random() * 6000.0d)) + 5000);
            } catch (InterruptedException e) {
            }
        }
    }
}
"""

# A retry sleep inside a package path containing 'crypto'/'keystore': strong
# sink evidence must beat the weaker security-path hint.
FIXTURE_SLEEP_IN_CRYPTO_PACKAGE = """package com.example.core.crypto.android.keystore;

public final class b {
    public static Object e(String str, Exception exc, Runnable r) {
        try {
            Thread.sleep((long) (Math.random() * 100.0d));
        } catch (InterruptedException unused) {
        }
        r.run();
        return null;
    }
}
"""

# Per-category background colour.
FIXTURE_COLOR = """package com.example.views.categories;

import java.util.Random;

public class CategoryController {
    public static int getBackgroundColour(Context context, String str) {
        return Color.HSVToColor(new float[]{new Random(str.hashCode()).nextFloat() * 360.0f, 0.4f, 0.5f});
    }
}
"""

# Unknown fixture: no evidence either way. Must stay visible at LOW, neither
# promoted to HIGH nor buried at INFO.
FIXTURE_UNKNOWN = """package com.example.model;

import java.util.Random;

public class NodeIdInt {
    private int id = -1;

    public NodeIdInt(int i, int i2) {
        this.id = (i2 & 1) != 0 ? new Random().nextInt() : i;
    }
}
"""


SECURITY_FIXTURES = {
    "l6.java": FIXTURE_FIDO2,
    "SessionManager.java": FIXTURE_TOKEN,
    "Crypto.java": FIXTURE_CRYPTO_IV,
    "PasswordReset.java": FIXTURE_OTP,
}
NON_SECURITY_FIXTURES = {
    "AlarmUploadScheduler.java": FIXTURE_JITTER,
    "Reporter.java": FIXTURE_SAMPLING,
    "ImageFetcher.java": FIXTURE_BACKOFF,
    "b.java": FIXTURE_SLEEP_IN_CRYPTO_PACKAGE,
    "CategoryController.java": FIXTURE_COLOR,
}
UNKNOWN_FIXTURES = {
    "NodeIdInt.java": FIXTURE_UNKNOWN,
}


def _classify_all(fixtures, rel_dir):
    """Grade every weak-PRNG line of each fixture with classify() directly, so
    the check runs without semgrep installed."""
    out = {}
    for fname, content in fixtures.items():
        rel = os.path.join(rel_dir(fname), fname)
        lines = content.split("\n")
        for i, ln in enumerate(lines, start=1):
            if "new Random(" in ln or "Math.random()" in ln:
                out[f"{fname}:{i}"] = weak_prng_context.classify(content, i, rel)
    return out


def _pkg_dir(content):
    first = content.strip().split("\n", 1)[0]
    return first.replace("package", "").replace(";", "").strip().replace(".", "/")


def test_security_context_stays_high():
    """A weak PRNG whose output becomes a FIDO2 credential handle, a session
    token, a cipher IV or an OTP must stay HIGH."""
    graded = _classify_all(
        SECURITY_FIXTURES,
        lambda f: "sources/" + _pkg_dir(SECURITY_FIXTURES[f]),
    )
    bad = {k: v for k, v in graded.items() if v["context"] != "security"}
    assert not bad, (
        "security-sensitive weak-PRNG use was not graded 'security': "
        f"{bad}"
    )
    assert all(v["severity"] == "HIGH" for v in graded.values()), graded


def test_non_security_context_downgraded_to_info():
    """Metrics jitter, sampling coin flips, retry backoff sleeps and colour
    generation are not CWE-338."""
    graded = _classify_all(
        NON_SECURITY_FIXTURES,
        lambda f: "sources/" + _pkg_dir(NON_SECURITY_FIXTURES[f]),
    )
    bad = {k: v for k, v in graded.items() if v["context"] != "non_security"}
    assert not bad, f"non-security weak-PRNG use not downgraded: {bad}"
    assert all(v["severity"] == "INFO" for v in graded.values()), graded


def test_sink_evidence_beats_security_package_path():
    """A `Thread.sleep(Math.random()*100)` inside a crypto/keystore package
    must not be HIGH just because the package path says 'crypto'."""
    v = weak_prng_context.classify(
        FIXTURE_SLEEP_IN_CRYPTO_PACKAGE, 6,
        "sources/com/example/core/crypto/android/keystore/b.java",
    )
    assert v["context"] == "non_security", v
    assert "sleep" in v["evidence"].lower(), v


def test_unknown_stays_visible_at_low():
    """No evidence either way must be neither dropped nor promoted to HIGH."""
    graded = _classify_all(
        UNKNOWN_FIXTURES,
        lambda f: "sources/" + _pkg_dir(UNKNOWN_FIXTURES[f]),
    )
    assert graded, "fixture produced no weak-PRNG line"
    for k, v in graded.items():
        assert v["context"] == "unknown", (k, v)
        assert v["severity"] == "LOW", (k, v)


def test_duplicate_same_file_line_collapsed():
    """One line constructing 11 sampling counters yields 11 semgrep matches at
    the same file:line."""
    dupes = [
        {"rule_id": RULE_ID, "file_path": "sources/a/B.java", "line": 219}
        for _ in range(11)
    ]
    dupes.append({"rule_id": RULE_ID, "file_path": "sources/a/B.java", "line": 220})
    dupes.append({"rule_id": "other-rule", "file_path": "sources/a/B.java", "line": 219})
    out = weak_prng_context.dedupe_by_location(dupes)
    assert len(out) == 3, out


def test_nothing_is_dropped():
    """Grading must never reduce the finding count, only re-severity it."""
    findings = [
        {"rule_id": RULE_ID, "file_path": "sources/x/Y.java", "line": 1,
         "severity": "CRITICAL"},
    ]
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "sources", "x"))
        with open(os.path.join(d, "sources", "x", "Y.java"), "w") as fh:
            fh.write("int a = new java.util.Random().nextInt();\n")
        out = weak_prng_context.apply(findings, d)
    assert len(out) == 1
    assert out[0]["severity"] in ("HIGH", "LOW", "INFO")
    assert out[0]["original_severity"] == "CRITICAL"
    assert out[0]["details"]["prng_context"]


def test_unreadable_file_keeps_original_severity():
    """Fail-open: never silently downgrade a finding whose file we could
    not read."""
    findings = [
        {"rule_id": RULE_ID, "file_path": "does/not/exist.java", "line": 1,
         "severity": "CRITICAL"},
    ]
    out = weak_prng_context.apply(findings, "/tmp")
    assert out[0]["severity"] == "CRITICAL"
    assert out[0]["details"]["prng_context"] == "unreadable"


def test_end_to_end_grading_through_semgrep():
    """The full path: semgrep fires the rule, run_semgrep grades it."""
    if not semgrep_engine.is_available():
        return  # semgrep not installed here
    with tempfile.TemporaryDirectory() as d:
        sec_dir = os.path.join(d, "sources", "com", "example", "identity", "auth", "device")
        os.makedirs(sec_dir)
        with open(os.path.join(sec_dir, "l6.java"), "w") as fh:
            fh.write(FIXTURE_FIDO2)
        ns_dir = os.path.join(d, "sources", "com", "example", "net")
        os.makedirs(ns_dir)
        with open(os.path.join(ns_dir, "ImageFetcher.java"), "w") as fh:
            fh.write(FIXTURE_BACKOFF)
        results = semgrep_engine.run_semgrep(d, timeout=120) or []
    prng = [r for r in results if r["rule_id"] == RULE_ID]
    assert prng, "android-weak-prng did not fire at all through semgrep"
    by_ctx = {r["details"]["prng_context"] for r in prng}
    assert "security" in by_ctx, (
        f"FIDO2 nextBytes case lost through the semgrep path: {prng}")
    assert "non_security" in by_ctx, (
        f"retry-sleep case not downgraded through the semgrep path: {prng}")
    for r in prng:
        assert r["details"]["prng_context_evidence"], r


if __name__ == "__main__":
    test_security_context_stays_high()
    test_non_security_context_downgraded_to_info()
    test_sink_evidence_beats_security_package_path()
    test_unknown_stays_visible_at_low()
    test_duplicate_same_file_line_collapsed()
    test_nothing_is_dropped()
    test_unreadable_file_keeps_original_severity()
    test_end_to_end_grading_through_semgrep()
    print("PASS: android-weak-prng usage-context grading OK "
          "(security kept HIGH, non-security -> INFO, unknown -> LOW, "
          "nothing dropped)")
