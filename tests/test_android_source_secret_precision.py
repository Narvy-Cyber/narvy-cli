"""Android hardcoded-secret rules: key names and type names aren't secrets, real ones still fire."""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.android import source_analyzer


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _make_repo(root: str) -> None:
    _write(os.path.join(root, "settings.gradle"), "rootProject.name = 'app'\ninclude ':app'\n")
    _write(os.path.join(root, "app", "build.gradle"),
           "apply plugin: 'com.android.application'\nandroid {\n    namespace 'com.example.app'\n}\n")
    _write(os.path.join(root, "app", "src", "main", "AndroidManifest.xml"),
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android"></manifest>')
    main_java = os.path.join(root, "app", "src", "main", "java", "com", "example")
    # Preference-key-name constants (FP): the literal echoes the constant name.
    _write(os.path.join(main_java, "ConstantsBase.java"),
           "package com.example;\n"
           "interface ConstantsBase {\n"
           '  String PREF_PASSWORD = "password";\n'
           '  String PREF_PASSWORD_QUESTION = "password_question";\n'
           "}\n")
    _write(os.path.join(main_java, "SettingsStore.kt"),
           "package com.example\n"
           'const val PREF_TRANSLATION_API_KEY = "pref_translation_api_key"\n'
           # KEY_*-named preference constant holding a settings-key slug (FP).
           'const val KEY_SECRET_TOKEN = "secret_token_pref"\n')
    # Name-based rule match with a function-call RHS, no string literal (FP).
    _write(os.path.join(main_java, "PirateWeatherService.kt"),
           "package com.example\n"
           "class PirateWeatherService {\n"
           "  val apiKey = getApiKeyOrDefault()\n"
           "  fun getApiKeyOrDefault(): String { return \"\" }\n"
           "}\n")
    # Genuine hardcoded provider secrets (protected TRUE POSITIVES).
    _write(os.path.join(main_java, "Secrets.kt"),
           "package com.example\n"
           'const val AWS = "AKIAIOSFODNN7EXAMPLE1"\n'
           f'const val STRIPE = "{"sk_live_" + "4eC39HqLyjWDarjtT1zdp7dcXXYYZZ00"}"\n')
    # Class/type name that merely contains "ApiKey" (FP).
    _write(os.path.join(main_java, "VisualTransformationApiKey.kt"),
           "package com.example\n"
           "class VisualTransformationApiKey : VisualTransformation {\n}\n")
    # Real embedded secret (protected TRUE POSITIVE).
    _write(os.path.join(main_java, "Retrofit.kt"),
           "package com.example\n"
           'private const val HARDCODED_PASSWORD = "feeder_secret_1234"\n')
    # Test fixture with an embedded credential (down-ranked, not dropped).
    test_java = os.path.join(root, "app", "src", "androidTest", "java", "com", "example")
    _write(os.path.join(test_java, "BackupHelperTest.java"),
           "package com.example;\n"
           "class BackupHelperTest {\n"
           '  String password = "uglypassword";\n'
           "}\n")


def _by_file(findings, basename):
    return [f for f in findings
            if os.path.basename(f.get("file_path", "")) == basename
            and (str(f.get("rule_id", "")).startswith("AND-S")
                 or "hardcoded-credential" in str(f.get("rule_id", "")))]


def test_prefkey_echo_and_typename_dropped_real_secret_kept():
    with tempfile.TemporaryDirectory() as root:
        _make_repo(root)
        result = source_analyzer.analyze_source(root)
        assert result["ok"], result.get("error")
        findings = result["findings"]

        # FPs are gone.
        assert not _by_file(findings, "ConstantsBase.java")
        assert not _by_file(findings, "SettingsStore.kt")  # PREF_ and KEY_ pref keys
        assert not _by_file(findings, "VisualTransformationApiKey.kt")
        # Function-call RHS (no string literal) must not read as a hardcoded key.
        assert not _by_file(findings, "PirateWeatherService.kt")

        # The real embedded secret still fires at CRITICAL.
        real = _by_file(findings, "Retrofit.kt")
        assert real, "protected true positive HARDCODED_PASSWORD was lost"
        assert any(f["severity"] == "CRITICAL" for f in real)

        # Genuine provider secrets still fire at CRITICAL.
        secrets = _by_file(findings, "Secrets.kt")
        assert any(f["severity"] == "CRITICAL" for f in secrets), "AWS/Stripe secret lost"


def test_test_path_secret_downranked_not_dropped():
    with tempfile.TemporaryDirectory() as root:
        _make_repo(root)
        findings = source_analyzer.analyze_source(root)["findings"]
        hits = _by_file(findings, "BackupHelperTest.java")
        assert hits, "test-fixture credential should still be reported"
        assert all(f["severity"] == "LOW" for f in hits)


def test_echo_helper_unit():
    assert source_analyzer._is_prefkey_echo_or_typename(
        '  String PREF_PASSWORD = "password";')
    assert source_analyzer._is_prefkey_echo_or_typename(
        'const val PREF_TRANSLATION_API_KEY = "pref_translation_api_key"')
    assert source_analyzer._is_prefkey_echo_or_typename(
        'class VisualTransformationApiKey : VisualTransformation {')
    # KEY_*-named preference constant holding a settings-key slug.
    assert source_analyzer._is_prefkey_echo_or_typename(
        'const val KEY_SECRET_TOKEN = "secret_token_pref"')
    # A real secret is NOT an echo of its own variable name.
    assert not source_analyzer._is_prefkey_echo_or_typename(
        'private const val HARDCODED_PASSWORD = "feeder_secret_1234"')


def test_function_call_rhs_has_no_string_literal():
    # `val apiKey = getApiKeyOrDefault()` is a function call, not a hardcoded secret.
    assert source_analyzer._has_no_string_literal_rhs('    val apiKey = getApiKeyOrDefault()')
    # A quoted literal is a real candidate secret.
    assert not source_analyzer._has_no_string_literal_rhs('val apiKey = "AKIAIOSFODNN7EXAMPLE1"')
