"""iOS binary FP tests: symbol definitions, RNG severity, anti-tamper, keychain, SQL formatting."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy.ios.binary_analyzer import (  # noqa: E402
    _RULES,
    _ANTI_TAMPER_PATTERNS,
    _blank_sql_like_wildcard_literals,
    _check_dangerous_apis,
    _check_keychain_accessibility,
    _check_rasp,
    _has_custom_objc_classes,
    _sql_built_by_string_formatting,
    _symbol_is_defined,
)


class _FakeSym:
    """Stand-in for a lief.MachO.Symbol carrying the raw nlist n_type byte."""

    def __init__(self, raw_type, value=0, is_external=True):
        self.raw_type = raw_type
        self.value = value
        self.is_external = is_external


def test_undefined_symbol_is_not_a_definition():
    """An N_UNDF symbol is an import, not a definition."""
    assert _symbol_is_defined(_FakeSym(0x01)) is False


def test_section_symbol_is_a_definition():
    """n_type 0x0f = N_EXT|N_SECT: defined in one of this image's sections."""
    assert _symbol_is_defined(_FakeSym(0x0f, value=51080, is_external=True)) is True
    assert _symbol_is_defined(_FakeSym(0x0e, value=4096, is_external=False)) is True


@pytest.mark.parametrize("raw", [0x20, 0x24, 0x26, 0x2e, 0x64])
def test_stab_debug_entries_are_not_definitions(raw):
    """Debug (stab) entries are not definitions."""
    assert _symbol_is_defined(_FakeSym(raw)) is False


def test_imported_system_class_does_not_make_a_module_objc():
    """Importing NSLock is not defining a custom Objective-C class."""
    assert _has_custom_objc_classes([]) is False


def test_swift_mangled_objc_class_is_not_hand_written_objc():
    """_TtC classes are Swift, not hand-written ObjC."""
    assert _has_custom_objc_classes([
        "_OBJC_CLASS_$__TtC17AppRecoveryPublic16APAppRecoveryKey",
        "_OBJC_CLASS_$__TtC17AppRecoveryPublic17AppRefreshPayload",
    ]) is False


def test_real_objc_class_still_detected():
    """The fix must not blind the check to genuine Objective-C."""
    assert _has_custom_objc_classes(["_OBJC_CLASS_$_MyLoginViewController"]) is True


def test_stripped_swift_launcher_stub_case():
    """A Swift stub that only imports UIApplication defines no ObjC class."""
    assert _has_custom_objc_classes([]) is False          # defined set is empty
    # ...and the full symbol list, which is what used to be passed in:
    assert "_OBJC_CLASS_$_UIApplication" not in []


def test_stack_canary_rule_still_high_by_default():
    """Rule severity unchanged; only embedded frameworks are demoted."""
    assert _RULES["IOS-BIN-SEC-002"]["severity"] == "HIGH"


def test_insecure_rng_rule_is_informational():
    """rand + CommonCrypto co-presence can't justify HIGH."""
    assert _RULES["IOS-BIN-CRYPTO-003"]["severity"] == "INFO"


def test_insecure_rng_description_is_honest():
    desc = _RULES["IOS-BIN-CRYPTO-003"]["details"]["description"].lower()
    assert "informational only" in desc
    assert "call-site" in desc


@pytest.mark.parametrize("term", [
    "jailbroken", "jailbreak", "Cydia", "MobileSubstrate", "libhooker",
    "/var/jb", "DYLD_INSERT",
])
def test_jailbreak_terms_are_actually_in_the_pattern_list(term):
    """The pattern list contains the terms the finding mentions."""
    assert term in _ANTI_TAMPER_PATTERNS


def test_jailbreak_symbols_now_detected():
    """Named jailbreak detection is not reported as 'No RASP detected'."""
    findings, notes = [], []
    _check_rasp(
        strings_list=[],
        symbol_names=["_AppDeviceReportWithJailbreakInfo",
                       "_AppDeviceAppearsJailbroken", "_AppDeviceIsJailbroken"],
        file_path="SampleApp", findings=findings, notes=notes, encrypted=False,
    )
    assert findings == [], "jailbreak detection present -> must not claim 'No RASP'"
    assert any("anti-tampering" in n for n in notes)


def test_single_jailbreak_symbol_is_enough():
    """One unambiguous jailbreak symbol is enough."""
    findings, notes = [], []
    _check_rasp([], ["_AppDeviceAppearsJailbroken"], "SampleApp", findings, notes,
                 encrypted=False)
    assert findings == []
    assert any("anti-tampering" in n for n in notes)


def test_anti_tamper_matching_is_case_insensitive():
    """Real symbols are CamelCase, so a case-sensitive match finds none."""
    findings, notes = [], []
    _check_rasp([], ["_SomethingJailBrokenCheck"], "App", findings, notes,
                 encrypted=False)
    assert findings == []


def test_no_rasp_claim_is_suppressed_on_an_encrypted_binary():
    """No 'No RASP' claim on an encrypted binary."""
    findings, notes = [], []
    _check_rasp([], [], "SampleApp", findings, notes, encrypted=True)
    assert findings == []
    assert any("UNKNOWN" in n for n in notes)


def test_no_rasp_still_reported_on_a_decrypted_binary_with_no_evidence():
    """On a readable binary with no anti-tampering evidence the rule fires."""
    findings, notes = [], []
    _check_rasp(["hello world"], ["_main"], "MyApp", findings, notes, encrypted=False)
    assert [f["rule_id"] for f in findings] == ["IOS-BIN-RASP-001"]


# kSecAttrAccessibleAlways is a prefix of ...AlwaysThisDeviceOnly.

def test_this_device_only_no_longer_reported_as_the_bare_constant():
    """...ThisDeviceOnly is not reported as the bare constant."""
    findings = []
    _check_keychain_accessibility("_kSecAttrAccessibleAlwaysThisDeviceOnly", "x", findings)
    assert [(f["rule_id"], f["severity"]) for f in findings] == [
        ("IOS-BIN-API-006", "MEDIUM")]
    assert "ThisDeviceOnly" in findings[0]["details"]["description"]


def test_bare_always_still_high():
    """A genuine bare-constant hit must survive at HIGH."""
    findings = []
    _check_keychain_accessibility("uses kSecAttrAccessibleAlways here", "SampleApp", findings)
    assert [(f["rule_id"], f["severity"]) for f in findings] == [
        ("IOS-BIN-API-001", "HIGH")]


def test_both_constants_present_reports_both():
    findings = []
    _check_keychain_accessibility(
        "kSecAttrAccessibleAlways kSecAttrAccessibleAlwaysThisDeviceOnly", "x", findings)
    assert sorted(f["rule_id"] for f in findings) == [
        "IOS-BIN-API-001", "IOS-BIN-API-006"]


def test_unrelated_accessibility_constant_reports_nothing():
    findings = []
    _check_keychain_accessibility(
        "kSecAttrAccessibleWhenUnlockedThisDeviceOnly", "x", findings)
    assert findings == []


def test_keychain_check_is_wired_into_check_dangerous_apis():
    findings = []
    _check_dangerous_apis("kSecAttrAccessibleAlwaysThisDeviceOnly", "x", findings)
    assert [f["rule_id"] for f in findings] == ["IOS-BIN-API-006"]


SCHEMA_SQL = ("SELECT name FROM sqlite_schema WHERE type = 'table' "
              "AND name NOT LIKE 'sqlite_%'")


def test_sqlite_schema_query_is_not_string_formatting():
    """The static sqlite_master query is not string formatting."""
    assert _sql_built_by_string_formatting(SCHEMA_SQL) is False


@pytest.mark.parametrize("sql", [
    "SELECT * FROM users WHERE name = '%@'",
    "SELECT id FROM t WHERE uid = %d AND x = %@",
    "INSERT INTO logs VALUES (%@, %@)",
    "UPDATE users SET name = '%@' WHERE id = %ld",
    "DELETE FROM sess WHERE token = %s",
    "SELECT * FROM a WHERE b = %1$@",
])
def test_real_interpolated_sql_still_flagged(sql):
    """stringWithFormat SQL is still flagged, including '%@' and %1$@."""
    assert _sql_built_by_string_formatting(sql) is True


@pytest.mark.parametrize("sql", [
    SCHEMA_SQL,
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'foo%'",
    "SELECT * FROM t WHERE n LIKE '%s%'",
    "SELECT a FROM b WHERE c = 1",
])
def test_like_wildcards_and_static_sql_not_flagged(sql):
    assert _sql_built_by_string_formatting(sql) is False


def test_like_literal_blanking_leaves_interpolation_slots_alone():
    """Blank LIKE patterns, keep %@ slots."""
    assert "sqlite_" not in _blank_sql_like_wildcard_literals("x LIKE 'sqlite_%'")
    assert "%@" in _blank_sql_like_wildcard_literals("x = '%@'")
