""".narvy-scope.yml parsing and matching."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.scope_config import load_scope_config, entry_matches, segment_prefix_match, EMPTY, ScopeConfig
from narvy.third_party_filter import check_android_override, resolve_file_scope
from narvy.ios.third_party_filter import check_ios_override


def _check(label, condition):
    if not condition:
        print(f"  FAIL: {label}")
        return False
    print(f"  ok: {label}")
    return True


def test_load_missing_file() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as d:
        cfg = load_scope_config(os.path.join(d, "fake.apk"))
        ok &= _check("missing file -> EMPTY", bool(cfg) is False)
    return ok


def test_load_valid_file() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, ".narvy-scope.yml"), "w") as f:
            f.write("own:\n  - coreframework\n  - coreui\nvendor:\n  - some.unknown.sdk\n")
        apk = os.path.join(d, "app.apk")
        open(apk, "w").close()
        cfg = load_scope_config(apk)
        ok &= _check("own parsed", cfg.own == frozenset({"coreframework", "coreui"}))
        ok &= _check("vendor parsed", cfg.vendor == frozenset({"some.unknown.sdk"}))
    return ok


def test_load_malformed_yaml_degrades_safely() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, ".narvy-scope.yml"), "w") as f:
            f.write("own: [unterminated\n  - broken: : :\n")
        apk = os.path.join(d, "app.apk")
        open(apk, "w").close()
        cfg = load_scope_config(apk)  # must not raise
        ok &= _check("malformed YAML -> EMPTY, no crash", bool(cfg) is False)
    return ok


def test_load_wrong_shape_degrades_safely() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, ".narvy-scope.yml"), "w") as f:
            f.write("- just\n- a\n- list\n")  # not a mapping
        apk = os.path.join(d, "app.apk")
        open(apk, "w").close()
        cfg = load_scope_config(apk)
        ok &= _check("non-mapping YAML -> EMPTY, no crash", bool(cfg) is False)
    return ok


def test_load_conflict_drops_both() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, ".narvy-scope.yml"), "w") as f:
            f.write("own:\n  - foo\nvendor:\n  - foo\n")
        apk = os.path.join(d, "app.apk")
        open(apk, "w").close()
        cfg = load_scope_config(apk)
        ok &= _check("identical entry in both lists dropped from both",
                     "foo" not in cfg.own and "foo" not in cfg.vendor)
    return ok


def test_load_priority_cwd_over_target() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as d:
        target_dir = os.path.join(d, "targetdir")
        os.makedirs(target_dir)
        with open(os.path.join(target_dir, ".narvy-scope.yml"), "w") as f:
            f.write("own:\n  - target-side\n")
        with open(os.path.join(d, ".narvy-scope.yml"), "w") as f:
            f.write("own:\n  - cwd-side\n")
        apk = os.path.join(target_dir, "app.apk")
        open(apk, "w").close()
        old_cwd = os.getcwd()
        try:
            os.chdir(d)
            cfg = load_scope_config(apk)
        finally:
            os.chdir(old_cwd)
        ok &= _check("cwd/project-root file wins when both exist", cfg.own == frozenset({"cwd-side"}))
    return ok


def test_entry_matches_exact_by_default() -> bool:
    ok = True
    ok &= _check("exact match", entry_matches("core", "core") is True)
    ok &= _check("no accidental prefix match without glob", entry_matches("core", "coreframework") is False)
    ok &= _check("explicit glob matches prefix", entry_matches("core*", "coreframework") is True)
    ok &= _check("'auth' does not match 'oauthkit'", entry_matches("auth", "oauthkit") is False)
    ok &= _check("'auth' does not match 'firebaseauth'", entry_matches("auth", "firebaseauth") is False)
    ok &= _check("'auth' does not match 'appauth'", entry_matches("auth", "appauth") is False)
    return ok


def test_segment_prefix_match() -> bool:
    ok = True
    ok &= _check("dotted prefix matches nested segment",
                 segment_prefix_match("com.google.android", "com.google.android.gms") is True)
    ok &= _check("dotted prefix does not false-match a sibling segment",
                 segment_prefix_match("com.google.android", "com.google.androidx") is False)
    ok &= _check("single segment 'auth' does not match 'authkit' segment",
                 segment_prefix_match("auth", "authkit.foo") is False)
    ok &= _check("trailing '*' is a no-op for segment matching",
                 segment_prefix_match("com.acme.*", "com.acme.sdk") is True)
    return ok


def test_check_android_override() -> bool:
    ok = True
    cfg = ScopeConfig(own=frozenset({"coreframework"}), vendor=frozenset({"com.google.android"}))
    ok &= _check("android own hit",
                 check_android_override("/x/sources/coreframework/Bar.java", cfg) == "own")
    ok &= _check("android vendor hit (multi-segment exact entry)",
                 check_android_override("/x/sources/com/google/android/gms/Foo.java", cfg) == "vendor")
    ok &= _check("android no false positive on sibling namespace",
                 check_android_override("/x/sources/com/google/androidx/Foo.java", cfg) is None)
    ok &= _check("android no match outside sources/",
                 check_android_override("/x/resources/AndroidManifest.xml", cfg) is None)
    ok &= _check("android EMPTY config never matches", check_android_override("/x/sources/coreframework/Bar.java", EMPTY) is None)
    return ok


def test_resolve_file_scope_override_wins() -> bool:
    ok = True
    own_roots = {"com.example.app"}
    ok &= _check("no override: own root scanned",
                 resolve_file_scope("/x/sources/com/example/app/Foo.java", own_roots, None) is True)
    ok &= _check("no override: non-own path skipped",
                 resolve_file_scope("/x/sources/com/google/android/gms/Foo.java", own_roots, None) is False)
    cfg = ScopeConfig(own=frozenset(), vendor=frozenset({"com.example"}))
    ok &= _check("vendor override wins over own_roots allowlist",
                 resolve_file_scope("/x/sources/com/example/app/Foo.java", own_roots, cfg) is False)
    return ok


def test_check_ios_override() -> bool:
    ok = True
    cfg = ScopeConfig(own=frozenset({"coreframework"}), vendor=frozenset({"vendorruntime"}))
    ok &= _check("ios own hit by name",
                 check_ios_override("coreframework", "org.cocoapods.coreframework", cfg) == "own")
    ok &= _check("ios vendor hit by name",
                 check_ios_override("VendorRuntime", "com.vendorsoft.VendorRuntime", cfg) == "vendor")
    ok &= _check("ios no match for unrelated framework",
                 check_ios_override("SomeOtherFramework", "org.cocoapods.SomeOtherFramework", cfg) is None)

    cfg_auth = ScopeConfig(own=frozenset({"auth"}), vendor=frozenset())
    for bad_name in ["OAuthKit", "FirebaseAuth", "AppAuth"]:
        ok &= _check(f"'auth' does not match {bad_name!r}",
                     check_ios_override(bad_name, "org.cocoapods." + bad_name, cfg_auth) is None)

    cfg_fb = ScopeConfig(own=frozenset(), vendor=frozenset({"com.vendorsoft.sdk"}))
    ok &= _check("3-segment bundle-id namespace matches",
                 check_ios_override("VendorCoreKit", "com.vendorsoft.sdk.VendorCoreKit".lower(), cfg_fb) == "vendor")
    ok &= _check("3-segment bundle-id namespace has no false positive on sibling namespace",
                 check_ios_override("VendorCoreKit", "com.vendorsoft.other.VendorCoreKit".lower(), cfg_fb) is None)
    return ok


def test_own_wins_on_cross_pattern_conflict() -> bool:
    ok = True
    cfg_ios = ScopeConfig(own=frozenset({"core*"}), vendor=frozenset({"coreframework"}))
    ok &= _check("ios: own wins over vendor on different-pattern overlap",
                 check_ios_override("coreframework", "org.cocoapods.coreframework", cfg_ios) == "own")

    cfg_android = ScopeConfig(own=frozenset({"com.acme"}), vendor=frozenset({"com.acme.legacy"}))
    ok &= _check("android: own wins over vendor on different-pattern overlap",
                 check_android_override("/x/sources/com/acme/legacy/Old.java", cfg_android) == "own")
    return ok


def main():
    tests = [
        test_load_missing_file,
        test_load_valid_file,
        test_load_malformed_yaml_degrades_safely,
        test_load_wrong_shape_degrades_safely,
        test_load_conflict_drops_both,
        test_load_priority_cwd_over_target,
        test_entry_matches_exact_by_default,
        test_segment_prefix_match,
        test_check_android_override,
        test_resolve_file_scope_override_wins,
        test_check_ios_override,
        test_own_wins_on_cross_pattern_conflict,
    ]
    all_ok = True
    for t in tests:
        print(f"{t.__name__}:")
        all_ok &= t()
    if not all_ok:
        print("\nREGRESSION: .narvy-scope.yml handling is broken. Do not ship until this passes.")
        sys.exit(1)
    print("\nAll clear.")


if __name__ == "__main__":
    main()
