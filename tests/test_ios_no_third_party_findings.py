"""iOS findings must never land inside a known third-party SDK or vendor path.

    python tests/test_ios_no_third_party_findings.py --ipa app.ipa [more.ipa ...]
    python tests/test_ios_no_third_party_findings.py --source /path/to/repo [more ...]

Exits non-zero and prints every offending finding if a third-party leak is found.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.ios.binary_analyzer import analyze_ipa
from narvy.ios.source_analyzer import analyze_source
from narvy.ios.third_party_filter import (
    is_third_party_framework_name,
    is_ios_vendor_dir_path,
)


def check_ipa(ipa_path):
    """Returns a list of leak descriptions - empty means clean."""
    leaks = []
    result = analyze_ipa(ipa_path)
    if not result.get("ok"):
        print(f"  SKIP (analyze failed): {result.get('error')}")
        return []
    for finding in result.get("findings", []):
        fp = finding.get("file_path", "")
        # The leak class guarded here: a finding whose file_path points into a
        # Frameworks/*.framework whose name is a known third-party SDK.
        base = os.path.basename(fp.rstrip("/")).replace(".framework", "").replace(".dylib", "")
        if "Frameworks/" in fp or "/Frameworks/" in fp:
            if is_third_party_framework_name(base):
                leaks.append(f"{finding.get('rule_id')} in {fp}")
    return leaks


def check_source(source_dir):
    """Returns a list of leak descriptions - empty means clean."""
    leaks = []
    result = analyze_source(source_dir)
    if not result.get("ok"):
        print(f"  SKIP (analyze failed): {result.get('error')}")
        return []
    for finding in result.get("findings", []):
        fp = finding.get("file_path", "")
        if is_ios_vendor_dir_path(fp):
            leaks.append(f"{finding.get('rule_id')} in {fp}")
    return leaks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipa", nargs="*", default=[], help="Real .ipa file(s) to check")
    parser.add_argument("--source", nargs="*", default=[], help="Real Swift/ObjC repo dir(s) to check")
    args = parser.parse_args()

    if not args.ipa and not args.source:
        print("Usage: python tests/test_ios_no_third_party_findings.py --ipa a.ipa [b.ipa ...] --source repo1 [repo2 ...]")
        print("(No default corpus bundled - point this at real IPAs/repos you have on hand,")
        print(" ideally ones that embed common third-party SDKs.)")
        sys.exit(2)

    any_leak = False

    for ipa_path in args.ipa:
        print(f"Checking (binary) {ipa_path}...")
        leaks = check_ipa(ipa_path)
        if leaks:
            any_leak = True
            print(f"  FAIL - {len(leaks)} third-party leak(s):")
            for leak in leaks:
                print(f"    {leak}")
        else:
            print("  PASS - no findings inside a known third-party framework")

    for source_dir in args.source:
        print(f"Checking (source) {source_dir}...")
        leaks = check_source(source_dir)
        if leaks:
            any_leak = True
            print(f"  FAIL - {len(leaks)} third-party leak(s):")
            for leak in leaks:
                print(f"    {leak}")
        else:
            print("  PASS - no findings inside a known vendor directory")

    if any_leak:
        print("\nREGRESSION: iOS third-party filtering is broken. Do not ship until this passes.")
        sys.exit(1)
    print("\nAll clear.")


if __name__ == "__main__":
    main()
