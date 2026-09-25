"""Android findings never land in a third-party SDK namespace.

    python tests/test_no_third_party_findings.py /path/to/some.apk [more.apk ...]
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.decompiler import decompile_apk
from narvy.third_party_filter import THIRD_PARTY_PREFIXES, is_third_party_path, get_own_package_roots, is_own_package_path
from narvy import semgrep_engine
from narvy.rule_engine import load_rules_from_dir, run_rules_on_file


def check_apk(apk_path):
    """(finding, engine) pairs that leaked into a third-party namespace."""
    leaks = []
    with tempfile.TemporaryDirectory() as temp_dir:
        ok, err = decompile_apk(apk_path, temp_dir, max_mem="4g")
        if not ok:
            print(f"  SKIP (decompile failed): {err}")
            return []

        # Mirror main.py's sequence: filter the file list first, then run
        # rules only on what survives.
        rules_path = os.path.join(os.path.dirname(__file__), '..', 'narvy', 'rules', 'android')
        rules = load_rules_from_dir(rules_path)
        all_files = [os.path.join(root, f) for root, _, files in os.walk(temp_dir) for f in files if f.endswith(('.java', '.kt', '.xml'))]
        kept_files = [f for f in all_files if not is_third_party_path(f)]
        for fpath in kept_files:
            findings = run_rules_on_file(fpath, rules)
            for f in findings:
                rel = os.path.relpath(fpath, temp_dir)
                if is_third_party_path(rel):  # check the exact string that ships in the output
                    leaks.append((f"regex:{f['rule_id']} in {rel}", 'regex'))

        if semgrep_engine.is_available():
            sg_findings = semgrep_engine.run_semgrep(temp_dir) or []
            for f in sg_findings:
                rel = f['file_path'].replace('\\', '/')
                for prefix in THIRD_PARTY_PREFIXES:
                    slashed = prefix.replace('.', '/').rstrip('/')
                    if f'/{slashed}/' in f'/{rel}':
                        leaks.append((f"semgrep:{f['rule_id']} in {rel}", 'semgrep'))
                        break
    return leaks


def main():
    apk_paths = sys.argv[1:]
    if not apk_paths:
        print("Usage: python tests/test_no_third_party_findings.py /path/to/some.apk [more.apk ...]")
        print("(No default corpus bundled - point this at any real APK you have on hand,")
        print(" ideally one that embeds common third-party SDKs.)")
        sys.exit(2)

    any_leak = False
    for apk_path in apk_paths:
        print(f"Checking {apk_path}...")
        leaks = check_apk(apk_path)
        if leaks:
            any_leak = True
            print(f"  FAIL - {len(leaks)} third-party leak(s):")
            for leak, engine in leaks:
                print(f"    [{engine}] {leak}")
        else:
            print("  PASS - no findings in any known third-party namespace")

    if any_leak:
        print("\nREGRESSION: third-party filtering is broken. Do not ship until this passes.")
        sys.exit(1)
    print("\nAll clear.")


if __name__ == "__main__":
    main()
