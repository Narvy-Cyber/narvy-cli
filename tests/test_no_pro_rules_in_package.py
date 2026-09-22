"""Guard: the extended rule tree and the private benchmark corpus must never
reach the public repository or a built artifact.

The private material (the extended rule tree, the benchmark corpus, and the
provenance record) lives in a separate private checkout. These checks fail if
any of the private paths reappears
under git tracking, in the packaging declaration, or in an actual wheel build,
and confirm the loader still resolves the base packs when the tree is absent.
"""
import glob
import os
import subprocess
import sys
import tempfile
import zipfile

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRO_DIR = os.path.join(REPO, "narvy", "_pro_rules")
PYPROJECT = os.path.join(REPO, "pyproject.toml")

FORBIDDEN = "_pro_rules"

# Any tracked path or wheel member matching one of these is a leak of private
# material back into the public repository.
FORBIDDEN_PATH_MARKERS = ("_pro_rules", "PROVENANCE")
FORBIDDEN_TRACKED_MARKERS = FORBIDDEN_PATH_MARKERS + ("private/",)


def _tracked_files():
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    return [line for line in out.splitlines() if line]


def test_no_private_material_is_tracked_by_git():
    """The pro rule tree, the benchmark corpus and the provenance record moved
    to a separate private repo; none of it may be tracked here."""
    offenders = []
    for rel in _tracked_files():
        # The guard test and packaging config name these markers on purpose.
        if os.path.basename(rel) in (
            "test_no_pro_rules_in_package.py", "MANIFEST.in", ".gitignore"
        ):
            continue
        for marker in FORBIDDEN_TRACKED_MARKERS:
            if marker in rel:
                offenders.append(rel)
    assert not offenders, f"private material tracked by git: {offenders}"


def _package_data_globs():
    """The package-data globs declared for narvy in pyproject.toml."""
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib
    with open(PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    pkg_data = data["tool"]["setuptools"]["package-data"]
    return pkg_data["narvy"]


def test_pro_dir_is_not_matched_by_any_package_data_glob():
    if not os.path.isdir(PRO_DIR):
        pytest.skip("extended rule tree not installed in this checkout")
    root = os.path.join(REPO, "narvy")
    for pattern in _package_data_globs():
        matches = glob.glob(os.path.join(root, pattern), recursive=True)
        offenders = [m for m in matches if FORBIDDEN in os.path.relpath(m, root)]
        assert not offenders, f"package-data glob {pattern!r} matches {offenders}"


def test_pro_dir_has_no_init_py():
    """An __init__.py would turn the tree into a discoverable package."""
    if not os.path.isdir(PRO_DIR):
        pytest.skip("extended rule tree not installed in this checkout")
    for dirpath, _dirnames, filenames in os.walk(PRO_DIR):
        assert "__init__.py" not in filenames, f"{dirpath} declares a package"


def test_loader_works_without_the_pro_tree(tmp_path, monkeypatch):
    """Rule resolution must return base packs only, with no exception, when
    the tree is absent."""
    from narvy.web import source_analyzer

    monkeypatch.setattr(
        source_analyzer, "_PRO_WEB_RULES_DIR", str(tmp_path / "absent")
    )
    monkeypatch.setattr(
        source_analyzer, "_PRO_WEB_LOCAL_RULES_DIR", str(tmp_path / "absent" / "local")
    )
    configs = source_analyzer._resolve_configs({"java", "python", "javascript"})
    assert configs, "no base rule pack resolved"
    assert all(FORBIDDEN not in c for c in configs), configs
    defs = source_analyzer._load_all_rule_defs(configs)
    assert len(defs) > 100, f"only {len(defs)} rule defs loaded from base packs"


def test_built_wheel_contains_no_private_material():
    """Build a real wheel and inspect its member list.

    Build isolation is deliberate: the PEP 621 metadata needs setuptools>=61,
    which the checkout's own interpreter is not required to have.
    """
    with tempfile.TemporaryDirectory() as out:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "wheel", ".", "-w", out,
             "--no-deps", "-q"],
            cwd=REPO, capture_output=True, text=True, timeout=900,
        )
        if proc.returncode != 0:
            pytest.skip(f"wheel build unavailable: {proc.stderr[-400:]}")
        wheels = [f for f in os.listdir(out) if f.endswith(".whl")]
        assert wheels, "no wheel produced"
        with zipfile.ZipFile(os.path.join(out, wheels[0])) as z:
            names = z.namelist()
        offenders = [
            n for n in names
            if any(m in n for m in FORBIDDEN_PATH_MARKERS) or "/private/" in n
        ]
        assert not offenders, f"wheel ships private material: {offenders}"
        assert any(n.endswith("rules/web/python.yml") for n in names), \
            "base rule packs missing from the wheel"
