"""C/C++ code is never analyzed, so it must be surfaced; APK uploads must be labelled binary."""
import os

from narvy import main as narvy_main


def _write(root, rel, text="x"):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def test_c_sources_in_web_source_scan_are_flagged(tmp_path):
    root = str(tmp_path)
    _write(root, "main.c", "int main(){char b[8];gets(b);}")
    _write(root, "scripts/requirements.txt", "requests==2.31.0\n")
    _write(root, "scripts/a.py", "print(1)\n")
    notes = narvy_main._uncovered_surface_notes(root, "web-source")
    assert any("C/C++" in n for n in notes), notes


def test_vendored_c_does_not_trigger_note(tmp_path):
    root = str(tmp_path)
    _write(root, "third_party/zlib/inflate.c")
    _write(root, "node_modules/x/binding.cc")
    _write(root, "package.json", "{}")
    _write(root, "index.js", "console.log(1)")
    notes = narvy_main._uncovered_surface_notes(root, "web-source")
    assert not any("C/C++" in n for n in notes), notes


def test_plain_web_repo_has_no_c_note(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", "{}")
    _write(root, "src/app.ts", "export const a = 1")
    assert not any("C/C++" in n for n in narvy_main._uncovered_surface_notes(root, "web-source"))


def test_apk_upload_is_labelled_binary():
    assert narvy_main._ingest_scan_mode_label("android") == "android-binary"
    for mode in ("android-source", "android-bundle", "ios-binary", "ios-source", "web-source"):
        assert narvy_main._ingest_scan_mode_label(mode) == mode
