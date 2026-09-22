"""Hybrid mobile monorepos. React Native / Capacitor (root package.json + JS/TS
primary surface, native confined under android/ dirs) are detected WEB-SOURCE so
the JS/TS is scanned, with a loud note naming the uncovered native shell. Flutter
(pubspec.yaml + Dart, no JS/TS) stays android-source. A native Android app with a
stray root package.json must NOT flip. Detection precedence for the JS-primary
case changed on purpose (founder-approved); the coverage note stays loud.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import main


def _write(root, rel, content=""):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)


def _make_rn(root):
    _write(root, "package.json", '{"name":"app","dependencies":{"react-native":"0.74.0"}}')
    _write(root, "App.js", "export default function App(){ return null; }\n")
    _write(root, "src/api.js", "const x = 1;\n")
    _write(root, "android/settings.gradle", "include ':app'\n")
    _write(root, "android/app/build.gradle", "apply plugin: 'com.android.application'\n")
    _write(root, "android/app/src/main/AndroidManifest.xml", "<manifest/>")
    _write(root, "android/app/src/main/java/com/app/MainActivity.java", "class MainActivity {}\n")
    _write(root, "ios/App.xcodeproj/project.pbxproj", "// pbx\n")
    _write(root, "ios/App/AppDelegate.swift", "import UIKit\n")


def _make_flutter(root):
    _write(root, "pubspec.yaml", "name: app\n")
    _write(root, "lib/main.dart", "void main() {}\n")
    _write(root, "android/app/build.gradle", "apply plugin: 'com.android.application'\n")
    _write(root, "android/app/src/main/AndroidManifest.xml", "<manifest/>")
    _write(root, "ios/Runner.xcodeproj/project.pbxproj", "// pbx\n")


def test_react_native_scans_js_and_flags_native():
    # RN/Capacitor: JS/TS is the primary surface -> web-source; native shell is
    # confined under android/ so it is left uncovered with a loud note.
    with tempfile.TemporaryDirectory() as root:
        _make_rn(root)
        mode = main._detect_scan_mode(root)
        assert mode == "web-source"  # JS/TS primary surface now scanned
        notes = main._uncovered_surface_notes(root, mode)
        joined = " ".join(notes)
        assert "android/" in joined and "ios/" in joined
        assert any("narvy scan" in n for n in notes)


def test_expo_monorepo_with_scattered_native_modules_is_web_source():
    # Native code under modules/x/android and modules/x/ios (no top-level
    # android/) must still be recognized as a JS-primary hybrid, with a
    # tree-wide native-uncovered note.
    with tempfile.TemporaryDirectory() as root:
        _write(root, "package.json", '{"name":"app","dependencies":{"expo":"51.0.0"}}')
        _write(root, "src/App.tsx", "export default function A(){ return null; }\n")
        _write(root, "modules/native-x/android/build.gradle",
               "apply plugin: 'com.android.library'\n")
        _write(root, "modules/native-x/android/src/main/AndroidManifest.xml", "<manifest/>")
        _write(root, "modules/native-x/android/src/main/java/x/M.kt", "class M {}\n")
        _write(root, "modules/native-x/ios/Module.swift", "import Foundation\n")
        mode = main._detect_scan_mode(root)
        assert mode == "web-source"
        joined = " ".join(main._uncovered_surface_notes(root, mode))
        assert "Native Android" in joined and "Native iOS" in joined


def test_native_android_with_stray_root_package_json_stays_android():
    # A gradle project that IS the root (markers at root / app/, outside any
    # android/ dir) plus a build-tooling package.json and a helper .js must NOT
    # flip to web-source - that would drop the whole Android SAST surface.
    with tempfile.TemporaryDirectory() as root:
        _write(root, "settings.gradle", "include ':app'\n")
        _write(root, "build.gradle", "// top level\n")
        _write(root, "app/build.gradle", "apply plugin: 'com.android.application'\n")
        _write(root, "app/src/main/AndroidManifest.xml", "<manifest/>")
        _write(root, "app/src/main/java/com/app/Main.java", "class Main {}\n")
        _write(root, "package.json", '{"name":"tooling","devDependencies":{"husky":"^8"}}')
        _write(root, "scripts/release.js", "const fs=require('fs');\n")
        assert main._detect_scan_mode(root) == "android-source"


def test_flutter_flags_dart_and_ios():
    with tempfile.TemporaryDirectory() as root:
        _make_flutter(root)
        mode = main._detect_scan_mode(root)
        assert mode == "android-source"
        notes = main._uncovered_surface_notes(root, mode)
        joined = " ".join(notes)
        assert "Dart/Flutter" in joined
        assert "ios/" in joined


def test_pure_single_surface_projects_get_no_note():
    # Pure Android (no JS/Dart/ios tree).
    with tempfile.TemporaryDirectory() as root:
        _write(root, "settings.gradle", "include ':app'\n")
        _write(root, "app/build.gradle", "apply plugin: 'com.android.application'\n")
        _write(root, "app/src/main/AndroidManifest.xml", "<manifest/>")
        _write(root, "app/src/main/java/com/app/Main.java", "class Main {}\n")
        assert main._uncovered_surface_notes(root, main._detect_scan_mode(root)) == []
    # Pure web (JS is the scanned surface, so no note).
    with tempfile.TemporaryDirectory() as root:
        _write(root, "package.json", '{"name":"x","dependencies":{"express":"4.0.0"}}')
        _write(root, "app.js", "const x = 1;\n")
        assert main._uncovered_surface_notes(root, main._detect_scan_mode(root)) == []
