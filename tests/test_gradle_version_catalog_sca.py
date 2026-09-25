"""SCA resolves `libs.*` deps from gradle/libs.versions.toml."""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.sca import web_deps

_CATALOG = """\
[versions]
androidxCore = "1.15.0"
okhttp = "5.0.0-alpha.10"
room = "2.6.1"

[libraries]
androidx-core-ktx = { group = "androidx.core", name = "core-ktx", version.ref = "androidxCore" }
okhttp = { group = "com.squareup.okhttp3", name = "okhttp", version.ref = "okhttp" }
room-runtime = { module = "androidx.room:room-runtime", version.ref = "room" }
gson = { module = "com.google.code.gson:gson", version = "2.10.1" }
retrofit = "com.squareup.retrofit2:retrofit:2.9.0"
# commented-out = { group = "x", name = "y", version = "1.0.0" }
no-version = { group = "androidx.compose", name = "material" }

[plugins]
kotlin-android = { id = "org.jetbrains.kotlin.android", version.ref = "androidxCore" }

[bundles]
core = ["androidx-core-ktx", "okhttp"]
"""


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def test_parse_version_catalog_resolves_all_forms():
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, "gradle", "libs.versions.toml")
        _write(path, _CATALOG)
        got = {(g, a): v for g, a, v in web_deps._parse_gradle_version_catalog(path)}

        assert got[("androidx.core", "core-ktx")] == "1.15.0"        # group/name + version.ref
        assert got[("com.squareup.okhttp3", "okhttp")] == "5.0.0-alpha.10"
        assert got[("androidx.room", "room-runtime")] == "2.6.1"     # module + version.ref
        assert got[("com.google.code.gson", "gson")] == "2.10.1"     # module + literal
        assert got[("com.squareup.retrofit2", "retrofit")] == "2.9.0"  # compact string form

        # A library with no version (BOM-managed) is skipped, not guessed.
        assert ("androidx.compose", "material") not in got
        # Plugins are not runtime dependencies.
        assert not any(a == "org.jetbrains.kotlin.android" for _, a in got)


def test_collect_maven_deps_reads_catalog_when_no_pom_or_gradle():
    with tempfile.TemporaryDirectory() as root:
        # A modern app whose deps live only in the version catalog.
        _write(os.path.join(root, "gradle", "libs.versions.toml"), _CATALOG)
        _write(os.path.join(root, "app", "build.gradle.kts"),
               "dependencies {\n    implementation(libs.androidx.core.ktx)\n}\n")
        deps = web_deps._collect_maven_deps(root)
        names = {d.name for d in deps}
        assert "androidx.core:core-ktx" in names
        assert "com.squareup.okhttp3:okhttp" in names
        assert "com.google.code.gson:gson" in names
        assert all(d.ecosystem == "Maven" for d in deps)
