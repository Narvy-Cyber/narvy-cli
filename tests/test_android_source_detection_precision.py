"""A Gradle file alone doesn't make an Android project."""
from __future__ import annotations

import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import main
from narvy.web import source_analyzer as web_source_analyzer


def _write(path: str, content: str = "") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _detect(path: str) -> str:
    """_detect_scan_mode with the exception flattened to a sentinel string."""
    try:
        return main._detect_scan_mode(path)
    except main.UnsupportedScanTarget:
        return "UNSUPPORTED"


def _make_classic_android_app(root: str) -> None:
    """Root Gradle files with AGP plus an app module with a manifest."""
    _write(os.path.join(root, "build.gradle"),
           "plugins {\n    id 'com.android.application' version '8.2.0' apply false\n}\n")
    _write(os.path.join(root, "settings.gradle"), "rootProject.name = 'app'\ninclude ':app'\n")
    _write(os.path.join(root, "app", "build.gradle"),
           "apply plugin: 'com.android.application'\nandroid {\n    namespace 'com.example.app'\n}\n")
    _write(os.path.join(root, "app", "src", "main", "AndroidManifest.xml"),
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android"></manifest>')
    _write(os.path.join(root, "app", "src", "main", "java", "com", "example", "Main.java"),
           "package com.example;\nclass Main {}\n")


def _make_agp_library_module_without_manifest(root: str) -> None:
    """AGP 7+ library module with no manifest; the plugin id is the only marker."""
    _write(os.path.join(root, "build.gradle.kts"),
           'plugins {\n    id("com.android.library")\n}\n'
           'android {\n    namespace = "tech.example.sdk"\n}\n')
    _write(os.path.join(root, "src", "main", "kotlin", "tech", "example", "Sdk.kt"),
           "package tech.example\nclass Sdk\n")


def _make_version_catalog_android_app(root: str) -> None:
    """The AGP plugin id only appears in gradle/libs.versions.toml."""
    _write(os.path.join(root, "build.gradle.kts"),
           "plugins {\n    alias(libs.plugins.android.application) apply false\n}\n")
    _write(os.path.join(root, "settings.gradle.kts"), 'rootProject.name = "app"\n')
    _write(os.path.join(root, "gradle", "libs.versions.toml"),
           "[versions]\nagp = \"8.2.0\"\n\n[plugins]\n"
           "android-application = { id = \"com.android.application\", version.ref = \"agp\" }\n")
    _write(os.path.join(root, "app", "src", "main", "kotlin", "MainActivity.kt"),
           "class MainActivity\n")


def _make_convention_plugin_android_app(root: str) -> None:
    """AGP via convention plugins; only the `android { }` block remains."""
    _write(os.path.join(root, "build.gradle.kts"), "plugins {\n    alias(libs.plugins.myapp.android.library)\n}\n")
    _write(os.path.join(root, "core", "ui", "build.gradle.kts"),
           "plugins {\n    alias(libs.plugins.myapp.android.library)\n}\n\n"
           "android {\n    defaultConfig {\n        minSdk = 24\n    }\n}\n")
    _write(os.path.join(root, "core", "ui", "src", "main", "kotlin", "Ui.kt"), "class Ui\n")


def _make_androidx_properties_only_app(root: str) -> None:
    """gradle.properties with AndroidX flags, manifest too deep to find."""
    _write(os.path.join(root, "build.gradle"), "// generated\n")
    _write(os.path.join(root, "settings.gradle"), "rootProject.name = 'app'\n")
    _write(os.path.join(root, "gradle.properties"),
           "org.gradle.jvmargs=-Xmx2048m\nandroid.useAndroidX=true\nandroid.enableJetifier=false\n")
    _write(os.path.join(root, "app", "src", "main", "java", "Main.java"), "class Main {}\n")


def _make_legacy_agp_app(root: str) -> None:
    """Pre-1.0 AGP syntax (`apply plugin: 'android'`)."""
    _write(os.path.join(root, "build.gradle"), "apply plugin: 'android'\n\ndependencies {\n}\n")
    _write(os.path.join(root, "src", "main", "java", "Main.java"), "class Main {}\n")


_SPRING_CONTROLLER_JAVA = """package com.example.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OwnerController {
    @GetMapping("/owners")
    public String owners() {
        return "owners";
    }
}
"""


def _make_gradle_spring_boot(root: str) -> None:
    """Gradle-only JVM backend, no Android anything."""
    _write(os.path.join(root, "build.gradle"),
           "plugins {\n    id 'java'\n    id 'org.springframework.boot' version '3.2.0'\n}\n\n"
           "repositories { mavenCentral() }\n\n"
           "dependencies {\n    implementation 'org.springframework.boot:spring-boot-starter-web'\n}\n")
    _write(os.path.join(root, "settings.gradle"), "rootProject.name = 'backend'\n")
    _write(os.path.join(root, "src", "main", "java", "com", "example", "web", "OwnerController.java"),
           _SPRING_CONTROLLER_JAVA)


def _make_kts_ktor_backend(root: str) -> None:
    """Kotlin DSL flavour of the same thing."""
    _write(os.path.join(root, "build.gradle.kts"),
           'plugins {\n    kotlin("jvm") version "1.9.22"\n    id("io.ktor.plugin") version "2.3.7"\n}\n')
    _write(os.path.join(root, "settings.gradle.kts"), 'rootProject.name = "service"\n')
    _write(os.path.join(root, "src", "main", "kotlin", "Application.kt"),
           "fun main() { println(\"ktor\") }\n")


def _make_maven_spring_boot(root: str) -> None:
    """pom.xml, no Gradle at all."""
    _write(os.path.join(root, "pom.xml"),
           '<?xml version="1.0" encoding="UTF-8"?>\n<project>\n'
           '  <artifactId>backend</artifactId>\n</project>\n')
    _write(os.path.join(root, "src", "main", "java", "com", "example", "web", "OwnerController.java"),
           _SPRING_CONTROLLER_JAVA)


def _make_plain_java_library(root: str) -> None:
    """Plain `java-library` Gradle project, not Android."""
    _write(os.path.join(root, "build.gradle.kts"), 'plugins {\n    `java-library`\n}\n')
    _write(os.path.join(root, "settings.gradle.kts"),
           'rootProject.name = "extractor"\ninclude("extractor")\n')
    _write(os.path.join(root, "extractor", "build.gradle.kts"),
           'plugins {\n    `java-library`\n}\n\ndependencies {\n'
           '    implementation("com.squareup.okhttp3:okhttp:4.12.0")\n}\n')
    _write(os.path.join(root, "extractor", "src", "main", "java", "org", "example", "Extractor.java"),
           "package org.example;\npublic class Extractor {}\n")


def _make_polyglot_jvm_plus_js(root: str) -> None:
    """Spring Boot backend plus a ui/ package.json. Should be web-source."""
    _make_gradle_spring_boot(root)
    _write(os.path.join(root, "ui", "package.json"),
           '{"name": "ui", "dependencies": {"vue": "3.4.0"}}')
    _write(os.path.join(root, "ui", "src", "main.ts"), "export const x = 1;\n")


def test_classic_android_app_still_detected():
    with tempfile.TemporaryDirectory() as d:
        _make_classic_android_app(d)
        assert main._looks_like_android_source_dir(d)
        assert _detect(d) == "android-source"


def test_agp_library_module_without_manifest_still_detected():
    with tempfile.TemporaryDirectory() as d:
        _make_agp_library_module_without_manifest(d)
        assert _detect(d) == "android-source", (
            "an AGP 7+ library module ships no AndroidManifest.xml, so the "
            "com.android.library plugin id is the only Android evidence"
        )


def test_version_catalog_android_app_still_detected():
    with tempfile.TemporaryDirectory() as d:
        _make_version_catalog_android_app(d)
        assert _detect(d) == "android-source", (
            "the literal com.android.application id lives only in "
            "gradle/libs.versions.toml in a version-catalog project"
        )


def test_convention_plugin_android_app_still_detected():
    with tempfile.TemporaryDirectory() as d:
        _make_convention_plugin_android_app(d)
        assert _detect(d) == "android-source", (
            "AGP behind the repo's own convention plugins, so `android { }` "
            "is the only marker left"
        )


def test_androidx_gradle_properties_still_detected():
    with tempfile.TemporaryDirectory() as d:
        _make_androidx_properties_only_app(d)
        assert _detect(d) == "android-source"


def test_legacy_apply_plugin_android_still_detected():
    with tempfile.TemporaryDirectory() as d:
        _make_legacy_agp_app(d)
        assert _detect(d) == "android-source"


def test_android_app_with_package_json_still_beats_web_source():
    """An Android app with a package.json stays android-source."""
    with tempfile.TemporaryDirectory() as d:
        _make_classic_android_app(d)
        _write(os.path.join(d, "package.json"), '{"name": "tooling"}')
        assert _detect(d) == "android-source"


def test_gradle_spring_boot_is_not_android():
    with tempfile.TemporaryDirectory() as d:
        _make_gradle_spring_boot(d)
        assert not main._looks_like_android_source_dir(d), (
            "a Gradle Spring Boot backend was routed to android-source; it "
            "gets Android-only rules that cannot match, and reports a false "
            "'no issues found'"
        )
        assert _detect(d) == "web-source"


def test_kotlin_ktor_backend_is_not_android():
    with tempfile.TemporaryDirectory() as d:
        _make_kts_ktor_backend(d)
        assert not main._looks_like_android_source_dir(d)
        assert _detect(d) == "web-source"


def test_maven_spring_boot_is_not_android():
    with tempfile.TemporaryDirectory() as d:
        _make_maven_spring_boot(d)
        assert not main._looks_like_android_source_dir(d)
        assert _detect(d) == "web-source"


def test_plain_java_library_is_not_android():
    with tempfile.TemporaryDirectory() as d:
        _make_plain_java_library(d)
        assert not main._looks_like_android_source_dir(d)
        assert _detect(d) == "web-source"


def test_jvm_dependency_coordinates_do_not_fake_an_android_marker():
    """Mentioning com.android in a JVM backend doesn't make it Android."""
    with tempfile.TemporaryDirectory() as d:
        _make_gradle_spring_boot(d)
        _write(os.path.join(d, "build.gradle"),
               "// no android support here\n"
               "plugins { id 'java' }\n"
               "dependencies {\n"
               "    testImplementation 'com.android.tools:r8:8.2.42'\n"
               "}\n")
        assert not main._looks_like_android_source_dir(d)
        assert _detect(d) == "web-source"


def test_jvm_non_android_resolves_to_the_java_stack_not_an_empty_scan():
    """A JVM backend routed to web-source must get the Java packs."""
    for maker in (_make_gradle_spring_boot, _make_maven_spring_boot,
                  _make_kts_ktor_backend, _make_plain_java_library):
        with tempfile.TemporaryDirectory() as d:
            maker(d)
            ported, _ = web_source_analyzer.detect_web_stacks(d)
            assert "java" in ported, (maker.__name__, ported)
            configs = web_source_analyzer._resolve_configs(ported)
            names = [os.path.basename(c) for c in configs]
            assert "java.yml" in names, (maker.__name__, names)
            assert "kotlin.yml" in names, (maker.__name__, names)
            assert "java.yml" in names, (maker.__name__, names)


def test_polyglot_jvm_plus_js_routes_to_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_polyglot_jvm_plus_js(d)
        assert _detect(d) == "web-source", (
            "the JS/TS front-end is covered, so this must be scanned rather "
            "than refused"
        )


def test_polyglot_jvm_plus_js_resolves_both_stacks():
    """Both the JVM and JS halves get scanned."""
    with tempfile.TemporaryDirectory() as d:
        _make_polyglot_jvm_plus_js(d)
        ported, unported = web_source_analyzer.detect_web_stacks(d)
        assert "java" in ported, (ported, unported)
        assert ported & {"javascript", "typescript"}, (ported, unported)
        assert "java" not in unported, (ported, unported)
        configs = web_source_analyzer._resolve_configs(ported)
        names = [os.path.basename(c) for c in configs]
        for expected in ("java.yml", "kotlin.yml", "javascript.yml"):
            assert expected in names, (expected, names)
        assert "java.yml" in names, names


def test_supported_languages_label_claims_java_only_with_routing_in_place():
    """The languages label matches the routing."""
    label = web_source_analyzer.SUPPORTED_LANGUAGES_LABEL
    # `\bJava\b` on purpose: "JavaScript" is in this label and must not count
    # as a Java claim.
    claims_java = bool(re.search(r"\bJava\b", label))
    assert claims_java, "SUPPORTED_LANGUAGES_LABEL stopped claiming Java"
    assert "java" not in web_source_analyzer._UNPORTED_STACK_LABELS
    assert "java" in web_source_analyzer.WEB_PACK_MAP
    with tempfile.TemporaryDirectory() as d:
        _make_gradle_spring_boot(d)
        assert _detect(d) == "web-source", (
            "the label claims Java but a JVM-non-Android repo is still not "
            "routed anywhere that runs the Java packs"
        )


def test_csharp_is_a_real_ported_stack_not_the_remaining_gap():
    """A .NET repo gets real AST rules, not just secret patterns."""
    assert "csharp" not in web_source_analyzer._UNPORTED_STACK_LABELS
    assert "csharp" in web_source_analyzer.WEB_PACK_MAP
    assert "csharp" in web_source_analyzer._LOCAL_PACK_DIRS
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "Api.csproj"),
               "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n")
        _write(os.path.join(d, "Program.cs"), "class P { static void Main() {} }\n")
        _write(os.path.join(d, "package.json"),
               '{"name":"ui","dependencies":{"react":"18.0.0"}}\n')
        _write(os.path.join(d, "app.js"), "const x = 1;\n")
        ported, unported = web_source_analyzer.detect_web_stacks(d)
        assert "csharp" in ported, (ported, unported)
        assert "csharp" not in unported, (ported, unported)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"PASS: {len(fns)} Android-source detection precision tests OK")
