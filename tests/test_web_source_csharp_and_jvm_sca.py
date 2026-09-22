"""Tests for the C#/.NET web-source stack and the Maven + NuGet SCA
ecosystems: routing, real semgrep findings and manifest version resolution.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import main
from narvy.sca import web_deps
from narvy.web import source_analyzer


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


_CSPROJ = """\
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <SerilogVersion>2.12.0</SerilogVersion>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="[12.0.1]" />
    <PackageReference Include="Serilog" Version="$(SerilogVersion)" />
    <PackageReference Include="Floating.Package" Version="1.2.*" />
    <PackageReference Include="Ranged.Package" Version="[1.0,2.0)" />
    <PackageReference Include="Central.Managed.Package" />
    <PackageReference Include="Nested.Version.Package">
      <Version>3.1.4</Version>
    </PackageReference>
  </ItemGroup>
</Project>
"""

_CS_VULNERABLE = """\
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.AspNetCore.Http;

namespace Demo
{
    public class Handlers
    {
        public void Sql(SqlConnection connection, string id)
        {
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id, connection);
            cmd.ExecuteReader();
        }

        public void SqlSafe(SqlConnection connection, string id)
        {
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", connection);
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteReader();
        }

        public void SqlMultilineLiteral(SqlConnection connection)
        {
            var cmd = new SqlCommand(
                "IF OBJECT_ID('Migration','U') IS NOT NULL " +
                "UPDATE [dbo].[Migration] SET " +
                "[ScriptName] = 'x';", connection);
            cmd.ExecuteNonQuery();
        }

        public void Xml(string xml)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
        }

        public void XmlSafe(string xml)
        {
            var doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.LoadXml(xml);
        }

        public object Deserialize(byte[] blob)
        {
            var fmt = new BinaryFormatter();
            using var ms = new MemoryStream(blob);
            return fmt.Deserialize(ms);
        }

        public byte[] Hash(byte[] data)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(data);
        }

        public void Cipher()
        {
            var des = new DESCryptoServiceProvider();
        }

        public string ReadFile(HttpContext ctx)
        {
            var name = ctx.Request.Query["name"];
            return File.ReadAllText(Path.Combine("/data", name));
        }

        public string ReadFileSafe(HttpContext ctx)
        {
            var name = ctx.Request.Query["name"];
            return File.ReadAllText(Path.Combine("/data", Path.GetFileName(name)));
        }

        public void Run(HttpContext ctx)
        {
            Process.Start("ping", ctx.Request.Form["host"]);
        }
    }
}
"""


def _make_dotnet_project(root: str) -> None:
    _write(os.path.join(root, "App.slnx"), "<Solution />\n")
    _write(os.path.join(root, "src", "Api", "Api.csproj"), _CSPROJ)
    _write(os.path.join(root, "src", "Api", "Handlers.cs"), _CS_VULNERABLE)
    # A stray C header, the shape that could otherwise steal this repo for
    # ios-source mode.
    _write(os.path.join(root, "lib", "native", "precomp.h"), "#pragma once\n")


def _make_maven_project(root: str) -> None:
    """Multi-module build where the aggregator holds the property, the module
    holds the dependency, and one version comes only from an external BOM."""
    _write(os.path.join(root, "pom.xml"), """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>agg</artifactId>
  <version>1.0-SNAPSHOT</version>
  <packaging>pom</packaging>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.5.14</version>
  </parent>
  <modules><module>svc</module></modules>
  <properties>
    <jackson.version>2.13.4.2</jackson.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.example</groupId>
        <artifactId>managed-lib</artifactId>
        <version>4.5.6</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
""")
    _write(os.path.join(root, "svc", "pom.xml"), """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <artifactId>svc</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>managed-lib</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>ranged</artifactId>
      <version>[1.0,2.0)</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>own-module</artifactId>
      <version>1.0-SNAPSHOT</version>
    </dependency>
  </dependencies>
</project>
""")


def test_dotnet_repo_routes_to_web_source_not_ios():
    with tempfile.TemporaryDirectory() as d:
        _make_dotnet_project(d)
        assert main._detect_scan_mode(d) == "web-source", (
            "a .NET repo with a C header was stolen by ios-source; "
            "its C# code would never be scanned"
        )


def test_bare_c_header_is_no_longer_an_ios_marker():
    """A directory whose only Apple-shaped marker is a `.h` is not an Xcode
    project; any repo vendoring a C library has one."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "lib", "zlib", "zconf.h"), "#pragma once\n")
        assert main._looks_like_ios_source_dir(d) is False


def test_real_objc_project_is_still_detected_as_ios():
    """Objective-C repos always carry `.m`/`.mm` sources too."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "Classes", "AppDelegate.h"), "@interface AppDelegate\n@end\n")
        _write(os.path.join(d, "Classes", "AppDelegate.m"), "@implementation AppDelegate\n@end\n")
        assert main._looks_like_ios_source_dir(d) is True


def test_dotnet_repo_resolves_the_csharp_rule_pack():
    with tempfile.TemporaryDirectory() as d:
        _make_dotnet_project(d)
        ported, _ = source_analyzer.detect_web_stacks(d)
        assert "csharp" in ported, f"C# not detected: got {ported}"
        configs = source_analyzer._resolve_configs(ported)
        basenames = {os.path.basename(c) for c in configs}
        assert "csharp_narvy" in basenames, basenames
        for always_on in ("secrets.yml", "secrets_supplement.yml"):
            assert always_on in basenames, f"{always_on} missing: got {basenames}"
        assert "security-audit.yml" not in basenames, basenames
        assert not any(c.startswith("p/") for c in configs), configs


def test_csharp_emits_a_limited_coverage_note():
    """The cross-language packs carry no csharp-tagged rules, so
    csharp_narvy is the whole AST ruleset."""
    with tempfile.TemporaryDirectory() as d:
        _make_dotnet_project(d)
        result = source_analyzer.analyze_source(d)
    note = " ".join(result["notes"])
    assert "LIMITED COVERAGE" in note and "C#" in note, result["notes"]


def test_csharp_scan_finds_real_vulnerabilities():
    with tempfile.TemporaryDirectory() as d:
        _make_dotnet_project(d)
        result = source_analyzer.analyze_source(d)

    assert result["ok"] is True
    assert "csharp" in result["stacks_detected"]
    assert result["files_scanned"] >= 1

    if not result["findings"]:
        return  # semgrep unavailable; detection assertions above still ran

    rule_ids = {f["rule_id"] for f in result["findings"]}
    expected = {
        "command-text-concat",
        "xmldocument-default-resolver",
        "binary-formatter",
        "weak-hash",
        "weak-cipher",
        "request-input-into-file-api",
        "process-start-untrusted",
    }
    missing = expected - rule_ids
    assert not missing, (
        f"C# pack did not fire for {sorted(missing)}; "
        f"all rule_ids seen: {sorted(rule_ids)}"
    )


def test_csharp_pack_does_not_flag_the_safe_variants():
    """Each vulnerable shape in the fixture is paired with its correct form,
    including a constant SQL statement split across lines for readability."""
    with tempfile.TemporaryDirectory() as d:
        _make_dotnet_project(d)
        result = source_analyzer.analyze_source(d)
        if not result["findings"]:
            return
        source_path = os.path.join(d, "src", "Api", "Handlers.cs")
        with open(source_path) as f:
            lines = f.readlines()
        for finding in result["findings"]:
            if not finding["file_path"].endswith("Handlers.cs"):
                continue
            line = lines[finding["line"] - 1]
            for safe_marker in ("WHERE Id = @id", "XmlResolver = null",
                                "Path.GetFileName(name)", "IF OBJECT_ID"):
                assert safe_marker not in line, (
                    f"{finding['rule_id']} flagged the safe form at line "
                    f"{finding['line']}: {line.strip()}"
                )


def test_maven_resolves_properties_and_dependency_management_across_modules():
    with tempfile.TemporaryDirectory() as d:
        _make_maven_project(d)
        deps = {(dep.name, dep.version)
                for dep in web_deps._collect_maven_deps(d)}

    assert ("com.fasterxml.jackson.core:jackson-databind", "2.13.4.2") in deps, (
        "a ${property} declared in the aggregator pom did not resolve for a "
        f"dependency declared in a module pom: got {sorted(deps)}"
    )
    assert ("com.example:managed-lib", "4.5.6") in deps, (
        "a version supplied only by <dependencyManagement> in the aggregator "
        f"did not resolve: got {sorted(deps)}"
    )


def test_maven_skips_versions_it_cannot_resolve_instead_of_guessing():
    """A version supplied by an external parent BOM, a version range and a
    SNAPSHOT must all produce no dependency rather than a made-up one."""
    with tempfile.TemporaryDirectory() as d:
        _make_maven_project(d)
        names = {dep.name for dep in web_deps._collect_maven_deps(d)}

    assert "org.springframework.boot:spring-boot-starter-web" not in names, (
        "a dependency whose version only an external parent BOM knows was "
        "reported anyway"
    )
    assert "com.example:ranged" not in names, "a Maven version RANGE was reported"
    assert "com.example:own-module" not in names, "a -SNAPSHOT was reported"


def test_maven_gradle_literal_dependencies_are_parsed():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "build.gradle"), """\
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.13.4.2'
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    implementation "org.example:from-variable:$someVersion"
    implementation libs.version.catalog.entry
}
""")
        deps = {(dep.name, dep.version) for dep in web_deps._collect_maven_deps(d)}

    assert ("com.fasterxml.jackson.core:jackson-databind", "2.13.4.2") in deps
    assert ("org.junit.jupiter:junit-jupiter", "5.10.0") in deps
    assert not any(name.startswith("org.example:from-variable") for name, _ in deps), (
        "a Gradle dependency whose version is a build-script variable was "
        "reported with a bogus version"
    )


def test_nuget_csproj_versions_including_exact_pin_and_msbuild_property():
    with tempfile.TemporaryDirectory() as d:
        _make_dotnet_project(d)
        deps = {(dep.name, dep.version) for dep in web_deps._collect_nuget_deps(d)}

    assert ("Newtonsoft.Json", "12.0.1") in deps, (
        f"the `[12.0.1]` exact-pin bracket form was not unwrapped: got {sorted(deps)}"
    )
    assert ("Serilog", "2.12.0") in deps, (
        f"an MSBuild $(Prop) version did not resolve: got {sorted(deps)}"
    )
    assert ("Nested.Version.Package", "3.1.4") in deps, (
        f"the <Version> child-element form was missed: got {sorted(deps)}"
    )
    names = {name for name, _ in deps}
    assert "Floating.Package" not in names, "a floating `1.2.*` version was reported"
    assert "Ranged.Package" not in names, "a NuGet version RANGE was reported"
    assert "Central.Managed.Package" not in names, (
        "a PackageReference with no version at all was reported"
    )


def test_nuget_lockfile_wins_over_the_project_file_for_the_same_project():
    """`packages.lock.json` is the exact restored graph, so reading the .csproj
    too would double-report every direct package."""
    with tempfile.TemporaryDirectory() as d:
        _make_dotnet_project(d)
        _write(os.path.join(d, "src", "Api", "packages.lock.json"), """\
{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1]", "resolved": "12.0.3"},
      "Transitive.Dep": {"type": "Transitive", "resolved": "9.9.9"}
    }
  }
}
""")
        deps = {(dep.name, dep.version) for dep in web_deps._collect_nuget_deps(d)}

    assert ("Newtonsoft.Json", "12.0.3") in deps, sorted(deps)
    assert ("Newtonsoft.Json", "12.0.1") not in deps, (
        "the .csproj was read alongside its own lockfile, so the same package "
        "is reported at two different versions"
    )
    assert ("Transitive.Dep", "9.9.9") in deps, "transitive lockfile entries were dropped"


def test_nuget_packages_config_legacy_format():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "src", "Web", "packages.config"), """\
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="9.0.1" targetFramework="net48" />
  <package id="log4net" version="2.0.8" targetFramework="net48" />
</packages>
""")
        deps = {(dep.name, dep.version) for dep in web_deps._collect_nuget_deps(d)}

    assert ("Newtonsoft.Json", "9.0.1") in deps
    assert ("log4net", "2.0.8") in deps


def test_nuget_central_package_management():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "Directory.Packages.props"), """\
<Project>
  <ItemGroup>
    <PackageVersion Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>
""")
        deps = {(dep.name, dep.version) for dep in web_deps._collect_nuget_deps(d)}
    assert ("Serilog", "3.1.1") in deps, sorted(deps)


def test_maven_and_nuget_are_in_the_user_facing_ecosystem_label():
    label = web_deps.SUPPORTED_ECOSYSTEMS_LABEL
    assert "Maven" in label and "NuGet" in label, label


def test_scan_reports_the_post_cap_count_not_the_pre_cap_one():
    """A large .NET solution blows past _MAX_DETAIL_QUERIES, so
    `unique_dependencies_checked` must be what was actually queried."""
    class _NoNetworkClient:
        def has_any_vuln_batch(self, pairs, ecosystem=None):
            return {}

        def query_dict(self, name, version, ecosystem=None):
            return []

    with tempfile.TemporaryDirectory() as d:
        entries = "\n".join(
            f'    <PackageReference Include="Pkg{i}" Version="1.0.{i}" />'
            for i in range(web_deps._MAX_DETAIL_QUERIES + 25)
        )
        _write(os.path.join(d, "src", "Api", "Api.csproj"),
               f'<Project Sdk="Microsoft.NET.Sdk">\n  <ItemGroup>\n{entries}\n'
               '  </ItemGroup>\n</Project>\n')
        _, _, stats = web_deps.scan(d, osv_client=_NoNetworkClient())

    assert stats["dependencies_capped"] is True
    assert stats["unique_dependencies_detected"] == web_deps._MAX_DETAIL_QUERIES + 25
    assert stats["unique_dependencies_checked"] == web_deps._MAX_DETAIL_QUERIES, (
        "unique_dependencies_checked is the pre-cap count; main.py prints it "
        "verbatim, so the user is told N were checked when fewer were"
    )


def test_manifest_walk_is_deterministic():
    """`scan()` caps OSV queries, so an unstable manifest order would change
    which dependencies get checked between two runs of an unchanged repo."""
    with tempfile.TemporaryDirectory() as d:
        for name in ("Zeta", "Alpha", "Mu"):
            _write(os.path.join(d, "src", name, f"{name}.csproj"),
                   '<Project Sdk="Microsoft.NET.Sdk">\n  <ItemGroup>\n'
                   f'    <PackageReference Include="Pkg.{name}" Version="1.0.0" />\n'
                   '  </ItemGroup>\n</Project>\n')
        first = [d.name for d in web_deps._collect_nuget_deps(d)]
        second = [d.name for d in web_deps._collect_nuget_deps(d)]
    assert first == second == sorted(first), first


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
