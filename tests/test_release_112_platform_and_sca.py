"""1.1.2: `python -m narvy`, PATH hint, Windows-safe subprocess calls, SCA dedupe and yarn.lock."""
import io
import os
import subprocess
import sys
import textwrap

import pytest

from narvy import __version__, decompiler, pathhint, proc
from narvy.sca import web_deps
from narvy.sca.web_deps import _WebDep


# --- python -m narvy ------------------------------------------------------

def test_python_dash_m_narvy_runs_the_cli():
    out = subprocess.run([sys.executable, "-m", "narvy", "--version"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == f"narvy {__version__}"


def test_python_dash_m_usage_names_the_module_form():
    out = subprocess.run([sys.executable, "-m", "narvy", "--help"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert "-m narvy" in out.stdout.splitlines()[0]


def test_python_dash_m_bad_argument_keeps_exit_code_3():
    out = subprocess.run([sys.executable, "-m", "narvy", "scan"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 3


# --- PATH hint ------------------------------------------------------------

def _fake_scripts(tmp_path, monkeypatch, launcher="narvy"):
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    exe = scripts / launcher
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(pathhint, "_candidate_script_dirs", lambda: [str(scripts)])
    return scripts


def test_hint_found_when_launcher_dir_not_on_path(tmp_path, monkeypatch):
    scripts = _fake_scripts(tmp_path, monkeypatch)
    assert pathhint.find_unlisted_scripts_dir({"PATH": "/usr/bin"}) == str(scripts)


def test_no_hint_when_dir_already_on_path(tmp_path, monkeypatch):
    scripts = _fake_scripts(tmp_path, monkeypatch)
    assert pathhint.find_unlisted_scripts_dir({"PATH": f"/usr/bin{os.pathsep}{scripts}"}) is None


def test_no_hint_when_no_launcher_installed(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(pathhint, "_candidate_script_dirs", lambda: [str(empty)])
    assert pathhint.find_unlisted_scripts_dir({"PATH": "/usr/bin"}) is None


def test_windows_hint_is_one_powershell_line_and_escapes_quotes():
    text = pathhint.hint_text(r"C:\Users\Jean O'Neil\AppData\Roaming\Python\Python314\Scripts", "win32")
    assert "\n" not in text
    assert "[Environment]::SetEnvironmentVariable('Path'" in text
    assert "Jean O''Neil" in text          # PowerShell single-quote escape
    assert "'User')" in text
    assert "py -m narvy" in text


def test_posix_hint_names_the_shell_rc():
    assert "~/.zshrc" in pathhint.hint_text("/Users/x/Library/Python/3.14/bin", "darwin")
    assert "~/.bashrc" in pathhint.hint_text("/home/x/.local/bin", "linux")


def test_hint_printed_once_then_marker(tmp_path, monkeypatch):
    _fake_scripts(tmp_path, monkeypatch)
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.delenv("NARVY_NO_PATH_HINT", raising=False)
    monkeypatch.setattr(pathhint, "MARKER", str(tmp_path / "marker"))
    err = io.StringIO()
    err.isatty = lambda: True
    monkeypatch.setattr(sys, "stderr", err)
    pathhint.maybe_print_path_hint()
    assert "not on PATH" in err.getvalue()
    err.truncate(0)
    err.seek(0)
    pathhint.maybe_print_path_hint()
    assert err.getvalue() == ""


def test_hint_silent_off_tty(tmp_path, monkeypatch):
    _fake_scripts(tmp_path, monkeypatch)
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(pathhint, "MARKER", str(tmp_path / "marker"))
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    pathhint.maybe_print_path_hint()
    assert err.getvalue() == ""


def test_hint_never_touches_path(tmp_path, monkeypatch):
    _fake_scripts(tmp_path, monkeypatch)
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(pathhint, "MARKER", str(tmp_path / "marker"))
    err = io.StringIO()
    err.isatty = lambda: True
    monkeypatch.setattr(sys, "stderr", err)
    pathhint.maybe_print_path_hint()
    assert os.environ["PATH"] == "/usr/bin"


# --- Windows jadx invocation ---------------------------------------------

def test_windows_bat_command_survives_spaces_in_every_path(monkeypatch):
    monkeypatch.setattr(decompiler, "_IS_WINDOWS", True)
    bat = r"C:\Users\Jean Dupont\.narvy\tools\jadx-1.5.0\bin\jadx.bat"
    apk = r"C:\Users\Jean Dupont\Downloads\OneGlass v1.3.7.apk"
    out = r"C:\Users\Jean Dupont\AppData\Local\Temp\tmp x"
    cmd = decompiler._jadx_cmd(bat, ["--output-dir", out, apk])
    assert isinstance(cmd, str)
    assert cmd.startswith('cmd /d /s /c "')
    assert cmd.endswith('"')
    # cmd /s strips exactly the outer pair; what is left is a normal quoted line.
    inner = cmd[len('cmd /d /s /c "'):-1]
    assert inner == subprocess.list2cmdline([bat, "--output-dir", out, apk])
    assert f'"{bat}"' in inner and f'"{apk}"' in inner


def test_posix_jadx_command_is_a_plain_list(monkeypatch):
    monkeypatch.setattr(decompiler, "_IS_WINDOWS", False)
    assert decompiler._jadx_cmd("/x/jadx", ["a b.apk"]) == ["/x/jadx", "a b.apk"]


# --- subprocess decoding --------------------------------------------------

def test_run_tree_decodes_utf8_whatever_the_locale():
    code = "import sys; sys.stdout.buffer.write('\u0141\u00e9\u2713'.encode('utf-8'))"
    res = proc.run_tree([sys.executable, "-c", code], timeout=60)
    assert res.stdout == "\u0141\u00e9\u2713"


def test_run_tree_invalid_bytes_do_not_raise():
    code = "import sys; sys.stdout.buffer.write(b'ok\\x81\\xff')"
    res = proc.run_tree([sys.executable, "-c", code], timeout=60)
    assert res.stdout.startswith("ok")


def test_semgrep_env_forces_utf8():
    from narvy.semgrep_engine import semgrep_env
    env = semgrep_env()
    assert env["PYTHONUTF8"] == "1" and env["PYTHONIOENCODING"] == "utf-8"


def test_cp1252_redirected_console_does_not_crash(monkeypatch):
    from narvy import main as narvy_main
    buf = io.BytesIO()
    stream = io.TextIOWrapper(buf, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    narvy_main._safe_console_streams()
    sys.stdout.write("snippet \u0141 \u2713\n")
    sys.stdout.flush()
    assert b"snippet" in buf.getvalue()


# --- SCA dedupe -----------------------------------------------------------

def test_dedupe_keeps_every_locked_version():
    deps = [
        _WebDep("lodash", "4.17.21", "npm", "package-lock.json"),
        _WebDep("lodash", "4.17.4", "npm", "package-lock.json"),
        _WebDep("lodash", "4.17.21", "npm", "yarn.lock"),
    ]
    got = sorted(d.version for d in web_deps._dedupe(deps))
    assert got == ["4.17.21", "4.17.4"]


def test_dedupe_drops_manifest_floor_when_a_lockfile_resolves_the_package():
    deps = [
        _WebDep("lodash", "4.17.21", "npm", "yarn.lock"),
        _WebDep("lodash", "4.0.0", "npm", "packages/a/package.json"),
        _WebDep("left-pad", "1.1.0", "npm", "examples/x/package.json"),
    ]
    got = sorted((d.name, d.version) for d in web_deps._dedupe(deps))
    assert got == [("left-pad", "1.1.0"), ("lodash", "4.17.21")]


def test_dedupe_same_name_other_ecosystem_is_separate():
    deps = [_WebDep("requests", "2.0.0", "PyPI", "poetry.lock"),
            _WebDep("requests", "2.0.0", "npm", "package-lock.json")]
    assert len(web_deps._dedupe(deps)) == 2


def test_two_versions_both_reach_osv(tmp_path):
    (tmp_path / "package-lock.json").write_text("""{
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "app"},
        "node_modules/minimist": {"version": "1.2.8"},
        "node_modules/mkdirp/node_modules/minimist": {"version": "0.0.8"}
      }}""")

    class Client:
        query_failures_no_cache = 0

        def __init__(self):
            self.asked = []

        def has_any_vuln_batch(self, pairs, ecosystem):
            self.asked.extend(pairs)
            return {}

    c = Client()
    web_deps.scan(str(tmp_path), osv_client=c)
    assert ("minimist", "0.0.8") in c.asked and ("minimist", "1.2.8") in c.asked


# --- yarn.lock ------------------------------------------------------------

_BERRY = textwrap.dedent('''\
    # This file is generated by running "yarn install" inside your project.
    # Manual changes might be lost - proceed with caution!

    __metadata:
      version: 8
      cacheKey: 10c0

    "@babel/core@npm:^7.0.0, @babel/core@npm:^7.23.0":
      version: 7.23.9
      resolution: "@babel/core@npm:7.23.9"
      dependencies:
        debug: "npm:^4.1.0"
      checksum: 10c0/abc
      languageName: node
      linkType: hard

    "string-width-cjs@npm:string-width@^4.2.0":
      version: 4.2.3
      resolution: "string-width@npm:4.2.3"
      languageName: node
      linkType: hard

    "resolve@patch:resolve@npm%3A^1.22.0#optional!builtin<compat/resolve>":
      version: 1.22.8
      resolution: "resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=c3c19d"
      languageName: node
      linkType: hard

    "resolve@npm:^1.22.0":
      version: 1.22.8
      resolution: "resolve@npm:1.22.8"
      languageName: node
      linkType: hard

    "my-app@workspace:.":
      version: 0.0.0-use.local
      resolution: "my-app@workspace:."
      languageName: unknown
      linkType: soft
    ''')


def test_yarn_berry_uses_resolution_and_skips_metadata_and_workspaces(tmp_path):
    p = tmp_path / "yarn.lock"
    p.write_text(_BERRY)
    got = sorted((d.name, d.version) for d in web_deps._parse_yarn_lock(str(p)))
    assert got == [("@babel/core", "7.23.9"), ("resolve", "1.22.8"), ("string-width", "4.2.3")]


def test_yarn_berry_with_crlf_line_endings(tmp_path):
    p = tmp_path / "yarn.lock"
    p.write_bytes(_BERRY.replace("\n", "\r\n").encode())
    got = sorted((d.name, d.version) for d in web_deps._parse_yarn_lock(str(p)))
    assert got == [("@babel/core", "7.23.9"), ("resolve", "1.22.8"), ("string-width", "4.2.3")]


def test_yarn_classic_alias_git_and_scoped(tmp_path):
    p = tmp_path / "yarn.lock"
    p.write_text(textwrap.dedent('''\
        # yarn lockfile v1


        "string-width-cjs@npm:string-width@^4.2.0":
          version "4.2.3"
          resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz"

        "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
          version "7.12.13"

        lodash@^4.17.11:
          version "4.17.11"

        mylib@git+https://github.com/x/mylib.git#abc:
          version "1.0.0"
        '''))
    got = sorted((d.name, d.version) for d in web_deps._parse_yarn_lock(str(p)))
    assert got == [("@babel/code-frame", "7.12.13"), ("lodash", "4.17.11"), ("string-width", "4.2.3")]


def test_yarn_berry_project_reaches_collection(tmp_path):
    (tmp_path / "yarn.lock").write_text(_BERRY)
    (tmp_path / "package.json").write_text('{"dependencies": {"@babel/core": "^7.0.0"}}')
    deps = web_deps.collect_dependencies(str(tmp_path))
    assert ("@babel/core", "7.23.9") in {(d.name, d.version) for d in deps}
    assert not [d for d in deps if d.source.endswith("package.json")]


def test_semgrep_found_in_user_scripts_dir_off_path(tmp_path, monkeypatch):
    """pip --user put semgrep in a Scripts/bin dir that is not on PATH (python -m narvy case)."""
    from narvy import semgrep_engine
    scripts = tmp_path / "userbin"
    scripts.mkdir()
    exe = scripts / ("semgrep.exe" if os.name == "nt" else "semgrep")
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(pathhint, "_candidate_script_dirs", lambda: [str(scripts)])
    monkeypatch.setattr(sys, "executable", str(tmp_path / "nopython" / "python3"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert semgrep_engine.semgrep_bin() == str(exe)


def test_semgrep_env_puts_semgrep_dir_on_path(tmp_path, monkeypatch):
    """osemgrep execs pysemgrep via PATH: the Scripts/bin dir must be on the child's PATH."""
    from narvy import semgrep_engine
    scripts = tmp_path / "userbin"
    scripts.mkdir()
    exe = scripts / ("semgrep.exe" if os.name == "nt" else "semgrep")
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(semgrep_engine, "semgrep_bin", lambda: str(exe))
    monkeypatch.setenv("PATH", "/usr/bin")
    env = semgrep_engine.semgrep_env()
    assert env["PATH"].split(os.pathsep)[0] == str(scripts)
    assert os.environ["PATH"] == "/usr/bin"


def test_jre_bin_dir_finds_macos_bundle_layout(tmp_path, monkeypatch):
    home = tmp_path / "jre-17"
    (home / "jdk-17.0.20.1+1-jre" / "Contents" / "Home" / "bin").mkdir(parents=True)
    monkeypatch.setattr(decompiler, "JRE_HOME", str(home))
    assert decompiler._jre_bin_dir().endswith(os.path.join("Contents", "Home", "bin"))


def test_jre_bin_dir_linux_windows_layout(tmp_path, monkeypatch):
    home = tmp_path / "jre-17"
    (home / "jdk-17.0.20.1+1-jre" / "bin").mkdir(parents=True)
    monkeypatch.setattr(decompiler, "JRE_HOME", str(home))
    assert decompiler._jre_bin_dir() == str(home / "jdk-17.0.20.1+1-jre" / "bin")


def test_jre_download_arch_matches_machine():
    import platform as _platform
    machine = _platform.machine().lower()
    if os.name == "nt":
        assert decompiler._JRE_ADOPTIUM_ARCH == "x64"
    elif machine in ("arm64", "aarch64"):
        assert decompiler._JRE_ADOPTIUM_ARCH == "aarch64"
    else:
        assert decompiler._JRE_ADOPTIUM_ARCH == "x64"


def test_cached_jre_that_does_not_run_is_replaced(tmp_path, monkeypatch):
    home = tmp_path / "jre-17"
    (home / "jdk" / "bin").mkdir(parents=True)
    monkeypatch.setattr(decompiler, "JRE_HOME", str(home))
    monkeypatch.setattr(decompiler.shutil, "which", lambda name: None)
    monkeypatch.setattr(decompiler, "_java_major_version", lambda j: None)
    monkeypatch.setattr(decompiler, "_download_jre", lambda: "fresh")
    assert decompiler.resolve_java_home() == "fresh"
