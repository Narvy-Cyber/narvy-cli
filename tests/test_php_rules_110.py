"""PHP rules: command injection, cross-file inclusion, reflected XSS, and negatives."""
import json
import os
import subprocess

import pytest

from narvy import semgrep_engine

PHP_PACK = os.path.join(os.path.dirname(semgrep_engine.__file__), "rules", "web", "php.yml")

pytestmark = pytest.mark.skipif(not semgrep_engine.is_available(), reason="semgrep not installed")


def _scan(tmp_path, files):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    out = subprocess.run(
        [semgrep_engine.semgrep_bin(), "--metrics=off", "--quiet", "--json", "--jobs", "1",
         "--no-git-ignore", "--config", PHP_PACK, str(tmp_path)],
        capture_output=True, text=True, timeout=300,
    )
    data = json.loads(out.stdout)
    return {(r["check_id"].rsplit(".", 1)[-1], os.path.relpath(r["path"], tmp_path), r["start"]["line"])
            for r in data["results"]}


def _hits(found, rule):
    return sorted((p, l) for r, p, l in found if r == rule)


def test_exec_with_trailing_concat_is_caught(tmp_path):
    found = _scan(tmp_path, {"ping.php": (
        "<?php\n"
        "$target = $_REQUEST['ip'];\n"
        "$cmd = shell_exec('ping -c 4 ' . $target);\n"
        "$safe = shell_exec('ping -c 4 ' . escapeshellarg($target));\n"
    )})
    assert _hits(found, "tainted-exec-family") == [("ping.php", 3)]


def test_exec_after_numeric_validation_is_not_flagged(tmp_path):
    found = _scan(tmp_path, {"ping.php": (
        "<?php\n"
        "$target = $_REQUEST['ip'];\n"
        "$octet = explode('.', $target);\n"
        "if (is_numeric($octet[0]) && is_numeric($octet[1]) && is_numeric($octet[2]) && is_numeric($octet[3])) {\n"
        "    $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];\n"
        "    $cmd = shell_exec('ping -c 4 ' . $target);\n"
        "}\n"
    )})
    assert _hits(found, "tainted-exec-family") == []


def test_include_of_variable_defined_in_another_file(tmp_path):
    found = _scan(tmp_path, {
        "fi/source/low.php": "<?php\n$file = $_GET['page'];\n",
        "fi/index.php": (
            "<?php\n"
            "require_once 'source/low.php';\n"
            "if (isset($file))\n"
            "    include($file);\n"
        ),
        "ok/local.php": "<?php\n$tpl = 'views/home.php';\ninclude $tpl;\n",
        "ok/switch.php": (
            "<?php\nswitch ($lvl) { case 'a': $t = 'a.php'; break; default: $t = 'b.php'; }\n"
            "require_once $t;\n"
        ),
        "ok/loop.php": "<?php\nforeach (glob('plugins/*.php') as $p) { include $p; }\n",
        "ok/func.php": "<?php\nfunction render($view) { include $view; }\n",
    })
    assert _hits(found, "include-variable-defined-elsewhere") == [("fi/index.php", 4)]


def test_reflected_xss_into_html_string(tmp_path):
    found = _scan(tmp_path, {"xss.php": (
        "<?php\n"
        "$html .= '<pre>Hello ' . $_GET['name'] . '</pre>';\n"
        "$name = str_replace('<script>', '', $_GET['name']);\n"
        "$html .= \"<pre>Hello {$name}</pre>\";\n"
        "$clean = htmlspecialchars($_GET['name']);\n"
        "$html .= \"<pre>Hello {$clean}</pre>\";\n"
        "$sql = \"SELECT * FROM users WHERE id = '\" . $_GET['id'] . \"'\";\n"
        "echo '<b>' . h($_GET['q']) . '</b>';\n"
        "echo '<p>' . ($_GET['x'] == '' ? 'a' : 'b') . '</p>';\n"
    )})
    assert _hits(found, "request-input-in-html-string") == [("xss.php", 2), ("xss.php", 4)]


def test_framework_rules_are_not_shipped():
    """Framework-specific rules (Laravel, Symfony, ...) are premium."""
    import yaml
    ids = [r["id"] for r in yaml.safe_load(open(PHP_PACK))["rules"]]
    assert not [i for i in ids if ".laravel." in i or ".symfony." in i or "blade" in i]
