"""Rule precision fixes synced from the platform rule set (November 2026)."""
import json
import os
import subprocess
import textwrap

import pytest

from narvy import semgrep_engine

RULES = os.path.join(os.path.dirname(semgrep_engine.__file__), "rules")

pytestmark = pytest.mark.skipif(not semgrep_engine.is_available(), reason="semgrep not installed")


def _hits(pack, filename, code, tmp_path):
    src = tmp_path / filename
    src.write_text(textwrap.dedent(code))
    p = subprocess.run([semgrep_engine.semgrep_bin(), "--metrics=off", "--quiet", "--json", "--jobs", "1",
                        "--no-git-ignore", "--config", os.path.join(RULES, pack), str(src)],
                       capture_output=True, text=True, timeout=300)
    out = json.loads(p.stdout)
    assert not out["errors"], out["errors"]
    return sorted((r["check_id"].rsplit(".", 1)[-1], r["start"]["line"]) for r in out["results"])


def _lines(hits, rule):
    return [line for r, line in hits if r == rule]


# --- secrets: a PUBKEY name is a public key, not a secret ---------------------

def test_high_entropy_exempts_pubkey_names(tmp_path):
    hits = _hits("web/secrets_supplement.yml", "AppConfig.kt", """\
        object AppConfig {
            const val RELAY_PUBKEY = "5fc48ac4765ff81e9c51014b9d2f2c91621370f4c6b5452a9c06456e4cccaeb1"
            val serverPublicKey = "q9Xv2LmT8sKp4RwZ7nYb3HcJ6dFg1AeU5oIiWxQz"
            val nodePub_Key = "q9Xv2LmT8sKp4RwZ7nYb3HcJ6dFg1AeU5oIiWxQz"
            val SIGNING_SECRET_KEY = "q9Xv2LmT8sKp4RwZ7nYb3HcJ6dFg1AeU5oIiWxQz"
        }
        """, tmp_path)
    assert _lines(hits, "generic-high-entropy-assignment") == [5]


# --- java: zip-slip needs a real zip entry, honours braceless checks ---------

ZIP_RULE = "zip-entry-no-canonical-check"


def test_zip_slip_needs_zip_entry_and_honours_braceless_check(tmp_path):
    hits = _hits("web/java.yml", "ZipSlip.java", """\
        import java.io.File;
        import java.io.IOException;
        import java.util.zip.ZipEntry;
        import java.util.zip.ZipInputStream;

        class ZipSlip {
            void unchecked(ZipInputStream zis, File dir) throws IOException {
                ZipEntry e;
                while ((e = zis.getNextEntry()) != null) {
                    String name = e.getName();
                    File out = new File(dir, name);
                }
            }

            void checkedBraceless(ZipInputStream zis, File root) throws IOException {
                String prefix = root.getCanonicalPath() + File.separator;
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    String name = entry.getName();
                    File destination = new File(root, name);
                    if (!destination.getCanonicalPath().startsWith(prefix)) throw new IOException("escape");
                }
            }

            File notAZipEntry(File source, File outDir) {
                String name = source.getParentFile().getName();
                File result = new File(outDir, name);
                return result;
            }
        }
        """, tmp_path)
    assert _lines(hits, ZIP_RULE) == [11]


def test_zip_slip_entry_sources_still_caught(tmp_path):
    hits = _hits("web/java.yml", "Recall.java", """\
        import java.io.*;
        import java.util.*;
        import java.util.jar.*;
        import java.util.zip.*;

        class Recall {
            void direct(ZipInputStream zis, File dir) throws IOException {
                ZipEntry e = zis.getNextEntry();
                File out = new File(dir, e.getName());
            }
            void zipFileEnum(ZipFile zf, File dir) {
                Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry ze = en.nextElement();
                    String n = ze.getName();
                    File out = new File(dir, n);
                }
            }
            void forEach(List<ZipEntry> list, File dir) {
                for (ZipEntry ze : list) {
                    File out = new File(dir, ze.getName());
                }
            }
            void param(ZipEntry ze, File dir) {
                File out = new File(dir, ze.getName());
            }
            void jar(JarInputStream jis, File dir) throws IOException {
                JarEntry je;
                while ((je = jis.getNextJarEntry()) != null) {
                    String n = je.getName();
                    File out = new File(dir, n);
                }
            }
            void bracedCheck(ZipInputStream zis, File dir) throws IOException {
                ZipEntry e = zis.getNextEntry();
                File out = new File(dir, e.getName());
                if (!out.getCanonicalPath().startsWith(dir.getCanonicalPath())) { throw new IOException("x"); }
            }
            void normalizedCheck(ZipInputStream zis, File dir) throws IOException {
                ZipEntry e = zis.getNextEntry();
                File out = new File(dir, e.getName());
                if (!out.toPath().normalize().startsWith(dir.toPath())) throw new IOException("x");
            }
        }
        """, tmp_path)
    assert _lines(hits, ZIP_RULE) == [9, 16, 21, 25, 31]


# --- iOS: a UserDefaults key naming a setting ABOUT a secret is not the secret -

def test_swift_userdefaults_skips_setting_names(tmp_path):
    hits = _hits("ios_swift.yml", "Settings.swift", """\
        import Foundation

        final class Settings {
            func save(token: String, mode: Int, cfg: Data) {
                UserDefaults.standard.set(token, forKey: "authToken")
                UserDefaults.standard.set(token, forKey: "userPassword")
                UserDefaults.standard.set(cfg, forKey: "passwordGeneratorConfig")
                UserDefaults.standard.set(mode, forKey: "passwordMinLength")
                UserDefaults.standard.set(mode, forKey: "tokenExpiryInterval")
                UserDefaults.standard.set(mode, forKey: "secretRevealEnabled")
                defaults.set(token, forKey: "api_key")
            }
        }
        """, tmp_path)
    assert _lines(hits, "ios-swift-userdefaults-sensitive-data") == [5, 6, 11]


def test_objc_userdefaults_skips_setting_names(tmp_path):
    from narvy.ios import source_analyzer
    from narvy.rule_engine import load_rules_from_dir, run_rules_on_file

    src = tmp_path / "Settings.m"
    src.write_text(textwrap.dedent("""\
        - (void)save {
            [[NSUserDefaults standardUserDefaults] setObject:t forKey:@"authToken"];
            [[NSUserDefaults standardUserDefaults] setObject:p forKey:@"userPassword"];
            [[NSUserDefaults standardUserDefaults] setObject:c forKey:@"passwordGeneratorConfig"];
            [[NSUserDefaults standardUserDefaults] setObject:n forKey:@"passwordMinLength"];
            [[NSUserDefaults standardUserDefaults] setObject:i forKey:@"tokenExpiryInterval"];
        }
        """))
    rules = [r for r in load_rules_from_dir(source_analyzer.OBJC_RULES_DIR) if r["id"] == "IOS-OBJC-STORAGE-001"]
    assert len(rules) == 1
    assert sorted(f["line"] for f in run_rules_on_file(str(src), rules)) == [2, 3]


# --- python: name-keyed deserialization rules count `request` only as input --

PY_NAME_KEYED = """\
    import marshal
    import pickle
    import shelve
    import zipfile

    import jsonpickle
    from flask import request


    def server_state(self, dest, redis_conn, k, request_bytes):
        pickle.loads(request.session["blob"])          # 11 ok
        pickle.loads(request.user.profile_blob)        # 12 ok
        pickle.loads(request.method.encode())          # 13 ok
        pickle.loads(request.data_cache)               # 14 ok
        marshal.loads(request.session["code"])         # 15 ok
        jsonpickle.decode(request.user.prefs)          # 16 ok
        shelve.open(request.session["db"])             # 17 ok
        z = zipfile.ZipFile(request.session["archive"])
        z.extractall(dest)                             # 19 ok


    def request_input(self, dest, redis_conn, k, request_bytes):
        pickle.loads(request.body)                     # 23
        pickle.loads(request.FILES["f"].read())        # 24
        pickle.loads(request.get_data())               # 25
        pickle.loads(self.request.POST["b"])           # 26 (missed on 1.3.3)
        pickle.loads(request_bytes)                    # 27
        pickle.loads(redis_conn.get(k))                # 28
        marshal.loads(request.data)                    # 29
        jsonpickle.decode(request.cookies["p"])        # 30
        shelve.open(request.args["db"])                # 31
        pickle.loads(request.text)                     # 32
        pickle.loads(request.content)                  # 33
        pickle.loads(request.environ["wsgi.input"].read())  # 34
        pickle.loads(request.params["b"])              # 35
        jsonpickle.decode(request.json_body["p"])      # 36
        marshal.loads(request.matchdict["c"])          # 37
        pickle.loads(request.query_params["b"])        # 38
        shelve.open(request.path_params["db"])         # 39
        z = zipfile.ZipFile(request.files["archive"])
        z.extractall(dest)                             # 41
    """


def test_python_name_keyed_rules_count_request_only_as_input(tmp_path):
    hits = _hits("web/python.yml", "views.py", PY_NAME_KEYED, tmp_path)
    keyed = {"pickle-loads-untrusted", "marshal-loads-untrusted", "jsonpickle-decode-untrusted",
             "shelve-open-untrusted-path", "zipfile-extractall-untrusted-archive"}
    lines = sorted({line for r, line in hits if r in keyed})
    assert lines == list(range(23, 40)) + [41]
