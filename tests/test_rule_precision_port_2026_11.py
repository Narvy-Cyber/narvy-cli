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
