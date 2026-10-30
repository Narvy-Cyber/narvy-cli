"""narvy sbom / cbom / verify-sbom: CycloneDX output, Ed25519 signing, open PQC inventory."""
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from narvy import cbom, sbom

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _key_files(tmp_path: Path):
    key = ed25519.Ed25519PrivateKey.generate()
    priv = tmp_path / "key.pem"
    pub = tmp_path / "pub.pem"
    priv.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    _write(root / "package-lock.json", json.dumps({
        "name": "demo", "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/lodash": {"version": "4.17.21", "license": "MIT"},
            "node_modules/@scope/pkg": {"version": "1.0.0"},
        },
    }))
    _write(root / "api" / "requirements.txt", "Django_Rest==3.1.0\nrequests>=2\n")
    _write(root / "svc" / "go.mod", "module example.com/svc\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n")
    _write(root / "composer.json", json.dumps({"require": {"monolog/monolog": "^2.0.0"}}))
    return root


# ---------------------------------------------------------------- SBOM

def test_purls():
    assert sbom.purl("npm", "@scope/pkg", "1.0.0") == "pkg:npm/%40scope/pkg@1.0.0"
    assert sbom.purl("PyPI", "Django_Rest", "3.1.0") == "pkg:pypi/django-rest@3.1.0"
    assert sbom.purl("Maven", "com.squareup.okhttp3:okhttp", "4.12.0") == "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"
    assert sbom.purl("Go", "github.com/gin-gonic/gin", "v1.9.1") == "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
    assert sbom.purl("Packagist", "monolog/monolog", "2.0.0") == "pkg:composer/monolog/monolog@2.0.0"
    assert sbom.purl("SwiftPM", "alamofire", "5.8.0", "github.com/Alamofire/Alamofire") == \
        "pkg:swift/github.com/Alamofire/Alamofire@5.8.0"
    assert sbom.purl("SwiftPM", "alamofire", "5.8.0") is None


def test_sbom_from_source_directory(project):
    doc = sbom.build_sbom(str(project))
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    by_purl = {c.get("purl"): c for c in doc["components"]}
    assert "pkg:npm/lodash@4.17.21" in by_purl
    assert "pkg:npm/%40scope/pkg@1.0.0" in by_purl
    assert "pkg:pypi/django-rest@3.1.0" in by_purl
    assert "pkg:golang/github.com/gin-gonic/gin@v1.9.1" in by_purl
    # unpinned range is not invented
    assert not any("requests" in (p or "") for p in by_purl)
    # license only where the lockfile records it
    assert by_purl["pkg:npm/lodash@4.17.21"]["licenses"] == [{"license": {"id": "MIT"}}]
    assert "licenses" not in by_purl["pkg:npm/%40scope/pkg@1.0.0"]
    # a manifest-only version is labelled as such
    props = {p["name"]: p["value"] for p in by_purl["pkg:composer/monolog/monolog@2.0.0"]["properties"]}
    assert props["narvy:version-source"] == "manifest-range-floor"
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert "Not included" in meta["narvy:vulnerabilities"]
    assert meta["narvy:component-count"] == str(len(doc["components"]))


def test_sbom_license_from_installed_node_modules(project):
    _write(project / "node_modules" / "@scope" / "pkg" / "package.json",
           json.dumps({"name": "@scope/pkg", "version": "1.0.0", "license": "Apache-2.0"}))
    doc = sbom.build_sbom(str(project))
    comp = next(c for c in doc["components"] if c.get("purl") == "pkg:npm/%40scope/pkg@1.0.0")
    assert comp["licenses"] == [{"license": {"id": "Apache-2.0"}}]


def test_sbom_rejects_unknown_target(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("x")
    with pytest.raises(ValueError):
        sbom.build_sbom(str(f))


def test_sign_and_verify_roundtrip(project, tmp_path):
    priv, pub = _key_files(tmp_path)
    doc = sbom.sign_document(sbom.build_sbom(str(project)), sbom.load_private_key(str(priv)))
    assert doc["signature"]["algorithm"] == "Ed25519"
    assert doc["signature"]["publicKey"]["kty"] == "OKP"
    # survives a write/read cycle
    out = tmp_path / "s.json"
    sbom.write_json(doc, str(out))
    loaded = json.loads(out.read_text())
    assert sbom.verify_document(loaded) == (True, "valid (key not pinned: integrity only)")
    assert sbom.verify_document(loaded, str(pub)) == (True, "valid")


def test_tampered_sbom_fails(project, tmp_path):
    priv, pub = _key_files(tmp_path)
    doc = sbom.sign_document(sbom.build_sbom(str(project)), sbom.load_private_key(str(priv)))
    doc["components"][0]["version"] = "0.0.0-evil"
    ok, reason = sbom.verify_document(doc, str(pub))
    assert not ok and reason == "signature does not match the content"


def test_other_key_fails_when_pinned(project, tmp_path):
    priv, _ = _key_files(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    _, other_pub = _key_files(other)
    doc = sbom.sign_document(sbom.build_sbom(str(project)), sbom.load_private_key(str(priv)))
    ok, reason = sbom.verify_document(doc, str(other_pub))
    assert not ok and "different key" in reason


def test_unsigned_is_reported_unsigned(project):
    assert sbom.verify_document(sbom.build_sbom(str(project))) == (False, "unsigned")


def test_non_ed25519_key_refused(tmp_path):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p = tmp_path / "rsa.pem"
    p.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with pytest.raises(ValueError):
        sbom.load_private_key(str(p))


def test_signature_matches_rfc8032_vector():
    """RFC 8032 test 1 key: the JSF value is a plain Ed25519 signature over the canonical bytes."""
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    doc = sbom.sign_document({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}, key)
    assert doc["signature"]["publicKey"]["x"] == sbom._b64u(bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
    unsigned = json.loads(json.dumps(doc))
    sig = sbom._b64u_dec(unsigned["signature"].pop("value"))
    expected = (b'{"bomFormat":"CycloneDX","signature":{"algorithm":"Ed25519","publicKey":{"crv":"Ed25519",'
                b'"kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},"specVersion":"1.6","version":1}')
    assert sbom.canonical_json(unsigned) == expected
    key.public_key().verify(sig, expected)


def test_canonical_json_refuses_floats():
    with pytest.raises(ValueError):
        sbom.canonical_json({"a": 1.5})


# ---------------------------------------------------------------- CBOM

def _families(doc):
    return {c["name"]: c for c in doc["components"]}


def test_cbom_source_inventory_and_score(tmp_path):
    root = tmp_path / "app"
    _write(root / "src" / "Crypto.java", '\n'.join([
        'class Crypto {',
        '  // Cipher.getInstance("DES") is not used anymore',
        '  /* KeyPairGenerator.getInstance("DSA") */',
        '  Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");',
        '  Signature s = Signature.getInstance("SHA256withECDSA");',
        '}',
    ]))
    _write(root / "pq.py", "import oqs\nkem = oqs.KeyEncapsulation('ML-KEM-768')\nh = hashlib.md5(b'x')  # cache key\n")
    _write(root / "tests" / "test_x.py", "hashlib.sha1(b'x')\n")
    _write(root / "src" / "Crypto.test.ts", "createHash('sha1')\n")
    _write(root / "node_modules" / "lib" / "index.js", "crypto.createECDH('prime256v1')\n")
    doc, summary = cbom.build_cbom(str(root))
    fams = _families(doc)
    assert set(fams) == {"RSA", "ECDSA", "ML-KEM", "MD5"}
    assert fams["RSA"]["evidence"]["occurrences"][0]["line"] == 4
    assert fams["RSA"]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert fams["ML-KEM"]["cryptoProperties"]["algorithmProperties"]["primitive"] == "kem"
    # 1 PQC family vs 2 quantum-vulnerable families
    assert summary["score"] == 33
    assert summary["vulnerable"] == ["ECDSA", "RSA"] and summary["weak"] == ["MD5"]
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["narvy:pqc-score"] == "33"
    assert "open basic" in meta["narvy:edition"]


def test_cbom_no_asymmetric_crypto_gives_no_score(tmp_path):
    root = tmp_path / "app"
    _write(root / "a.py", "import hashlib\nhashlib.md5(b'x')\n")
    doc, summary = cbom.build_cbom(str(root))
    assert summary["score"] is None
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["narvy:pqc-score"].startswith("none")


def test_cbom_bare_words_do_not_match(tmp_path):
    root = tmp_path / "app"
    _write(root / "a.js", "const RSA = 1; // RSA ECDSA md5\nlet ecdhNote = 'see docs';\nconsole.log(RSA)\n")
    _, summary = cbom.build_cbom(str(root))
    assert summary["occurrences"] == {}


def _dex(strings):
    """Minimal dex: header with string_ids, then string_data items (uleb128 length + MUTF-8 + NUL)."""
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    ids_off = 0x70
    data_off = ids_off + 4 * len(strings)
    ids = bytearray()
    data = bytearray()
    for s in strings:
        ids += struct.pack("<I", data_off + len(data))
        raw = s.encode()
        data += bytes([len(s)]) + raw + b"\x00"
    struct.pack_into("<II", header, 0x38, len(strings), ids_off)
    return bytes(header + ids + data)


def test_cbom_apk_reads_dex_string_table(tmp_path):
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", _dex(["RSA", "MD5", "Lcom/example/Main;",
                                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "ML-KEM-768", "ECDSAnot"]))
        z.writestr("AndroidManifest.xml", b"")
    doc, summary = cbom.build_cbom(str(apk))
    assert set(_families(doc)) == {"RSA", "MD5", "ML-KEM"}
    assert summary["score"] == 50
    assert summary["scanned"] == 1


def test_cbom_apk_bundled_bouncy_castle_pqc_not_scored(tmp_path):
    apk = tmp_path / "b.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", _dex(["RSA", "ML-KEM", "Dilithium", "Lorg/bouncycastle/pqc/X;"]))
    doc, summary = cbom.build_cbom(str(apk))
    assert {"RSA", "ML-KEM", "ML-DSA"} <= set(_families(doc))
    assert summary["providers"] == ["Bouncy Castle"]
    assert summary["score"] == 0
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert "Bouncy Castle" in meta["narvy:bundled-crypto-provider"]


def test_cbom_type_declarations_are_not_call_sites(tmp_path):
    root = tmp_path / "app"
    _write(root / "flow-typed" / "node.js", "declare function createECDH(curveName: string): crypto$ECDH;\n")
    _write(root / "types" / "crypto.d.ts", "export function createDiffieHellman(p: number): DH;\n")
    _write(root / "lib.ts", "export declare function createECDH(c: string): ECDH;\n")
    _, summary = cbom.build_cbom(str(root))
    assert summary["occurrences"] == {}


def test_cbom_pqc_names_need_a_parameter_set(tmp_path):
    root = tmp_path / "app"
    _write(root / "a.ts", "import { KyberNetwork } from 'kyber';\nconst Dilithium = loadToken();\n")
    _, summary = cbom.build_cbom(str(root))
    assert summary["occurrences"] == {}


def test_cbom_ipa_reads_cryptokit_and_go_symbols(tmp_path):
    ipa = tmp_path / "a.ipa"
    macho = b"\xcf\xfa\xed\xfe" + b"\x00" * 64
    with zipfile.ZipFile(ipa, "w") as z:
        z.writestr("Payload/App.app/App", macho + b"$s9CryptoKit4P256O7SigningO10PrivateKeyV\x00")
        z.writestr("Payload/App.app/Frameworks/Go.framework/Go", macho + b"crypto/rsa.SignPKCS1v15\x00")
        z.writestr("Payload/App.app/PlugIns/Share.appex/Share", macho + b"_CC_MD5\x00")
        z.writestr("Payload/App.app/Info.plist", b"kSecAttrKeyTypeRSA not a binary")
    doc, summary = cbom.build_cbom(str(ipa))
    assert set(_families(doc)) == {"ECDSA", "RSA", "MD5"}
    assert summary["scanned"] == 3 and summary["score"] == 0


def test_dex_strings_bad_input():
    assert cbom.dex_strings(b"not a dex") == []


# ---------------------------------------------------------------- CLI

def _cli(*args, cwd):
    r = subprocess.run([sys.executable, "-m", "narvy", *args], cwd=cwd, capture_output=True, text=True,
                       env={"PYTHONPATH": str(ROOT), "NARVY_TELEMETRY": "0", "PATH": "/usr/bin:/bin",
                            "HOME": str(cwd), "COLUMNS": "200"})
    # progress and notes go to stderr; keep one stream for the assertions
    r.stdout = r.stdout + r.stderr
    return r


def test_cli_sbom_sign_verify_and_cbom(project, tmp_path):
    priv, pub = _key_files(tmp_path)
    r = _cli("sbom", str(project), "-f", "out.json", "--sign-key", str(priv), cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "signed (Ed25519)" in r.stdout
    r = _cli("verify-sbom", "out.json", "--public-key", str(pub), cwd=tmp_path)
    assert r.returncode == 0 and "Signature valid." in r.stdout
    doc = json.loads((tmp_path / "out.json").read_text())
    doc["components"].pop()
    (tmp_path / "bad.json").write_text(json.dumps(doc))
    r = _cli("verify-sbom", "bad.json", "--public-key", str(pub), cwd=tmp_path)
    assert r.returncode == 1 and "does not match" in r.stdout

    r = _cli("sbom", str(project), "-f", "plain.json", cwd=tmp_path)
    assert r.returncode == 0 and "unsigned" in r.stdout
    r = _cli("verify-sbom", "plain.json", cwd=tmp_path)
    assert r.returncode == 1 and "unsigned" in r.stdout

    r = _cli("cbom", str(project), "-f", "c.json", cwd=tmp_path)
    assert r.returncode == 0 and "PQC score: none" in r.stdout


def test_cli_scan_sign_key_without_sbom_is_refused(project, tmp_path):
    priv, _ = _key_files(tmp_path)
    r = _cli("scan", str(project), "--sign-key", str(priv), cwd=tmp_path)
    assert r.returncode == 3 and "add --sbom FILE" in r.stdout


def test_cli_refuses_non_zip_binary_instead_of_empty_sbom(tmp_path):
    bad = tmp_path / "broken.ipa"
    bad.write_bytes(b"not a zip at all")
    for cmd in ("sbom", "cbom"):
        r = _cli(cmd, str(bad), "-f", "o.json", cwd=tmp_path)
        assert r.returncode == 3, r.stdout
        assert "valid .apk/.aab/.ipa" in r.stdout
        assert not (tmp_path / "o.json").exists()
