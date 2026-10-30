"""GET-only template verdict cache: keyed by content + filter code, never by
path/mtime/size, and a corrupted entry is never read as GET-only."""
import hashlib
import json
import os

import pytest

from narvy.web.scanner import NucleiScanner as N

GET = "id: t\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/a']\n"
PUT = "id: t\nhttp:\n  - method: PUT\n    path: ['{{BaseURL}}/a']\n"


@pytest.fixture
def cls(tmp_path, monkeypatch):
    monkeypatch.setenv("NARVY_GET_ONLY_CACHE", str(tmp_path / "c" / "cache.json"))
    monkeypatch.setattr(N, "_GET_ONLY_CACHE", {})
    monkeypatch.setattr(N, "_GET_ONLY_DISK_LOADED", False)
    monkeypatch.setattr(N, "_GET_ONLY_DIRTY", False)
    root = tmp_path / "tpl"
    (root / "http" / "misconfiguration").mkdir(parents=True)
    monkeypatch.setattr(N, "_resolve_templates_root", classmethod(lambda c: str(root)))
    return root / "http" / "misconfiguration"


def _fresh(monkeypatch):
    monkeypatch.setattr(N, "_GET_ONLY_CACHE", {})
    monkeypatch.setattr(N, "_GET_ONLY_DISK_LOADED", False)


def test_parsed_once_then_served_from_disk(cls, monkeypatch):
    for i in range(3):
        (cls / f"t{i}.yaml").write_text(GET.replace("/a", f"/{i}"))
    assert len(N._filter_get_only_templates(["http/misconfiguration/"])) == 3
    _fresh(monkeypatch)
    calls = []
    real = N._template_is_get_only_uncached.__func__
    monkeypatch.setattr(N, "_template_is_get_only_uncached",
                        classmethod(lambda c, p, content=None: (calls.append(p), real(c, p, content))[1]))
    assert len(N._filter_get_only_templates(["http/misconfiguration/"])) == 3
    assert calls == []


def test_same_size_rewrite_with_preserved_mtime_is_reparsed(cls, monkeypatch):
    f = cls / "x.yaml"
    f.write_text(GET)
    assert len(N._filter_get_only_templates(["http/misconfiguration/"])) == 1
    st = os.stat(f)
    f.write_text(PUT)
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert N._filter_get_only_templates(["http/misconfiguration/"]) == []
    _fresh(monkeypatch)
    assert N._filter_get_only_templates(["http/misconfiguration/"]) == []


def test_filter_code_change_invalidates_the_disk_cache(cls, monkeypatch):
    (cls / "x.yaml").write_text(GET)
    N._filter_get_only_templates(["http/misconfiguration/"])
    _fresh(monkeypatch)
    monkeypatch.setattr(N, "_GET_ONLY_FILTER_SIG", "0" * 64)
    calls = []
    real = N._template_is_get_only_uncached.__func__
    monkeypatch.setattr(N, "_template_is_get_only_uncached",
                        classmethod(lambda c, p, content=None: (calls.append(p), real(c, p, content))[1]))
    N._filter_get_only_templates(["http/misconfiguration/"])
    assert len(calls) == 1


def test_corrupted_false_string_entry_is_not_get_only(cls):
    (cls / "p.yaml").write_text(PUT)
    os.makedirs(os.path.dirname(os.environ["NARVY_GET_ONLY_CACHE"]), exist_ok=True)
    with open(os.environ["NARVY_GET_ONLY_CACHE"], "w") as fh:
        json.dump({"version": N._GET_ONLY_CACHE_VERSION, "filter_sig": N._get_only_filter_signature(),
                   "entries": {hashlib.sha256(PUT.encode()).hexdigest(): "false"}}, fh)
    assert N._filter_get_only_templates(["http/misconfiguration/"]) == []
