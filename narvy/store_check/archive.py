"""In-memory access to ZIP based containers (APK, AAB, APKS/XAPK/APKM, IPA).

Nothing is extracted to disk: entries are read into memory on demand, with
size limits so a hostile archive (zip bomb) cannot exhaust memory.
"""
from __future__ import annotations

import io
import zipfile
from typing import Dict, Iterator, List, Optional

# Hard caps. A single entry above MAX_ENTRY_BYTES is never inflated.
MAX_ENTRY_BYTES = 1024 * 1024 * 1024  # 1 GiB (large iOS executables exist)
MAX_RATIO = 200  # uncompressed / compressed, beyond this we refuse to inflate


class ArchiveError(Exception):
    pass


class EntryTooLarge(ArchiveError):
    pass


class Archive:
    """Thin wrapper over ``zipfile.ZipFile`` with safe reads."""

    def __init__(self, source, label: str = "") -> None:
        self.label = label
        try:
            self._zf = zipfile.ZipFile(source)
        except zipfile.BadZipFile as exc:
            raise ArchiveError(f"not a valid ZIP container: {exc}") from exc
        self._infos: Dict[str, zipfile.ZipInfo] = {}
        for info in self._zf.infolist():
            # Keep the first occurrence of a duplicated name, like Android's
            # installer and Apple's tooling would reject or ignore duplicates.
            self._infos.setdefault(info.filename, info)

    @classmethod
    def from_bytes(cls, data: bytes, label: str = "") -> "Archive":
        return cls(io.BytesIO(data), label=label)

    def names(self) -> List[str]:
        return list(self._infos.keys())

    def has(self, name: str) -> bool:
        return name in self._infos

    def info(self, name: str) -> Optional[zipfile.ZipInfo]:
        return self._infos.get(name)

    def size(self, name: str) -> int:
        return self._infos[name].file_size

    def read(self, name: str, limit: int = MAX_ENTRY_BYTES) -> bytes:
        info = self._infos.get(name)
        if info is None:
            raise KeyError(name)
        if info.flag_bits & 0x1:
            raise ArchiveError(f"{name}: entry is encrypted")
        if info.file_size > limit:
            raise EntryTooLarge(f"{name}: {info.file_size} bytes exceeds limit {limit}")
        if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_RATIO and info.file_size > 50 * 1024 * 1024:
            raise EntryTooLarge(f"{name}: suspicious compression ratio")
        try:
            with self._zf.open(info) as fh:
                data = fh.read(limit + 1)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError) as exc:
            raise ArchiveError(f"{name}: cannot read entry: {exc}") from exc
        if len(data) > limit:
            raise EntryTooLarge(f"{name}: inflated size exceeds limit")
        return data

    def read_head(self, name: str, n: int) -> bytes:
        info = self._infos[name]
        with self._zf.open(info) as fh:
            return fh.read(n)

    def data_offset(self, name: str) -> Optional[int]:
        """Absolute offset of the entry's data inside the archive file.

        Computed from the local file header (its extra field can differ from the
        central directory one), exactly like ``zipalign -c`` does.
        """
        info = self._infos[name]
        fp = self._zf.fp
        if fp is None:
            return None
        pos = fp.tell()
        try:
            fp.seek(info.header_offset)
            hdr = fp.read(30)
        finally:
            fp.seek(pos)
        if len(hdr) < 30 or hdr[:4] != b"PK\x03\x04":
            return None
        name_len = int.from_bytes(hdr[26:28], "little")
        extra_len = int.from_bytes(hdr[28:30], "little")
        return info.header_offset + 30 + name_len + extra_len

    def iter_prefix(self, prefix: str) -> Iterator[str]:
        for n in self._infos:
            if n.startswith(prefix):
                yield n

    def close(self) -> None:
        self._zf.close()
