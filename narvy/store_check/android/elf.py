"""ELF program header reader for the 16 KB page size check.

Google's documented check (developer.android.com/guide/practices/page-sizes)
is: every PT_LOAD segment of a 64-bit shared library (arm64-v8a, x86_64) must
have p_align >= 2**14. This reads exactly those fields.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List

PT_LOAD = 1
ELFCLASS32 = 1
ELFCLASS64 = 2


class ELFError(Exception):
    pass


@dataclass
class LoadSegment:
    offset: int
    vaddr: int
    align: int


@dataclass
class ELFInfo:
    elf_class: int  # 1 = 32-bit, 2 = 64-bit
    machine: int
    loads: List[LoadSegment]

    @property
    def min_load_align(self) -> int:
        return min((s.align for s in self.loads), default=0)


def parse_elf_header(head: bytes) -> ELFInfo:
    """Parse from the first bytes of the file (must include program headers)."""
    if len(head) < 64 or head[:4] != b"\x7fELF":
        raise ELFError("not an ELF file")
    ei_class = head[4]
    ei_data = head[5]
    if ei_data not in (1, 2):
        raise ELFError("bad ELF data encoding")
    end = "<" if ei_data == 1 else ">"
    if ei_class == ELFCLASS64:
        machine = struct.unpack_from(end + "H", head, 18)[0]
        phoff = struct.unpack_from(end + "Q", head, 32)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", head, 54)
        if phentsize < 56:
            raise ELFError("bad phentsize")
        loads = []
        for i in range(phnum):
            p = phoff + i * phentsize
            if p + 56 > len(head):
                raise ELFError("program headers beyond read window")
            p_type, _flags, p_offset, p_vaddr, _paddr, _filesz, _memsz, p_align = struct.unpack_from(end + "IIQQQQQQ", head, p)
            if p_type == PT_LOAD:
                loads.append(LoadSegment(p_offset, p_vaddr, p_align))
        return ELFInfo(ELFCLASS64, machine, loads)
    if ei_class == ELFCLASS32:
        machine = struct.unpack_from(end + "H", head, 18)[0]
        phoff = struct.unpack_from(end + "I", head, 28)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", head, 42)
        if phentsize < 32:
            raise ELFError("bad phentsize")
        loads = []
        for i in range(phnum):
            p = phoff + i * phentsize
            if p + 32 > len(head):
                raise ELFError("program headers beyond read window")
            p_type, p_offset, p_vaddr, _paddr, _filesz, _memsz, _flags, p_align = struct.unpack_from(end + "IIIIIIII", head, p)
            if p_type == PT_LOAD:
                loads.append(LoadSegment(p_offset, p_vaddr, p_align))
        return ELFInfo(ELFCLASS32, machine, loads)
    raise ELFError("unknown ELF class")
