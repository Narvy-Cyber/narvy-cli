"""Check whether an ELF has any function the stack protector would have instrumented."""
from __future__ import annotations

import logging
import struct
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:  # pragma: no cover
    LIEF_AVAILABLE = False

# Cap pure-Python decoding on very large .text sections.
_MAX_TEXT_SCAN_BYTES = 8 * 1024 * 1024


def _aarch64_takes_stack_address(code: bytes) -> bool:
    """AArch64 is fixed-width, so every 4-byte aligned word is an instruction."""
    for off in range(0, min(len(code), _MAX_TEXT_SCAN_BYTES) // 4 * 4, 4):
        w = struct.unpack_from("<I", code, off)[0]
        # ADD (immediate), 64-bit; mask covers both shift forms.
        if (w & 0xFF800000) == 0x91000000:
            rd, rn = w & 0x1F, (w >> 5) & 0x1F
            # Rd 31/29 are sp/frame-pointer setup, not an escaping address.
            if rd not in (29, 31) and rn in (29, 31):
                return True
        # SUB (immediate), 64-bit: a slot below the frame pointer.
        elif (w & 0xFF800000) == 0xD1000000:
            rd, rn = w & 0x1F, (w >> 5) & 0x1F
            if rd not in (29, 31) and rn == 29:
                return True
    return False


def _arm32_takes_stack_address(code: bytes) -> bool:
    """ARM32 mixes A32 and Thumb-2 in one .text, so both decodings are scanned."""
    limit = min(len(code), _MAX_TEXT_SCAN_BYTES)
    # A32
    for off in range(0, limit // 4 * 4, 4):
        w = struct.unpack_from("<I", code, off)[0]
        rd = (w >> 12) & 0xF
        rn = (w >> 16) & 0xF
        if rd == 13:
            continue
        if (w & 0x0FE00000) == 0x02800000 and rn == 13:  # ADD Rd, sp, #imm
            return True
        if (w & 0x0FE00000) == 0x02400000 and rn == 11:  # SUB Rd, r11(fp), #imm
            return True
        if (w & 0x0FEF0FFF) == 0x01A0000D:               # MOV Rd, sp
            return True
    # Thumb-2
    for off in range(0, limit - 1, 2):
        h = struct.unpack_from("<H", code, off)[0]
        if 0xA800 <= h <= 0xAFFF:                        # ADD Rd, SP, #imm8*4
            return True
        if (h & 0xFF78) == 0x4668:                       # MOV Rd, SP
            return True
        # ADD.W Rd, SP, #const (T3) and ADDW Rd, SP, #imm12 (T4).
        if h in (0xF10D, 0xF50D, 0xF20D, 0xF60D) and off + 3 < limit:
            h2 = struct.unpack_from("<H", code, off + 2)[0]
            if ((h2 >> 8) & 0xF) != 13:
                return True
    return False


def has_instrumentable_stack_code(binary) -> Optional[bool]:
    """Does this ELF hold a function `-fstack-protector-strong` would instrument? True: absent `__stack_chk_fail` means protector off; False: proves nothing; None: no analysis. Never raises."""
    if not LIEF_AVAILABLE or binary is None:
        return None
    try:
        machine = binary.header.machine_type
        if machine == lief.ELF.ARCH.AARCH64:
            decode = _aarch64_takes_stack_address
        elif machine == lief.ELF.ARCH.ARM:
            decode = _arm32_takes_stack_address
        else:
            return None

        code = None
        for section in binary.sections:
            if section.name == ".text":
                code = bytes(section.content)
                break
        if not code:
            # A missing .text is "no analysis"; an empty one is a real verdict.
            return None if code is None else False
        return decode(code)
    except Exception as e:  # pragma: no cover
        logger.debug(f"[stack-protector-evidence] analysis failed: {e}")
        return None
