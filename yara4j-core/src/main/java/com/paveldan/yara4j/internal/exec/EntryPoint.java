package com.paveldan.yara4j.internal.exec;

import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.util.BinaryReader;

/** Entry point detection for the deprecated "entrypoint" keyword. Port of exefiles.c. */
final class EntryPoint {
  private EntryPoint() {}

  private static final long ULONG_MAX = -1L;

  /** Returns the offset of the PE header or -1. */
  static long peHeader(BinaryReader r) {
    long len = r.size();
    if (len < 64) {
      return -1;
    }
    if (r.u16(0) != 0x5A4D) {
      return -1;
    }
    int lfanew = r.s32(0x3C);
    if (lfanew < 0) {
      return -1;
    }
    long headersSize = (lfanew & 0xFFFFFFFFL) + 4 + 20;
    if (len < headersSize) {
      return -1;
    }
    long pe = lfanew & 0xFFFFFFFFL;
    headersSize += 224;
    int machine = r.u16(pe + 4);
    if (r.u32(pe) == 0x00004550 && (machine == 0x014c || machine == 0x8664) && len > headersSize) {
      return pe;
    }
    return -1;
  }

  private static long peRvaToOffset(BinaryReader r, long pe, long rva, long bufferLength) {
    int numberOfSections = r.u16(pe + 6);
    int sizeOfOptionalHeader = r.u16(pe + 20);
    long section = pe + 24 + sizeOfOptionalHeader;
    long sectionRva = 0;
    long sectionOffset = 0;
    int i = 0;
    while (i < Math.min(numberOfSections, 60)) {
      if (section - pe + 40 < bufferLength) {
        long va = r.u32(section + 12);
        if (Long.compareUnsigned(rva, va) >= 0 && sectionRva <= va) {
          sectionRva = va;
          sectionOffset = r.u32(section + 20);
        }
        section += 40;
        i++;
      } else {
        return 0;
      }
    }
    return sectionOffset + (rva - sectionRva);
  }

  private static int elfType(BinaryReader r) {
    long len = r.size();
    if (len < 16) {
      return 0;
    }
    if (r.u32(0) != 0x464C457FL) {
      return 0;
    }
    int cls = r.u8(4);
    switch (cls) {
      case 1:
        if (len < 52) {
          return 0;
        }
        break;
      case 2:
        if (len < 64) {
          return 0;
        }
        break;
      default:
        return 0;
    }
    return cls;
  }

  private static long elfRvaToOffset32(BinaryReader r, long rva, long len) {
    if (r.u16(16) == 2) {
      long phOffset = r.u32(28);
      int phCount = r.u16(44);
      if (phOffset == 0 || phCount == 0) {
        return 0;
      }
      if (phOffset + 32L * phCount > len) {
        return 0;
      }
      long program = phOffset;
      for (int i = 0; i < phCount; i++) {
        long vaddr = r.u32(program + 8);
        long memSize = r.u32(program + 20);
        if (rva >= vaddr && rva < vaddr + memSize) {
          return r.u32(program + 4) + (rva - vaddr);
        }
        program += 32;
      }
    } else {
      long shOffset = r.u32(32);
      int shCount = r.u16(48);
      if (shOffset == 0 || shCount == 0) {
        return 0;
      }
      if (shOffset + 40L * shCount > len) {
        return 0;
      }
      long section = shOffset;
      for (int i = 0; i < shCount; i++) {
        long type = r.u32(section + 4);
        long addr = r.u32(section + 12);
        long size = r.u32(section + 20);
        if (type != 0 && type != 8 && rva >= addr && rva < addr + size) {
          return r.u32(section + 16) + (rva - addr);
        }
        section += 40;
      }
    }
    return 0;
  }

  private static long elfRvaToOffset64(BinaryReader r, long rva, long len) {
    if (r.u16(16) == 2) {
      long phOffset = r.u64(32);
      int phCount = r.u16(56);
      if (phOffset == 0 || phCount == 0) {
        return 0;
      }
      if (Long.compareUnsigned(ULONG_MAX - phOffset, 56L * phCount) < 0) {
        return 0;
      }
      if (Long.compareUnsigned(phOffset + 56L * phCount, len) > 0) {
        return 0;
      }
      long program = phOffset;
      for (int i = 0; i < phCount; i++) {
        long vaddr = r.u64(program + 16);
        long memSize = r.u64(program + 40);
        if (Long.compareUnsigned(rva, vaddr) >= 0
            && Long.compareUnsigned(rva, vaddr + memSize) < 0) {
          return r.u64(program + 8) + (rva - vaddr);
        }
        program += 56;
      }
    } else {
      long shOffset = r.u64(40);
      int shCount = r.u16(60);
      if (shOffset == 0 || shCount == 0) {
        return 0;
      }
      if (Long.compareUnsigned(ULONG_MAX - shOffset, 64L * shCount) < 0) {
        return 0;
      }
      if (Long.compareUnsigned(shOffset + 64L * shCount, len) > 0) {
        return 0;
      }
      long section = shOffset;
      for (int i = 0; i < shCount; i++) {
        long type = r.u32(section + 4);
        long addr = r.u64(section + 16);
        long size = r.u64(section + 32);
        if (type != 0
            && type != 8
            && Long.compareUnsigned(rva, addr) >= 0
            && Long.compareUnsigned(rva, addr + size) < 0) {
          return r.u64(section + 24) + (rva - addr);
        }
        section += 64;
      }
    }
    return 0;
  }

  /** Port of yr_get_entry_point_offset. */
  static long offset(BinaryReader r) {
    long pe = peHeader(r);
    if (pe >= 0) {
      return peRvaToOffset(r, pe, r.u32(pe + 24 + 16), r.size() - pe);
    }
    switch (elfType(r)) {
      case 1:
        return elfRvaToOffset32(r, r.u32(24), r.size());
      case 2:
        return elfRvaToOffset64(r, r.u64(24), r.size());
      default:
        return YObject.UNDEFINED;
    }
  }
}
