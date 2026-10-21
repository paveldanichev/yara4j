package com.paveldan.yara4j.modules.macho;

import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BinaryReader;

/** The "macho" module. Port of libyara/modules/macho/macho.c. */
public final class MachoModule implements YaraModule {

  static final long MH_MAGIC = 0xfeedfaceL;
  static final long MH_CIGAM = 0xcefaedfeL;
  static final long MH_MAGIC_64 = 0xfeedfacfL;
  static final long MH_CIGAM_64 = 0xcffaedfeL;
  static final long FAT_MAGIC = 0xcafebabeL;
  static final long FAT_CIGAM = 0xbebafecaL;
  static final long FAT_MAGIC_64 = 0xcafebabfL;
  static final long FAT_CIGAM_64 = 0xbfbafecaL;

  static final long LC_SEGMENT = 0x1;
  static final long LC_UNIXTHREAD = 0x5;
  static final long LC_SEGMENT_64 = 0x19;
  static final long LC_MAIN = 0x80000028L;

  static final int CPU_TYPE_MC680X0 = 0x00000006;
  static final int CPU_TYPE_X86 = 0x00000007;
  static final int CPU_TYPE_X86_64 = 0x01000007;
  static final int CPU_TYPE_ARM = 0x0000000c;
  static final int CPU_TYPE_ARM64 = 0x0100000c;
  static final int CPU_TYPE_MC88000 = 0x0000000d;
  static final int CPU_TYPE_SPARC = 0x0000000e;
  static final int CPU_TYPE_POWERPC = 0x00000012;
  static final int CPU_TYPE_POWERPC64 = 0x01000012;

  private static final int SEGMENT_COMMAND_32_SIZE = 56;
  private static final int SEGMENT_COMMAND_64_SIZE = 72;
  private static final int SECTION_32_SIZE = 68;
  private static final int SECTION_64_SIZE = 80;
  private static final int THREAD_COMMAND_SIZE = 16;
  private static final int ENTRY_POINT_COMMAND_SIZE = 24;

  @Override
  public String name() {
    return "macho";
  }

  private static boolean isMachoMagic(long m) {
    return m == MH_MAGIC || m == MH_CIGAM || m == MH_MAGIC_64 || m == MH_CIGAM_64;
  }

  private static boolean isFatMagic(long m) {
    return m == FAT_MAGIC || m == FAT_CIGAM || m == FAT_MAGIC_64 || m == FAT_CIGAM_64;
  }

  private static boolean is32(long magic) {
    return magic == MH_MAGIC || magic == MH_CIGAM;
  }

  /** True if the file is big-endian (fields must be swapped on a little-endian host). */
  private static boolean shouldSwap(long magic) {
    return magic == MH_MAGIC || magic == MH_MAGIC_64 || magic == FAT_MAGIC || magic == FAT_MAGIC_64;
  }

  /** Reader for a Mach-O image located at a given offset of the block. */
  private static final class Image {
    final BinaryReader r;
    final long base;
    final long size;
    final boolean swap;

    Image(BinaryReader r, long base, long size, boolean swap) {
      this.r = r;
      this.base = base;
      this.size = size;
      this.swap = swap;
    }

    long u32(long off) {
      return swap ? r.u32be(base + off) : r.u32(base + off);
    }

    long u64(long off) {
      return swap ? r.u64be(base + off) : r.u64(base + off);
    }

    /** Raw little-endian read, used where libyara forgets to swap. */
    long rawU32(long off) {
      return r.u32(base + off);
    }

    byte[] name16(long off) {
      int n = 0;
      while (n < 16 && r.u8(base + off + n) != 0) {
        n++;
      }
      return r.bytes(base + off, n);
    }
  }

  private static boolean rvaToOffset(long address, long[] result, YObject object) {
    long segmentCount = object.getInteger("number_of_segments");
    for (int i = 0; Long.compareUnsigned(i, segmentCount) < 0; i++) {
      long start = object.getInteger("segments[%i].vmaddr", i);
      long end = start + object.getInteger("segments[%i].vmsize", i);
      if (Long.compareUnsigned(address, start) >= 0 && Long.compareUnsigned(address, end) < 0) {
        long fileoff = object.getInteger("segments[%i].fileoff", i);
        result[0] = fileoff + (address - start);
        return true;
      }
    }
    return false;
  }

  private static void handleUnixThread(Image m, long cmd, long size, YObject object) {
    boolean swap = shouldSwap(object.getInteger("magic"));
    boolean is64 = false;
    if (size < THREAD_COMMAND_SIZE) {
      return;
    }
    // libyara doesn't swap cmdsize here.
    long commandSize = Math.min(size, m.rawU32(cmd + 4));
    if (commandSize < THREAD_COMMAND_SIZE) {
      return;
    }
    long threadStateSize = commandSize - THREAD_COMMAND_SIZE;
    long state = cmd + THREAD_COMMAND_SIZE;
    long address;
    long cputype = object.getInteger("cputype");
    BinaryReader r = m.r;
    long abs = m.base + state;
    if (cputype == CPU_TYPE_MC680X0) {
      if (threadStateSize < 72) {
        return;
      }
      address = r.u32(abs + 68);
    } else if (cputype == CPU_TYPE_MC88000) {
      if (threadStateSize < 136) {
        return;
      }
      address = r.u32(abs + 124);
    } else if (cputype == CPU_TYPE_SPARC) {
      if (threadStateSize < 76) {
        return;
      }
      address = r.u32(abs + 4);
    } else if (cputype == CPU_TYPE_POWERPC) {
      if (threadStateSize < 160) {
        return;
      }
      address = r.u32(abs);
    } else if (cputype == CPU_TYPE_X86) {
      if (threadStateSize < 64) {
        return;
      }
      address = r.u32(abs + 40);
    } else if (cputype == CPU_TYPE_ARM) {
      if (threadStateSize < 68) {
        return;
      }
      address = r.u32(abs + 60);
    } else if (cputype == CPU_TYPE_X86_64) {
      if (threadStateSize < 168) {
        return;
      }
      address = r.u64(abs + 128);
      is64 = true;
    } else if (cputype == CPU_TYPE_ARM64) {
      if (threadStateSize < 268) {
        return;
      }
      address = r.u64(abs + 256);
      is64 = true;
    } else if (cputype == CPU_TYPE_POWERPC64) {
      if (threadStateSize < 304) {
        return;
      }
      address = r.u64(abs);
      is64 = true;
    } else {
      return;
    }
    if (swap) {
      address = is64 ? Long.reverseBytes(address) : (Integer.reverseBytes((int) address) & 0xFFFFFFFFL);
    }
    long[] offset = new long[1];
    if (rvaToOffset(address, offset, object)) {
      object.setInteger(offset[0], "entry_point");
    }
  }

  private static void handleMain(Image m, long cmd, long size, YObject object) {
    if (size < ENTRY_POINT_COMMAND_SIZE) {
      return;
    }
    boolean swap = shouldSwap(object.getInteger("magic"));
    long entryoff = swap ? m.r.u64be(m.base + cmd + 8) : m.r.u64(m.base + cmd + 8);
    long stacksize = swap ? m.r.u64be(m.base + cmd + 16) : m.r.u64(m.base + cmd + 16);
    object.setInteger(entryoff, "entry_point");
    object.setInteger(stacksize, "stack_size");
  }

  private static void handleSegment(Image m, long cmd, long size, int i, YObject object) {
    if (size < SEGMENT_COMMAND_32_SIZE) {
      return;
    }
    long cmdsize = m.u32(cmd + 4);
    object.setString(m.name16(cmd + 8), "segments[%i].segname", i);
    object.setInteger(m.u32(cmd + 24), "segments[%i].vmaddr", i);
    object.setInteger(m.u32(cmd + 28), "segments[%i].vmsize", i);
    object.setInteger(m.u32(cmd + 32), "segments[%i].fileoff", i);
    object.setInteger(m.u32(cmd + 36), "segments[%i].fsize", i);
    object.setInteger(m.u32(cmd + 40), "segments[%i].maxprot", i);
    object.setInteger(m.u32(cmd + 44), "segments[%i].initprot", i);
    long nsects = m.u32(cmd + 48);
    object.setInteger(nsects, "segments[%i].nsects", i);
    object.setInteger(m.u32(cmd + 52), "segments[%i].flags", i);
    long parsedSize = SEGMENT_COMMAND_32_SIZE;
    for (int j = 0; j < nsects; ++j) {
      parsedSize += SECTION_32_SIZE;
      if (cmdsize < parsedSize) {
        break;
      }
      long sec = cmd + SEGMENT_COMMAND_32_SIZE + (long) j * SECTION_32_SIZE;
      object.setString(m.name16(sec + 16), "segments[%i].sections[%i].segname", i, j);
      object.setString(m.name16(sec), "segments[%i].sections[%i].sectname", i, j);
      object.setInteger(m.u32(sec + 32), "segments[%i].sections[%i].addr", i, j);
      object.setInteger(m.u32(sec + 36), "segments[%i].sections[%i].size", i, j);
      object.setInteger(m.u32(sec + 40), "segments[%i].sections[%i].offset", i, j);
      object.setInteger(m.u32(sec + 44), "segments[%i].sections[%i].align", i, j);
      object.setInteger(m.u32(sec + 48), "segments[%i].sections[%i].reloff", i, j);
      object.setInteger(m.u32(sec + 52), "segments[%i].sections[%i].nreloc", i, j);
      object.setInteger(m.u32(sec + 56), "segments[%i].sections[%i].flags", i, j);
      object.setInteger(m.u32(sec + 60), "segments[%i].sections[%i].reserved1", i, j);
      object.setInteger(m.u32(sec + 64), "segments[%i].sections[%i].reserved2", i, j);
    }
  }

  private static void handleSegment64(Image m, long cmd, long size, int i, YObject object) {
    if (size < SEGMENT_COMMAND_64_SIZE) {
      return;
    }
    long cmdsize = m.u32(cmd + 4);
    object.setString(m.name16(cmd + 8), "segments[%i].segname", i);
    object.setInteger(m.u64(cmd + 24), "segments[%i].vmaddr", i);
    object.setInteger(m.u64(cmd + 32), "segments[%i].vmsize", i);
    object.setInteger(m.u64(cmd + 40), "segments[%i].fileoff", i);
    object.setInteger(m.u64(cmd + 48), "segments[%i].fsize", i);
    object.setInteger(m.u32(cmd + 56), "segments[%i].maxprot", i);
    object.setInteger(m.u32(cmd + 60), "segments[%i].initprot", i);
    long nsects = m.u32(cmd + 64);
    object.setInteger(nsects, "segments[%i].nsects", i);
    object.setInteger(m.u32(cmd + 68), "segments[%i].flags", i);
    long parsedSize = SEGMENT_COMMAND_64_SIZE;
    for (int j = 0; j < nsects; ++j) {
      parsedSize += SECTION_64_SIZE;
      if (cmdsize < parsedSize) {
        break;
      }
      long sec = cmd + SEGMENT_COMMAND_64_SIZE + (long) j * SECTION_64_SIZE;
      object.setString(m.name16(sec + 16), "segments[%i].sections[%i].segname", i, j);
      object.setString(m.name16(sec), "segments[%i].sections[%i].sectname", i, j);
      object.setInteger(m.u64(sec + 32), "segments[%i].sections[%i].addr", i, j);
      object.setInteger(m.u64(sec + 40), "segments[%i].sections[%i].size", i, j);
      object.setInteger(m.u32(sec + 48), "segments[%i].sections[%i].offset", i, j);
      object.setInteger(m.u32(sec + 52), "segments[%i].sections[%i].align", i, j);
      object.setInteger(m.u32(sec + 56), "segments[%i].sections[%i].reloff", i, j);
      object.setInteger(m.u32(sec + 60), "segments[%i].sections[%i].nreloc", i, j);
      object.setInteger(m.u32(sec + 64), "segments[%i].sections[%i].flags", i, j);
      object.setInteger(m.u32(sec + 68), "segments[%i].sections[%i].reserved1", i, j);
      object.setInteger(m.u32(sec + 72), "segments[%i].sections[%i].reserved2", i, j);
      object.setInteger(m.u32(sec + 76), "segments[%i].sections[%i].reserved3", i, j);
    }
  }

  private static void parseFile(BinaryReader r, long base, long size, YObject object) {
    if (size < 32) {
      return;
    }
    long magic = r.u32be(base);
    long headerSize = (magic == MH_MAGIC || magic == MH_CIGAM) ? 28 : 32;
    boolean swap = shouldSwap(magic);
    Image m = new Image(r, base, size, swap);
    long ncmds = m.u32(16);
    object.setInteger(magic, "magic");
    object.setInteger(m.u32(4), "cputype");
    object.setInteger(m.u32(8), "cpusubtype");
    object.setInteger(m.u32(12), "filetype");
    object.setInteger(ncmds, "ncmds");
    object.setInteger(m.u32(20), "sizeofcmds");
    object.setInteger(m.u32(24), "flags");
    if (!is32(magic)) {
      object.setInteger(m.u32(28), "reserved");
    }
    int segCount = 0;
    for (int pass = 0; pass < 2; pass++) {
      long parsedSize = headerSize;
      long command = headerSize;
      for (long i = 0; i < ncmds; i++) {
        if (size < command + 8) {
          break;
        }
        long cmd = m.u32(command);
        long cmdsize = m.u32(command + 4);
        if (size - parsedSize < cmdsize) {
          break;
        }
        if (cmdsize < 8) {
          break;
        }
        long avail = size - parsedSize;
        if (pass == 0) {
          if (cmd == LC_SEGMENT) {
            handleSegment(m, command, avail, segCount++, object);
          } else if (cmd == LC_SEGMENT_64) {
            handleSegment64(m, command, avail, segCount++, object);
          }
        } else {
          if (cmd == LC_UNIXTHREAD) {
            handleUnixThread(m, command, avail, object);
          } else if (cmd == LC_MAIN) {
            handleMain(m, command, avail, object);
          }
        }
        command += cmdsize;
        parsedSize += cmdsize;
      }
      if (pass == 0) {
        object.setInteger(segCount, "number_of_segments");
      }
    }
  }

  private static void parseFatFile(BinaryReader r, long size, YStructure object) {
    boolean fat32 = r.u32be(0) == FAT_MAGIC;
    long fatArchSize = fat32 ? 20 : 32;
    if (size < 8) {
      return;
    }
    object.setInteger(r.u32be(0), "fat_magic");
    long count = r.u32be(4);
    object.setInteger(count, "nfat_arch");
    if (count > (size - 8) / fatArchSize) {
      return;
    }
    for (int i = 0; i < count; i++) {
      long a = 8 + i * fatArchSize;
      long cputype;
      long cpusubtype;
      long offset;
      long archSize;
      long align;
      long reserved;
      if (fat32) {
        cputype = r.u32be(a);
        cpusubtype = r.u32be(a + 4);
        offset = r.u32be(a + 8);
        archSize = r.u32be(a + 12);
        align = r.u32be(a + 16);
        reserved = 0;
      } else {
        cputype = r.u32be(a);
        cpusubtype = r.u32be(a + 4);
        offset = r.u64be(a + 8);
        archSize = r.u64be(a + 16);
        align = r.u32be(a + 24);
        reserved = r.u32be(a + 28);
      }
      object.setInteger(cputype, "fat_arch[%i].cputype", i);
      object.setInteger(cpusubtype, "fat_arch[%i].cpusubtype", i);
      object.setInteger(offset, "fat_arch[%i].offset", i);
      object.setInteger(archSize, "fat_arch[%i].size", i);
      object.setInteger(align, "fat_arch[%i].align", i);
      object.setInteger(reserved, "fat_arch[%i].reserved", i);
      if (Long.compareUnsigned(offset + archSize, offset) < 0) {
        continue;
      }
      if (Long.compareUnsigned(size, offset + archSize) < 0) {
        continue;
      }
      object.setInteger(YObject.UNDEFINED, "file[%i].magic", i);
      parseFile(r, offset, archSize, object.lookup("file[%i]", i));
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Functions

  /**
   * Upper bound for the loops over nfat_arch in the functions below. libyara iterates up to
   * nfat_arch, which comes straight from the file and can be ~2^32 in corrupted files. Every
   * index past the end of the arrays gives the same (undefined) values, so evaluating only the
   * first of them produces the same result in a bounded time.
   */
  private static int loopLimit(YObject module, long nfat, String... arrays) {
    long max = 0;
    for (String a : arrays) {
      YObject o = module.lookup(a);
      if (o instanceof com.paveldan.yara4j.object.YArray) {
        max = Math.max(max, ((com.paveldan.yara4j.object.YArray) o).length());
      }
    }
    long limit = max + 1;
    if (Long.compareUnsigned(nfat, limit) < 0) {
      limit = nfat;
    }
    return (int) Math.min(limit, Integer.MAX_VALUE);
  }

  private static Object fileIndexType(FunctionCall c) {
    YObject module = c.module();
    long typeArg = c.integerArgument(1);
    long nfat = module.getInteger("nfat_arch");
    if (module.isUndefined("nfat_arch")) {
      return YObject.UNDEFINED;
    }
    int limit = loopLimit(module, nfat, "file");
    for (int i = 0; i < limit; i++) {
      if (module.getInteger("file[%i].cputype", i) == typeArg) {
        return (long) i;
      }
    }
    return YObject.UNDEFINED;
  }

  private static Object fileIndexSubtype(FunctionCall c) {
    YObject module = c.module();
    long typeArg = c.integerArgument(1);
    long subtypeArg = c.integerArgument(2);
    long nfat = module.getInteger("nfat_arch");
    if (module.isUndefined("nfat_arch")) {
      return YObject.UNDEFINED;
    }
    int limit = loopLimit(module, nfat, "file");
    for (int i = 0; i < limit; i++) {
      if (module.getInteger("file[%i].cputype", i) == typeArg
          && module.getInteger("file[%i].cpusubtype", i) == subtypeArg) {
        return (long) i;
      }
    }
    return YObject.UNDEFINED;
  }

  private static Object epForArchType(FunctionCall c) {
    YObject module = c.module();
    long typeArg = c.integerArgument(1);
    long nfat = module.getInteger("nfat_arch");
    if (module.isUndefined("nfat_arch")) {
      return YObject.UNDEFINED;
    }
    int limit = loopLimit(module, nfat, "file", "fat_arch");
    for (int i = 0; i < limit; i++) {
      if (module.getInteger("fat_arch[%i].cputype", i) == typeArg) {
        long fileOffset = module.getInteger("fat_arch[%i].offset", i);
        long entryPoint = module.getInteger("file[%i].entry_point", i);
        return fileOffset + entryPoint;
      }
    }
    return YObject.UNDEFINED;
  }

  private static Object epForArchSubtype(FunctionCall c) {
    YObject module = c.module();
    long typeArg = c.integerArgument(1);
    long subtypeArg = c.integerArgument(2);
    long nfat = module.getInteger("nfat_arch");
    if (module.isUndefined("nfat_arch")) {
      return YObject.UNDEFINED;
    }
    int limit = loopLimit(module, nfat, "file", "fat_arch");
    for (int i = 0; i < limit; i++) {
      if (module.getInteger("fat_arch[%i].cputype", i) == typeArg
          && module.getInteger("fat_arch[%i].cpusubtype", i) == subtypeArg) {
        long entryPoint = module.getInteger("file[%i].entry_point", i);
        long fileOffset = module.getInteger("fat_arch[%i].offset", i);
        if (entryPoint == YObject.UNDEFINED) {
          return YObject.UNDEFINED;
        }
        return fileOffset + entryPoint;
      }
    }
    return YObject.UNDEFINED;
  }

  // ---------------------------------------------------------------------------------------------

  private static final Object[][] CONSTANTS = {
    {"MH_MAGIC", MH_MAGIC}, {"MH_CIGAM", MH_CIGAM}, {"MH_MAGIC_64", MH_MAGIC_64},
    {"MH_CIGAM_64", MH_CIGAM_64}, {"FAT_MAGIC", FAT_MAGIC}, {"FAT_CIGAM", FAT_CIGAM},
    {"FAT_MAGIC_64", FAT_MAGIC_64}, {"FAT_CIGAM_64", FAT_CIGAM_64},
    {"CPU_ARCH_ABI64", 0x01000000L}, {"CPU_SUBTYPE_LIB64", 0x80000000L},
    {"CPU_TYPE_MC680X0", 0x00000006L}, {"CPU_TYPE_X86", 0x00000007L},
    {"CPU_TYPE_I386", 0x00000007L}, {"CPU_TYPE_X86_64", 0x01000007L},
    {"CPU_TYPE_MIPS", 0x00000008L}, {"CPU_TYPE_MC98000", 0x0000000aL},
    {"CPU_TYPE_ARM", 0x0000000cL}, {"CPU_TYPE_ARM64", 0x0100000cL},
    {"CPU_TYPE_MC88000", 0x0000000dL}, {"CPU_TYPE_SPARC", 0x0000000eL},
    {"CPU_TYPE_POWERPC", 0x00000012L}, {"CPU_TYPE_POWERPC64", 0x01000012L},
    {"CPU_SUBTYPE_INTEL_MODEL_ALL", 0x00L}, {"CPU_SUBTYPE_386", 0x03L},
    {"CPU_SUBTYPE_I386_ALL", 0x03L}, {"CPU_SUBTYPE_X86_64_ALL", 0x03L},
    {"CPU_SUBTYPE_486", 0x04L}, {"CPU_SUBTYPE_486SX", 0x84L}, {"CPU_SUBTYPE_586", 0x05L},
    {"CPU_SUBTYPE_PENT", 0x05L}, {"CPU_SUBTYPE_PENTPRO", 0x16L},
    {"CPU_SUBTYPE_PENTII_M3", 0x36L}, {"CPU_SUBTYPE_PENTII_M5", 0x56L},
    {"CPU_SUBTYPE_CELERON", 0x67L}, {"CPU_SUBTYPE_CELERON_MOBILE", 0x77L},
    {"CPU_SUBTYPE_PENTIUM_3", 0x08L}, {"CPU_SUBTYPE_PENTIUM_3_M", 0x18L},
    {"CPU_SUBTYPE_PENTIUM_3_XEON", 0x28L}, {"CPU_SUBTYPE_PENTIUM_M", 0x09L},
    {"CPU_SUBTYPE_PENTIUM_4", 0x0aL}, {"CPU_SUBTYPE_PENTIUM_4_M", 0x1aL},
    {"CPU_SUBTYPE_ITANIUM", 0x0bL}, {"CPU_SUBTYPE_ITANIUM_2", 0x1bL},
    {"CPU_SUBTYPE_XEON", 0x0cL}, {"CPU_SUBTYPE_XEON_MP", 0x1cL},
    {"CPU_SUBTYPE_ARM_ALL", 0x00L}, {"CPU_SUBTYPE_ARM_V4T", 0x05L},
    {"CPU_SUBTYPE_ARM_V6", 0x06L}, {"CPU_SUBTYPE_ARM_V5", 0x07L},
    {"CPU_SUBTYPE_ARM_V5TEJ", 0x07L}, {"CPU_SUBTYPE_ARM_XSCALE", 0x08L},
    {"CPU_SUBTYPE_ARM_V7", 0x09L}, {"CPU_SUBTYPE_ARM_V7F", 0x0aL},
    {"CPU_SUBTYPE_ARM_V7S", 0x0bL}, {"CPU_SUBTYPE_ARM_V7K", 0x0cL},
    {"CPU_SUBTYPE_ARM_V6M", 0x0eL}, {"CPU_SUBTYPE_ARM_V7M", 0x0fL},
    {"CPU_SUBTYPE_ARM_V7EM", 0x10L}, {"CPU_SUBTYPE_ARM64_ALL", 0x00L},
    {"CPU_SUBTYPE_SPARC_ALL", 0x00L}, {"CPU_SUBTYPE_POWERPC_ALL", 0x00L},
    {"CPU_SUBTYPE_MC980000_ALL", 0x00L}, {"CPU_SUBTYPE_POWERPC_601", 0x01L},
    {"CPU_SUBTYPE_MC98601", 0x01L}, {"CPU_SUBTYPE_POWERPC_602", 0x02L},
    {"CPU_SUBTYPE_POWERPC_603", 0x03L}, {"CPU_SUBTYPE_POWERPC_603e", 0x04L},
    {"CPU_SUBTYPE_POWERPC_603ev", 0x05L}, {"CPU_SUBTYPE_POWERPC_604", 0x06L},
    {"CPU_SUBTYPE_POWERPC_604e", 0x07L}, {"CPU_SUBTYPE_POWERPC_620", 0x08L},
    {"CPU_SUBTYPE_POWERPC_750", 0x09L}, {"CPU_SUBTYPE_POWERPC_7400", 0x0aL},
    {"CPU_SUBTYPE_POWERPC_7450", 0x0bL}, {"CPU_SUBTYPE_POWERPC_970", 0x64L},
    {"MH_OBJECT", 0x01L}, {"MH_EXECUTE", 0x02L}, {"MH_FVMLIB", 0x03L}, {"MH_CORE", 0x04L},
    {"MH_PRELOAD", 0x05L}, {"MH_DYLIB", 0x06L}, {"MH_DYLINKER", 0x07L}, {"MH_BUNDLE", 0x08L},
    {"MH_DYLIB_STUB", 0x09L}, {"MH_DSYM", 0x0aL}, {"MH_KEXT_BUNDLE", 0x0bL},
    {"MH_NOUNDEFS", 0x00000001L}, {"MH_INCRLINK", 0x00000002L}, {"MH_DYLDLINK", 0x00000004L},
    {"MH_BINDATLOAD", 0x00000008L}, {"MH_PREBOUND", 0x00000010L},
    {"MH_SPLIT_SEGS", 0x00000020L}, {"MH_LAZY_INIT", 0x00000040L},
    {"MH_TWOLEVEL", 0x00000080L}, {"MH_FORCE_FLAT", 0x00000100L},
    {"MH_NOMULTIDEFS", 0x00000200L}, {"MH_NOFIXPREBINDING", 0x00000400L},
    {"MH_PREBINDABLE", 0x00000800L}, {"MH_ALLMODSBOUND", 0x00001000L},
    {"MH_SUBSECTIONS_VIA_SYMBOLS", 0x00002000L}, {"MH_CANONICAL", 0x00004000L},
    {"MH_WEAK_DEFINES", 0x00008000L}, {"MH_BINDS_TO_WEAK", 0x00010000L},
    {"MH_ALLOW_STACK_EXECUTION", 0x00020000L}, {"MH_ROOT_SAFE", 0x00040000L},
    {"MH_SETUID_SAFE", 0x00080000L}, {"MH_NO_REEXPORTED_DYLIBS", 0x00100000L},
    {"MH_PIE", 0x00200000L}, {"MH_DEAD_STRIPPABLE_DYLIB", 0x00400000L},
    {"MH_HAS_TLV_DESCRIPTORS", 0x00800000L}, {"MH_NO_HEAP_EXECUTION", 0x01000000L},
    {"MH_APP_EXTENSION_SAFE", 0x02000000L},
    {"SG_HIGHVM", 0x00000001L}, {"SG_FVMLIB", 0x00000002L}, {"SG_NORELOC", 0x00000004L},
    {"SG_PROTECTED_VERSION_1", 0x00000008L},
    {"SECTION_TYPE", 0x000000ffL}, {"SECTION_ATTRIBUTES", 0xffffff00L},
    {"S_REGULAR", 0x00L}, {"S_ZEROFILL", 0x01L}, {"S_CSTRING_LITERALS", 0x02L},
    {"S_4BYTE_LITERALS", 0x03L}, {"S_8BYTE_LITERALS", 0x04L},
    {"S_NON_LAZY_SYMBOL_POINTERS", 0x06L}, {"S_LAZY_SYMBOL_POINTERS", 0x07L},
    {"S_LITERAL_POINTERS", 0x05L}, {"S_SYMBOL_STUBS", 0x08L},
    {"S_MOD_INIT_FUNC_POINTERS", 0x09L}, {"S_MOD_TERM_FUNC_POINTERS", 0x0aL},
    {"S_COALESCED", 0x0bL}, {"S_GB_ZEROFILL", 0x0cL}, {"S_INTERPOSING", 0x0dL},
    {"S_16BYTE_LITERALS", 0x0eL}, {"S_DTRACE_DOF", 0x0fL},
    {"S_LAZY_DYLIB_SYMBOL_POINTERS", 0x10L}, {"S_THREAD_LOCAL_REGULAR", 0x11L},
    {"S_THREAD_LOCAL_ZEROFILL", 0x12L}, {"S_THREAD_LOCAL_VARIABLES", 0x13L},
    {"S_THREAD_LOCAL_VARIABLE_POINTERS", 0x14L},
    {"S_THREAD_LOCAL_INIT_FUNCTION_POINTERS", 0x15L},
    {"S_ATTR_PURE_INSTRUCTIONS", 0x80000000L}, {"S_ATTR_NO_TOC", 0x40000000L},
    {"S_ATTR_STRIP_STATIC_SYMS", 0x20000000L}, {"S_ATTR_NO_DEAD_STRIP", 0x10000000L},
    {"S_ATTR_LIVE_SUPPORT", 0x08000000L}, {"S_ATTR_SELF_MODIFYING_CODE", 0x04000000L},
    {"S_ATTR_DEBUG", 0x02000000L}, {"S_ATTR_SOME_INSTRUCTIONS", 0x00000400L},
    {"S_ATTR_EXT_RELOC", 0x00000200L}, {"S_ATTR_LOC_RELOC", 0x00000100L},
  };

  private static final String[] DECLARED_CONSTANTS = {
    "MH_MAGIC", "MH_CIGAM", "MH_MAGIC_64", "MH_CIGAM_64", "FAT_MAGIC", "FAT_CIGAM",
    "FAT_MAGIC_64", "FAT_CIGAM_64", "CPU_ARCH_ABI64", "CPU_SUBTYPE_LIB64", "CPU_TYPE_MC680X0",
    "CPU_TYPE_X86", "CPU_TYPE_I386", "CPU_TYPE_X86_64", "CPU_TYPE_MIPS", "CPU_TYPE_MC98000",
    "CPU_TYPE_ARM", "CPU_TYPE_ARM64", "CPU_TYPE_MC88000", "CPU_TYPE_SPARC", "CPU_TYPE_POWERPC",
    "CPU_TYPE_POWERPC64", "CPU_SUBTYPE_INTEL_MODEL_ALL", "CPU_SUBTYPE_386",
    "CPU_SUBTYPE_I386_ALL", "CPU_SUBTYPE_X86_64_ALL", "CPU_SUBTYPE_486", "CPU_SUBTYPE_486SX",
    "CPU_SUBTYPE_586", "CPU_SUBTYPE_PENT", "CPU_SUBTYPE_PENTPRO", "CPU_SUBTYPE_PENTII_M3",
    "CPU_SUBTYPE_PENTII_M5", "CPU_SUBTYPE_CELERON", "CPU_SUBTYPE_CELERON_MOBILE",
    "CPU_SUBTYPE_PENTIUM_3", "CPU_SUBTYPE_PENTIUM_3_M", "CPU_SUBTYPE_PENTIUM_3_XEON",
    "CPU_SUBTYPE_PENTIUM_M", "CPU_SUBTYPE_PENTIUM_4", "CPU_SUBTYPE_PENTIUM_4_M",
    "CPU_SUBTYPE_ITANIUM", "CPU_SUBTYPE_ITANIUM_2", "CPU_SUBTYPE_XEON", "CPU_SUBTYPE_XEON_MP",
    "CPU_SUBTYPE_ARM_ALL", "CPU_SUBTYPE_ARM_V4T", "CPU_SUBTYPE_ARM_V6", "CPU_SUBTYPE_ARM_V5",
    "CPU_SUBTYPE_ARM_V5TEJ", "CPU_SUBTYPE_ARM_XSCALE", "CPU_SUBTYPE_ARM_V7",
    "CPU_SUBTYPE_ARM_V7F", "CPU_SUBTYPE_ARM_V7S", "CPU_SUBTYPE_ARM_V7K", "CPU_SUBTYPE_ARM_V6M",
    "CPU_SUBTYPE_ARM_V7M", "CPU_SUBTYPE_ARM_V7EM", "CPU_SUBTYPE_ARM64_ALL",
    "CPU_SUBTYPE_SPARC_ALL", "CPU_SUBTYPE_POWERPC_ALL", "CPU_SUBTYPE_MC980000_ALL",
    "CPU_SUBTYPE_POWERPC_601", "CPU_SUBTYPE_MC98601", "CPU_SUBTYPE_POWERPC_602",
    "CPU_SUBTYPE_POWERPC_603", "CPU_SUBTYPE_POWERPC_603e", "CPU_SUBTYPE_POWERPC_603ev",
    "CPU_SUBTYPE_POWERPC_604", "CPU_SUBTYPE_POWERPC_604e", "CPU_SUBTYPE_POWERPC_620",
    "CPU_SUBTYPE_POWERPC_750", "CPU_SUBTYPE_POWERPC_7400", "CPU_SUBTYPE_POWERPC_7450",
    "CPU_SUBTYPE_POWERPC_970", "MH_OBJECT", "MH_EXECUTE", "MH_FVMLIB", "MH_CORE",
    "MH_PRELOAD", "MH_DYLIB", "MH_DYLINKER", "MH_BUNDLE", "MH_DYLIB_STUB", "MH_DSYM",
    "MH_KEXT_BUNDLE", "MH_NOUNDEFS", "MH_INCRLINK", "MH_DYLDLINK", "MH_BINDATLOAD",
    "MH_PREBOUND", "MH_SPLIT_SEGS", "MH_LAZY_INIT", "MH_TWOLEVEL", "MH_FORCE_FLAT",
    "MH_NOMULTIDEFS", "MH_NOFIXPREBINDING", "MH_PREBINDABLE", "MH_ALLMODSBOUND",
    "MH_SUBSECTIONS_VIA_SYMBOLS", "MH_CANONICAL", "MH_WEAK_DEFINES", "MH_BINDS_TO_WEAK",
    "MH_ALLOW_STACK_EXECUTION", "MH_ROOT_SAFE", "MH_SETUID_SAFE", "MH_NO_REEXPORTED_DYLIBS",
    "MH_PIE", "MH_DEAD_STRIPPABLE_DYLIB", "MH_HAS_TLV_DESCRIPTORS", "MH_NO_HEAP_EXECUTION",
    "MH_APP_EXTENSION_SAFE", "SG_HIGHVM", "SG_FVMLIB", "SG_NORELOC", "SG_PROTECTED_VERSION_1",
    "SECTION_TYPE", "SECTION_ATTRIBUTES", "S_REGULAR", "S_ZEROFILL", "S_CSTRING_LITERALS",
    "S_4BYTE_LITERALS", "S_8BYTE_LITERALS", "S_LITERAL_POINTERS",
    "S_NON_LAZY_SYMBOL_POINTERS", "S_LAZY_SYMBOL_POINTERS", "S_SYMBOL_STUBS",
    "S_MOD_INIT_FUNC_POINTERS", "S_MOD_TERM_FUNC_POINTERS", "S_COALESCED", "S_GB_ZEROFILL",
    "S_INTERPOSING", "S_16BYTE_LITERALS", "S_DTRACE_DOF", "S_LAZY_DYLIB_SYMBOL_POINTERS",
    "S_THREAD_LOCAL_REGULAR", "S_THREAD_LOCAL_ZEROFILL", "S_THREAD_LOCAL_VARIABLES",
    "S_THREAD_LOCAL_VARIABLE_POINTERS", "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",
    "S_ATTR_PURE_INSTRUCTIONS", "S_ATTR_NO_TOC", "S_ATTR_STRIP_STATIC_SYMS",
    "S_ATTR_NO_DEAD_STRIP", "S_ATTR_LIVE_SUPPORT", "S_ATTR_SELF_MODIFYING_CODE",
    "S_ATTR_DEBUG", "S_ATTR_SOME_INSTRUCTIONS", "S_ATTR_EXT_RELOC", "S_ATTR_LOC_RELOC"
  };

  private static void declareFile(ModuleDeclarations d) {
    for (String n :
        new String[] {"magic", "cputype", "cpusubtype", "filetype", "ncmds", "sizeofcmds",
          "flags", "reserved", "number_of_segments"}) {
      d.declareInteger(n);
    }
    d.beginStructArray("segments").declareString("segname");
    for (String n :
        new String[] {"vmaddr", "vmsize", "fileoff", "fsize", "maxprot", "initprot", "nsects",
          "flags"}) {
      d.declareInteger(n);
    }
    d.beginStructArray("sections").declareString("sectname").declareString("segname");
    for (String n :
        new String[] {"addr", "size", "offset", "align", "reloff", "nreloc", "flags",
          "reserved1", "reserved2", "reserved3"}) {
      d.declareInteger(n);
    }
    d.endStructArray("sections");
    d.endStructArray("segments");
    d.declareInteger("entry_point");
    d.declareInteger("stack_size");
  }

  @Override
  public void declare(ModuleDeclarations d) {
    for (String n : DECLARED_CONSTANTS) {
      d.declareInteger(n);
    }
    declareFile(d);
    d.declareInteger("fat_magic");
    d.declareInteger("nfat_arch");
    d.beginStructArray("fat_arch");
    for (String n : new String[] {"cputype", "cpusubtype", "offset", "size", "align"}) {
      d.declareInteger(n);
    }
    d.endStructArray("fat_arch");
    d.beginStructArray("file");
    declareFile(d);
    d.endStructArray("file");
    d.declareFunction("file_index_for_arch", "i", "i", MachoModule::fileIndexType);
    d.declareFunction("file_index_for_arch", "ii", "i", MachoModule::fileIndexSubtype);
    d.declareFunction("entry_point_for_arch", "i", "i", MachoModule::epForArchType);
    d.declareFunction("entry_point_for_arch", "ii", "i", MachoModule::epForArchSubtype);
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {
    for (MemoryBlock block : context.blocks()) {
      if (block.size() < 4) {
        continue;
      }
      BinaryReader r = new BinaryReader(block.data());
      long magic = r.u32(0);
      if (isMachoMagic(magic)) {
        parseFile(r, 0, r.size(), module);
        break;
      }
      if (isFatMagic(magic)) {
        parseFatFile(r, r.size(), module);
        break;
      }
    }
    for (Object[] c : CONSTANTS) {
      module.setInteger((Long) c[1], (String) c[0]);
    }
  }
}
