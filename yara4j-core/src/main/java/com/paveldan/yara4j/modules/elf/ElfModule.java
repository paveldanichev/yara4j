package com.paveldan.yara4j.modules.elf;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BinaryReader;
import com.paveldan.yara4j.util.Tlsh;

/** The "elf" module. Port of libyara/modules/elf/elf.c. */
public final class ElfModule implements YaraModule {

  static final int ET_EXEC = 2;
  static final int SHT_NULL = 0;
  static final int SHT_SYMTAB = 2;
  static final int SHT_STRTAB = 3;
  static final int SHT_NOBITS = 8;
  static final int SHT_DYNSYM = 11;
  static final int SHN_LORESERVE = 0xFF00;
  static final int PN_XNUM = 0xffff;
  static final int PT_DYNAMIC = 2;
  static final int STB_GLOBAL = 1;
  static final int STT_FUNC = 2;
  static final int STV_DEFAULT = 0;

  /** A symbol, kept for telfhash and import_md5. */
  static final class Symbol {
    String name;
    int bind;
    int type;
    int shndx;
    int visibility;
  }

  /** Per-scan data (libyara's ELF struct). */
  static final class ElfData {
    List<Symbol> symtab;
    List<Symbol> dynsym;
    String telfhash;
    String importHash;
  }

  @Override
  public String name() {
    return "elf";
  }

  // ---------------------------------------------------------------------------------------------
  // Structure layouts

  /** Field reader handling 32/64 bits and endianness. */
  private static final class Elf {
    final BinaryReader r;
    final boolean is64;
    final boolean be;
    final long size;

    Elf(BinaryReader r, boolean is64, boolean be) {
      this.r = r;
      this.is64 = is64;
      this.be = be;
      this.size = r.size();
    }

    int u16(long off) {
      return be ? r.u16be(off) : r.u16(off);
    }

    long u32(long off) {
      return be ? r.u32be(off) : r.u32(off);
    }

    long u64(long off) {
      return be ? r.u64be(off) : r.u64(off);
    }

    /** Reads an address-sized field (32 or 64 bits). */
    long word(long off) {
      return is64 ? u64(off) : u32(off);
    }

    // header fields
    int type() {
      return u16(16);
    }

    int machine() {
      return u16(18);
    }

    long entry() {
      return word(24);
    }

    long phOffset() {
      return is64 ? u64(32) : u32(28);
    }

    long shOffset() {
      return is64 ? u64(40) : u32(32);
    }

    int phEntrySize() {
      return u16(is64 ? 54 : 42);
    }

    int phEntryCount() {
      return u16(is64 ? 56 : 44);
    }

    int shEntrySize() {
      return u16(is64 ? 58 : 46);
    }

    int shEntryCount() {
      return u16(is64 ? 60 : 48);
    }

    int shStrTableIndex() {
      return u16(is64 ? 62 : 50);
    }

    int sectionSize() {
      return is64 ? 64 : 40;
    }

    int programSize() {
      return is64 ? 56 : 32;
    }

    int symSize() {
      return is64 ? 24 : 16;
    }

    int dynSize() {
      return is64 ? 16 : 8;
    }

    // section fields (s is the offset of the section header)
    long secName(long s) {
      return u32(s);
    }

    long secType(long s) {
      return u32(s + 4);
    }

    long secFlags(long s) {
      return is64 ? u64(s + 8) : u32(s + 8);
    }

    long secAddr(long s) {
      return is64 ? u64(s + 16) : u32(s + 12);
    }

    long secOffset(long s) {
      return is64 ? u64(s + 24) : u32(s + 16);
    }

    long secSize(long s) {
      return is64 ? u64(s + 32) : u32(s + 20);
    }

    long secLink(long s) {
      return is64 ? u32(s + 40) : u32(s + 24);
    }

    // program header fields
    long phType(long p) {
      return u32(p);
    }

    long phFlags(long p) {
      return is64 ? u32(p + 4) : u32(p + 24);
    }

    long phOffsetField(long p) {
      return is64 ? u64(p + 8) : u32(p + 4);
    }

    long phVaddr(long p) {
      return is64 ? u64(p + 16) : u32(p + 8);
    }

    long phPaddr(long p) {
      return is64 ? u64(p + 24) : u32(p + 12);
    }

    long phFileSize(long p) {
      return is64 ? u64(p + 32) : u32(p + 16);
    }

    long phMemSize(long p) {
      return is64 ? u64(p + 40) : u32(p + 20);
    }

    long phAlign(long p) {
      return is64 ? u64(p + 48) : u32(p + 28);
    }

    // symbol fields
    long symName(long s) {
      return u32(s);
    }

    int symInfo(long s) {
      return r.u8(s + (is64 ? 4 : 12));
    }

    int symOther(long s) {
      return r.u8(s + (is64 ? 5 : 13));
    }

    int symShndx(long s) {
      return u16(s + (is64 ? 6 : 14));
    }

    long symValue(long s) {
      return is64 ? u64(s + 8) : u32(s + 4);
    }

    long symSize(long s) {
      return is64 ? u64(s + 16) : u32(s + 8);
    }
  }

  /** a <= b for unsigned 64 bits values. */
  private static boolean ule(long a, long b) {
    return Long.compareUnsigned(a, b) <= 0;
  }

  private static boolean ult(long a, long b) {
    return Long.compareUnsigned(a, b) < 0;
  }

  /** is_valid_ptr(base, size, base + off, len), with off == -1 meaning NULL. */
  private static boolean isValidPtr(long size, long off, long len) {
    return off >= 0 && ule(len, size) && ule(off, size) && ule(off + len, size) && off + len >= off;
  }

  /** str_table_entry: returns the string or null. limit is the end offset of the table. */
  private static byte[] strTableEntry(BinaryReader r, long base, long limit, long index) {
    if (base < 0 || base >= limit) {
      return null;
    }
    if (base >= r.size()) {
      return null;
    }
    if (r.u8(base) != 0) {
      return null;
    }
    // index is an uint32 converted to int in libyara
    int idx = (int) index;
    if (idx < 0) {
      return null;
    }
    if (idx >= limit - base) {
      return null;
    }
    long entry = base + idx;
    long max = Math.min(limit, r.size()) - entry;
    int len = r.strnlen(entry, max);
    if (len < 0 || entry + len == limit || entry + len >= r.size()) {
      return null;
    }
    return r.bytes(entry, len);
  }

  private static long rvaToOffset(Elf e, long rva) {
    long elfSize = e.size;
    if (e.type() == ET_EXEC) {
      long phOffset = e.phOffset();
      long tableSize = (long) e.programSize() * e.phEntryCount();
      if (ult(-1L - phOffset, tableSize)) {
        return YObject.UNDEFINED;
      }
      if (phOffset == 0
          || ult(elfSize, phOffset)
          || ult(elfSize, phOffset + tableSize)
          || e.phEntryCount() == 0) {
        return YObject.UNDEFINED;
      }
      long p = phOffset;
      for (int i = 0; i < e.phEntryCount(); i++) {
        long vaddr = e.phVaddr(p);
        if (ule(vaddr, rva) && ult(rva, vaddr + e.phMemSize(p))) {
          return e.phOffsetField(p) + (rva - vaddr);
        }
        p += e.programSize();
      }
    } else {
      long shOffset = e.shOffset();
      long tableSize = (long) e.sectionSize() * e.shEntryCount();
      if (ult(-1L - shOffset, tableSize)) {
        return YObject.UNDEFINED;
      }
      if (shOffset == 0
          || ult(elfSize, shOffset)
          || ult(elfSize, shOffset + tableSize)
          || e.shEntryCount() == 0) {
        return YObject.UNDEFINED;
      }
      long s = shOffset;
      for (int i = 0; i < e.shEntryCount(); i++) {
        long type = e.secType(s);
        long addr = e.secAddr(s);
        if (type != SHT_NULL
            && type != SHT_NOBITS
            && ule(addr, rva)
            && ult(rva, addr + e.secSize(s))) {
          return e.secOffset(s) + (rva - addr);
        }
        s += e.sectionSize();
      }
    }
    return YObject.UNDEFINED;
  }

  private static List<Symbol> parseSymbols(
      Elf e, YStructure obj, String array, long table, long tableSize, long strTable,
      long strTableSize) {
    List<Symbol> symbols = new ArrayList<>();
    long count = Long.divideUnsigned(tableSize, e.symSize());
    long sym = table;
    int j;
    for (j = 0; j < count; j++, sym += e.symSize()) {
      Symbol s = new Symbol();
      byte[] name = strTableEntry(e.r, strTable, strTable + strTableSize, e.symName(sym));
      if (name != null) {
        obj.setString(name, array + "[%i].name", j);
        s.name = new String(name, StandardCharsets.ISO_8859_1);
      }
      int info = e.symInfo(sym);
      s.bind = info >> 4;
      obj.setInteger(s.bind, array + "[%i].bind", j);
      s.type = info & 0xf;
      obj.setInteger(s.type, array + "[%i].type", j);
      s.shndx = e.symShndx(sym);
      obj.setInteger(s.shndx, array + "[%i].shndx", j);
      obj.setInteger(e.symValue(sym), array + "[%i].value", j);
      obj.setInteger(e.symSize(sym), array + "[%i].size", j);
      s.visibility = e.symOther(sym) & 0x3;
      symbols.add(s);
    }
    return symbols;
  }

  private static void parseElfHeader(Elf e, ElfData data, YStructure obj) {
    long elfSize = e.size;
    int strTableIndex = e.shStrTableIndex();
    long symTable = -1;
    long symStrTable = -1;
    long dynSymTable = -1;
    long dynSymStrTable = -1;
    long symTableSize = 0;
    long symStrTableSize = 0;
    long dynSymTableSize = 0;
    long dynSymStrTableSize = 0;
    long mask = e.is64 ? -1L : 0xFFFFFFFFL;

    obj.setInteger(e.type(), "type");
    obj.setInteger(e.machine(), "machine");
    obj.setInteger(e.shOffset(), "sh_offset");
    obj.setInteger(e.shEntrySize(), "sh_entry_size");
    obj.setInteger(e.shEntryCount(), "number_of_sections");
    obj.setInteger(e.phOffset(), "ph_offset");
    obj.setInteger(e.phEntrySize(), "ph_entry_size");
    obj.setInteger(e.phEntryCount(), "number_of_segments");

    if (e.entry() != 0) {
      obj.setInteger(rvaToOffset(e, e.entry()), "entry_point");
    }

    long shOffset = e.shOffset();
    int shCount = e.shEntryCount();
    if (shCount < SHN_LORESERVE
        && strTableIndex < shCount
        && ult(shOffset, elfSize)
        && ule(shOffset + (long) shCount * e.sectionSize(), elfSize)) {
      long strTable = -1;
      long sectionTable = shOffset;
      long strSec = sectionTable + (long) strTableIndex * e.sectionSize();
      if (ult(e.secOffset(strSec), elfSize)) {
        strTable = e.secOffset(strSec);
      }
      long section = sectionTable;
      for (int i = 0; i < shCount; i++, section += e.sectionSize()) {
        obj.setInteger(e.secType(section), "sections[%i].type", i);
        obj.setInteger(e.secFlags(section), "sections[%i].flags", i);
        obj.setInteger(e.secAddr(section), "sections[%i].address", i);
        obj.setInteger(e.secSize(section), "sections[%i].size", i);
        obj.setInteger(e.secOffset(section), "sections[%i].offset", i);
        if (e.secName(section) < elfSize && strTable > 0) {
          byte[] name = strTableEntry(e.r, strTable, elfSize, e.secName(section));
          if (name != null) {
            obj.setString(name, "sections[%i].name", i);
          }
        }
        if (e.secType(section) == SHT_SYMTAB && e.secLink(section) < shCount) {
          long stringSection = sectionTable + e.secLink(section) * e.sectionSize();
          if (isValidPtr(elfSize, stringSection, e.sectionSize())
              && e.secType(stringSection) == SHT_STRTAB) {
            symTable = e.secOffset(section);
            symStrTable = e.secOffset(stringSection);
            symTableSize = e.secSize(section) & mask;
            symStrTableSize = e.secSize(stringSection) & mask;
          }
        }
        if (e.secType(section) == SHT_DYNSYM && e.secLink(section) < shCount) {
          long dynstrSection = sectionTable + e.secLink(section) * e.sectionSize();
          if (isValidPtr(elfSize, dynstrSection, e.sectionSize())
              && e.secType(dynstrSection) == SHT_STRTAB) {
            dynSymTable = e.secOffset(section);
            dynSymStrTable = e.secOffset(dynstrSection);
            dynSymTableSize = e.secSize(section) & mask;
            dynSymStrTableSize = e.secSize(dynstrSection) & mask;
          }
        }
      }
      if (isValidPtr(elfSize, symStrTable, symStrTableSize)
          && isValidPtr(elfSize, symTable, symTableSize)) {
        data.symtab =
            parseSymbols(e, obj, "symtab", symTable, symTableSize, symStrTable, symStrTableSize);
        obj.setInteger(data.symtab.size(), "symtab_entries");
      }
      if (isValidPtr(elfSize, dynSymStrTable, dynSymStrTableSize)
          && isValidPtr(elfSize, dynSymTable, dynSymTableSize)) {
        data.dynsym =
            parseSymbols(
                e, obj, "dynsym", dynSymTable, dynSymTableSize, dynSymStrTable,
                dynSymStrTableSize);
        obj.setInteger(data.dynsym.size(), "dynsym_entries");
      }
    }

    long phOffset = e.phOffset();
    int phCount = e.phEntryCount();
    if (phCount > 0
        && phCount < PN_XNUM
        && ult(phOffset, elfSize)
        && ule(phOffset + (long) phCount * e.programSize(), elfSize)) {
      long segment = phOffset;
      for (int i = 0; i < phCount; i++, segment += e.programSize()) {
        obj.setInteger(e.phType(segment), "segments[%i].type", i);
        obj.setInteger(e.phFlags(segment), "segments[%i].flags", i);
        obj.setInteger(e.phOffsetField(segment), "segments[%i].offset", i);
        obj.setInteger(e.phVaddr(segment), "segments[%i].virtual_address", i);
        obj.setInteger(e.phPaddr(segment), "segments[%i].physical_address", i);
        obj.setInteger(e.phFileSize(segment), "segments[%i].file_size", i);
        obj.setInteger(e.phMemSize(segment), "segments[%i].memory_size", i);
        obj.setInteger(e.phAlign(segment), "segments[%i].alignment", i);
        if (e.phType(segment) == PT_DYNAMIC) {
          int j = 0;
          long off = e.phOffsetField(segment);
          if (ult(off, elfSize)) {
            long dyn = off;
            for (j = 0; isValidPtr(elfSize, dyn, e.dynSize()); dyn += e.dynSize(), j++) {
              long tag = e.word(dyn);
              obj.setInteger(tag, "dynamic[%i].type", j);
              obj.setInteger(e.word(dyn + (e.is64 ? 8 : 4)), "dynamic[%i].val", j);
              if (tag == 0) {
                j++;
                break;
              }
            }
          }
          obj.setInteger(j, "dynamic_section_entries");
        }
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Functions

  private static final String[] TELFHASH_EXCLUDE = {
    "__libc_start_main", "main", "abort", "cachectl", "cacheflush", "puts", "atol", "malloc_trim"
  };

  private static String lower(String s) {
    StringBuilder sb = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      sb.append(c >= 'A' && c <= 'Z' ? (char) (c + 32) : c);
    }
    return sb.toString();
  }

  /** Sorts like strcmp (unsigned bytes). */
  private static void sortStrcmp(List<String> names) {
    Collections.sort(
        names,
        (a, b) -> {
          int n = Math.min(a.length(), b.length());
          for (int i = 0; i < n; i++) {
            int c = (a.charAt(i) & 0xFF) - (b.charAt(i) & 0xFF);
            if (c != 0) {
              return c;
            }
          }
          return a.length() - b.length();
        });
  }

  private static Object telfhash(FunctionCall c) {
    ElfData elf = (ElfData) c.module().getData();
    if (elf == null) {
      return null;
    }
    if (elf.telfhash != null) {
      return elf.telfhash;
    }
    List<Symbol> list = elf.dynsym != null ? elf.dynsym : elf.symtab;
    if (list == null) {
      return null;
    }
    List<String> clean = new ArrayList<>();
    for (Symbol s : list) {
      String name = s.name;
      if (name == null) {
        continue;
      }
      if (s.bind != STB_GLOBAL || s.type != STT_FUNC || s.visibility != STV_DEFAULT) {
        continue;
      }
      boolean badPrefix = name.startsWith(".") || name.startsWith("_");
      boolean x8664 = name.length() >= 2 && name.endsWith("64");
      boolean memOrStr = name.startsWith("str") || name.startsWith("mem");
      if (badPrefix || x8664 || memOrStr) {
        continue;
      }
      boolean excluded = false;
      for (String ex : TELFHASH_EXCLUDE) {
        if (name.equals(ex)) {
          excluded = true;
          break;
        }
      }
      if (excluded) {
        continue;
      }
      clean.add(lower(name));
    }
    if (clean.isEmpty()) {
      return null;
    }
    sortStrcmp(clean);
    String joined = String.join(",", clean);
    String hash = Tlsh.hash(joined.getBytes(StandardCharsets.ISO_8859_1));
    if (hash == null) {
      // tlsh_get_hash returns an empty string for invalid hashes.
      hash = "";
    }
    elf.telfhash = hash;
    return hash;
  }

  private static Object importMd5(FunctionCall c) {
    ElfData elf = (ElfData) c.module().getData();
    if (elf == null) {
      return null;
    }
    if (elf.importHash != null) {
      return elf.importHash;
    }
    List<Symbol> list = elf.dynsym != null ? elf.dynsym : elf.symtab;
    if (list == null) {
      return null;
    }
    List<String> clean = new ArrayList<>();
    for (Symbol s : list) {
      if (s.name == null || s.shndx != 0 || s.name.isEmpty()) {
        continue;
      }
      clean.add(lower(s.name));
    }
    if (clean.isEmpty()) {
      return null;
    }
    sortStrcmp(clean);
    String joined = String.join(",", clean);
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      byte[] d = md.digest(joined.getBytes(StandardCharsets.ISO_8859_1));
      elf.importHash = com.paveldan.yara4j.modules.hash.HashModule.hex(d);
      return elf.importHash;
    } catch (java.security.NoSuchAlgorithmException ex) {
      return null;
    }
  }

  // ---------------------------------------------------------------------------------------------

  private static final Object[][] CONSTANTS = {
    {"ET_NONE", 0}, {"ET_REL", 1}, {"ET_EXEC", 2}, {"ET_DYN", 3}, {"ET_CORE", 4},
    {"EM_NONE", 0x0000}, {"EM_M32", 0x0001}, {"EM_SPARC", 0x0002}, {"EM_386", 0x0003},
    {"EM_68K", 0x0004}, {"EM_88K", 0x0005}, {"EM_860", 0x0007}, {"EM_MIPS", 0x0008},
    {"EM_MIPS_RS3_LE", 0x000A}, {"EM_PARISC", 0x000F}, {"EM_SPARC32PLUS", 0x0012},
    {"EM_PPC", 0x0014}, {"EM_PPC64", 0x0015}, {"EM_S390", 0x0016}, {"EM_MCORE", 0x0027},
    {"EM_RCE", 0x0027}, {"EM_ARM", 0x0028}, {"EM_SH", 0x002A}, {"EM_SPARCV9", 0x002B},
    {"EM_X86_64", 0x003E}, {"EM_ARC_COMPACT", 0x005D}, {"EM_AARCH64", 0x00B7},
    {"EM_BPF", 0x00F7}, {"EM_LOONGARCH", 0x0102},
    {"SHT_NULL", 0}, {"SHT_PROGBITS", 1}, {"SHT_SYMTAB", 2}, {"SHT_STRTAB", 3},
    {"SHT_RELA", 4}, {"SHT_HASH", 5}, {"SHT_DYNAMIC", 6}, {"SHT_NOTE", 7}, {"SHT_NOBITS", 8},
    {"SHT_REL", 9}, {"SHT_SHLIB", 10}, {"SHT_DYNSYM", 11},
    {"SHF_WRITE", 0x1}, {"SHF_ALLOC", 0x2}, {"SHF_EXECINSTR", 0x4},
    {"PT_NULL", 0}, {"PT_LOAD", 1}, {"PT_DYNAMIC", 2}, {"PT_INTERP", 3}, {"PT_NOTE", 4},
    {"PT_SHLIB", 5}, {"PT_PHDR", 6}, {"PT_TLS", 7}, {"PT_GNU_EH_FRAME", 0x6474e550},
    {"PT_GNU_STACK", 0x6474e551},
    {"DT_NULL", 0}, {"DT_NEEDED", 1}, {"DT_PLTRELSZ", 2}, {"DT_PLTGOT", 3}, {"DT_HASH", 4},
    {"DT_STRTAB", 5}, {"DT_SYMTAB", 6}, {"DT_RELA", 7}, {"DT_RELASZ", 8}, {"DT_RELAENT", 9},
    {"DT_STRSZ", 10}, {"DT_SYMENT", 11}, {"DT_INIT", 12}, {"DT_FINI", 13}, {"DT_SONAME", 14},
    {"DT_RPATH", 15}, {"DT_SYMBOLIC", 16}, {"DT_REL", 17}, {"DT_RELSZ", 18},
    {"DT_RELENT", 19}, {"DT_PLTREL", 20}, {"DT_DEBUG", 21}, {"DT_TEXTREL", 22},
    {"DT_JMPREL", 23}, {"DT_BIND_NOW", 24}, {"DT_INIT_ARRAY", 25}, {"DT_FINI_ARRAY", 26},
    {"DT_INIT_ARRAYSZ", 27}, {"DT_FINI_ARRAYSZ", 28}, {"DT_RUNPATH", 29}, {"DT_FLAGS", 30},
    {"DT_ENCODING", 32},
    {"STT_NOTYPE", 0}, {"STT_OBJECT", 1}, {"STT_FUNC", 2}, {"STT_SECTION", 3},
    {"STT_FILE", 4}, {"STT_COMMON", 5}, {"STT_TLS", 6},
    {"STB_LOCAL", 0}, {"STB_GLOBAL", 1}, {"STB_WEAK", 2},
    {"PF_X", 0x1}, {"PF_W", 0x2}, {"PF_R", 0x4},
  };

  @Override
  public void declare(ModuleDeclarations d) {
    for (String n :
        new String[] {"ET_NONE", "ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE", "EM_NONE", "EM_M32",
          "EM_SPARC", "EM_386", "EM_68K", "EM_88K", "EM_860", "EM_MIPS", "EM_MIPS_RS3_LE",
          "EM_PARISC", "EM_SPARC32PLUS", "EM_PPC", "EM_PPC64", "EM_S390", "EM_MCORE", "EM_RCE",
          "EM_ARM", "EM_SH", "EM_SPARCV9", "EM_X86_64", "EM_ARC_COMPACT", "EM_AARCH64",
          "EM_BPF", "EM_LOONGARCH", "SHT_NULL", "SHT_PROGBITS", "SHT_SYMTAB", "SHT_STRTAB",
          "SHT_RELA", "SHT_HASH", "SHT_DYNAMIC", "SHT_NOTE", "SHT_NOBITS", "SHT_REL",
          "SHT_SHLIB", "SHT_DYNSYM", "SHF_WRITE", "SHF_ALLOC", "SHF_EXECINSTR", "type",
          "machine", "entry_point", "number_of_sections", "sh_offset", "sh_entry_size",
          "number_of_segments", "ph_offset", "ph_entry_size"}) {
      d.declareInteger(n);
    }
    d.beginStructArray("sections")
        .declareInteger("type")
        .declareInteger("flags")
        .declareInteger("address")
        .declareString("name")
        .declareInteger("size")
        .declareInteger("offset")
        .endStructArray("sections");
    for (String n :
        new String[] {"PT_NULL", "PT_LOAD", "PT_DYNAMIC", "PT_INTERP", "PT_NOTE", "PT_SHLIB",
          "PT_PHDR", "PT_TLS", "PT_GNU_EH_FRAME", "PT_GNU_STACK", "DT_NULL", "DT_NEEDED",
          "DT_PLTRELSZ", "DT_PLTGOT", "DT_HASH", "DT_STRTAB", "DT_SYMTAB", "DT_RELA",
          "DT_RELASZ", "DT_RELAENT", "DT_STRSZ", "DT_SYMENT", "DT_INIT", "DT_FINI",
          "DT_SONAME", "DT_RPATH", "DT_SYMBOLIC", "DT_REL", "DT_RELSZ", "DT_RELENT",
          "DT_PLTREL", "DT_DEBUG", "DT_TEXTREL", "DT_JMPREL", "DT_BIND_NOW", "DT_INIT_ARRAY",
          "DT_FINI_ARRAY", "DT_INIT_ARRAYSZ", "DT_FINI_ARRAYSZ", "DT_RUNPATH", "DT_FLAGS",
          "DT_ENCODING", "STT_NOTYPE", "STT_OBJECT", "STT_FUNC", "STT_SECTION", "STT_FILE",
          "STT_COMMON", "STT_TLS", "STB_LOCAL", "STB_GLOBAL", "STB_WEAK", "PF_X", "PF_W",
          "PF_R"}) {
      d.declareInteger(n);
    }
    d.beginStructArray("segments")
        .declareInteger("type")
        .declareInteger("flags")
        .declareInteger("offset")
        .declareInteger("virtual_address")
        .declareInteger("physical_address")
        .declareInteger("file_size")
        .declareInteger("memory_size")
        .declareInteger("alignment")
        .endStructArray("segments");
    d.declareInteger("dynamic_section_entries");
    d.beginStructArray("dynamic").declareInteger("type").declareInteger("val").endStructArray(
        "dynamic");
    d.declareInteger("symtab_entries");
    d.beginStructArray("symtab")
        .declareString("name")
        .declareInteger("value")
        .declareInteger("size")
        .declareInteger("type")
        .declareInteger("bind")
        .declareInteger("shndx")
        .endStructArray("symtab");
    d.declareInteger("dynsym_entries");
    d.beginStructArray("dynsym")
        .declareString("name")
        .declareInteger("value")
        .declareInteger("size")
        .declareInteger("type")
        .declareInteger("bind")
        .declareInteger("shndx")
        .endStructArray("dynsym");
    d.declareFunction("telfhash", "", "s", ElfModule::telfhash);
    d.declareFunction("import_md5", "", "s", ElfModule::importMd5);
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {
    for (Object[] c : CONSTANTS) {
      module.setInteger(((Number) c[1]).longValue(), (String) c[0]);
    }
    for (MemoryBlock block : context.blocks()) {
      ElfData elf = new ElfData();
      module.setData(elf);
      BinaryReader r = new BinaryReader(block.data());
      if (r.size() < 16 || r.u32(0) != 0x464C457FL) {
        continue;
      }
      int cls = r.u8(4);
      int dataEnc = r.u8(5);
      boolean is64;
      boolean be;
      if (cls == 1 && dataEnc == 1 && r.size() > 52) {
        is64 = false;
        be = false;
      } else if (cls == 1 && dataEnc == 2 && r.size() > 52) {
        is64 = false;
        be = true;
      } else if (cls == 2 && dataEnc == 1 && r.size() > 64) {
        is64 = true;
        be = false;
      } else if (cls == 2 && dataEnc == 2 && r.size() > 64) {
        is64 = true;
        be = true;
      } else {
        continue;
      }
      parseElfHeader(new Elf(r, is64, be), elf, module);
      break;
    }
  }

  @Override
  public void unload(YStructure module) {
    module.setData(null);
  }
}
