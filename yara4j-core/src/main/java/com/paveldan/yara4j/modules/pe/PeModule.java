package com.paveldan.yara4j.modules.pe;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.Regexp;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.modules.hash.HashModule;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BinaryReader;
import com.paveldan.yara4j.util.CStrings;

/** The "pe" module. Port of libyara/modules/pe/pe.c and pe_utils.c. */
public final class PeModule implements YaraModule {

  static final long UNDEFINED = YObject.UNDEFINED;

  static final int IMPORT_STANDARD = 1;
  static final int IMPORT_DELAYED = 2;

  static final int RESOURCE_TYPE_VERSION = 16;

  static final int MAX_PE_SECTIONS = 96;
  static final int MAX_PE_IMPORTS = 16384;
  static final int MAX_PE_EXPORTS = 16384;
  static final int MAX_EXPORT_NAME_LENGTH = 512;
  static final int MAX_IMPORT_DLL_NAME_LENGTH = 256;
  static final int MAX_RESOURCES = 65536;
  static final int YR_MAX_PATH = 4096;

  static final int IMAGE_DOS_SIGNATURE = 0x5A4D;
  static final long IMAGE_NT_SIGNATURE = 0x00004550L;
  static final int IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
  static final int IMAGE_FILE_DLL = 0x2000;
  static final int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
  static final int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
  static final int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
  static final int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
  static final int IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
  static final int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
  static final int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
  static final int IMAGE_DEBUG_TYPE_CODEVIEW = 2;
  static final long CVINFO_PDB70_CVSIGNATURE = 0x53445352L;
  static final long CVINFO_PDB20_CVSIGNATURE = 0x3031424eL;
  static final long CODEVIEW_SIGNATURE_MTOC = 0x434f544dL;
  static final long RICH_DANS = 0x536e6144L;
  static final long RICH_RICH = 0x68636952L;
  static final int PE_PAGE_SIZE = 0x1000;
  static final int PE_SECTOR_SIZE = 0x0200;

  // Structure sizes (all structures are packed).
  static final int SIZEOF_DOS_HEADER = 64;
  static final int SIZEOF_FILE_HEADER = 20;
  static final int SIZEOF_OPTIONAL_HEADER32 = 224;
  static final int SIZEOF_OPTIONAL_HEADER64 = 240;
  static final int SIZEOF_SECTION_HEADER = 40;
  static final int SIZEOF_DATA_DIRECTORY = 8;
  static final int SIZEOF_DEBUG_DIRECTORY = 28;
  static final int SIZEOF_RESOURCE_DIRECTORY = 16;
  static final int SIZEOF_RESOURCE_DIRECTORY_ENTRY = 8;
  static final int SIZEOF_RESOURCE_DATA_ENTRY = 16;
  static final int SIZEOF_IMPORT_DESCRIPTOR = 20;
  static final int SIZEOF_IMPORT_BY_NAME = 3;
  static final int SIZEOF_DELAYLOAD_DESCRIPTOR = 32;
  static final int SIZEOF_EXPORT_DIRECTORY = 40;
  static final int SIZEOF_SYMBOL = 18;
  static final int SIZEOF_VERSION_INFO = 6;
  static final int SIZEOF_RICH_SIGNATURE = 16;
  static final int SIZEOF_RICH_VERSION_INFO = 8;

  /** An imported function (IMPORT_FUNCTION). */
  static final class ImportFunction {
    byte[] name;
    boolean hasOrdinal;
    int ordinal;
    long rva;
  }

  /** An imported DLL (IMPORTED_DLL). */
  static final class ImportedDll {
    byte[] name;
    List<ImportFunction> functions;
  }

  /**
   * Parsing state, equivalent of the PE structure in pe_utils.h. It is also used by the dotnet
   * module.
   */
  public static final class Pe {
    public final BinaryReader r;
    public final long size;
    final long header;
    final YStructure object;
    public final boolean is64;
    final long optionalHeader;
    final long firstSection;
    final int numberOfSections;
    List<ImportedDll> importedDlls;
    List<ImportedDll> delayImportedDlls;
    int resources;
    int versionInfos;
    String imphash;

    // Section headers used by rvaToOffset, decoded once.
    private final boolean sectionsTruncated;
    private final long[] secVa;
    private final long[] secVirtualSize;
    private final long[] secRawOffset;
    private final long[] secRawSize;

    public Pe(BinaryReader r, long header, YStructure object) {
      this.r = r;
      this.size = r.size();
      this.header = header;
      this.object = object;
      this.optionalHeader = header + 4 + SIZEOF_FILE_HEADER;
      this.is64 = r.u16(optionalHeader) == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
      this.firstSection = optionalHeader + r.u16(header + 4 + 16);
      this.numberOfSections = r.u16(header + 4 + 2);
      int n = Math.min(numberOfSections, MAX_PE_SECTIONS);
      secVa = new long[n];
      secVirtualSize = new long[n];
      secRawOffset = new long[n];
      secRawSize = new long[n];
      boolean truncated = false;
      for (int i = 0; i < n; i++) {
        long s = firstSection + (long) i * SIZEOF_SECTION_HEADER;
        if (!fits(s, SIZEOF_SECTION_HEADER)) {
          truncated = true;
          break;
        }
        secVirtualSize[i] = r.u32(s + 8);
        secVa[i] = r.u32(s + 12);
        secRawSize[i] = r.u32(s + 16);
        secRawOffset[i] = r.u32(s + 20);
      }
      sectionsTruncated = truncated;
    }

    public boolean fits(long offset, long length) {
      return length <= size && offset >= 0 && offset <= size - length;
    }

    public long availableSpace(long offset) {
      if (offset < 0 || offset >= size) {
        return 0;
      }
      return size - offset;
    }

    public int u8(long o) {
      return o >= 0 && o < size ? r.u8(o) : 0;
    }

    public int u16(long o) {
      return r.u16(o);
    }

    public long u32(long o) {
      return r.u32(o);
    }

    // Optional header fields, the offsets differ between PE32 and PE32+.

    long addressOfEntryPoint() {
      return u32(optionalHeader + 16);
    }

    long imageBase() {
      return is64 ? r.u64(optionalHeader + 24) : u32(optionalHeader + 28);
    }

    long sectionAlignment() {
      return u32(optionalHeader + 32);
    }

    long fileAlignment() {
      return u32(optionalHeader + 36);
    }

    long sizeOfImage() {
      return u32(optionalHeader + 56);
    }

    public long numberOfRvaAndSizes() {
      return u32(optionalHeader + (is64 ? 108 : 92));
    }

    long dataDirectories() {
      return optionalHeader + (is64 ? 112 : 96);
    }

    long ohSized(int off32, int off64) {
      return is64 ? r.u64(optionalHeader + off64) : u32(optionalHeader + off32);
    }

    /** See {@link BinaryReader#tick}. */
    public void tick() {
      r.tick();
    }

    /** pe_get_directory_entry: offset of the data directory entry or -1. */
    public long directoryEntry(int entry) {
      long result = dataDirectories() + (long) entry * SIZEOF_DATA_DIRECTORY;
      if (!fits(result, SIZEOF_DATA_DIRECTORY)) {
        return -1;
      }
      return result;
    }

    /** pe_rva_to_offset. The rva is an unsigned 64-bit value. */
    public long rvaToOffset(long rva) {
      if (sectionsTruncated) {
        return -1;
      }
      long lowestSectionRva = 0xffffffffL;
      long sectionRva = 0;
      long sectionOffset = 0;
      long sectionRawSize = 0;
      for (int i = 0; i < secVa.length; i++) {
        long va = secVa[i];
        if (lowestSectionRva > va) {
          lowestSectionRva = va;
        }
        long virtualSize = Math.max(secVirtualSize[i], secRawSize[i]);
        if (Long.compareUnsigned(rva, va) >= 0
            && Long.compareUnsigned(rva - va, virtualSize) < 0
            && sectionRva <= va) {
          long alignment = Math.min(fileAlignment(), 0x200);
          sectionRva = va;
          sectionOffset = secRawOffset[i];
          sectionRawSize = secRawSize[i];
          if (alignment != 0) {
            long rest = sectionOffset % alignment;
            if (rest != 0) {
              sectionOffset -= rest;
            }
          }
          if (sectionAlignment() >= PE_PAGE_SIZE) {
            sectionOffset = sectionOffset & ~(PE_SECTOR_SIZE - 1L);
          }
        }
      }
      if (Long.compareUnsigned(rva, lowestSectionRva) < 0) {
        sectionRva = 0;
        sectionOffset = 0;
        sectionRawSize = size & 0xffffffffL;
      }
      if (Long.compareUnsigned(rva - sectionRva, sectionRawSize) >= 0) {
        return -1;
      }
      long result = sectionOffset + (rva - sectionRva);
      if (Long.compareUnsigned(result, size) >= 0) {
        return -1;
      }
      return result;
    }

    /** strndup(data + offset, n). */
    byte[] strndup(long offset, long n) {
      int len = r.strnlen(offset, n);
      return len <= 0 ? new byte[0] : r.bytes(offset, len);
    }

    /** strnlen(data + offset, n) where the caller guarantees offset is inside the data. */
    int strnlen(long offset, long n) {
      int len = r.strnlen(offset, n);
      return Math.max(len, 0);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Header parsing

  /** pe_get_header: returns the offset of the NT headers or -1. */
  public static long getHeader(BinaryReader r) {
    long size = r.size();
    if (size < SIZEOF_DOS_HEADER) {
      return -1;
    }
    if (r.u16(0) != IMAGE_DOS_SIGNATURE) {
      return -1;
    }
    long lfanew = r.u32(60);
    if ((int) lfanew < 0) {
      return -1;
    }
    long headersSize = lfanew + 4 + SIZEOF_FILE_HEADER;
    if (size < headersSize) {
      return -1;
    }
    if (r.u32(lfanew) != IMAGE_NT_SIGNATURE) {
      return -1;
    }
    if (size < headersSize + SIZEOF_OPTIONAL_HEADER32) {
      return -1;
    }
    if (r.u16(headersSize) == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      headersSize += SIZEOF_OPTIONAL_HEADER64;
    } else {
      headersSize += SIZEOF_OPTIONAL_HEADER32;
    }
    if (size < headersSize) {
      return -1;
    }
    return lfanew;
  }

  static void parseRichSignature(Pe pe, long baseAddress) {
    if (pe.size < SIZEOF_DOS_HEADER) {
      return;
    }
    if (pe.u16(0) != IMAGE_DOS_SIGNATURE) {
      return;
    }
    long nthdrOffset = pe.u32(60);
    if (nthdrOffset > pe.size + 4 || nthdrOffset < 4) {
      return;
    }
    long p = nthdrOffset - 4;
    long key = 0;
    long richPtr = 0;
    while (p >= SIZEOF_DOS_HEADER) {
      if (pe.fits(p, 4) && pe.u32(p) == RICH_RICH) {
        key = pe.fits(p + 4, 4) ? pe.u32(p + 4) : 0;
        richPtr = p;
        p -= 4;
        break;
      }
      p -= 4;
    }
    if (key == 0) {
      return;
    }
    long richSignature = -1;
    while (p >= SIZEOF_DOS_HEADER) {
      if ((pe.u32(p) ^ key) == RICH_DANS) {
        richSignature = p;
        break;
      }
      p -= 4;
    }
    if (richSignature < 0) {
      return;
    }
    int richLen = (int) (richPtr - richSignature);
    byte[] raw = pe.r.bytes(richSignature, richLen);
    YStructure o = pe.object;
    o.setInteger(baseAddress + richSignature, "rich_signature.offset");
    o.setInteger(richLen, "rich_signature.length");
    o.setInteger(key, "rich_signature.key");
    byte[] clear = raw.clone();
    for (int i = 0; i + 4 <= richLen; i += 4) {
      clear[i] ^= (byte) key;
      clear[i + 1] ^= (byte) (key >>> 8);
      clear[i + 2] ^= (byte) (key >>> 16);
      clear[i + 3] ^= (byte) (key >>> 24);
    }
    o.setString(raw, "rich_signature.raw_data");
    o.setString(clear, "rich_signature.clear_data");
    if (richLen < SIZEOF_RICH_SIGNATURE) {
      return;
    }
    int richCount = (richLen - SIZEOF_RICH_SIGNATURE) / SIZEOF_RICH_VERSION_INFO;
    byte[] versionData = new byte[richCount * 4];
    for (int i = 0; i < richCount; i++) {
      System.arraycopy(
          clear, SIZEOF_RICH_SIGNATURE + i * SIZEOF_RICH_VERSION_INFO, versionData, i * 4, 4);
    }
    o.setString(versionData, "rich_signature.version_data");
  }

  static void parseDebugDirectory(Pe pe) {
    long dataDir = pe.directoryEntry(IMAGE_DIRECTORY_ENTRY_DEBUG);
    if (dataDir < 0) {
      return;
    }
    long dirSize = pe.u32(dataDir + 4);
    long dirVa = pe.u32(dataDir);
    if (dirSize == 0 || dirVa == 0) {
      return;
    }
    long debugDirOffset = pe.rvaToOffset(dirVa);
    if (debugDirOffset < 0) {
      return;
    }
    int dcount = (int) (dirSize / SIZEOF_DEBUG_DIRECTORY);
    for (int i = 0; i < dcount; i++) {
      long debugDir = debugDirOffset + (long) i * SIZEOF_DEBUG_DIRECTORY;
      if (!pe.fits(debugDir, SIZEOF_DEBUG_DIRECTORY)) {
        break;
      }
      if (pe.u32(debugDir + 12) != IMAGE_DEBUG_TYPE_CODEVIEW) {
        continue;
      }
      long pcvHdrOffset = 0;
      long addressOfRawData = pe.u32(debugDir + 20);
      long pointerToRawData = pe.u32(debugDir + 24);
      if (addressOfRawData != 0) {
        pcvHdrOffset = pe.rvaToOffset(addressOfRawData);
      }
      if (pcvHdrOffset <= 0 && pointerToRawData != 0) {
        pcvHdrOffset = pointerToRawData;
      }
      if (pcvHdrOffset <= 0) {
        continue;
      }
      long cvHdr = pcvHdrOffset;
      if (!pe.fits(cvHdr, 8)) {
        continue;
      }
      long pdbPath = -1;
      long sig = pe.u32(cvHdr);
      if (sig == CVINFO_PDB20_CVSIGNATURE) {
        if (pe.fits(cvHdr, 17)) {
          pdbPath = cvHdr + 16;
        }
      } else if (sig == CVINFO_PDB70_CVSIGNATURE) {
        if (pe.fits(cvHdr, 25)) {
          pdbPath = cvHdr + 24;
        }
      } else if (sig == CODEVIEW_SIGNATURE_MTOC) {
        if (pe.fits(cvHdr, 21)) {
          pdbPath = cvHdr + 20;
        }
      }
      if (pdbPath >= 0) {
        int len = pe.strnlen(pdbPath, Math.min(pe.availableSpace(pdbPath), YR_MAX_PATH));
        if (len < YR_MAX_PATH) {
          pe.object.setString(pe.r.bytes(pdbPath, len), "pdb_path");
          break;
        }
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Resources

  /** parse_resource_name: offset of the IMAGE_RESOURCE_DIR_STRING_U or -1. */
  static long parseResourceName(Pe pe, long rsrcData, long entry) {
    long name = pe.u32(entry);
    if ((name & 0x80000000L) != 0) {
      long nameString = rsrcData + (name & 0x7FFFFFFFL);
      if (!pe.fits(nameString, 2)) {
        return -1;
      }
      int length = pe.u16(nameString);
      if (length > 1000) {
        return -1;
      }
      if (!pe.fits(nameString, 2 + length * 2L)) {
        return -1;
      }
      return nameString;
    }
    return -1;
  }

  /** Shared state of the resource iteration (the type/id/language pointers in the C code). */
  private static final class ResourceIds {
    int type = -1;
    int id = -1;
    int language = -1;
  }

  private static boolean iterateResources(
      Pe pe,
      long resourceDir,
      long rsrcData,
      int level,
      ResourceIds ids,
      long typeString,
      long nameString,
      long langString) {
    boolean aborted = false;
    int numberOfNamed = pe.u16(resourceDir + 12);
    int numberOfIds = pe.u16(resourceDir + 14);
    if (pe.u32(resourceDir) != 0 || numberOfNamed > 32768 || numberOfIds > 32768) {
      return false;
    }
    int totalEntries = numberOfNamed + numberOfIds;
    long entry = resourceDir + SIZEOF_RESOURCE_DIRECTORY;
    if (!pe.fits(entry, (long) totalEntries * SIZEOF_RESOURCE_DIRECTORY_ENTRY)) {
      return false;
    }
    for (int i = 0; i < totalEntries; i++) {
      long offsetToData = pe.u32(entry + 4);
      if (offsetToData == 0) {
        // The C code does "continue" without advancing the entry pointer.
        continue;
      }
      switch (level) {
        case 0:
          ids.type = (int) pe.u32(entry);
          typeString = parseResourceName(pe, rsrcData, entry);
          break;
        case 1:
          ids.id = (int) pe.u32(entry);
          nameString = parseResourceName(pe, rsrcData, entry);
          break;
        case 2:
          ids.language = (int) pe.u32(entry);
          langString = parseResourceName(pe, rsrcData, entry);
          break;
        default:
          break;
      }
      long target = rsrcData + (offsetToData & 0x7FFFFFFFL);
      if ((offsetToData & 0x80000000L) != 0 && level < 2) {
        if (target != resourceDir && pe.fits(target, SIZEOF_RESOURCE_DIRECTORY)) {
          aborted =
              iterateResources(
                  pe, target, rsrcData, level + 1, ids, typeString, nameString, langString);
        }
      } else {
        if (pe.fits(target, SIZEOF_RESOURCE_DATA_ENTRY)) {
          long size = pe.u32(target + 4);
          if (size > 0 && size <= 0x3FFFFFFF) {
            if (!collectResource(
                pe, target, ids.type, ids.id, ids.language, typeString, nameString, langString)) {
              aborted = true;
            }
          }
        }
      }
      if (aborted) {
        break;
      }
      entry += SIZEOF_RESOURCE_DIRECTORY_ENTRY;
    }
    return aborted;
  }

  static void iterateResources(Pe pe) {
    long directory = pe.directoryEntry(IMAGE_DIRECTORY_ENTRY_RESOURCE);
    if (directory < 0) {
      return;
    }
    long va = pe.u32(directory);
    if (va != 0) {
      long offset = pe.rvaToOffset(va);
      if (offset < 0) {
        return;
      }
      if (pe.fits(offset, SIZEOF_RESOURCE_DIRECTORY)) {
        pe.object.setInteger(pe.u32(offset + 4), "resource_timestamp");
        pe.object.setInteger(pe.u16(offset + 8), "resource_version.major");
        pe.object.setInteger(pe.u16(offset + 10), "resource_version.minor");
        iterateResources(pe, offset, offset, 0, new ResourceIds(), -1, -1, -1);
      }
    }
  }

  private static void setResourceStringOrId(
      Pe pe, long rsrcString, int rsrcInt, String stringPath, String intPath) {
    if (rsrcString >= 0) {
      long length = pe.u16(rsrcString) * 2L;
      if (pe.fits(rsrcString + 2, length)) {
        pe.object.setString(pe.r.bytes(rsrcString + 2, (int) length), stringPath, pe.resources);
      }
    } else if (rsrcInt != -1) {
      pe.object.setInteger(rsrcInt, intPath, pe.resources);
    }
  }

  /** pe_collect_resources, returns false to abort the iteration. */
  private static boolean collectResource(
      Pe pe,
      long dataEntry,
      int type,
      int id,
      int language,
      long typeString,
      long nameString,
      long langString) {
    if (pe.resources >= MAX_RESOURCES) {
      return false;
    }
    YStructure o = pe.object;
    long rva = pe.u32(dataEntry);
    o.setInteger(rva, "resources[%i].rva", pe.resources);
    long offset = pe.rvaToOffset(rva);
    if (offset < 0) {
      offset = UNDEFINED;
    }
    o.setInteger(offset, "resources[%i].offset", pe.resources);
    o.setInteger(pe.u32(dataEntry + 4), "resources[%i].length", pe.resources);
    setResourceStringOrId(
        pe, typeString, type, "resources[%i].type_string", "resources[%i].type");
    setResourceStringOrId(pe, nameString, id, "resources[%i].name_string", "resources[%i].id");
    setResourceStringOrId(
        pe, langString, language, "resources[%i].language_string", "resources[%i].language");
    if (type == RESOURCE_TYPE_VERSION) {
      parseVersionInfo(pe, dataEntry);
    }
    pe.resources++;
    return true;
  }

  // Wide string helpers from strutils.c

  private static boolean wideStringFits(Pe pe, long data) {
    long spaceLeft = pe.availableSpace(data);
    long i = 0;
    while (spaceLeft >= 2) {
      if (pe.u8(data + i) == 0 && pe.u8(data + i + 1) == 0) {
        return true;
      }
      spaceLeft -= 2;
      i += 2;
    }
    return false;
  }

  /** strcmp_w(w, s) == 0. */
  private static boolean wideEquals(Pe pe, long w, String s) {
    for (int k = 0; k < s.length(); k++) {
      if (pe.u8(w) != s.charAt(k) || pe.u8(w + 1) != 0) {
        return false;
      }
      w += 2;
    }
    return pe.u8(w) == 0 && pe.u8(w + 1) == 0;
  }

  private static int strnlenW(Pe pe, long w) {
    int len = 0;
    while (pe.u8(w) != 0 || pe.u8(w + 1) != 0) {
      w += 2;
      len++;
    }
    return len;
  }

  private static byte[] strlcpyW(Pe pe, long s, int n) {
    byte[] out = new byte[n];
    int d = 0;
    while (n > 1 && pe.u8(s) != 0) {
      out[d++] = (byte) pe.u8(s);
      n--;
      s += 2;
    }
    return java.util.Arrays.copyOf(out, d);
  }

  private static long addOffset(long ptr, long offset) {
    return ptr + ((offset + 3) & ~3L);
  }

  static void parseVersionInfo(Pe pe, long rsrcData) {
    long versionInfo = pe.rvaToOffset(pe.u32(rsrcData));
    if (versionInfo < 0) {
      return;
    }
    if (!pe.fits(versionInfo, SIZEOF_VERSION_INFO)) {
      return;
    }
    if (!pe.fits(versionInfo + 6, 16 * 2)) {
      return;
    }
    if (!wideEquals(pe, versionInfo + 6, "VS_VERSION_INFO")) {
      return;
    }
    versionInfo = addOffset(versionInfo, SIZEOF_VERSION_INFO + 86);
    while (pe.fits(versionInfo + 6, 12 * 2)
        && wideEquals(pe, versionInfo + 6, "VarFileInfo")
        && pe.u16(versionInfo) != 0) {
      versionInfo = addOffset(versionInfo, pe.u16(versionInfo));
    }
    while (pe.fits(versionInfo + 6, 15 * 2)
        && wideEquals(pe, versionInfo + 6, "StringFileInfo")
        && pe.u16(versionInfo) != 0) {
      long stringTable = addOffset(versionInfo, SIZEOF_VERSION_INFO + 30);
      versionInfo = addOffset(versionInfo, pe.u16(versionInfo));
      while (pe.fits(stringTable, SIZEOF_VERSION_INFO)
          && wideStringFits(pe, stringTable + 6)
          && pe.u16(stringTable) != 0
          && stringTable < versionInfo) {
        long string =
            addOffset(stringTable, SIZEOF_VERSION_INFO + 2L * (strnlenW(pe, stringTable + 6) + 1));
        stringTable = addOffset(stringTable, pe.u16(stringTable));
        while (pe.fits(string, SIZEOF_VERSION_INFO)
            && wideStringFits(pe, string + 6)
            && pe.u16(string) != 0
            && string < stringTable) {
          long stringValue =
              addOffset(string, SIZEOF_VERSION_INFO + 2L * (strnlenW(pe, string + 6) + 1));
          if (wideStringFits(pe, stringValue)) {
            byte[] key = strlcpyW(pe, string + 6, 64);
            byte[] value = strlcpyW(pe, stringValue, 256);
            if (pe.u16(string + 2) == 0) {
              value = new byte[0];
            }
            pe.object.setString(value, "version_info[%s]", key);
            pe.object.setString(key, "version_info_list[%i].key", pe.versionInfos);
            pe.object.setString(value, "version_info_list[%i].value", pe.versionInfos);
            pe.versionInfos++;
          }
          string = addOffset(string, pe.u16(string));
        }
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Imports

  private static boolean validFunctionName(byte[] name) {
    if (name.length == 0) {
      return false;
    }
    for (byte b : name) {
      char c = (char) (b & 0xFF);
      if (!(c >= 'a' && c <= 'z')
          && !(c >= 'A' && c <= 'Z')
          && !(c >= '0' && c <= '9')
          && c != '.'
          && c != '_'
          && c != '?'
          && c != '@'
          && c != '$'
          && c != '('
          && c != ')'
          && c != '<'
          && c != '>') {
        return false;
      }
    }
    return true;
  }

  private static byte[] ordLookup(byte[] dllName, int ordinal) {
    return Ordinals.lookup(BinaryReader.latin1(dllName), ordinal)
        .getBytes(StandardCharsets.ISO_8859_1);
  }

  /** The counter shared by all the descriptors (num_function_imports). */
  private static final class Counter {
    int value;
  }

  private static List<ImportFunction> parseImportDescriptor(
      Pe pe, long descriptor, byte[] dllName, Counter numFunctionImports) {
    List<ImportFunction> result = new ArrayList<>();
    int parsedImports = 0;
    long firstThunk = pe.u32(descriptor + 16);
    long offset = pe.rvaToOffset(pe.u32(descriptor));
    if (offset <= 0) {
      offset = pe.rvaToOffset(firstThunk);
    }
    if (offset < 0) {
      return result;
    }
    int thunkSize = pe.is64 ? 8 : 4;
    long thunk = offset;
    long funcIdx = 0;
    while (pe.fits(thunk, thunkSize)
        && parsedImports < MAX_PE_IMPORTS
        && numFunctionImports.value < MAX_PE_IMPORTS) {
      long value = pe.is64 ? pe.r.u64(thunk) : pe.u32(thunk);
      if (value == 0) {
        break;
      }
      byte[] name = null;
      int ordinal = 0;
      boolean hasOrdinal = false;
      parsedImports++;
      boolean byOrdinal = pe.is64 ? value < 0 : (value & 0x80000000L) != 0;
      if (!byOrdinal) {
        long nameOffset = pe.rvaToOffset(value);
        if (nameOffset >= 0 && pe.fits(nameOffset, SIZEOF_IMPORT_BY_NAME)) {
          name =
              pe.strndup(nameOffset + 2, Math.min(pe.availableSpace(nameOffset + 2), 512));
        }
      } else {
        boolean inRange =
            pe.is64
                ? Long.compareUnsigned(value, 0x800000000000ffffL) <= 0
                : value <= 0x8000ffffL;
        if (inRange) {
          ordinal = (int) (value & 0xFFFF);
          name = ordLookup(dllName, ordinal);
          hasOrdinal = true;
        }
      }
      long rvaAddress = firstThunk + thunkSize * funcIdx;
      if (!pe.is64) {
        rvaAddress &= 0xffffffffL;
      }
      if (name != null && !validFunctionName(name)) {
        thunk += thunkSize;
        funcIdx++;
        continue;
      }
      if (name != null || hasOrdinal) {
        ImportFunction f = new ImportFunction();
        f.name = name;
        f.ordinal = ordinal;
        f.hasOrdinal = hasOrdinal;
        f.rva = rvaAddress;
        result.add(f);
        numFunctionImports.value++;
      }
      thunk += thunkSize;
      funcIdx++;
    }
    return result;
  }

  private static boolean validDllName(Pe pe, long offset, long n) {
    long l = 0;
    while (l < n && pe.u8(offset + l) != 0) {
      int c = pe.u8(offset + l);
      if (c < ' ' || c > 0x7e || c == '"' || c == '*' || c == '<' || c == '>' || c == '?'
          || c == '|') {
        return false;
      }
      l++;
    }
    return l > 0 && l < n;
  }

  private static void setImports(
      Pe pe,
      List<ImportedDll> dlls,
      String dllName,
      String dllNumberOfFunctions,
      String funName,
      String funOrdinal,
      String rva) {
    YStructure o = pe.object;
    for (int dllCnt = 0; dllCnt < dlls.size(); dllCnt++) {
      ImportedDll dll = dlls.get(dllCnt);
      int funCnt = 0;
      for (ImportFunction func : dll.functions) {
        o.setString(func.name, funName, dllCnt, funCnt);
        o.setInteger(func.hasOrdinal ? func.ordinal : UNDEFINED, funOrdinal, dllCnt, funCnt);
        o.setInteger(func.rva != 0 ? func.rva : UNDEFINED, rva, dllCnt, funCnt);
        funCnt++;
      }
      o.setString(dll.name, dllName, dllCnt);
      o.setInteger(funCnt, dllNumberOfFunctions, dllCnt);
    }
  }

  static List<ImportedDll> parseImports(Pe pe) {
    List<ImportedDll> result = new ArrayList<>();
    int parsedImports = 0;
    int numImports = 0;
    Counter numFunctionImports = new Counter();
    pe.object.setInteger(0, "number_of_imports");
    pe.object.setInteger(0, "number_of_imported_functions");
    long directory = pe.directoryEntry(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (directory < 0) {
      return result;
    }
    long va = pe.u32(directory);
    if (va == 0) {
      return result;
    }
    long imports = pe.rvaToOffset(va);
    if (imports < 0) {
      return result;
    }
    while (pe.fits(imports, SIZEOF_IMPORT_DESCRIPTOR)
        && pe.u32(imports + 12) != 0
        && parsedImports < MAX_PE_IMPORTS) {
      parsedImports++;
      long offset = pe.rvaToOffset(pe.u32(imports + 12));
      if (offset >= 0) {
        if (!validDllName(pe, offset, Math.min(pe.size - offset, MAX_IMPORT_DLL_NAME_LENGTH))) {
          imports += SIZEOF_IMPORT_DESCRIPTOR;
          continue;
        }
        byte[] dllName = pe.r.cstring(offset);
        List<ImportFunction> functions =
            parseImportDescriptor(pe, imports, dllName, numFunctionImports);
        if (!functions.isEmpty()) {
          ImportedDll dll = new ImportedDll();
          dll.name = dllName;
          dll.functions = functions;
          result.add(dll);
          numImports++;
        }
      }
      imports += SIZEOF_IMPORT_DESCRIPTOR;
    }
    pe.object.setInteger(numImports, "number_of_imports");
    pe.object.setInteger(numFunctionImports.value, "number_of_imported_functions");
    setImports(
        pe,
        result,
        "import_details[%i].library_name",
        "import_details[%i].number_of_functions",
        "import_details[%i].functions[%i].name",
        "import_details[%i].functions[%i].ordinal",
        "import_details[%i].functions[%i].rva");
    return result;
  }

  private static long normalizeDelayImportValue(long imageBase, long virtualAddress) {
    if (virtualAddress != 0) {
      if (Long.compareUnsigned(virtualAddress, imageBase) > 0) {
        virtualAddress = virtualAddress - imageBase;
      }
    }
    return virtualAddress;
  }

  private static long parseDelayImportPointer(Pe pe, int pointerSize, long rva) {
    long offset = pe.rvaToOffset(rva);
    if (offset < 0) {
      return UNDEFINED;
    }
    if (!pe.fits(offset, pointerSize)) {
      return UNDEFINED;
    }
    return pe.is64 ? pe.r.u64(offset) : pe.u32(offset);
  }

  static List<ImportedDll> parseDelayedImports(Pe pe) {
    List<ImportedDll> result = new ArrayList<>();
    long numImports = 0;
    long numFunctionImports = 0;
    long imageBase = pe.imageBase();
    long sizeOfImage = pe.sizeOfImage();
    int pointerSize = pe.is64 ? 8 : 4;
    long ordinalMask = pe.is64 ? 0x8000000000000000L : 0x80000000L;
    pe.object.setInteger(0, "number_of_delayed_imports");
    pe.object.setInteger(0, "number_of_delayed_imported_functions");
    long directory = pe.directoryEntry(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    if (directory < 0) {
      return result;
    }
    long va = pe.u32(directory);
    if (va == 0) {
      return result;
    }
    long descriptor = pe.rvaToOffset(va);
    if (descriptor < 0) {
      return result;
    }
    for (;
        pe.fits(descriptor, SIZEOF_DELAYLOAD_DESCRIPTOR) && numImports < MAX_PE_IMPORTS;
        descriptor += SIZEOF_DELAYLOAD_DESCRIPTOR) {
      long attributes = pe.u32(descriptor);
      long dllNameRva = pe.u32(descriptor + 4);
      long moduleHandleRva = pe.u32(descriptor + 8);
      long importAddressTableRva = pe.u32(descriptor + 12);
      long importNameTableRva = pe.u32(descriptor + 16);
      long boundImportAddressTableRva = pe.u32(descriptor + 20);
      long unloadInformationTableRva = pe.u32(descriptor + 24);
      long timeDateStamp = pe.u32(descriptor + 28);
      if (attributes == 0
          && dllNameRva == 0
          && moduleHandleRva == 0
          && importAddressTableRva == 0
          && importNameTableRva == 0
          && boundImportAddressTableRva == 0
          && unloadInformationTableRva == 0
          && timeDateStamp == 0) {
        break;
      }
      if (attributes > 1) {
        break;
      }
      if (!pe.is64 && attributes == 0) {
        dllNameRva = normalizeDelayImportValue(imageBase, dllNameRva) & 0xffffffffL;
        importAddressTableRva =
            normalizeDelayImportValue(imageBase, importAddressTableRva) & 0xffffffffL;
        importNameTableRva = normalizeDelayImportValue(imageBase, importNameTableRva) & 0xffffffffL;
      }
      if (importNameTableRva >= sizeOfImage
          || importAddressTableRva >= sizeOfImage
          || dllNameRva < SIZEOF_DOS_HEADER
          || importNameTableRva < SIZEOF_DOS_HEADER) {
        break;
      }
      long dllNameOffset = pe.rvaToOffset(dllNameRva);
      if (dllNameOffset < 0 || !validDllName(pe, dllNameOffset, pe.size - dllNameOffset)) {
        continue;
      }
      ImportedDll dll = new ImportedDll();
      dll.name = pe.r.cstring(dllNameOffset);
      dll.functions = new ArrayList<>();
      long nameRva = importNameTableRva;
      long funcRva = importAddressTableRva;
      while (numFunctionImports < MAX_PE_IMPORTS) {
        long nameAddress = parseDelayImportPointer(pe, pointerSize, nameRva);
        long funcAddress = parseDelayImportPointer(pe, pointerSize, funcRva);
        if (nameAddress == UNDEFINED || funcAddress == UNDEFINED) {
          break;
        }
        if (nameAddress == 0 || funcAddress == 0) {
          break;
        }
        byte[] funcName;
        boolean hasOrdinal = false;
        if ((nameAddress & ordinalMask) == 0) {
          if (attributes == 0) {
            nameAddress = normalizeDelayImportValue(imageBase, nameAddress);
          }
          long offset = pe.rvaToOffset(nameAddress + 2);
          if (offset < 0) {
            nameRva += pointerSize;
            funcRva += pointerSize;
            continue;
          }
          funcName = pe.strndup(offset, Math.min(pe.availableSpace(offset), 512));
        } else {
          funcName = ordLookup(dll.name, (int) (nameAddress & 0xFFFF));
          hasOrdinal = true;
        }
        ImportFunction f = new ImportFunction();
        f.name = funcName;
        f.rva = funcRva;
        f.hasOrdinal = hasOrdinal;
        f.ordinal = hasOrdinal ? (int) (nameAddress & 0xFFFF) : 0;
        numFunctionImports++;
        nameRva += pointerSize;
        funcRva += pointerSize;
        dll.functions.add(f);
      }
      numImports++;
      result.add(dll);
    }
    pe.object.setInteger(numImports, "number_of_delayed_imports");
    pe.object.setInteger(numFunctionImports, "number_of_delayed_imported_functions");
    setImports(
        pe,
        result,
        "delayed_import_details[%i].library_name",
        "delayed_import_details[%i].number_of_functions",
        "delayed_import_details[%i].functions[%i].name",
        "delayed_import_details[%i].functions[%i].ordinal",
        "delayed_import_details[%i].functions[%i].rva");
    return result;
  }

  // ---------------------------------------------------------------------------------------------
  // Exports

  static void parseExports(Pe pe) {
    YStructure o = pe.object;
    o.setInteger(0, "number_of_exports");
    long directory = pe.directoryEntry(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (directory < 0) {
      return;
    }
    long va = pe.u32(directory);
    if (va == 0) {
      return;
    }
    long offset = pe.rvaToOffset(va);
    if (offset < 0) {
      return;
    }
    long exportStart = offset;
    long exportSize = pe.u32(directory + 4);
    long exports = offset;
    if (!pe.fits(exports, SIZEOF_EXPORT_DIRECTORY)) {
      return;
    }
    int numberOfExports = (int) Math.min(pe.u32(exports + 20), MAX_PE_EXPORTS);
    long ordinalBase = pe.u32(exports + 16);
    long numberOfNamesRaw = pe.u32(exports + 24);
    o.setInteger(pe.u32(exports + 4), "export_timestamp");
    offset = pe.rvaToOffset(pe.u32(exports + 12));
    if (offset > 0) {
      int nameLen = pe.strnlen(offset, pe.size - offset);
      o.setString(pe.r.bytes(offset, nameLen), "dll_name");
    }
    if (numberOfExports * 4L > pe.size - offset) {
      return;
    }
    long names = -1;
    if (numberOfNamesRaw > 0) {
      offset = pe.rvaToOffset(pe.u32(exports + 32));
      if (offset < 0) {
        return;
      }
      if (numberOfNamesRaw > (pe.size - offset) / 4) {
        return;
      }
      names = offset;
    }
    offset = pe.rvaToOffset(pe.u32(exports + 36));
    if (offset < 0) {
      return;
    }
    long ordinals = offset;
    if (pe.availableSpace(ordinals) < 2L * numberOfExports) {
      return;
    }
    offset = pe.rvaToOffset(pe.u32(exports + 28));
    if (offset < 0) {
      return;
    }
    long functionAddrs = offset;
    if (pe.availableSpace(functionAddrs) < 4L * numberOfExports) {
      return;
    }
    int numberOfNames = (int) Math.min(numberOfNamesRaw, numberOfExports);
    // For each ordinal value the first index j < number_of_names with ordinals[j] == value. This
    // is equivalent to the nested loop in the C code.
    int[] nameIndex = null;
    if (names >= 0) {
      nameIndex = new int[65536];
      java.util.Arrays.fill(nameIndex, -1);
      for (int j = numberOfNames - 1; j >= 0; j--) {
        nameIndex[pe.u16(ordinals + 2L * j)] = j;
      }
    }
    int expSz = 0;
    for (int i = 0; i < numberOfExports; i++) {
      o.setInteger((ordinalBase + i) & 0xffffffffL, "export_details[%i].ordinal", expSz);
      long functionRva = pe.u32(functionAddrs + 4L * i);
      o.setInteger(functionRva, "export_details[%i].rva", expSz);
      offset = pe.rvaToOffset(functionRva);
      if (offset > exportStart && offset < exportStart + exportSize) {
        int nameLen = pe.strnlen(offset, pe.size - offset);
        o.setString(
            pe.r.bytes(offset, Math.min(nameLen, MAX_EXPORT_NAME_LENGTH)),
            "export_details[%i].forward_name",
            expSz);
      } else {
        if (offset < 0) {
          offset = UNDEFINED;
        }
        o.setInteger(offset, "export_details[%i].offset", expSz);
      }
      if (nameIndex != null && i < 65536 && nameIndex[i] >= 0) {
        int j = nameIndex[i];
        offset = pe.rvaToOffset(pe.u32(names + 4L * j));
        if (offset > 0) {
          int nameLen = pe.strnlen(offset, pe.size - offset);
          o.setString(
              pe.r.bytes(offset, Math.min(nameLen, MAX_EXPORT_NAME_LENGTH)),
              "export_details[%i].name",
              expSz);
        }
      }
      expSz++;
    }
    o.setInteger(expSz, "number_of_exports");
  }

  // ---------------------------------------------------------------------------------------------

  /** pe_get_section_full_name, returns null if the name can't be resolved. */
  private static byte[] sectionFullName(Pe pe, byte[] sectionName, int sectionNameLength) {
    long coffOffset = pe.u32(pe.header + 4 + 8);
    long coffNumber = pe.u32(pe.header + 4 + 12);
    if (coffOffset == 0 || sectionName[0] != '/') {
      return java.util.Arrays.copyOf(sectionName, sectionNameLength);
    }
    long stringOffset = coffOffset + coffNumber * SIZEOF_SYMBOL;
    long stringIndex = 0;
    for (int i = 1; i < 8 && sectionName[i] >= '0' && sectionName[i] <= '9'; i++) {
      stringIndex = stringIndex * 10 + (sectionName[i] - '0');
    }
    long string = stringOffset + stringIndex;
    for (long len = 0; pe.fits(string, len + 1); len++) {
      int c = pe.u8(string + len);
      if (c == 0) {
        return pe.r.bytes(string, (int) len);
      }
      if (!CStrings.isPrint(c)) {
        return null;
      }
    }
    return null;
  }

  static void parseHeader(Pe pe, long baseAddress) {
    YStructure o = pe.object;
    long fh = pe.header + 4;
    long oh = pe.optionalHeader;
    o.setInteger(1, "is_pe");
    o.setInteger(pe.u16(fh), "machine");
    o.setInteger(pe.u16(fh + 2), "number_of_sections");
    o.setInteger(pe.u32(fh + 4), "timestamp");
    o.setInteger(pe.u32(fh + 8), "pointer_to_symbol_table");
    o.setInteger(pe.u32(fh + 12), "number_of_symbols");
    o.setInteger(pe.u16(fh + 16), "size_of_optional_header");
    o.setInteger(pe.u16(fh + 18), "characteristics");
    o.setInteger(pe.rvaToOffset(pe.addressOfEntryPoint()), "entry_point");
    o.setInteger(pe.addressOfEntryPoint(), "entry_point_raw");
    o.setInteger(pe.imageBase(), "image_base");
    o.setInteger(pe.numberOfRvaAndSizes(), "number_of_rva_and_sizes");
    o.setInteger(pe.u16(oh), "opthdr_magic");
    o.setInteger(pe.u8(oh + 2), "linker_version.major");
    o.setInteger(pe.u8(oh + 3), "linker_version.minor");
    o.setInteger(pe.u32(oh + 4), "size_of_code");
    o.setInteger(pe.u32(oh + 8), "size_of_initialized_data");
    o.setInteger(pe.u32(oh + 12), "size_of_uninitialized_data");
    o.setInteger(pe.u32(oh + 20), "base_of_code");
    if (!pe.is64) {
      o.setInteger(pe.u32(oh + 24), "base_of_data");
    }
    o.setInteger(pe.sectionAlignment(), "section_alignment");
    o.setInteger(pe.fileAlignment(), "file_alignment");
    o.setInteger(pe.u16(oh + 40), "os_version.major");
    o.setInteger(pe.u16(oh + 42), "os_version.minor");
    o.setInteger(pe.u16(oh + 44), "image_version.major");
    o.setInteger(pe.u16(oh + 46), "image_version.minor");
    o.setInteger(pe.u16(oh + 48), "subsystem_version.major");
    o.setInteger(pe.u16(oh + 50), "subsystem_version.minor");
    o.setInteger(pe.u32(oh + 52), "win32_version_value");
    o.setInteger(pe.sizeOfImage(), "size_of_image");
    o.setInteger(pe.u32(oh + 60), "size_of_headers");
    o.setInteger(pe.u32(oh + 64), "checksum");
    o.setInteger(pe.u16(oh + 68), "subsystem");
    o.setInteger(pe.u16(oh + 70), "dll_characteristics");
    o.setInteger(pe.ohSized(72, 72), "size_of_stack_reserve");
    o.setInteger(pe.ohSized(76, 80), "size_of_stack_commit");
    o.setInteger(pe.ohSized(80, 88), "size_of_heap_reserve");
    o.setInteger(pe.ohSized(84, 96), "size_of_heap_commit");
    o.setInteger(pe.u32(oh + (pe.is64 ? 104 : 88)), "loader_flags");

    long dataDir = pe.dataDirectories();
    long ddcount = Math.min(pe.numberOfRvaAndSizes(), IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    for (int i = 0; i < ddcount; i++) {
      if (!pe.fits(dataDir, SIZEOF_DATA_DIRECTORY)) {
        break;
      }
      o.setInteger(pe.u32(dataDir), "data_directories[%i].virtual_address", i);
      o.setInteger(pe.u32(dataDir + 4), "data_directories[%i].size", i);
      dataDir += SIZEOF_DATA_DIRECTORY;
    }

    iterateResources(pe);
    o.setInteger(pe.resources, "number_of_resources");
    o.setInteger(pe.versionInfos, "number_of_version_infos");

    long section = pe.firstSection;
    int scount = Math.min(pe.numberOfSections, MAX_PE_SECTIONS);
    long highestSecSiz = 0;
    long highestSecOfs = 0;
    for (int i = 0; i < scount; i++) {
      if (!pe.fits(section, SIZEOF_SECTION_HEADER)) {
        break;
      }
      byte[] sectionName = pe.r.bytes(section, 8);
      int sectNameLength;
      for (sectNameLength = 7; sectNameLength >= 0; --sectNameLength) {
        if (sectionName[sectNameLength] != 0) {
          break;
        }
      }
      byte[] fullName = sectionFullName(pe, sectionName, sectNameLength + 1);
      o.setString(java.util.Arrays.copyOf(sectionName, sectNameLength + 1), "sections[%i].name", i);
      o.setString(fullName, "sections[%i].full_name", i);
      o.setInteger(pe.u32(section + 36), "sections[%i].characteristics", i);
      o.setInteger(pe.u32(section + 16), "sections[%i].raw_data_size", i);
      o.setInteger(pe.u32(section + 20), "sections[%i].raw_data_offset", i);
      o.setInteger(pe.u32(section + 12), "sections[%i].virtual_address", i);
      o.setInteger(pe.u32(section + 8), "sections[%i].virtual_size", i);
      o.setInteger(pe.u32(section + 24), "sections[%i].pointer_to_relocations", i);
      o.setInteger(pe.u32(section + 28), "sections[%i].pointer_to_line_numbers", i);
      o.setInteger(pe.u16(section + 32), "sections[%i].number_of_relocations", i);
      o.setInteger(pe.u16(section + 34), "sections[%i].number_of_line_numbers", i);
      long sectionEnd = pe.u32(section + 20) + pe.u32(section + 16);
      if (sectionEnd > highestSecOfs + highestSecSiz) {
        highestSecOfs = pe.u32(section + 20);
        highestSecSiz = pe.u32(section + 16);
      }
      section += SIZEOF_SECTION_HEADER;
    }
    long lastSectionEnd = highestSecSiz + highestSecOfs;
    if (lastSectionEnd != 0 && pe.size > lastSectionEnd) {
      o.setInteger(lastSectionEnd, "overlay.offset");
      o.setInteger(pe.size - lastSectionEnd, "overlay.size");
    } else {
      o.setInteger(0, "overlay.offset");
      o.setInteger(0, "overlay.size");
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Functions

  private static Pe pe(FunctionCall c) {
    return (Pe) c.module().getData();
  }

  private static int lower(int c) {
    return c >= 'A' && c <= 'Z' ? c + 32 : c;
  }

  /** ss_icompare(a, b) == 0. */
  static boolean ssIequals(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    for (int i = 0; i < a.length; i++) {
      if (lower(a[i] & 0xFF) != lower(b[i] & 0xFF)) {
        return false;
      }
    }
    return true;
  }

  /** strcasecmp(a, b) == 0 for C strings. */
  static boolean strcaseeq(byte[] a, byte[] b) {
    return ssIequals(CStrings.cstr(a), CStrings.cstr(b));
  }

  private static Object validOn(FunctionCall c) {
    YObject parent = c.parent();
    if (parent.isUndefined("not_before") || parent.isUndefined("not_after")) {
      return null;
    }
    long timestamp = c.integerArgument(1);
    long notBefore = parent.getInteger("not_before");
    long notAfter = parent.getInteger("not_after");
    return timestamp >= notBefore && timestamp <= notAfter ? 1L : 0L;
  }

  private static Object sectionIndexAddr(FunctionCall c) {
    YObject module = c.module();
    long addr = c.integerArgument(1);
    long n = module.getInteger("number_of_sections");
    if (module.isUndefined("number_of_sections")) {
      return null;
    }
    boolean memory = c.context().isProcessMemory();
    for (int i = 0; i < Math.min(n, MAX_PE_SECTIONS); i++) {
      long offset;
      long size;
      if (memory) {
        offset = module.getInteger("sections[%i].virtual_address", i);
        size = module.getInteger("sections[%i].virtual_size", i);
      } else {
        offset = module.getInteger("sections[%i].raw_data_offset", i);
        size = module.getInteger("sections[%i].raw_data_size", i);
      }
      if (addr >= offset && addr < offset + size) {
        return (long) i;
      }
    }
    return null;
  }

  private static Object sectionIndexName(FunctionCall c) {
    YObject module = c.module();
    byte[] name = CStrings.cstr(c.stringArgument(1));
    long n = module.getInteger("number_of_sections");
    if (module.isUndefined("number_of_sections")) {
      return null;
    }
    for (int i = 0; i < Math.min(n, MAX_PE_SECTIONS); i++) {
      byte[] sect = module.getString("sections[%i].name", i);
      if (sect != null && java.util.Arrays.equals(name, CStrings.cstr(sect))) {
        return (long) i;
      }
    }
    return null;
  }

  private static Object exportsName(FunctionCall c) {
    byte[] searchName = c.stringArgument(1);
    YObject module = c.module();
    if (pe(c) == null) {
      return null;
    }
    int n = (int) module.getInteger("number_of_exports");
    for (int i = 0; i < n; i++) {
      byte[] functionName = module.getString("export_details[%i].name", i);
      if (functionName != null && ssIequals(functionName, searchName)) {
        return 1L;
      }
    }
    return 0L;
  }

  private static Object exportsRegexp(FunctionCall c) {
    Regexp regex = c.regexpArgument(1);
    YObject module = c.module();
    if (pe(c) == null) {
      return null;
    }
    int n = (int) module.getInteger("number_of_exports");
    for (int i = 0; i < n; i++) {
      byte[] functionName = module.getString("export_details[%i].name", i);
      if (functionName != null && regex.match(c.context(), CStrings.cstr(functionName)) != -1) {
        return 1L;
      }
    }
    return 0L;
  }

  private static Object exportsOrdinal(FunctionCall c) {
    long ordinal = c.integerArgument(1);
    YObject module = c.module();
    if (pe(c) == null) {
      return null;
    }
    int n = (int) module.getInteger("number_of_exports");
    if (n == 0) {
      return 0L;
    }
    if (ordinal == 0 || ordinal > n) {
      return 0L;
    }
    for (int i = 0; i < n; i++) {
      if (module.getInteger("export_details[%i].ordinal", i) == ordinal) {
        return 1L;
      }
    }
    return 0L;
  }

  private static Object exportsIndexName(FunctionCall c) {
    byte[] searchName = c.stringArgument(1);
    YObject module = c.module();
    if (pe(c) == null) {
      return null;
    }
    int n = (int) module.getInteger("number_of_exports");
    for (int i = 0; i < n; i++) {
      byte[] functionName = module.getString("export_details[%i].name", i);
      if (functionName != null && ssIequals(functionName, searchName)) {
        return (long) i;
      }
    }
    return null;
  }

  private static Object exportsIndexOrdinal(FunctionCall c) {
    long ordinal = c.integerArgument(1);
    YObject module = c.module();
    if (pe(c) == null) {
      return null;
    }
    int n = (int) module.getInteger("number_of_exports");
    if (n == 0 || ordinal == 0 || ordinal > n) {
      return null;
    }
    for (int i = 0; i < n; i++) {
      if (module.getInteger("export_details[%i].ordinal", i) == ordinal) {
        return (long) i;
      }
    }
    return null;
  }

  private static Object exportsIndexRegex(FunctionCall c) {
    Regexp regex = c.regexpArgument(1);
    YObject module = c.module();
    if (pe(c) == null) {
      return null;
    }
    int n = (int) module.getInteger("number_of_exports");
    for (int i = 0; i < n; i++) {
      byte[] functionName = module.getString("export_details[%i].name", i);
      if (functionName != null && regex.match(c.context(), CStrings.cstr(functionName)) != -1) {
        return (long) i;
      }
    }
    return null;
  }

  private static Object imphash(FunctionCall c) {
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    if (pe.imphash != null) {
      return pe.imphash;
    }
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
    boolean first = true;
    for (ImportedDll dll : pe.importedDlls) {
      byte[] name = dll.name;
      int dllNameLen = name.length;
      int ext = -1;
      for (int i = name.length - 1; i >= 0; i--) {
        if (name[i] == '.') {
          ext = i;
          break;
        }
      }
      if (ext >= 0) {
        byte[] e = java.util.Arrays.copyOfRange(name, ext, Math.min(name.length, ext + 4));
        byte[] el = CStrings.cstr(e);
        if (startsWithIgnoreCase(el, ".ocx")
            || startsWithIgnoreCase(el, ".sys")
            || startsWithIgnoreCase(el, ".dll")) {
          dllNameLen = ext;
        }
      }
      for (ImportFunction func : dll.functions) {
        StringBuilder sb = new StringBuilder();
        if (!first) {
          sb.append(',');
        }
        sb.append(BinaryReader.latin1(name), 0, dllNameLen);
        sb.append('.');
        sb.append(BinaryReader.latin1(func.name));
        byte[] b = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        for (int i = 0; i < b.length; i++) {
          b[i] = (byte) lower(b[i] & 0xFF);
        }
        md.update(b);
        first = false;
      }
    }
    pe.imphash = HashModule.hex(md.digest());
    return pe.imphash;
  }

  private static boolean startsWithIgnoreCase(byte[] s, String prefix) {
    if (s.length != prefix.length()) {
      return false;
    }
    for (int i = 0; i < s.length; i++) {
      if (lower(s[i] & 0xFF) != prefix.charAt(i)) {
        return false;
      }
    }
    return true;
  }

  private static long importsDll(List<ImportedDll> dlls, byte[] dllName) {
    long result = 0;
    for (ImportedDll dll : dlls) {
      if (strcaseeq(dll.name, dllName)) {
        result += dll.functions.size();
      }
    }
    return result;
  }

  private static boolean imports(List<ImportedDll> dlls, byte[] dllName, byte[] funName) {
    for (ImportedDll dll : dlls) {
      if (strcaseeq(dll.name, dllName)) {
        for (ImportFunction fun : dll.functions) {
          if (strcaseeq(fun.name, funName)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private static long importsRegexp(
      ScanContext context, List<ImportedDll> dlls, Regexp dllName, Regexp funName) {
    long result = 0;
    for (ImportedDll dll : dlls) {
      if (dllName.match(context, dll.name) > 0) {
        for (ImportFunction fun : dll.functions) {
          if (funName.match(context, CStrings.cstr(fun.name)) > 0) {
            result++;
          }
        }
      }
    }
    return result;
  }

  private static boolean importsOrdinal(List<ImportedDll> dlls, byte[] dllName, long ordinal) {
    for (ImportedDll dll : dlls) {
      if (strcaseeq(dll.name, dllName)) {
        for (ImportFunction fun : dll.functions) {
          if (fun.hasOrdinal && fun.ordinal == ordinal) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private static Object importsStandard(FunctionCall c) {
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    return imports(pe.importedDlls, c.stringArgument(1), c.stringArgument(2)) ? 1L : 0L;
  }

  private static Object importsFlags(FunctionCall c) {
    long flags = c.integerArgument(1);
    byte[] dllName = c.stringArgument(2);
    byte[] functionName = c.stringArgument(3);
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    if ((flags & IMPORT_STANDARD) != 0 && imports(pe.importedDlls, dllName, functionName)) {
      return 1L;
    }
    if ((flags & IMPORT_DELAYED) != 0 && imports(pe.delayImportedDlls, dllName, functionName)) {
      return 1L;
    }
    return 0L;
  }

  private static Object importsStandardOrdinal(FunctionCall c) {
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    return importsOrdinal(pe.importedDlls, c.stringArgument(1), c.integerArgument(2)) ? 1L : 0L;
  }

  private static Object importsOrdinalFlags(FunctionCall c) {
    long flags = c.integerArgument(1);
    byte[] dllName = c.stringArgument(2);
    long ordinal = c.integerArgument(3);
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    if ((flags & IMPORT_STANDARD) != 0 && importsOrdinal(pe.importedDlls, dllName, ordinal)) {
      return 1L;
    }
    if ((flags & IMPORT_DELAYED) != 0 && importsOrdinal(pe.delayImportedDlls, dllName, ordinal)) {
      return 1L;
    }
    return 0L;
  }

  private static Object importsStandardRegex(FunctionCall c) {
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    return importsRegexp(
        c.context(), pe.importedDlls, c.regexpArgument(1), c.regexpArgument(2));
  }

  private static Object importsRegexFlags(FunctionCall c) {
    long flags = c.integerArgument(1);
    Regexp dllName = c.regexpArgument(2);
    Regexp functionName = c.regexpArgument(3);
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    long result = 0;
    if ((flags & IMPORT_STANDARD) != 0) {
      result += importsRegexp(c.context(), pe.importedDlls, dllName, functionName);
    }
    if ((flags & IMPORT_DELAYED) != 0) {
      result += importsRegexp(c.context(), pe.delayImportedDlls, dllName, functionName);
    }
    return result;
  }

  private static Object importsStandardDll(FunctionCall c) {
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    return importsDll(pe.importedDlls, c.stringArgument(1));
  }

  private static Object importsDllFlags(FunctionCall c) {
    long flags = c.integerArgument(1);
    byte[] dllName = c.stringArgument(2);
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    long result = 0;
    if ((flags & IMPORT_STANDARD) != 0) {
      result += importsDll(pe.importedDlls, dllName);
    }
    if ((flags & IMPORT_DELAYED) != 0) {
      result += importsDll(pe.delayImportedDlls, dllName);
    }
    return result;
  }

  private static Object importRva(FunctionCall c, String prefix, boolean byOrdinal) {
    byte[] inDllName = c.stringArgument(1);
    YObject module = c.module();
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    long numImports = module.getInteger("number_of_" + prefix + "s");
    if (numImports == UNDEFINED) {
      return null;
    }
    String details = prefix + "_details[%i]";
    for (int i = 0; i < numImports; i++) {
      byte[] dllName = module.getString(details + ".library_name", i);
      if (dllName == null || !ssIequals(inDllName, dllName)) {
        continue;
      }
      long numFunctions = module.getInteger(details + ".number_of_functions", i);
      if (numFunctions == UNDEFINED) {
        return null;
      }
      for (int j = 0; j < numFunctions; j++) {
        if (byOrdinal) {
          long ordinal = module.getInteger(details + ".functions[%i].ordinal", i, j);
          if (ordinal == UNDEFINED) {
            continue;
          }
          if (ordinal == c.integerArgument(2)) {
            return module.getInteger(details + ".functions[%i].rva", i, j);
          }
        } else {
          byte[] functionName = module.getString(details + ".functions[%i].name", i, j);
          if (functionName == null) {
            continue;
          }
          if (ssIequals(c.stringArgument(2), functionName)) {
            return module.getInteger(details + ".functions[%i].rva", i, j);
          }
        }
      }
    }
    return null;
  }

  private static Object locale(FunctionCall c, long mask) {
    YObject module = c.module();
    long locale = c.integerArgument(1);
    if (module.isUndefined("number_of_resources")) {
      return null;
    }
    if (pe(c) == null) {
      return null;
    }
    int n = (int) module.getInteger("number_of_resources");
    for (int i = 0; i < n; i++) {
      long rsrcLanguage = module.getInteger("resources[%i].language", i);
      if ((rsrcLanguage & mask) == locale) {
        return 1L;
      }
    }
    return 0L;
  }

  private static Object isDll(FunctionCall c) {
    YObject module = c.module();
    if (module.isUndefined("characteristics")) {
      return null;
    }
    return module.getInteger("characteristics") & IMAGE_FILE_DLL;
  }

  private static Object is32bit(FunctionCall c) {
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    return pe.is64 ? 0L : 1L;
  }

  private static Object is64bit(FunctionCall c) {
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    return pe.is64 ? 1L : 0L;
  }

  private static long richVersion(YObject module, long version, long toolid) {
    if (module.isUndefined("rich_signature.length")) {
      return UNDEFINED;
    }
    long richLength = module.getInteger("rich_signature.length");
    byte[] richString = module.getString("rich_signature.clear_data");
    if (richString == null) {
      return UNDEFINED;
    }
    if (Long.compareUnsigned(richLength, SIZEOF_RICH_SIGNATURE) < 0) {
      return UNDEFINED;
    }
    if (version == UNDEFINED && toolid == UNDEFINED) {
      return 0;
    }
    BinaryReader r = new BinaryReader(richString);
    long richCount = (richLength - SIZEOF_RICH_SIGNATURE) / SIZEOF_RICH_VERSION_INFO;
    long result = 0;
    for (int i = 0; i < richCount; i++) {
      long idVersion = r.u32(SIZEOF_RICH_SIGNATURE + 8L * i);
      boolean matchVersion = version == (idVersion & 0xFFFF);
      boolean matchToolid = toolid == (idVersion >>> 16);
      if ((version == UNDEFINED || matchVersion) && (toolid == UNDEFINED || matchToolid)) {
        result += r.u32(SIZEOF_RICH_SIGNATURE + 8L * i + 4);
      }
    }
    return result;
  }

  private static Object calculateChecksum(FunctionCall c) {
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    long csum = 0;
    long csumOffset = pe.optionalHeader + 64;
    long size = pe.size;
    java.nio.ByteBuffer data = pe.r.buffer();
    for (long i = 0; i <= size / 4; i++) {
      if (4 * i == csumOffset) {
        continue;
      }
      if (4 * i + 4 <= size) {
        int p = (int) (4 * i);
        csum +=
            (data.get(p) & 0xFFL)
                + ((data.get(p + 1) & 0xFFL) << 8)
                + ((data.get(p + 2) & 0xFFL) << 16)
                + ((data.get(p + 3) & 0xFFL) << 24);
      } else {
        for (long j = 0; j < size % 4; j++) {
          csum += (data.get((int) (4 * i + j)) & 0xFFL) << (8 * j);
        }
      }
      if (csum > 0xffffffffL) {
        csum = (csum & 0xffffffffL) + (csum >>> 32);
      }
    }
    csum = (csum & 0xffff) + (csum >>> 16);
    csum += (csum >>> 16);
    csum &= 0xffff;
    csum += size;
    return csum;
  }

  private static Object rvaToOffset(FunctionCall c) {
    Pe pe = pe(c);
    if (pe == null) {
      return null;
    }
    long offset = pe.rvaToOffset(c.integerArgument(1));
    if (offset == -1) {
      return null;
    }
    return offset;
  }

  // ---------------------------------------------------------------------------------------------
  // Declarations

  @Override
  public String name() {
    return "pe";
  }

  private static void declareCertificate(ModuleDeclarations d) {
    d.declareString("thumbprint")
        .declareString("issuer")
        .declareString("subject")
        .declareInteger("version")
        .declareString("algorithm")
        .declareString("algorithm_oid")
        .declareString("serial")
        .declareInteger("not_before")
        .declareInteger("not_after");
  }

  @Override
  public void declare(ModuleDeclarations d) {
    for (String n : PeConstants.CONSTANT_DECLS) {
      d.declareInteger(n);
    }
    d.declareInteger("is_pe")
        .declareInteger("machine")
        .declareInteger("number_of_sections")
        .declareInteger("timestamp")
        .declareInteger("pointer_to_symbol_table")
        .declareInteger("number_of_symbols")
        .declareInteger("size_of_optional_header")
        .declareInteger("characteristics")
        .declareInteger("entry_point")
        .declareInteger("entry_point_raw")
        .declareInteger("image_base")
        .declareInteger("number_of_rva_and_sizes")
        .declareInteger("number_of_version_infos")
        .declareStringDictionary("version_info")
        .beginStructArray("version_info_list")
        .declareString("key")
        .declareString("value")
        .endStructArray("version_info_list")
        .declareInteger("opthdr_magic")
        .declareInteger("size_of_code")
        .declareInteger("size_of_initialized_data")
        .declareInteger("size_of_uninitialized_data")
        .declareInteger("base_of_code")
        .declareInteger("base_of_data")
        .declareInteger("section_alignment")
        .declareInteger("file_alignment");
    for (String s :
        new String[] {"linker_version", "os_version", "image_version", "subsystem_version"}) {
      d.beginStruct(s).declareInteger("major").declareInteger("minor").endStruct(s);
    }
    d.declareInteger("win32_version_value")
        .declareInteger("size_of_image")
        .declareInteger("size_of_headers")
        .declareInteger("checksum")
        .declareFunction("calculate_checksum", "", "i", PeModule::calculateChecksum)
        .declareInteger("subsystem")
        .declareInteger("dll_characteristics")
        .declareInteger("size_of_stack_reserve")
        .declareInteger("size_of_stack_commit")
        .declareInteger("size_of_heap_reserve")
        .declareInteger("size_of_heap_commit")
        .declareInteger("loader_flags")
        .beginStructArray("data_directories")
        .declareInteger("virtual_address")
        .declareInteger("size")
        .endStructArray("data_directories")
        .beginStructArray("sections")
        .declareString("name")
        .declareString("full_name")
        .declareInteger("characteristics")
        .declareInteger("virtual_address")
        .declareInteger("virtual_size")
        .declareInteger("raw_data_offset")
        .declareInteger("raw_data_size")
        .declareInteger("pointer_to_relocations")
        .declareInteger("pointer_to_line_numbers")
        .declareInteger("number_of_relocations")
        .declareInteger("number_of_line_numbers")
        .endStructArray("sections")
        .beginStruct("overlay")
        .declareInteger("offset")
        .declareInteger("size")
        .endStruct("overlay")
        .beginStruct("rich_signature")
        .declareInteger("offset")
        .declareInteger("length")
        .declareInteger("key")
        .declareString("raw_data")
        .declareString("clear_data")
        .declareString("version_data")
        .declareFunction(
            "version", "i", "i", c -> nullIfUndefined(
                richVersion(c.module(), c.integerArgument(1), UNDEFINED)))
        .declareFunction(
            "version", "ii", "i", c -> nullIfUndefined(
                richVersion(c.module(), c.integerArgument(1), c.integerArgument(2))))
        .declareFunction(
            "toolid", "i", "i", c -> nullIfUndefined(
                richVersion(c.module(), UNDEFINED, c.integerArgument(1))))
        .declareFunction(
            "toolid", "ii", "i", c -> nullIfUndefined(
                richVersion(c.module(), c.integerArgument(2), c.integerArgument(1))))
        .endStruct("rich_signature")
        .declareFunction("imphash", "", "s", PeModule::imphash)
        .declareFunction("section_index", "s", "i", PeModule::sectionIndexName)
        .declareFunction("section_index", "i", "i", PeModule::sectionIndexAddr)
        .declareFunction("exports", "s", "i", PeModule::exportsName)
        .declareFunction("exports", "r", "i", PeModule::exportsRegexp)
        .declareFunction("exports", "i", "i", PeModule::exportsOrdinal)
        .declareFunction("exports_index", "s", "i", PeModule::exportsIndexName)
        .declareFunction("exports_index", "i", "i", PeModule::exportsIndexOrdinal)
        .declareFunction("exports_index", "r", "i", PeModule::exportsIndexRegex)
        .declareFunction("imports", "ss", "i", PeModule::importsStandard)
        .declareFunction("imports", "si", "i", PeModule::importsStandardOrdinal)
        .declareFunction("imports", "s", "i", PeModule::importsStandardDll)
        .declareFunction("imports", "rr", "i", PeModule::importsStandardRegex)
        .declareFunction("imports", "iss", "i", PeModule::importsFlags)
        .declareFunction("imports", "isi", "i", PeModule::importsOrdinalFlags)
        .declareFunction("imports", "is", "i", PeModule::importsDllFlags)
        .declareFunction("imports", "irr", "i", PeModule::importsRegexFlags)
        .declareFunction("import_rva", "ss", "i", c -> importRva(c, "import", false))
        .declareFunction("import_rva", "si", "i", c -> importRva(c, "import", true))
        .declareFunction(
            "delayed_import_rva", "ss", "i", c -> importRva(c, "delayed_import", false))
        .declareFunction(
            "delayed_import_rva", "si", "i", c -> importRva(c, "delayed_import", true))
        .declareFunction("locale", "i", "i", c -> locale(c, 0xFFFF))
        .declareFunction("language", "i", "i", c -> locale(c, 0xFF))
        .declareFunction("is_dll", "", "i", PeModule::isDll)
        .declareFunction("is_32bit", "", "i", PeModule::is32bit)
        .declareFunction("is_64bit", "", "i", PeModule::is64bit)
        .declareInteger("number_of_imports")
        .declareInteger("number_of_imported_functions")
        .declareInteger("number_of_delayed_imports")
        .declareInteger("number_of_delayed_imported_functions")
        .declareInteger("number_of_exports")
        .declareString("dll_name")
        .declareInteger("export_timestamp")
        .beginStructArray("export_details")
        .declareInteger("offset")
        .declareString("name")
        .declareString("forward_name")
        .declareInteger("ordinal")
        .declareInteger("rva")
        .endStructArray("export_details");
    for (String s : new String[] {"import_details", "delayed_import_details"}) {
      d.beginStructArray(s)
          .declareString("library_name")
          .declareInteger("number_of_functions")
          .beginStructArray("functions")
          .declareString("name")
          .declareInteger("ordinal")
          .declareInteger("rva")
          .endStructArray("functions")
          .endStructArray(s);
    }
    d.declareInteger("resource_timestamp")
        .beginStruct("resource_version")
        .declareInteger("major")
        .declareInteger("minor")
        .endStruct("resource_version")
        .beginStructArray("resources")
        .declareInteger("rva")
        .declareInteger("offset")
        .declareInteger("length")
        .declareInteger("type")
        .declareInteger("id")
        .declareInteger("language")
        .declareString("type_string")
        .declareString("name_string")
        .declareString("language_string")
        .endStructArray("resources")
        .declareInteger("number_of_resources")
        .declareString("pdb_path");

    d.beginStructArray("signatures");
    declareCertificate(d);
    d.declareInteger("verified")
        .declareString("digest_alg")
        .declareString("digest")
        .declareString("file_digest")
        .declareInteger("number_of_certificates")
        .beginStructArray("certificates");
    declareCertificate(d);
    d.endStructArray("certificates")
        .beginStruct("signer_info")
        .declareString("program_name")
        .declareString("digest")
        .declareString("digest_alg")
        .declareInteger("length_of_chain")
        .beginStructArray("chain");
    declareCertificate(d);
    d.endStructArray("chain")
        .endStruct("signer_info")
        .declareInteger("number_of_countersignatures")
        .beginStructArray("countersignatures")
        .declareInteger("verified")
        .declareInteger("sign_time")
        .declareString("digest_alg")
        .declareString("digest")
        .declareInteger("length_of_chain")
        .beginStructArray("chain");
    declareCertificate(d);
    d.endStructArray("chain")
        .endStructArray("countersignatures")
        .declareFunction("valid_on", "i", "i", PeModule::validOn)
        .endStructArray("signatures")
        .declareInteger("is_signed")
        .declareInteger("number_of_signatures");

    d.declareFunction("rva_to_offset", "i", "i", PeModule::rvaToOffset);
  }

  private static Object nullIfUndefined(long v) {
    return v == UNDEFINED ? null : (Object) v;
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {
    for (Object[] c : PeConstants.CONSTANTS) {
      module.setInteger(((Number) c[1]).longValue(), (String) c[0]);
    }
    module.setInteger(0, "is_pe");
    for (MemoryBlock block : context.blocks()) {
      BinaryReader r = new BinaryReader(block.data(), context);
      long header = getHeader(r);
      if (header < 0) {
        continue;
      }
      Pe pe = new Pe(r, header, module);
      module.setData(pe);
      parseHeader(pe, block.base());
      parseRichSignature(pe, block.base());
      parseDebugDirectory(pe);
      Authenticode.parseCertificates(pe);
      pe.importedDlls = parseImports(pe);
      pe.delayImportedDlls = parseDelayedImports(pe);
      parseExports(pe);
      break;
    }
  }

  @Override
  public void unload(YStructure module) {
    module.setData(null);
  }
}
