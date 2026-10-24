package com.paveldan.yara4j;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds small malformed files whose structures reference each other, which used to make
 * modules use excessive memory or time.
 */
public final class CraftedFiles {
  private CraftedFiles() {}

  // ---------------------------------------------------------------------------------------------
  // PE with nested Authenticode signatures

  /** A DER element. A hole only counts its length and must be the last element written. */
  private abstract static class Der {
    abstract long contentLength();

    abstract void write(ByteArrayOutputStream out);

    long totalLength() {
      return headerLength(contentLength()) + contentLength();
    }
  }

  private static int headerLength(long len) {
    return len < 0x80 ? 2 : len < 0x100 ? 3 : len < 0x10000 ? 4 : len < 0x1000000 ? 5 : 6;
  }

  private static void header(ByteArrayOutputStream out, int tag, long len) {
    out.write(tag);
    if (len < 0x80) {
      out.write((int) len);
      return;
    }
    int n = headerLength(len) - 2;
    out.write(0x80 | n);
    for (int i = n - 1; i >= 0; i--) {
      out.write((int) (len >> (8 * i)) & 0xFF);
    }
  }

  private static Der raw(byte[] b) {
    return new Der() {
      @Override
      long contentLength() {
        return b.length;
      }

      @Override
      long totalLength() {
        return b.length;
      }

      @Override
      void write(ByteArrayOutputStream out) {
        out.write(b, 0, b.length);
      }
    };
  }

  private static Der hole(long len) {
    return new Der() {
      @Override
      long contentLength() {
        return len;
      }

      @Override
      long totalLength() {
        return len;
      }

      @Override
      void write(ByteArrayOutputStream out) {}
    };
  }

  private static Der tlv(int tag, Der... children) {
    return new Der() {
      @Override
      long contentLength() {
        long n = 0;
        for (Der c : children) {
          n += c.totalLength();
        }
        return n;
      }

      @Override
      void write(ByteArrayOutputStream out) {
        header(out, tag, contentLength());
        for (Der c : children) {
          c.write(out);
        }
      }
    };
  }

  private static Der oid(int... arcs) {
    ByteArrayOutputStream c = new ByteArrayOutputStream();
    c.write(arcs[0] * 40 + arcs[1]);
    for (int i = 2; i < arcs.length; i++) {
      int groups = 0;
      for (long v = arcs[i]; v >= 0x80; v >>= 7) {
        groups++;
      }
      for (int g = groups; g >= 0; g--) {
        c.write((arcs[i] >> (7 * g)) & 0x7F | (g > 0 ? 0x80 : 0));
      }
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    header(out, 0x06, c.size());
    out.write(c.toByteArray(), 0, c.size());
    return raw(out.toByteArray());
  }

  private static Der one() {
    return raw(new byte[] {2, 1, 1});
  }

  /**
   * A PKCS#7 SignedData with an SpcIndirectDataContent (SHA-256 digest of zeros), no
   * certificates and one signer whose unauthenticated attributes contain the nested signatures
   * as OCTET STRINGs.
   */
  private static Der signature(Der... nested) {
    Der sha256 = tlv(0x30, oid(2, 16, 840, 1, 101, 3, 4, 2, 1));
    Der indirectData =
        tlv(
            0x30,
            oid(1, 3, 6, 1, 4, 1, 311, 2, 1, 4),
            tlv(
                0xA0,
                tlv(
                    0x30,
                    tlv(0x30, oid(1, 3, 6, 1, 4, 1, 311, 2, 1, 15)),
                    tlv(0x30, sha256, tlv(0x04, raw(new byte[32]))))));
    List<Der> signer = new ArrayList<>();
    signer.add(one());
    signer.add(tlv(0x30, tlv(0x30), one()));
    signer.add(sha256);
    signer.add(tlv(0x30, oid(1, 2, 840, 113549, 1, 1, 1)));
    signer.add(tlv(0x04));
    if (nested.length > 0) {
      Der[] values = new Der[nested.length];
      for (int i = 0; i < nested.length; i++) {
        values[i] = tlv(0x04, nested[i]);
      }
      signer.add(
          tlv(0xA1, tlv(0x30, oid(1, 3, 6, 1, 4, 1, 311, 2, 4, 1), tlv(0x31, values))));
    }
    Der signedData =
        tlv(
            0x30,
            one(),
            tlv(0x31, sha256),
            indirectData,
            tlv(0xA0),
            tlv(0x31, tlv(0x30, signer.toArray(new Der[0]))));
    return tlv(0x30, oid(1, 2, 840, 113549, 1, 7, 2), tlv(0xA0, signedData));
  }

  private static byte[] encode(Der d) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    d.write(out);
    return out.toByteArray();
  }

  /**
   * A PE32 whose certificate table, at certTableOffset, contains a chain of signatures nested
   * in each other levels deep.
   */
  public static byte[] peWithNestedSignatures(int levels, int certTableOffset) {
    // Each level ends with the next one, so the encoding is the headers of all the levels from
    // the outermost one, followed by the innermost signature.
    byte[] innermost = encode(signature());
    List<byte[]> headers = new ArrayList<>();
    long len = innermost.length;
    for (int i = 0; i < levels; i++) {
      Der d = signature(hole(len));
      headers.add(encode(d));
      len = d.totalLength();
    }
    ByteArrayOutputStream blob = new ByteArrayOutputStream();
    for (int i = headers.size() - 1; i >= 0; i--) {
      blob.write(headers.get(i), 0, headers.get(i).length);
    }
    blob.write(innermost, 0, innermost.length);
    return pe(blob.toByteArray(), certTableOffset);
  }

  /** A signature with fanout nested signatures, each with fanout nested ones, depth levels. */
  private static Der signatureTree(int fanout, int depth) {
    if (depth == 0) {
      return signature();
    }
    Der[] nested = new Der[fanout];
    for (int i = 0; i < fanout; i++) {
      nested[i] = raw(encode(signatureTree(fanout, depth - 1)));
    }
    return signature(nested);
  }

  /** A PE32 whose signature is a tree of nested signatures. */
  public static byte[] peWithSignatureTree(int fanout, int depth) {
    return pe(encode(signatureTree(fanout, depth)), 0x200);
  }

  private static byte[] pe(byte[] b, int certTableOffset) {
    ByteBuffer pe =
        ByteBuffer.allocate(certTableOffset + 8 + b.length).order(ByteOrder.LITTLE_ENDIAN);
    pe.putShort(0, (short) 0x5A4D);
    pe.putInt(0x3C, 0x40);
    pe.putInt(0x40, 0x4550);
    pe.putShort(0x58, (short) 0x10B);
    pe.putInt(0xB4, 16); // NumberOfRvaAndSizes
    pe.putInt(0xD8, certTableOffset); // IMAGE_DIRECTORY_ENTRY_SECURITY
    pe.putInt(0xDC, 8 + b.length);
    pe.putInt(certTableOffset, 8 + b.length); // WIN_CERTIFICATE
    pe.putShort(certTableOffset + 4, (short) 0x200);
    pe.putShort(certTableOffset + 6, (short) 2);
    pe.position(certTableOffset + 8);
    pe.put(b);
    return pe.array();
  }

  // ---------------------------------------------------------------------------------------------
  // dex

  /**
   * A dex file with one class whose direct methods all have the same code item, whose
   * instructions span the rest of the file. Returns the file; the number of methods is
   * {@link #dexMethodCount}.
   */
  public static byte[] dexWithSharedCodeItem(int size) {
    ByteBuffer b = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
    b.put(0, "dex\n035\0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
    b.putInt(56, 1); // string_ids_size
    b.putInt(60, 0x70);
    b.putInt(88, 1); // method_ids_size
    b.putInt(92, 0x78);
    b.putInt(96, 1); // class_defs_size
    b.putInt(100, 0x80);
    b.putInt(0x70, 0x74); // string data: "a"
    b.put(0x74, (byte) 1);
    b.put(0x75, (byte) 'a');
    // The code item overlaps the class definition, its instructions extend to the end of the
    // file, over the class data.
    int codeOff = 0x88;
    b.putInt(codeOff + 12, (size - codeOff - 16) / 2);
    b.putInt(0x80 + 24, 0xA0); // class_data_offset
    int n = dexMethodCount(size);
    int p = 0xA0;
    b.put(p++, (byte) 0); // static fields
    b.put(p++, (byte) 0); // instance fields
    int v = n;
    do {
      int x = v & 0x7F;
      v >>>= 7;
      b.put(p++, (byte) (v != 0 ? x | 0x80 : x));
    } while (v != 0);
    b.put(p++, (byte) 0); // virtual methods
    for (int i = 0; i < n; i++) {
      // method_idx_diff 0, access_flags 0, code_off 0x88
      b.put(p++, (byte) 0);
      b.put(p++, (byte) 0);
      b.put(p++, (byte) 0x88);
      b.put(p++, (byte) 0x01);
    }
    return b.array();
  }

  public static int dexMethodCount(int size) {
    return (size - 0xA0 - 8 - 12) / 4;
  }

  private static int uleb128(ByteBuffer b, int p, int value) {
    int v = value;
    do {
      int x = v & 0x7F;
      v >>>= 7;
      b.put(p++, (byte) (v != 0 ? x | 0x80 : x));
    } while (v != 0);
    return p;
  }

  /**
   * A dex file with two classes: the first one has the given number of static fields followed
   * by a direct method with access flags firstFlags, the second one has no fields and a direct
   * method with access flags secondFlags.
   */
  public static byte[] dexWithFieldsThenMethod(int fields, int firstFlags, int secondFlags) {
    int classData = 0xD0;
    int size = classData + 16 + fields * 2 + 16 + 16;
    ByteBuffer b = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
    b.put(0, "dex\n035\0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
    b.putInt(56, 1); // string_ids_size
    b.putInt(60, 0x70);
    b.putInt(80, 1); // field_ids_size
    b.putInt(84, 0xC0);
    b.putInt(88, 1); // method_ids_size
    b.putInt(92, 0x78);
    b.putInt(96, 2); // class_defs_size
    b.putInt(100, 0x80);
    b.putInt(0x70, 0x74); // string data: "a"
    b.put(0x74, (byte) 1);
    b.put(0x75, (byte) 'a');
    // method_ids[0] at 0x78 and field_ids[0] at 0xC0 are zeros: both named "a".
    b.putInt(0x80 + 24, classData);
    int p = classData;
    p = uleb128(b, p, fields); // static fields
    p = uleb128(b, p, 0); // instance fields
    p = uleb128(b, p, 1); // direct methods
    p = uleb128(b, p, 0); // virtual methods
    for (int i = 0; i < fields; i++) {
      p = uleb128(b, p, 0); // field_idx_diff
      p = uleb128(b, p, 0); // access_flags
    }
    p = uleb128(b, p, 0); // method_idx_diff
    p = uleb128(b, p, firstFlags);
    p = uleb128(b, p, 0); // code_off
    b.putInt(0xA0 + 24, p);
    p = uleb128(b, p, 0);
    p = uleb128(b, p, 0);
    p = uleb128(b, p, 1);
    p = uleb128(b, p, 0);
    p = uleb128(b, p, 0);
    p = uleb128(b, p, secondFlags);
    uleb128(b, p, 0);
    return b.array();
  }

  // ---------------------------------------------------------------------------------------------
  // ELF

  /**
   * An ELF64 file whose symbols are all global functions named by the same string of
   * nameLength bytes.
   */
  public static byte[] elfWithSharedSymbolName(int symbols, int nameLength) {
    int strtab = 64;
    int strtabSize = nameLength + 2;
    int symtab = (strtab + strtabSize + 7) & ~7;
    int symtabSize = symbols * 24;
    int sections = symtab + symtabSize;
    ByteBuffer b = ByteBuffer.allocate(sections + 3 * 64).order(ByteOrder.LITTLE_ENDIAN);
    b.putInt(0, 0x464C457F);
    b.put(4, (byte) 2); // ELFCLASS64
    b.put(5, (byte) 1); // ELFDATA2LSB
    b.put(6, (byte) 1);
    b.putShort(16, (short) 2); // ET_EXEC
    b.putShort(18, (short) 62); // EM_X86_64
    b.putLong(0x28, sections); // e_shoff
    b.putShort(0x3A, (short) 64); // e_shentsize
    b.putShort(0x3C, (short) 3); // e_shnum
    b.putShort(0x3E, (short) 0); // e_shstrndx
    for (int i = 0; i < nameLength; i++) {
      b.put(strtab + 1 + i, (byte) 'f');
    }
    for (int i = 0; i < symbols; i++) {
      int s = symtab + i * 24;
      b.putInt(s, 1); // st_name
      b.put(s + 4, (byte) 0x12); // STB_GLOBAL, STT_FUNC
    }
    int sh = sections + 64; // section 1: .symtab, linked to section 2
    b.putInt(sh + 4, 2); // SHT_SYMTAB
    b.putLong(sh + 24, symtab);
    b.putLong(sh + 32, symtabSize);
    b.putInt(sh + 40, 2);
    b.putLong(sh + 56, 24);
    sh += 64; // section 2: .strtab
    b.putInt(sh + 4, 3); // SHT_STRTAB
    b.putLong(sh + 24, strtab);
    b.putLong(sh + 32, strtabSize);
    return b.array();
  }
}
