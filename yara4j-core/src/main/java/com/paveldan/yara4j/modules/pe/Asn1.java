package com.paveldan.yara4j.modules.pe;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Minimal BER/DER TLV reader. Unlike a full ASN.1 library it keeps the offsets of every element
 * in the original buffer, which is needed because Authenticode digests are computed over the
 * original encodings.
 */
final class Asn1 {
  static final int UNIVERSAL = 0;
  static final int CONTEXT = 2;

  static final int BOOLEAN = 1;
  static final int INTEGER = 2;
  static final int BIT_STRING = 3;
  static final int OCTET_STRING = 4;
  static final int NULL = 5;
  static final int OBJECT = 6;
  static final int UTF8_STRING = 12;
  static final int SEQUENCE = 16;
  static final int SET = 17;
  static final int PRINTABLE_STRING = 19;
  static final int T61_STRING = 20;
  static final int IA5_STRING = 22;
  static final int UTC_TIME = 23;
  static final int GENERALIZED_TIME = 24;
  static final int VISIBLE_STRING = 26;
  static final int GENERAL_STRING = 27;
  static final int UNIVERSAL_STRING = 28;
  static final int BMP_STRING = 30;

  private static final int MAX_DEPTH = 64;

  /** Thrown for malformed encodings. */
  static final class Asn1Exception extends Exception {
    private static final long serialVersionUID = 1L;

    Asn1Exception(String message) {
      super(message);
    }
  }

  final byte[] buf;
  final int start;
  final int tagClass;
  final boolean constructed;
  final int tag;
  final int contentStart;
  final int contentEnd;
  final int end;
  private List<Asn1> children;

  private Asn1(
      byte[] buf,
      int start,
      int tagClass,
      boolean constructed,
      int tag,
      int contentStart,
      int contentEnd,
      int end) {
    this.buf = buf;
    this.start = start;
    this.tagClass = tagClass;
    this.constructed = constructed;
    this.tag = tag;
    this.contentStart = contentStart;
    this.contentEnd = contentEnd;
    this.end = end;
  }

  /** Parses the element starting at off, which must end before limit. */
  static Asn1 parse(byte[] b, int off, int limit) throws Asn1Exception {
    return parse(b, off, limit, 0);
  }

  static Asn1 parse(byte[] b) throws Asn1Exception {
    return parse(b, 0, b.length, 0);
  }

  private static Asn1 parse(byte[] b, int off, int limit, int depth) throws Asn1Exception {
    if (depth > MAX_DEPTH) {
      throw new Asn1Exception("nested too deep");
    }
    int p = off;
    if (p >= limit) {
      throw new Asn1Exception("truncated");
    }
    int id = b[p++] & 0xFF;
    int cls = id >> 6;
    boolean cons = (id & 0x20) != 0;
    int tag = id & 0x1F;
    if (tag == 0x1F) {
      tag = 0;
      int c;
      do {
        if (p >= limit) {
          throw new Asn1Exception("truncated tag");
        }
        c = b[p++] & 0xFF;
        if (tag > (Integer.MAX_VALUE >> 7)) {
          throw new Asn1Exception("tag too large");
        }
        tag = (tag << 7) | (c & 0x7F);
      } while ((c & 0x80) != 0);
    }
    if (p >= limit) {
      throw new Asn1Exception("truncated length");
    }
    int l = b[p++] & 0xFF;
    if (l == 0x80) {
      if (!cons) {
        throw new Asn1Exception("indefinite primitive");
      }
      int cs = p;
      int q = p;
      while (true) {
        if (q + 2 <= limit && b[q] == 0 && b[q + 1] == 0) {
          break;
        }
        Asn1 child = parse(b, q, limit, depth + 1);
        q = child.end;
      }
      return new Asn1(b, off, cls, true, tag, cs, q, q + 2);
    }
    long len;
    if ((l & 0x80) != 0) {
      int n = l & 0x7F;
      if (n > 4) {
        throw new Asn1Exception("length too large");
      }
      len = 0;
      for (int i = 0; i < n; i++) {
        if (p >= limit) {
          throw new Asn1Exception("truncated length");
        }
        len = (len << 8) | (b[p++] & 0xFF);
      }
    } else {
      len = l;
    }
    if (len > limit - p) {
      throw new Asn1Exception("content too long");
    }
    int cs = p;
    int ce = (int) (p + len);
    Asn1 r = new Asn1(b, off, cls, cons, tag, cs, ce, ce);
    if (cons) {
      // Validate the children now so that malformed nested data fails early, like OpenSSL.
      r.children = parseChildren(b, cs, ce, depth + 1);
    }
    return r;
  }

  private static List<Asn1> parseChildren(byte[] b, int from, int to, int depth)
      throws Asn1Exception {
    List<Asn1> list = new ArrayList<>();
    int q = from;
    while (q < to) {
      Asn1 c = parse(b, q, to, depth);
      list.add(c);
      q = c.end;
    }
    return list;
  }

  List<Asn1> children() {
    if (!constructed) {
      return Collections.emptyList();
    }
    if (children == null) {
      try {
        children = parseChildren(buf, contentStart, contentEnd, 0);
      } catch (Asn1Exception e) {
        children = Collections.emptyList();
      }
    }
    return children;
  }

  int size() {
    return children().size();
  }

  Asn1 get(int i) {
    return children().get(i);
  }

  boolean is(int cls, int tagNumber) {
    return tagClass == cls && tag == tagNumber;
  }

  boolean isUniversal(int tagNumber) {
    return tagClass == UNIVERSAL && tag == tagNumber;
  }

  boolean isContext(int tagNumber) {
    return tagClass == CONTEXT && tag == tagNumber;
  }

  /** The full encoding of the element. */
  byte[] encoded() {
    byte[] r = new byte[end - start];
    System.arraycopy(buf, start, r, 0, r.length);
    return r;
  }

  int encodedLength() {
    return end - start;
  }

  /**
   * The content octets. For constructed (BER) strings the content of the segments is
   * concatenated.
   */
  byte[] contents() {
    if (!constructed) {
      byte[] r = new byte[contentEnd - contentStart];
      System.arraycopy(buf, contentStart, r, 0, r.length);
      return r;
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (Asn1 c : children()) {
      byte[] cc = c.contents();
      out.write(cc, 0, cc.length);
    }
    return out.toByteArray();
  }

  /** The raw content octets as they appear in the buffer (no segment concatenation). */
  byte[] rawContents() {
    byte[] r = new byte[contentEnd - contentStart];
    System.arraycopy(buf, contentStart, r, 0, r.length);
    return r;
  }

  void expect(int cls, int tagNumber) throws Asn1Exception {
    if (!is(cls, tagNumber)) {
      throw new Asn1Exception("unexpected tag " + tagClass + "/" + tag);
    }
  }

  void expectUniversal(int tagNumber) throws Asn1Exception {
    expect(UNIVERSAL, tagNumber);
  }

  void expectSequence() throws Asn1Exception {
    expectUniversal(SEQUENCE);
    if (!constructed) {
      throw new Asn1Exception("primitive sequence");
    }
  }

  void expectSet() throws Asn1Exception {
    expectUniversal(SET);
    if (!constructed) {
      throw new Asn1Exception("primitive set");
    }
  }

  /** Decodes an OBJECT IDENTIFIER as dotted text. */
  String oid() throws Asn1Exception {
    expectUniversal(OBJECT);
    return decodeOid(buf, contentStart, contentEnd);
  }

  static String decodeOid(byte[] b, int from, int to) throws Asn1Exception {
    if (from >= to || (b[to - 1] & 0x80) != 0) {
      throw new Asn1Exception("bad oid");
    }
    StringBuilder sb = new StringBuilder();
    boolean first = true;
    int p = from;
    while (p < to) {
      if ((b[p] & 0xFF) == 0x80) {
        throw new Asn1Exception("bad oid padding");
      }
      BigInteger v = BigInteger.ZERO;
      int c;
      do {
        c = b[p++] & 0xFF;
        v = v.shiftLeft(7).or(BigInteger.valueOf(c & 0x7F));
      } while ((c & 0x80) != 0 && p < to);
      if (first) {
        first = false;
        BigInteger forty = BigInteger.valueOf(40);
        if (v.compareTo(BigInteger.valueOf(80)) < 0) {
          sb.append(v.divide(forty)).append('.').append(v.mod(forty));
        } else {
          sb.append("2.").append(v.subtract(BigInteger.valueOf(80)));
        }
      } else {
        sb.append('.').append(v);
      }
    }
    return sb.toString();
  }

  /** Decodes an INTEGER, rejecting the illegal padding refused by OpenSSL. */
  BigInteger integer() throws Asn1Exception {
    expectUniversal(INTEGER);
    int n = contentEnd - contentStart;
    if (n == 0 || constructed) {
      throw new Asn1Exception("bad integer");
    }
    if (n > 1) {
      int b0 = buf[contentStart] & 0xFF;
      int b1 = buf[contentStart + 1] & 0x80;
      if ((b0 == 0 && b1 == 0) || (b0 == 0xFF && b1 != 0)) {
        throw new Asn1Exception("illegal integer padding");
      }
    }
    return new BigInteger(rawContents());
  }

  /** A range of bytes in a buffer. */
  static final class Slice {
    final byte[] buf;
    final int off;
    final int len;

    Slice(byte[] buf, int off, int len) {
      this.buf = buf;
      this.off = off;
      this.len = len;
    }
  }

  /**
   * The same bytes as {@link #anyValue}, referencing this element's buffer instead of copying
   * them when they are contiguous in it.
   */
  Slice anyValueSlice() {
    if (tagClass != UNIVERSAL || tag == SEQUENCE || tag == SET) {
      return new Slice(buf, start, end - start);
    }
    switch (tag) {
      case NULL:
      case BOOLEAN:
      case OBJECT:
        return null;
      default:
        if (!constructed) {
          return new Slice(buf, contentStart, contentEnd - contentStart);
        }
        byte[] c = contents();
        return new Slice(c, 0, c.length);
    }
  }

  /**
   * The value of an ASN1_TYPE as seen by OpenSSL's value.sequence / value.octet_string union
   * members, or null when OpenSSL would store something that isn't an ASN1_STRING.
   */
  byte[] anyValue() {
    if (tagClass != UNIVERSAL || tag == SEQUENCE || tag == SET) {
      return encoded();
    }
    switch (tag) {
      case NULL:
      case BOOLEAN:
      case OBJECT:
        return null;
      default:
        return contents();
    }
  }
}
