package com.paveldan.yara4j.util;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Bounds-aware little/big endian reader over a ByteBuffer, used by modules for parsing file
 * formats. Offsets are longs so that unchecked arithmetic on untrusted values can't overflow;
 * use {@link #fits} before reading, reads outside the buffer throw IndexOutOfBoundsException.
 */
public final class BinaryReader {
  private final ByteBuffer buf;
  private final long size;

  public BinaryReader(ByteBuffer buf) {
    this.buf = buf;
    this.size = buf.limit();
  }

  public BinaryReader(byte[] data) {
    this(ByteBuffer.wrap(data));
  }

  public ByteBuffer buffer() {
    return buf;
  }

  public long size() {
    return size;
  }

  /** True if [offset, offset + length) lies within the buffer. */
  public boolean fits(long offset, long length) {
    return offset >= 0 && length >= 0 && offset <= size && length <= size - offset;
  }

  private int idx(long offset, int n) {
    if (offset < 0 || offset + n > size) {
      throw new IndexOutOfBoundsException("offset " + offset + " size " + size);
    }
    return (int) offset;
  }

  public int u8(long offset) {
    return buf.get(idx(offset, 1)) & 0xFF;
  }

  public int s8(long offset) {
    return buf.get(idx(offset, 1));
  }

  public int u16(long offset) {
    int i = idx(offset, 2);
    return (buf.get(i) & 0xFF) | (buf.get(i + 1) & 0xFF) << 8;
  }

  public int u16be(long offset) {
    int i = idx(offset, 2);
    return (buf.get(i) & 0xFF) << 8 | (buf.get(i + 1) & 0xFF);
  }

  public int s16(long offset) {
    return (short) u16(offset);
  }

  public long u32(long offset) {
    int i = idx(offset, 4);
    return ((buf.get(i) & 0xFFL)
        | (buf.get(i + 1) & 0xFFL) << 8
        | (buf.get(i + 2) & 0xFFL) << 16
        | (buf.get(i + 3) & 0xFFL) << 24);
  }

  public long u32be(long offset) {
    int i = idx(offset, 4);
    return ((buf.get(i) & 0xFFL) << 24
        | (buf.get(i + 1) & 0xFFL) << 16
        | (buf.get(i + 2) & 0xFFL) << 8
        | (buf.get(i + 3) & 0xFFL));
  }

  public int s32(long offset) {
    return (int) u32(offset);
  }

  public int s32be(long offset) {
    return (int) u32be(offset);
  }

  public long u64(long offset) {
    return u32(offset) | u32(offset + 4) << 32;
  }

  public long u64be(long offset) {
    return u32be(offset) << 32 | u32be(offset + 4);
  }

  public byte[] bytes(long offset, int length) {
    int i = idx(offset, length);
    byte[] b = new byte[length];
    for (int k = 0; k < length; k++) {
      b[k] = buf.get(i + k);
    }
    return b;
  }

  /** Length of the NUL terminated string at offset, limited to the buffer end or -1. */
  public int strnlen(long offset, long max) {
    if (offset < 0 || offset >= size) {
      return -1;
    }
    long end = Math.min(size, offset + max);
    for (long p = offset; p < end; p++) {
      if (buf.get((int) p) == 0) {
        return (int) (p - offset);
      }
    }
    return (int) (end - offset);
  }

  /** True if a NUL terminated string starts at offset and ends within the buffer. */
  public boolean hasCString(long offset) {
    if (offset < 0 || offset >= size) {
      return false;
    }
    for (long p = offset; p < size; p++) {
      if (buf.get((int) p) == 0) {
        return true;
      }
    }
    return false;
  }

  /** Reads a NUL terminated string, stopping at the end of the buffer. */
  public byte[] cstring(long offset) {
    int n = strnlen(offset, size);
    if (n < 0) {
      return new byte[0];
    }
    return bytes(offset, n);
  }

  public static String latin1(byte[] b) {
    return new String(b, StandardCharsets.ISO_8859_1);
  }
}
