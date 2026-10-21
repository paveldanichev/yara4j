package com.paveldan.yara4j.internal.re;

import java.util.Arrays;

/**
 * Growable buffer holding the compiled code of all regular expressions in a rule set (the
 * equivalent of YR_RE_CODE_SECTION in libyara's arena). Code is referenced by offset.
 */
public final class ReCode {
  private byte[] buf;
  private int len;

  public ReCode() {
    this(1024);
  }

  public ReCode(int capacity) {
    buf = new byte[Math.max(capacity, 16)];
  }

  public ReCode(byte[] code) {
    buf = code;
    len = code.length;
  }

  public int offset() {
    return len;
  }

  private void ensure(int n) {
    if (len + n > buf.length) {
      buf = Arrays.copyOf(buf, Math.max(buf.length * 2, len + n));
    }
  }

  public void u8(int v) {
    ensure(1);
    buf[len++] = (byte) v;
  }

  public void u16(int v) {
    ensure(2);
    buf[len++] = (byte) v;
    buf[len++] = (byte) (v >> 8);
  }

  public void i32(int v) {
    ensure(4);
    buf[len++] = (byte) v;
    buf[len++] = (byte) (v >> 8);
    buf[len++] = (byte) (v >> 16);
    buf[len++] = (byte) (v >> 24);
  }

  public void bytes(byte[] b) {
    ensure(b.length);
    System.arraycopy(b, 0, buf, len, b.length);
    len += b.length;
  }

  public void putU16(int at, int v) {
    buf[at] = (byte) v;
    buf[at + 1] = (byte) (v >> 8);
  }

  public void putI32(int at, int v) {
    buf[at] = (byte) v;
    buf[at + 1] = (byte) (v >> 8);
    buf[at + 2] = (byte) (v >> 16);
    buf[at + 3] = (byte) (v >> 24);
  }

  /** Returns the underlying array, valid up to {@link #offset()}. */
  public byte[] array() {
    return buf;
  }

  /** Returns a trimmed copy of the code. */
  public byte[] toByteArray() {
    return Arrays.copyOf(buf, len);
  }
}
