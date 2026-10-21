package com.paveldan.yara4j.internal.re;

/** Character class, a 256 bits bitmap plus a negation flag (libyara's RE_CLASS). */
public final class ReClass {
  public boolean negated;
  public final byte[] bitmap = new byte[32];

  public void set(int c) {
    bitmap[c >> 3] |= (byte) (1 << (c & 7));
  }

  public boolean isSet(int c) {
    return (bitmap[c >> 3] & (1 << (c & 7))) != 0;
  }
}
