package com.paveldan.yara4j.internal.compiler;

/** String flags, same values as libyara's STRING_FLAGS_* constants. */
public final class StringFlags {
  private StringFlags() {}

  public static final int REFERENCED = 0x01;
  public static final int HEXADECIMAL = 0x02;
  public static final int NO_CASE = 0x04;
  public static final int ASCII = 0x08;
  public static final int WIDE = 0x10;
  public static final int REGEXP = 0x20;
  public static final int FAST_REGEXP = 0x40;
  public static final int FULL_WORD = 0x80;
  public static final int ANONYMOUS = 0x100;
  public static final int SINGLE_MATCH = 0x200;
  public static final int LITERAL = 0x400;
  public static final int FITS_IN_ATOM = 0x800;
  public static final int LAST_IN_RULE = 0x1000;
  public static final int CHAIN_PART = 0x2000;
  public static final int CHAIN_TAIL = 0x4000;
  public static final int FIXED_OFFSET = 0x8000;
  public static final int GREEDY_REGEXP = 0x10000;
  public static final int DOT_ALL = 0x20000;
  public static final int DISABLED = 0x40000;
  public static final int XOR = 0x80000;
  public static final int PRIVATE = 0x100000;
  public static final int BASE64 = 0x200000;
  public static final int BASE64_WIDE = 0x400000;
}
