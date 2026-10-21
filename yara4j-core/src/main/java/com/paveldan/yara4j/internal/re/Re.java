package com.paveldan.yara4j.internal.re;

/** Constants shared by the regular expression engine. */
public final class Re {
  private Re() {}

  public static final int MAX_RANGE = Short.MAX_VALUE;
  public static final int MAX_SPLIT_ID = 128;
  public static final int MAX_STACK = 1024;
  public static final int SCAN_LIMIT = 4096;
  public static final int MAX_FIBERS = 1024;
  public static final int STRING_CHAINING_THRESHOLD = 200;

  public static final int OP_ANY = 0xA0;
  public static final int OP_LITERAL = 0xA2;
  public static final int OP_MASKED_LITERAL = 0xA4;
  public static final int OP_CLASS = 0xA5;
  public static final int OP_WORD_CHAR = 0xA7;
  public static final int OP_NON_WORD_CHAR = 0xA8;
  public static final int OP_SPACE = 0xA9;
  public static final int OP_NON_SPACE = 0xAA;
  public static final int OP_DIGIT = 0xAB;
  public static final int OP_NON_DIGIT = 0xAC;
  public static final int OP_MATCH = 0xAD;
  public static final int OP_NOT_LITERAL = 0xAE;
  public static final int OP_MASKED_NOT_LITERAL = 0xAF;
  public static final int OP_MATCH_AT_END = 0xB0;
  public static final int OP_MATCH_AT_START = 0xB1;
  public static final int OP_WORD_BOUNDARY = 0xB2;
  public static final int OP_NON_WORD_BOUNDARY = 0xB3;
  public static final int OP_REPEAT_ANY_GREEDY = 0xB4;
  public static final int OP_REPEAT_ANY_UNGREEDY = 0xB5;
  public static final int OP_SPLIT_A = 0xC0;
  public static final int OP_SPLIT_B = 0xC1;
  public static final int OP_JUMP = 0xC2;
  public static final int OP_REPEAT_START_GREEDY = 0xC3;
  public static final int OP_REPEAT_END_GREEDY = 0xC4;
  public static final int OP_REPEAT_START_UNGREEDY = 0xC5;
  public static final int OP_REPEAT_END_UNGREEDY = 0xC6;

  public static final int FLAGS_FAST_REGEXP = 0x02;
  public static final int FLAGS_BACKWARDS = 0x04;
  public static final int FLAGS_EXHAUSTIVE = 0x08;
  public static final int FLAGS_WIDE = 0x10;
  public static final int FLAGS_NO_CASE = 0x20;
  public static final int FLAGS_SCAN = 0x40;
  public static final int FLAGS_DOT_ALL = 0x80;
  public static final int FLAGS_GREEDY = 0x400;
  public static final int FLAGS_UNGREEDY = 0x800;

  /** Size of RE_REPEAT_ARGS: uint16 min, uint16 max, int32 offset. */
  public static final int REPEAT_ARGS_SIZE = 8;
  /** Size of RE_REPEAT_ANY_ARGS: uint16 min, uint16 max. */
  public static final int REPEAT_ANY_ARGS_SIZE = 4;
  /** Size of RE_CLASS: uint8 negated + 32 bytes bitmap. */
  public static final int CLASS_SIZE = 33;

  static final byte[] LOWERCASE = new byte[256];
  static final byte[] ALTERCASE = new byte[256];

  static {
    for (int i = 0; i < 256; i++) {
      if (i >= 'a' && i <= 'z') {
        ALTERCASE[i] = (byte) (i - 32);
      } else if (i >= 'A' && i <= 'Z') {
        ALTERCASE[i] = (byte) (i + 32);
      } else {
        ALTERCASE[i] = (byte) i;
      }
      LOWERCASE[i] = (byte) ((i >= 'A' && i <= 'Z') ? i + 32 : i);
    }
  }

  /** ASCII lowercase, like tolower() in the C locale. */
  public static int lower(int c) {
    return LOWERCASE[c & 0xFF] & 0xFF;
  }

  public static int altercase(int c) {
    return ALTERCASE[c & 0xFF] & 0xFF;
  }

  public static boolean isAlnum(int c) {
    return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
  }
}
