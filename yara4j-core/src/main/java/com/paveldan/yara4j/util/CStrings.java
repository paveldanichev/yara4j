package com.paveldan.yara4j.util;

/** C library string functions with exact C semantics. */
public final class CStrings {
  private CStrings() {}

  /** Result of {@link #strtoll}. */
  public static final class ParseResult {
    public long value;
    /** Index of the first unparsed character. */
    public int end;

    public boolean overflow;
  }

  private static boolean isSpace(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == 0x0B || c == '\f' || c == '\r';
  }

  private static int digit(int c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'z') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'Z') {
      return c - 'A' + 10;
    }
    return 99;
  }

  /** Equivalent of strtoll(s, &end, base) on a NUL terminated byte string. */
  public static ParseResult strtoll(byte[] s, int base) {
    ParseResult r = new ParseResult();
    int len = 0;
    while (len < s.length && s[len] != 0) {
      len++;
    }
    int i = 0;
    while (i < len && isSpace(s[i] & 0xFF)) {
      i++;
    }
    boolean neg = false;
    if (i < len && (s[i] == '+' || s[i] == '-')) {
      neg = s[i] == '-';
      i++;
    }
    if ((base == 0 || base == 16)
        && i + 1 < len
        && s[i] == '0'
        && (s[i + 1] == 'x' || s[i + 1] == 'X')
        && i + 2 < len
        && digit(s[i + 2] & 0xFF) < 16) {
      i += 2;
      base = 16;
    } else if (base == 0) {
      base = (i < len && s[i] == '0') ? 8 : 10;
    }
    int start = i;
    // Accumulate as negative to handle LLONG_MIN.
    long acc = 0;
    boolean overflow = false;
    long limit = neg ? Long.MIN_VALUE : -Long.MAX_VALUE;
    long multmin = limit / base;
    while (i < len) {
      int d = digit(s[i] & 0xFF);
      if (d >= base) {
        break;
      }
      if (!overflow) {
        if (acc < multmin) {
          overflow = true;
        } else {
          acc *= base;
          if (acc < limit + d) {
            overflow = true;
          } else {
            acc -= d;
          }
        }
      }
      i++;
    }
    if (i == start) {
      r.end = 0;
      r.value = 0;
      return r;
    }
    r.end = i;
    r.overflow = overflow;
    if (overflow) {
      r.value = neg ? Long.MIN_VALUE : Long.MAX_VALUE;
    } else {
      r.value = neg ? acc : -acc;
    }
    return r;
  }

  /** Length of a C string (up to the first NUL). */
  public static int strlen(byte[] s) {
    int n = 0;
    while (n < s.length && s[n] != 0) {
      n++;
    }
    return n;
  }

  /** Copy of the bytes up to the first NUL. */
  public static byte[] cstr(byte[] s) {
    int n = strlen(s);
    return n == s.length ? s : java.util.Arrays.copyOf(s, n);
  }

  /** isprint() in the C locale. */
  public static boolean isPrint(int c) {
    return c >= 0x20 && c < 0x7F;
  }
}
