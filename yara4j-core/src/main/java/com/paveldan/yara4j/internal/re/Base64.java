package com.paveldan.yara4j.internal.re;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import com.paveldan.yara4j.internal.compiler.StringFlags;

/** Converts strings with the base64 and base64wide modifiers into regexps. Port of base64.c. */
public final class Base64 {
  private Base64() {}

  public static final byte[] DEFAULT_ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
          .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

  private static byte[] toWide(byte[] s) {
    byte[] w = new byte[s.length * 2];
    for (int i = 0; i < s.length; i++) {
      w[i * 2] = s[i];
    }
    return w;
  }

  private static byte[] encode(byte[] in, byte[] alphabet, int i, int[] padOut) {
    int len = in.length;
    int pad = ((i + len) % 3) != 0 ? 3 - ((i + len) % 3) : 0;
    padOut[0] = pad;
    byte[] src = new byte[len + i];
    for (int j = 0; j < i; j++) {
      src[j] = 'A';
    }
    System.arraycopy(in, 0, src, i, len);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int p = 0;
    int end = src.length;
    while (end - p >= 3) {
      int s0 = src[p] & 0xFF;
      int s1 = src[p + 1] & 0xFF;
      int s2 = src[p + 2] & 0xFF;
      out.write(alphabet[s0 >> 2]);
      out.write(alphabet[(s0 & 0x03) << 4 | s1 >> 4]);
      out.write(alphabet[(s1 & 0x0f) << 2 | s2 >> 6]);
      out.write(alphabet[s2 & 0x3f]);
      p += 3;
    }
    if (end - p > 0) {
      int s0 = src[p] & 0xFF;
      out.write(alphabet[s0 >> 2]);
      if (end - p == 1) {
        out.write(alphabet[(s0 & 0x03) << 4]);
        out.write('=');
      } else {
        int s1 = src[p + 1] & 0xFF;
        out.write(alphabet[(s0 & 0x03) << 4 | s1 >> 4]);
        out.write(alphabet[(s1 & 0x0f) << 2]);
      }
      out.write('=');
    }
    return out.toByteArray();
  }

  private static byte[] substring(byte[] encoded, boolean wide, int i, int pad) {
    int trailing = pad != 0 ? pad + 1 : 0;
    int leading = i != 0 ? i + 1 : 0;
    int length = encoded.length - (leading + trailing);
    byte[] s = new byte[length];
    System.arraycopy(encoded, leading, s, 0, length);
    return wide ? toWide(s) : s;
  }

  private static void createNodes(byte[] str, byte[] alphabet, boolean wide, List<byte[]> out) {
    for (int i = 0; i <= 2; i++) {
      if (i == 1 && str.length == 1) {
        continue;
      }
      int[] pad = new int[1];
      byte[] encoded = encode(str, alphabet, i, pad);
      out.add(substring(encoded, wide, i, pad[0]));
    }
  }

  private static boolean isMetachar(int x) {
    return x == '\\' || x == '^' || x == '$' || x == '|' || x == '(' || x == ')' || x == '['
        || x == ']' || x == '*' || x == '?' || x == '{' || x == ',' || x == '.' || x == '+'
        || x == '}';
  }

  /** Builds the regexp source "(alt1|alt2|...)" for the given string and modifiers. */
  public static byte[] regexpFor(byte[] in, int flags, byte[] alphabet) {
    List<byte[]> nodes = new ArrayList<>();
    if ((flags & StringFlags.WIDE) != 0) {
      byte[] wideStr = toWide(in);
      if ((flags & StringFlags.BASE64) != 0) {
        createNodes(wideStr, alphabet, false, nodes);
      }
      if ((flags & StringFlags.BASE64_WIDE) != 0) {
        createNodes(wideStr, alphabet, true, nodes);
      }
    }
    if ((flags & StringFlags.ASCII) != 0
        || ((flags & StringFlags.WIDE) == 0 && (flags & StringFlags.ASCII) == 0)) {
      if ((flags & StringFlags.BASE64) != 0) {
        createNodes(in, alphabet, false, nodes);
      }
      if ((flags & StringFlags.BASE64_WIDE) != 0) {
        createNodes(in, alphabet, true, nodes);
      }
    }
    ByteArrayOutputStream re = new ByteArrayOutputStream();
    re.write('(');
    for (int n = 0; n < nodes.size(); n++) {
      for (byte b : nodes.get(n)) {
        int c = b & 0xFF;
        if (isMetachar(c)) {
          re.write('\\');
        }
        if (c == 0) {
          re.write('\\');
          re.write('x');
          re.write('0');
          re.write('0');
        } else {
          re.write(c);
        }
      }
      if (n + 1 < nodes.size()) {
        re.write('|');
      }
    }
    re.write(')');
    return re.toByteArray();
  }

  /** Parses the base64 regexp for the string, port of yr_base64_ast_from_string. */
  public static RegexParser.Result astFromString(byte[] in, int flags, byte[] alphabet) {
    return RegexParser.parse(regexpFor(in, flags, alphabet), false);
  }
}
