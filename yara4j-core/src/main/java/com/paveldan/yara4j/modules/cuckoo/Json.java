package com.paveldan.yara4j.modules.cuckoo;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small JSON decoder with the semantics of jansson's json_loadb(JSON_ALLOW_NUL), used by the
 * cuckoo module. Objects are {@code Map<String, Object>}, arrays {@code List<Object>}, strings
 * {@code byte[]} (UTF-8), integers {@code Long}, reals {@code Double}, booleans {@code Boolean}
 * and null is {@link #NULL}.
 */
final class Json {
  static final Object NULL = new Object();

  private static final int MAX_DEPTH = 2048;

  /** Thrown for invalid JSON. */
  static final class JsonException extends Exception {
    private static final long serialVersionUID = 1L;

    JsonException(String message) {
      super(message);
    }
  }

  private final byte[] b;
  private int p;

  private Json(byte[] b) {
    this.b = b;
  }

  /** Decodes a JSON document whose top-level value must be an object or an array. */
  static Object parse(byte[] data) throws JsonException {
    validateUtf8(data);
    Json j = new Json(data);
    j.skipWhitespace();
    if (j.p >= data.length || (data[j.p] != '{' && data[j.p] != '[')) {
      throw new JsonException("'[' or '{' expected");
    }
    Object v = j.value(0);
    j.skipWhitespace();
    if (j.p != data.length) {
      throw new JsonException("end of file expected");
    }
    return v;
  }

  private static void validateUtf8(byte[] d) throws JsonException {
    int i = 0;
    while (i < d.length) {
      int c = d[i] & 0xFF;
      int n;
      int min;
      if (c < 0x80) {
        i++;
        continue;
      } else if (c >= 0xC2 && c <= 0xDF) {
        n = 1;
        min = 0x80;
      } else if (c >= 0xE0 && c <= 0xEF) {
        n = 2;
        min = 0x800;
      } else if (c >= 0xF0 && c <= 0xF4) {
        n = 3;
        min = 0x10000;
      } else {
        throw new JsonException("invalid UTF-8");
      }
      if (i + n >= d.length) {
        throw new JsonException("invalid UTF-8");
      }
      int v = c & (0x3F >> n);
      for (int k = 1; k <= n; k++) {
        int cc = d[i + k] & 0xFF;
        if ((cc & 0xC0) != 0x80) {
          throw new JsonException("invalid UTF-8");
        }
        v = (v << 6) | (cc & 0x3F);
      }
      if (v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) {
        throw new JsonException("invalid UTF-8");
      }
      i += n + 1;
    }
  }

  private void skipWhitespace() {
    while (p < b.length && (b[p] == ' ' || b[p] == '\t' || b[p] == '\n' || b[p] == '\r')) {
      p++;
    }
  }

  private Object value(int depth) throws JsonException {
    if (depth > MAX_DEPTH) {
      throw new JsonException("maximum parsing depth reached");
    }
    skipWhitespace();
    if (p >= b.length) {
      throw new JsonException("unexpected end of input");
    }
    byte c = b[p];
    switch (c) {
      case '{':
        return object(depth);
      case '[':
        return array(depth);
      case '"':
        return string();
      case 't':
        literal("true");
        return Boolean.TRUE;
      case 'f':
        literal("false");
        return Boolean.FALSE;
      case 'n':
        literal("null");
        return NULL;
      default:
        if (c == '-' || (c >= '0' && c <= '9')) {
          return number();
        }
        throw new JsonException("unexpected token");
    }
  }

  private void literal(String s) throws JsonException {
    for (int i = 0; i < s.length(); i++) {
      if (p + i >= b.length || b[p + i] != s.charAt(i)) {
        throw new JsonException("invalid token");
      }
    }
    p += s.length();
    // jansson reads a whole token made of letters, "truex" is invalid.
    if (p < b.length && isLetter(b[p])) {
      throw new JsonException("invalid token");
    }
  }

  private static boolean isLetter(byte c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  }

  private Map<String, Object> object(int depth) throws JsonException {
    p++;
    Map<String, Object> map = new LinkedHashMap<>();
    skipWhitespace();
    if (p < b.length && b[p] == '}') {
      p++;
      return map;
    }
    while (true) {
      skipWhitespace();
      if (p >= b.length || b[p] != '"') {
        throw new JsonException("string or '}' expected");
      }
      byte[] key = string();
      for (byte k : key) {
        if (k == 0) {
          throw new JsonException("NUL byte in object key not supported");
        }
      }
      skipWhitespace();
      if (p >= b.length || b[p] != ':') {
        throw new JsonException("':' expected");
      }
      p++;
      Object v = value(depth + 1);
      String k = new String(key, StandardCharsets.UTF_8);
      map.remove(k);
      map.put(k, v);
      skipWhitespace();
      if (p < b.length && b[p] == ',') {
        p++;
        continue;
      }
      if (p < b.length && b[p] == '}') {
        p++;
        return map;
      }
      throw new JsonException("'}' expected");
    }
  }

  private List<Object> array(int depth) throws JsonException {
    p++;
    List<Object> list = new ArrayList<>();
    skipWhitespace();
    if (p < b.length && b[p] == ']') {
      p++;
      return list;
    }
    while (true) {
      list.add(value(depth + 1));
      skipWhitespace();
      if (p < b.length && b[p] == ',') {
        p++;
        continue;
      }
      if (p < b.length && b[p] == ']') {
        p++;
        return list;
      }
      throw new JsonException("']' expected");
    }
  }

  private int hex4() throws JsonException {
    if (p + 4 > b.length) {
      throw new JsonException("invalid escape");
    }
    int v = 0;
    for (int i = 0; i < 4; i++) {
      int c = b[p++];
      int d;
      if (c >= '0' && c <= '9') {
        d = c - '0';
      } else if (c >= 'a' && c <= 'f') {
        d = c - 'a' + 10;
      } else if (c >= 'A' && c <= 'F') {
        d = c - 'A' + 10;
      } else {
        throw new JsonException("invalid escape");
      }
      v = (v << 4) | d;
    }
    return v;
  }

  private byte[] string() throws JsonException {
    p++;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    while (true) {
      if (p >= b.length) {
        throw new JsonException("premature end of input");
      }
      int c = b[p] & 0xFF;
      if (c == '"') {
        p++;
        return out.toByteArray();
      }
      if (c < 0x20) {
        throw new JsonException("control character in string");
      }
      if (c != '\\') {
        out.write(c);
        p++;
        continue;
      }
      p++;
      if (p >= b.length) {
        throw new JsonException("premature end of input");
      }
      c = b[p++];
      switch (c) {
        case '"':
        case '\\':
        case '/':
          out.write(c);
          break;
        case 'b':
          out.write('\b');
          break;
        case 'f':
          out.write('\f');
          break;
        case 'n':
          out.write('\n');
          break;
        case 'r':
          out.write('\r');
          break;
        case 't':
          out.write('\t');
          break;
        case 'u':
          {
            int v = hex4();
            if (v >= 0xD800 && v <= 0xDBFF) {
              if (p + 1 < b.length && b[p] == '\\' && b[p + 1] == 'u') {
                p += 2;
                int v2 = hex4();
                if (v2 >= 0xDC00 && v2 <= 0xDFFF) {
                  v = ((v - 0xD800) << 10) + (v2 - 0xDC00) + 0x10000;
                } else {
                  throw new JsonException("invalid Unicode");
                }
              } else {
                throw new JsonException("invalid Unicode");
              }
            } else if (v >= 0xDC00 && v <= 0xDFFF) {
              throw new JsonException("invalid Unicode");
            }
            byte[] enc = new String(Character.toChars(v)).getBytes(StandardCharsets.UTF_8);
            out.write(enc, 0, enc.length);
          }
          break;
        default:
          throw new JsonException("invalid escape");
      }
    }
  }

  private Object number() throws JsonException {
    int start = p;
    boolean real = false;
    if (b[p] == '-') {
      p++;
    }
    if (p >= b.length) {
      throw new JsonException("invalid token");
    }
    if (b[p] == '0') {
      p++;
      if (p < b.length && b[p] >= '0' && b[p] <= '9') {
        throw new JsonException("invalid token");
      }
    } else if (b[p] >= '1' && b[p] <= '9') {
      while (p < b.length && b[p] >= '0' && b[p] <= '9') {
        p++;
      }
    } else {
      throw new JsonException("invalid token");
    }
    if (p < b.length && b[p] == '.') {
      real = true;
      p++;
      if (p >= b.length || b[p] < '0' || b[p] > '9') {
        throw new JsonException("invalid token");
      }
      while (p < b.length && b[p] >= '0' && b[p] <= '9') {
        p++;
      }
    }
    if (p < b.length && (b[p] == 'e' || b[p] == 'E')) {
      real = true;
      p++;
      if (p < b.length && (b[p] == '+' || b[p] == '-')) {
        p++;
      }
      if (p >= b.length || b[p] < '0' || b[p] > '9') {
        throw new JsonException("invalid token");
      }
      while (p < b.length && b[p] >= '0' && b[p] <= '9') {
        p++;
      }
    }
    String s = new String(b, start, p - start, StandardCharsets.US_ASCII);
    if (!real) {
      try {
        return Long.parseLong(s);
      } catch (NumberFormatException e) {
        throw new JsonException("too big integer");
      }
    }
    double d = Double.parseDouble(s);
    if (Double.isInfinite(d)) {
      throw new JsonException("real number overflow");
    }
    return d;
  }
}
