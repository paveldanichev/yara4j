package com.paveldan.yara4j.object;

import java.nio.charset.StandardCharsets;

/**
 * Base class of the objects exposed by modules and external variables to rule conditions. This is
 * the equivalent of libyara's YR_OBJECT.
 *
 * <p>Values can be accessed with paths like {@code "sections[%i].name"} where {@code %i} and
 * {@code %s} are replaced by the extra arguments, exactly like the {@code yr_set_*} / {@code
 * yr_get_*} macros in libyara.
 */
public abstract class YObject {
  /** The value used by YARA to represent an undefined integer (YR_UNDEFINED). */
  public static final long UNDEFINED = 0xFFFABCDEFFFABCDEL;

  public enum Type {
    INTEGER,
    STRING,
    STRUCTURE,
    ARRAY,
    FUNCTION,
    DICTIONARY,
    FLOAT
  }

  final String identifier;
  YObject parent;
  private Object data;

  YObject(String identifier) {
    this.identifier = identifier;
  }

  public abstract Type type();

  public String identifier() {
    return identifier;
  }

  public YObject parent() {
    return parent;
  }

  /** Returns the root of the object tree (usually the module structure). */
  public YObject root() {
    YObject o = this;
    while (o.parent != null) {
      o = o.parent;
    }
    return o;
  }

  /** Arbitrary data attached to the object by a module (libyara's YR_OBJECT.data). */
  public Object getData() {
    return data;
  }

  public void setData(Object data) {
    this.data = data;
  }

  /** Deep copy, used for instantiating array/dictionary items from their prototype. */
  public abstract YObject copy();

  /** True if this object holds an undefined value (always false for compound objects). */
  public boolean isUndefined() {
    return false;
  }

  // ---------------------------------------------------------------------------------------------
  // Path based access, equivalent to yr_object_lookup / yr_object_set_* / yr_object_get_*.

  /** Looks up an object by path without creating missing array/dictionary items. */
  public YObject lookup(String path, Object... args) {
    return lookup(false, path, args);
  }

  YObject lookup(boolean create, String path, Object... args) {
    YObject obj = this;
    int p = 0;
    int n = path.length();
    int argIdx = 0;
    while (obj != null) {
      int start = p;
      while (p < n && path.charAt(p) != '.' && path.charAt(p) != '[') {
        p++;
      }
      String field = path.substring(start, p);
      if (!(obj instanceof YStructure)) {
        return null;
      }
      obj = ((YStructure) obj).field(field);
      if (obj == null) {
        return null;
      }
      if (p < n && path.charAt(p) == '[') {
        p++;
        int index = -1;
        String key = null;
        char c = path.charAt(p);
        if (c == '%') {
          p++;
          char f = path.charAt(p++);
          if (f == 'i') {
            index = ((Number) args[argIdx++]).intValue();
          } else if (f == 's') {
            Object a = args[argIdx++];
            key = a instanceof byte[] ? latin1((byte[]) a) : (String) a;
          } else {
            return null;
          }
        } else if (c >= '0' && c <= '9') {
          int s = p;
          while (p < n && Character.isDigit(path.charAt(p))) {
            p++;
          }
          index = Integer.parseInt(path.substring(s, p));
        } else if (c == '"') {
          p++;
          int s = p;
          while (p < n && path.charAt(p) != '"') {
            p++;
          }
          key = path.substring(s, p);
          p++;
        } else {
          return null;
        }
        // skip ']'
        p++;
        if (obj instanceof YArray) {
          obj = ((YArray) obj).get(index, create);
        } else if (obj instanceof YDictionary) {
          obj = ((YDictionary) obj).get(key, create);
        } else {
          return null;
        }
      }
      if (p >= n) {
        break;
      }
      p++;
    }
    return obj;
  }

  public boolean isUndefined(String path, Object... args) {
    YObject o = path == null ? this : lookup(false, path, args);
    return o == null || o.isUndefined();
  }

  public long getInteger(String path, Object... args) {
    YObject o = path == null ? this : lookup(false, path, args);
    if (!(o instanceof YInteger)) {
      return UNDEFINED;
    }
    return ((YInteger) o).value;
  }

  public double getFloat(String path, Object... args) {
    YObject o = path == null ? this : lookup(false, path, args);
    if (!(o instanceof YFloat)) {
      return Double.NaN;
    }
    return ((YFloat) o).value;
  }

  /** Returns the raw bytes of a string object, or null if undefined. */
  public byte[] getString(String path, Object... args) {
    YObject o = path == null ? this : lookup(false, path, args);
    if (!(o instanceof YString)) {
      return null;
    }
    return ((YString) o).value;
  }

  /**
   * Sets an integer value. Like in libyara, setting a value at an invalid path is silently
   * ignored.
   *
   * @return false if the path doesn't exist.
   */
  public boolean setInteger(long value, String path, Object... args) {
    YObject o = path == null ? this : lookup(true, path, args);
    if (!(o instanceof YInteger)) {
      return false;
    }
    ((YInteger) o).value = value;
    return true;
  }

  /** Sets a float value, see {@link #setInteger}. */
  public boolean setFloat(double value, String path, Object... args) {
    YObject o = path == null ? this : lookup(true, path, args);
    if (!(o instanceof YFloat)) {
      return false;
    }
    ((YFloat) o).value = value;
    return true;
  }

  /** Sets a string value. A null value makes the string undefined, see {@link #setInteger}. */
  public boolean setString(byte[] value, String path, Object... args) {
    YObject o = path == null ? this : lookup(true, path, args);
    if (!(o instanceof YString)) {
      return false;
    }
    ((YString) o).value = value;
    return true;
  }

  /** Sets a string value, the string is converted to bytes using ISO-8859-1. */
  public boolean setString(String value, String path, Object... args) {
    return setString(
        value == null ? null : value.getBytes(StandardCharsets.ISO_8859_1), path, args);
  }

  static String latin1(byte[] b) {
    return new String(b, StandardCharsets.ISO_8859_1);
  }

  /**
   * Prints the object data in the same format used by libyara's yr_object_print_data, this is
   * used by the command-line tool's --print-module-data option.
   */
  public void printData(StringBuilder sb, int indent, boolean printIdentifier) {
    StringBuilder ind = new StringBuilder();
    for (int i = 0; i < Math.min(indent, 31); i++) {
      ind.append('\t');
    }
    if (printIdentifier && type() != Type.FUNCTION) {
      sb.append(ind).append(identifier);
    }
    printValue(sb, ind.toString(), indent);
  }

  abstract void printValue(StringBuilder sb, String indentSpaces, int indent);
}
