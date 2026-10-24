package com.paveldan.yara4j.object;

/** String object holding raw bytes. Undefined values are represented by null. */
public final class YString extends YObject {
  byte[] value;

  public YString(String identifier) {
    super(identifier);
  }

  @Override
  public Type type() {
    return Type.STRING;
  }

  /**
   * The value, or null if undefined. Modules may share the same array between several values,
   * so it must not be modified.
   */
  public byte[] value() {
    return value;
  }

  public void set(byte[] value) {
    this.value = value;
  }

  @Override
  public boolean isUndefined() {
    return value == null;
  }

  @Override
  public YObject copy() {
    YString c = new YString(identifier);
    c.value = value == null ? null : value.clone();
    return c;
  }

  @Override
  void printValue(StringBuilder sb, String indentSpaces, int indent) {
    if (value != null) {
      sb.append(" = \"");
      for (byte b : value) {
        int c = b & 0xFF;
        if (c >= 32 && c < 127) {
          sb.append((char) c);
        } else {
          sb.append(String.format("\\x%02x", c));
        }
      }
      sb.append('"');
    } else {
      sb.append(" = YR_UNDEFINED");
    }
  }
}
