package com.paveldan.yara4j.object;

/** Integer object. Undefined values are represented by {@link YObject#UNDEFINED}. */
public final class YInteger extends YObject {
  long value = UNDEFINED;

  public YInteger(String identifier) {
    super(identifier);
  }

  @Override
  public Type type() {
    return Type.INTEGER;
  }

  public long value() {
    return value;
  }

  public void set(long value) {
    this.value = value;
  }

  @Override
  public boolean isUndefined() {
    return value == UNDEFINED;
  }

  @Override
  public YObject copy() {
    YInteger c = new YInteger(identifier);
    c.value = value;
    return c;
  }

  @Override
  void printValue(StringBuilder sb, String indentSpaces, int indent) {
    if (value != UNDEFINED) {
      sb.append(" = ").append(value);
    } else {
      sb.append(" = YR_UNDEFINED");
    }
  }
}
