package com.paveldan.yara4j.object;

import java.util.Locale;

/** Floating point object. Undefined values are represented by NaN. */
public final class YFloat extends YObject {
  double value = Double.NaN;

  public YFloat(String identifier) {
    super(identifier);
  }

  @Override
  public Type type() {
    return Type.FLOAT;
  }

  public double value() {
    return value;
  }

  public void set(double value) {
    this.value = value;
  }

  @Override
  public boolean isUndefined() {
    return Double.isNaN(value);
  }

  @Override
  public YObject copy() {
    YFloat c = new YFloat(identifier);
    c.value = value;
    return c;
  }

  @Override
  void printValue(StringBuilder sb, String indentSpaces, int indent) {
    // libyara checks the raw bits of the double against YR_UNDEFINED, which never happens in
    // practice, so floats are always printed.
    if (Double.isNaN(value)) {
      sb.append(" = ").append(Double.doubleToRawLongBits(value) < 0 ? "-nan" : "nan");
    } else if (Double.isInfinite(value)) {
      sb.append(" = ").append(value > 0 ? "inf" : "-inf");
    } else {
      sb.append(" = ").append(String.format(Locale.ROOT, "%f", value));
    }
  }
}
