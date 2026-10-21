package com.paveldan.yara4j.internal.rules;

/** Definition of an external variable with its default value. */
public final class ExternalDef {
  public static final int TYPE_FLOAT = 1;
  public static final int TYPE_INTEGER = 2;
  public static final int TYPE_BOOLEAN = 3;
  public static final int TYPE_STRING = 4;

  public final String identifier;
  public final int type;
  public final long integer;
  public final double dbl;
  public final byte[] string;

  public ExternalDef(String identifier, int type, long integer, double dbl, byte[] string) {
    this.identifier = identifier;
    this.type = type;
    this.integer = integer;
    this.dbl = dbl;
    this.string = string;
  }
}
