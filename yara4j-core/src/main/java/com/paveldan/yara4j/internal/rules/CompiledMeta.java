package com.paveldan.yara4j.internal.rules;

/** A metadata entry of a rule (libyara's YR_META). */
public final class CompiledMeta {
  public static final int TYPE_INTEGER = 1;
  public static final int TYPE_STRING = 2;
  public static final int TYPE_BOOLEAN = 3;

  public final int type;
  public final String identifier;
  public final byte[] string;
  public final long integer;

  public CompiledMeta(int type, String identifier, byte[] string, long integer) {
    this.type = type;
    this.identifier = identifier;
    this.string = string;
    this.integer = integer;
  }
}
