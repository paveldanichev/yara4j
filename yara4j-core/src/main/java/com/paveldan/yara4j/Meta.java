package com.paveldan.yara4j;

import java.nio.charset.StandardCharsets;

/** A metadata entry of a rule. */
public final class Meta {
  public enum Type {
    INTEGER,
    STRING,
    BOOLEAN
  }

  private final String identifier;
  private final Type type;
  private final long integer;
  private final byte[] string;

  Meta(String identifier, Type type, long integer, byte[] string) {
    this.identifier = identifier;
    this.type = type;
    this.integer = integer;
    this.string = string;
  }

  public String getIdentifier() {
    return identifier;
  }

  public Type getType() {
    return type;
  }

  /** Value of integer metadata, or 1/0 for booleans. */
  public long getInteger() {
    return integer;
  }

  public boolean getBoolean() {
    return integer != 0;
  }

  /** Raw bytes of string metadata, or null. */
  public byte[] getStringBytes() {
    return string == null ? null : string.clone();
  }

  /** String metadata decoded as UTF-8, or null. */
  public String getString() {
    return string == null ? null : new String(string, StandardCharsets.UTF_8);
  }

  /** The value as a Java object: Long, String or Boolean. */
  public Object getValue() {
    switch (type) {
      case INTEGER:
        return integer;
      case BOOLEAN:
        return integer != 0;
      default:
        return getString();
    }
  }

  @Override
  public String toString() {
    switch (type) {
      case STRING:
        return identifier + "=\"" + getString() + "\"";
      case BOOLEAN:
        return identifier + "=" + (integer != 0 ? "true" : "false");
      default:
        return identifier + "=" + integer;
    }
  }
}
