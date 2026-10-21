package com.paveldan.yara4j.internal.exec;

/**
 * Executable node of a rule condition. Integer, boolean and float values are returned by {@link
 * #evalLong} (floats as raw IEEE-754 bits), with {@link
 * com.paveldan.yara4j.object.YObject#UNDEFINED} representing undefined values, exactly like
 * libyara's YR_VALUE. Strings (byte[]), objects (YObject) and regexps are returned by {@link
 * #evalObj}, with null representing undefined.
 */
public abstract class Node {
  public long evalLong(ExecContext ctx) {
    throw new UnsupportedOperationException(getClass().getSimpleName());
  }

  public Object evalObj(ExecContext ctx) {
    throw new UnsupportedOperationException(getClass().getSimpleName());
  }
}
