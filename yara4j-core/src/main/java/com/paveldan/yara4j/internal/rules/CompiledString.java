package com.paveldan.yara4j.internal.rules;

import com.paveldan.yara4j.internal.compiler.StringFlags;
import com.paveldan.yara4j.object.YObject;

/** A string defined in a rule (libyara's YR_STRING). */
public final class CompiledString {
  public final String identifier;
  public int flags;
  /** Global index of the string within the rule set. */
  public final int idx;
  /** Index of the rule that defines the string. */
  public final int ruleIdx;
  /** Literal bytes for literal strings, null otherwise. */
  public byte[] string;
  public CompiledString chainedTo;
  public int chainGapMin;
  public int chainGapMax;
  public long fixedOffset = YObject.UNDEFINED;

  public CompiledString(String identifier, int idx, int ruleIdx) {
    this.identifier = identifier;
    this.idx = idx;
    this.ruleIdx = ruleIdx;
  }

  public int length() {
    return string == null ? 0 : string.length;
  }

  public boolean is(int flag) {
    return (flags & flag) != 0;
  }

  public boolean isPrivate() {
    return is(StringFlags.PRIVATE);
  }
}
