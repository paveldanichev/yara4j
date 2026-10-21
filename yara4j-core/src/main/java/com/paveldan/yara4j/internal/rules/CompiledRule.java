package com.paveldan.yara4j.internal.rules;

import java.util.ArrayList;
import java.util.List;
import com.paveldan.yara4j.internal.exec.Node;

/** A compiled rule (libyara's YR_RULE). */
public final class CompiledRule {
  public static final int FLAGS_PRIVATE = 0x01;
  public static final int FLAGS_GLOBAL = 0x02;
  public static final int FLAGS_NULL = 0x04;
  public static final int FLAGS_DISABLED = 0x08;

  public final String identifier;
  public final int idx;
  public final Namespace ns;
  public int flags;
  public final List<String> tags = new ArrayList<>();
  public final List<CompiledMeta> metas = new ArrayList<>();
  /** All the strings of the rule, including fragments of chained strings. */
  public final List<CompiledString> strings = new ArrayList<>();
  public Node condition;
  public int requiredStrings;
  public int numAtoms;

  public CompiledRule(String identifier, int idx, Namespace ns, int flags) {
    this.identifier = identifier;
    this.idx = idx;
    this.ns = ns;
    this.flags = flags;
  }

  public boolean isPrivate() {
    return (flags & FLAGS_PRIVATE) != 0;
  }

  public boolean isGlobal() {
    return (flags & FLAGS_GLOBAL) != 0;
  }

  public boolean isDisabled() {
    return (flags & FLAGS_DISABLED) != 0;
  }
}
