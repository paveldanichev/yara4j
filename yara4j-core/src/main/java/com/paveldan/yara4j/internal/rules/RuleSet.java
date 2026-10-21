package com.paveldan.yara4j.internal.rules;

import java.util.List;
import com.paveldan.yara4j.internal.ac.AhoCorasick;

/** Immutable compiled rule set (libyara's YR_RULES). */
public final class RuleSet {
  public final List<CompiledRule> rules;
  public final List<CompiledString> strings;
  public final List<Namespace> namespaces;
  public final List<ExternalDef> externals;
  /** Names of imported modules, in import order. */
  public final List<String> imports;
  /** Names of root objects (externals and modules) referenced by index from conditions. */
  public final List<String> rootObjects;

  public final byte[] reCode;
  public final AhoCorasick.Tables ac;
  public final boolean[] noRequiredStrings;

  public RuleSet(
      List<CompiledRule> rules,
      List<CompiledString> strings,
      List<Namespace> namespaces,
      List<ExternalDef> externals,
      List<String> imports,
      List<String> rootObjects,
      byte[] reCode,
      AhoCorasick.Tables ac) {
    this.rules = rules;
    this.strings = strings;
    this.namespaces = namespaces;
    this.externals = externals;
    this.imports = imports;
    this.rootObjects = rootObjects;
    this.reCode = reCode;
    this.ac = ac;
    this.noRequiredStrings = new boolean[rules.size()];
    for (int i = 0; i < rules.size(); i++) {
      noRequiredStrings[i] = rules.get(i).requiredStrings == 0;
    }
  }
}
