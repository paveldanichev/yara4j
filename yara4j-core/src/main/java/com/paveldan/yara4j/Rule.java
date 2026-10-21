package com.paveldan.yara4j;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import com.paveldan.yara4j.internal.rules.CompiledMeta;
import com.paveldan.yara4j.internal.rules.CompiledRule;
import com.paveldan.yara4j.internal.rules.CompiledString;

/** Information about a compiled rule. */
public class Rule {
  final CompiledRule rule;
  private final List<Meta> metas;
  private final List<String> stringIdentifiers;

  Rule(CompiledRule rule) {
    this.rule = rule;
    List<Meta> m = new ArrayList<>();
    for (CompiledMeta cm : rule.metas) {
      Meta.Type t =
          cm.type == CompiledMeta.TYPE_STRING
              ? Meta.Type.STRING
              : cm.type == CompiledMeta.TYPE_BOOLEAN ? Meta.Type.BOOLEAN : Meta.Type.INTEGER;
      m.add(new Meta(cm.identifier, t, cm.integer, cm.string));
    }
    this.metas = Collections.unmodifiableList(m);
    List<String> s = new ArrayList<>();
    for (CompiledString cs : rule.strings) {
      if (cs.chainedTo == null) {
        s.add(cs.identifier);
      }
    }
    this.stringIdentifiers = Collections.unmodifiableList(s);
  }

  Rule(Rule other) {
    this.rule = other.rule;
    this.metas = other.metas;
    this.stringIdentifiers = other.stringIdentifiers;
  }

  public String getIdentifier() {
    return rule.identifier;
  }

  public String getNamespace() {
    return rule.ns.name;
  }

  public List<String> getTags() {
    return Collections.unmodifiableList(rule.tags);
  }

  public List<Meta> getMetas() {
    return metas;
  }

  /** Returns the first metadata entry with the given identifier, or null. */
  public Meta getMeta(String identifier) {
    for (Meta m : metas) {
      if (m.getIdentifier().equals(identifier)) {
        return m;
      }
    }
    return null;
  }

  /** Identifiers of the strings defined in the rule. */
  public List<String> getStringIdentifiers() {
    return stringIdentifiers;
  }

  public boolean isPrivate() {
    return rule.isPrivate();
  }

  public boolean isGlobal() {
    return rule.isGlobal();
  }

  @Override
  public String toString() {
    return rule.ns.name + ":" + rule.identifier;
  }
}
