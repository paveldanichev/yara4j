package com.paveldan.yara4j;

import java.util.Collections;
import java.util.List;
import com.paveldan.yara4j.internal.rules.CompiledRule;

/** A matching rule together with the matches of its strings. */
public final class RuleMatch extends Rule {
  private final List<StringMatch> matches;

  RuleMatch(Rule rule, List<StringMatch> matches) {
    super(rule);
    this.matches = Collections.unmodifiableList(matches);
  }

  CompiledRule compiled() {
    return rule;
  }

  /** All the string matches, in string declaration order and then by offset. */
  public List<StringMatch> getStringMatches() {
    return matches;
  }

  /** Matches of non-private strings. */
  public List<StringMatch> getPublicStringMatches() {
    return matches.stream().filter(m -> !m.isPrivate()).collect(java.util.stream.Collectors.toList());
  }
}
