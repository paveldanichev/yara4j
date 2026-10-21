package com.paveldan.yara4j.module;

/** A compiled regular expression passed as argument ("r") to module functions. */
public interface Regexp {
  /**
   * Returns true if the regexp matches somewhere in the given data, with the same semantics
   * used by the "matches" operator.
   */
  boolean matches(ScanContext context, byte[] data);

  /**
   * Equivalent of libyara's yr_re_match: returns the length of the match found, or -1 if the
   * regexp doesn't match.
   */
  int match(ScanContext context, byte[] data);
}
