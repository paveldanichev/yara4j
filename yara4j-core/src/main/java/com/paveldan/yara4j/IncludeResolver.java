package com.paveldan.yara4j;

import java.io.IOException;

/** Resolves {@code include "..."} directives in rules. */
@FunctionalInterface
public interface IncludeResolver {
  /**
   * Returns the content of the included rules, or null if they can't be found.
   *
   * @param includeName the name used in the include directive (already combined with the
   *     directory of the including file when using the default resolver).
   * @param callingFileName name of the file containing the include directive, or null.
   * @param namespace namespace where the rules are being compiled.
   */
  byte[] resolve(String includeName, String callingFileName, String namespace) throws IOException;
}
