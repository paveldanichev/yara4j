package com.paveldan.yara4j;

import com.paveldan.yara4j.object.YStructure;

/**
 * Receives events during a scan. All methods have default implementations, override only the
 * ones you need. This is the equivalent of libyara's YR_CALLBACK_FUNC.
 */
public interface ScanCallback {

  /** A rule matched (CALLBACK_MSG_RULE_MATCHING). */
  default CallbackResult ruleMatching(RuleMatch match) {
    return CallbackResult.CONTINUE;
  }

  /** A rule didn't match (CALLBACK_MSG_RULE_NOT_MATCHING). */
  default CallbackResult ruleNotMatching(Rule rule) {
    return CallbackResult.CONTINUE;
  }

  /**
   * A module is about to be loaded (CALLBACK_MSG_IMPORT_MODULE). Return data for the module,
   * like the JSON report for the cuckoo module, or null.
   */
  default byte[] importModule(String moduleName) {
    return null;
  }

  /** A module has been loaded and its data can be inspected (CALLBACK_MSG_MODULE_IMPORTED). */
  default void moduleImported(String moduleName, YStructure module) {}

  /**
   * A string has too many matches (CALLBACK_MSG_TOO_MANY_MATCHES). Return true to continue the
   * scan ignoring further matches of the string, false to abort with ERROR_TOO_MANY_MATCHES.
   */
  default boolean tooManyMatches(Rule rule, String stringIdentifier) {
    return true;
  }

  /**
   * A string is slowing down the scan (CALLBACK_MSG_TOO_SLOW_SCANNING). Return true to
   * continue, false to abort with ERROR_TOO_SLOW_SCANNING.
   */
  default boolean tooSlowScanning(Rule rule, String stringIdentifier) {
    return true;
  }

  /** A message logged by the console module (CALLBACK_MSG_CONSOLE_LOG). */
  default void consoleLog(String message) {}

  /** The scan finished (CALLBACK_MSG_SCAN_FINISHED). */
  default void scanFinished() {}
}
