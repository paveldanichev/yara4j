package com.paveldan.yara4j;

/** Result returned by scan callbacks (CALLBACK_CONTINUE, CALLBACK_ABORT, CALLBACK_ERROR). */
public enum CallbackResult {
  /** Continue the scan. */
  CONTINUE,
  /** Stop the scan, without error. */
  ABORT,
  /** Stop the scan with ERROR_CALLBACK_ERROR. */
  ERROR
}
