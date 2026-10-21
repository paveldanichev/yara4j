package com.paveldan.yara4j.internal;

import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.YaraException;

/** Unchecked carrier for libyara error codes, used internally and converted at API boundaries. */
public final class YaraError extends RuntimeException {
  private static final long serialVersionUID = 1L;

  private final ErrorCode code;

  public YaraError(ErrorCode code) {
    super(code.name(), null, false, false);
    this.code = code;
  }

  public YaraError(ErrorCode code, String message) {
    super(message, null, false, false);
    this.code = code;
  }

  public ErrorCode code() {
    return code;
  }

  public YaraException toException() {
    return new YaraException(code, getMessage());
  }
}
