package com.paveldan.yara4j;

/** Exception raised by yara4j, carrying the libyara-compatible {@link ErrorCode}. */
public class YaraException extends Exception {
  private static final long serialVersionUID = 1L;

  private final ErrorCode errorCode;

  public YaraException(ErrorCode errorCode) {
    this(errorCode, errorCode.name().toLowerCase().replace('_', ' '));
  }

  public YaraException(ErrorCode errorCode, String message) {
    super(message);
    this.errorCode = errorCode;
  }

  public YaraException(ErrorCode errorCode, String message, Throwable cause) {
    super(message, cause);
    this.errorCode = errorCode;
  }

  public ErrorCode getErrorCode() {
    return errorCode;
  }
}
