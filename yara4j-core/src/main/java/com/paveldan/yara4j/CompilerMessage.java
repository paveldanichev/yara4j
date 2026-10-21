package com.paveldan.yara4j;

/** An error or warning produced while compiling rules. */
public final class CompilerMessage {
  public enum Level {
    ERROR,
    WARNING
  }

  private final Level level;
  private final ErrorCode errorCode;
  private final String fileName;
  private final int line;
  private final String ruleIdentifier;
  private final String message;

  public CompilerMessage(
      Level level,
      ErrorCode errorCode,
      String fileName,
      int line,
      String ruleIdentifier,
      String message) {
    this.level = level;
    this.errorCode = errorCode;
    this.fileName = fileName;
    this.line = line;
    this.ruleIdentifier = ruleIdentifier;
    this.message = message;
  }

  public Level getLevel() {
    return level;
  }

  /** Error code for errors, null for warnings. */
  public ErrorCode getErrorCode() {
    return errorCode;
  }

  /** Name of the file being compiled, or null if compiling from a string. */
  public String getFileName() {
    return fileName;
  }

  public int getLine() {
    return line;
  }

  /** Identifier of the rule being compiled when the message was produced, or null. */
  public String getRuleIdentifier() {
    return ruleIdentifier;
  }

  public String getMessage() {
    return message;
  }

  /** Formats the message like the yara command-line tool does. */
  @Override
  public String toString() {
    String prefix = level == Level.ERROR ? "error" : "warning";
    StringBuilder sb = new StringBuilder(prefix);
    if (ruleIdentifier != null) {
      sb.append(": rule \"").append(ruleIdentifier).append('"');
    }
    sb.append(" in ").append(fileName == null ? "line" : fileName + "(" + line + ")");
    if (fileName == null) {
      sb.append(' ').append(line);
    }
    sb.append(": ").append(message);
    return sb.toString();
  }
}
