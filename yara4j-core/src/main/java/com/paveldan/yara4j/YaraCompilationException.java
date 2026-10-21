package com.paveldan.yara4j;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/** Thrown when rules fail to compile. Contains the compiler errors and warnings. */
public final class YaraCompilationException extends YaraException {
  private static final long serialVersionUID = 1L;

  private final transient List<CompilerMessage> messages;

  public YaraCompilationException(ErrorCode code, List<CompilerMessage> messages) {
    super(code, describe(messages));
    this.messages = Collections.unmodifiableList(messages);
  }

  private static String describe(List<CompilerMessage> messages) {
    return messages.stream()
        .filter(m -> m.getLevel() == CompilerMessage.Level.ERROR)
        .map(CompilerMessage::toString)
        .collect(Collectors.joining("\n"));
  }

  public List<CompilerMessage> getMessages() {
    return messages;
  }

  public List<CompilerMessage> getErrors() {
    return messages.stream()
        .filter(m -> m.getLevel() == CompilerMessage.Level.ERROR)
        .collect(Collectors.toList());
  }
}
