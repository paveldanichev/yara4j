package com.paveldan.yara4j.module;

import java.nio.charset.StandardCharsets;
import com.paveldan.yara4j.object.YFunction;
import com.paveldan.yara4j.object.YObject;

/** Arguments and context of a module function invocation. Argument indexes start at 1. */
public final class FunctionCall {
  private final Object[] args;
  private final ScanContext context;
  private final YFunction function;

  public FunctionCall(Object[] args, ScanContext context, YFunction function) {
    this.args = args;
    this.context = context;
    this.function = function;
  }

  /** Integer (or boolean) argument n, 1-based. */
  public long integerArgument(int n) {
    return (Long) args[n - 1];
  }

  /** Float argument n, 1-based. */
  public double floatArgument(int n) {
    return (Double) args[n - 1];
  }

  /** String argument n, 1-based, as raw bytes. */
  public byte[] stringArgument(int n) {
    return (byte[]) args[n - 1];
  }

  /** String argument n, 1-based, decoded as ISO-8859-1 (lossless). */
  public String stringArgumentLatin1(int n) {
    return new String((byte[]) args[n - 1], StandardCharsets.ISO_8859_1);
  }

  /** Regular expression argument n, 1-based. */
  public Regexp regexpArgument(int n) {
    return (Regexp) args[n - 1];
  }

  public int argumentCount() {
    return args.length;
  }

  public ScanContext context() {
    return context;
  }

  /** The function object being invoked. */
  public YFunction function() {
    return function;
  }

  /** The structure containing the function. Equivalent to libyara's yr_parent(). */
  public YObject parent() {
    return function.parent();
  }

  /** The root object (module structure). Equivalent to libyara's yr_module(). */
  public YObject module() {
    return function.root();
  }
}
