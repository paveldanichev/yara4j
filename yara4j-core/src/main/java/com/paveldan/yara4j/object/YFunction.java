package com.paveldan.yara4j.object;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import com.paveldan.yara4j.module.ModuleFunction;

/** Function object, with up to 10 overloads sharing the same return type. */
public final class YFunction extends YObject {
  public static final int MAX_OVERLOADS = 10;

  /** A function overload: argument format (like "is") and implementation. */
  public static final class Overload {
    public final String argumentsFormat;
    public final ModuleFunction code;

    Overload(String argumentsFormat, ModuleFunction code) {
      this.argumentsFormat = argumentsFormat;
      this.code = code;
    }
  }

  private final YObject returnObject;
  private final List<Overload> overloads;

  public YFunction(String identifier, YObject returnObject) {
    this(identifier, returnObject, new ArrayList<>());
  }

  private YFunction(String identifier, YObject returnObject, List<Overload> overloads) {
    super(identifier);
    this.returnObject = returnObject;
    this.overloads = overloads;
    returnObject.parent = this;
  }

  @Override
  public Type type() {
    return Type.FUNCTION;
  }

  /** Prototype of the returned value, its type is the function's return type. */
  public YObject returnObject() {
    return returnObject;
  }

  public List<Overload> overloads() {
    return Collections.unmodifiableList(overloads);
  }

  public boolean addOverload(String argumentsFormat, ModuleFunction code) {
    if (overloads.size() >= MAX_OVERLOADS) {
      return false;
    }
    overloads.add(new Overload(argumentsFormat, code));
    return true;
  }

  public Overload findOverload(String argumentsFormat) {
    for (Overload o : overloads) {
      if (o.argumentsFormat.equals(argumentsFormat)) {
        return o;
      }
    }
    return null;
  }

  @Override
  public YObject copy() {
    return new YFunction(identifier, returnObject.copy(), new ArrayList<>(overloads));
  }

  @Override
  void printValue(StringBuilder sb, String indentSpaces, int indent) {}
}
