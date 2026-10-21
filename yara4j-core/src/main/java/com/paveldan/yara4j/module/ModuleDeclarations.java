package com.paveldan.yara4j.module;

import java.util.ArrayDeque;
import java.util.Deque;
import com.paveldan.yara4j.object.YArray;
import com.paveldan.yara4j.object.YDictionary;
import com.paveldan.yara4j.object.YFloat;
import com.paveldan.yara4j.object.YFunction;
import com.paveldan.yara4j.object.YInteger;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YString;
import com.paveldan.yara4j.object.YStructure;

/**
 * Builder used by modules for declaring their objects. Mirrors the begin_struct, declare_integer,
 * declare_function, etc. macros from libyara.
 */
public final class ModuleDeclarations {
  private final Deque<YStructure> stack = new ArrayDeque<>();

  public ModuleDeclarations(YStructure module) {
    stack.push(module);
  }

  private YStructure top() {
    return stack.peek();
  }

  private void add(YObject o) {
    if (!top().addMember(o)) {
      throw new IllegalStateException("duplicated structure member: " + o.identifier());
    }
  }

  public ModuleDeclarations beginStruct(String name) {
    YStructure s = new YStructure(name);
    add(s);
    stack.push(s);
    return this;
  }

  public ModuleDeclarations beginStructArray(String name) {
    YArray a = new YArray(name);
    YStructure s = new YStructure(name);
    a.setPrototype(s);
    add(a);
    stack.push(s);
    return this;
  }

  public ModuleDeclarations beginStructDictionary(String name) {
    YDictionary d = new YDictionary(name);
    YStructure s = new YStructure(name);
    d.setPrototype(s);
    add(d);
    stack.push(s);
    return this;
  }

  public ModuleDeclarations endStruct(String name) {
    YStructure s = stack.pop();
    if (!s.identifier().equals(name)) {
      throw new IllegalStateException("unbalanced beginStruct/endStruct: " + name);
    }
    return this;
  }

  public ModuleDeclarations endStructArray(String name) {
    return endStruct(name);
  }

  public ModuleDeclarations endStructDictionary(String name) {
    return endStruct(name);
  }

  public ModuleDeclarations declareInteger(String name) {
    add(new YInteger(name));
    return this;
  }

  public ModuleDeclarations declareIntegerArray(String name) {
    YArray a = new YArray(name);
    a.setPrototype(new YInteger(name));
    add(a);
    return this;
  }

  public ModuleDeclarations declareIntegerDictionary(String name) {
    YDictionary d = new YDictionary(name);
    d.setPrototype(new YInteger(name));
    add(d);
    return this;
  }

  public ModuleDeclarations declareFloat(String name) {
    add(new YFloat(name));
    return this;
  }

  public ModuleDeclarations declareFloatArray(String name) {
    YArray a = new YArray(name);
    a.setPrototype(new YFloat(name));
    add(a);
    return this;
  }

  public ModuleDeclarations declareFloatDictionary(String name) {
    YDictionary d = new YDictionary(name);
    d.setPrototype(new YFloat(name));
    add(d);
    return this;
  }

  public ModuleDeclarations declareString(String name) {
    add(new YString(name));
    return this;
  }

  public ModuleDeclarations declareStringArray(String name) {
    YArray a = new YArray(name);
    a.setPrototype(new YString(name));
    add(a);
    return this;
  }

  public ModuleDeclarations declareStringDictionary(String name) {
    YDictionary d = new YDictionary(name);
    d.setPrototype(new YString(name));
    add(d);
    return this;
  }

  /**
   * Declares a function. Calling it several times with the same name declares overloads, which
   * must have the same return type.
   *
   * @param name function name.
   * @param argumentsFormat one character per argument: i (integer), f (float), s (string), r
   *     (regexp), b (boolean).
   * @param returnFormat i, f or s.
   */
  public ModuleDeclarations declareFunction(
      String name, String argumentsFormat, String returnFormat, ModuleFunction code) {
    YObject ret;
    switch (returnFormat.charAt(0)) {
      case 'i':
        ret = new YInteger("result");
        break;
      case 's':
        ret = new YString("result");
        break;
      case 'f':
        ret = new YFloat("result");
        break;
      default:
        throw new IllegalArgumentException("invalid return format: " + returnFormat);
    }
    YObject existing = top().field(name);
    YFunction f;
    if (existing instanceof YFunction) {
      f = (YFunction) existing;
      if (f.returnObject().type() != ret.type()) {
        throw new IllegalStateException("wrong return type for overloaded function " + name);
      }
    } else {
      f = new YFunction(name, ret);
      add(f);
    }
    if (!f.addOverload(argumentsFormat, code)) {
      throw new IllegalStateException("too many overloads for function " + name);
    }
    return this;
  }
}
