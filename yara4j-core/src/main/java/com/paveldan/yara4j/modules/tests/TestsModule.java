package com.paveldan.yara4j.modules.tests;

import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.CStrings;

/** The "tests" module used by YARA's test suite. Port of libyara/modules/tests/tests.c. */
public final class TestsModule implements YaraModule {

  @Override
  public String name() {
    return "tests";
  }

  @Override
  public void declare(ModuleDeclarations d) {
    d.beginStruct("constants")
        .declareInteger("one")
        .declareInteger("two")
        .declareString("foo")
        .declareString("empty")
        .endStruct("constants");
    d.beginStruct("undefined").declareInteger("i").declareFloat("f").endStruct("undefined");
    d.declareString("module_data");
    d.declareIntegerArray("integer_array");
    d.declareStringArray("string_array");
    d.declareIntegerDictionary("integer_dict");
    d.declareStringDictionary("string_dict");
    d.beginStructArray("struct_array")
        .declareInteger("i")
        .declareString("s")
        .endStructArray("struct_array");
    d.beginStructDictionary("struct_dict")
        .declareInteger("i")
        .declareString("s")
        .endStructDictionary("struct_dict");
    d.beginStructDictionary("empty_struct_dict")
        .declareInteger("unused")
        .endStructDictionary("empty_struct_dict");
    d.beginStructArray("empty_struct_array");
    d.beginStructArray("struct_array").declareString("unused").endStructArray("struct_array");
    d.beginStructDictionary("struct_dict")
        .declareString("unused")
        .endStructDictionary("struct_dict");
    d.endStructArray("empty_struct_array");
    d.declareFunction("match", "rs", "i", TestsModule::match);
    d.declareFunction(
        "isum", "ii", "i", c -> c.integerArgument(1) + c.integerArgument(2));
    d.declareFunction(
        "isum",
        "iii",
        "i",
        c -> c.integerArgument(1) + c.integerArgument(2) + c.integerArgument(3));
    d.declareFunction("fsum", "ff", "f", c -> c.floatArgument(1) + c.floatArgument(2));
    d.declareFunction(
        "fsum", "fff", "f", c -> c.floatArgument(1) + c.floatArgument(2) + c.floatArgument(3));
    d.declareFunction(
        "length", "s", "i", c -> (long) CStrings.strlen(c.stringArgument(1)));
    d.declareFunction("empty", "", "s", c -> "");
    d.declareFunction("foobar", "i", "s", TestsModule::foobar);
  }

  private static Object match(FunctionCall c) {
    return (long) c.regexpArgument(1).match(c.context(), CStrings.cstr(c.stringArgument(2)));
  }

  private static Object foobar(FunctionCall c) {
    long arg = c.integerArgument(1);
    if (arg == 1) {
      return "foo";
    }
    if (arg == 2) {
      return "bar";
    }
    return "oops";
  }

  @Override
  public void load(ScanContext context, YStructure m, byte[] moduleData) {
    m.setInteger(1, "constants.one");
    m.setInteger(2, "constants.two");
    m.setString("foo", "constants.foo");
    m.setString("", "constants.empty");
    m.setInteger(1, "struct_array[1].i");
    m.setInteger(0, "integer_array[%i]", 0);
    m.setInteger(1, "integer_array[%i]", 1);
    m.setInteger(2, "integer_array[%i]", 2);
    m.setInteger(256, "integer_array[%i]", 256);
    m.setString("foo", "string_array[%i]", 0);
    m.setString("bar", "string_array[%i]", 1);
    m.setString("baz", "string_array[%i]", 2);
    m.setString("foo\0bar", "string_array[%i]", 3);
    m.setString("foo", "string_dict[%s]", "foo");
    m.setString("bar", "string_dict[\"bar\"]");
    m.setString("foo", "struct_dict[%s].s", "foo");
    m.setInteger(1, "struct_dict[%s].i", "foo");
    if (moduleData != null && moduleData.length > 0) {
      m.setString(moduleData, "module_data");
    }
  }
}
