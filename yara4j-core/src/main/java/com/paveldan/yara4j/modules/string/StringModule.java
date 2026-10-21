package com.paveldan.yara4j.modules.string;

import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.CStrings;

/** The "string" module. Port of libyara/modules/string/string.c. */
public final class StringModule implements YaraModule {
  @Override
  public String name() {
    return "string";
  }

  private static Object toInt(byte[] s, int base) {
    CStrings.ParseResult r = CStrings.strtoll(s, base);
    if (r.overflow || r.end == 0 || r.end != CStrings.strlen(s)) {
      return YObject.UNDEFINED;
    }
    return r.value;
  }

  @Override
  public void declare(ModuleDeclarations d) {
    d.declareFunction("to_int", "s", "i", c -> toInt(c.stringArgument(1), 0));
    d.declareFunction(
        "to_int",
        "si",
        "i",
        c -> {
          long base = c.integerArgument(2);
          if (!(base == 0 || (base >= 2 && base <= 36))) {
            return YObject.UNDEFINED;
          }
          return toInt(c.stringArgument(1), (int) base);
        });
    d.declareFunction("length", "s", "i", c -> (long) c.stringArgument(1).length);
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {}
}
