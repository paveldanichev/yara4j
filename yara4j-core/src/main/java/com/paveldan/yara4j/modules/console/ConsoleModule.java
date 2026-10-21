package com.paveldan.yara4j.modules.console;

import java.util.Locale;
import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BinaryReader;
import com.paveldan.yara4j.util.CStrings;

/** The "console" module. Port of libyara/modules/console/console.c. */
public final class ConsoleModule implements YaraModule {
  @Override
  public String name() {
    return "console";
  }

  private static String escape(byte[] s) {
    StringBuilder sb = new StringBuilder();
    for (byte b : s) {
      int c = b & 0xFF;
      if (CStrings.isPrint(c)) {
        sb.append((char) c);
      } else {
        sb.append(String.format("\\x%02x", c));
      }
    }
    return sb.toString();
  }

  private static String cstr(FunctionCall c, int n) {
    return BinaryReader.latin1(CStrings.cstr(c.stringArgument(n)));
  }

  private static Object log(FunctionCall c, String message) {
    c.context().consoleLog(message);
    return 1L;
  }

  private static String fmtFloat(double f) {
    if (Double.isNaN(f)) {
      return "nan";
    }
    if (Double.isInfinite(f)) {
      return f > 0 ? "inf" : "-inf";
    }
    return String.format(Locale.ROOT, "%f", f);
  }

  @Override
  public void declare(ModuleDeclarations d) {
    d.declareFunction("log", "s", "i", c -> log(c, escape(c.stringArgument(1))));
    d.declareFunction(
        "log", "ss", "i", c -> log(c, cstr(c, 1) + escape(c.stringArgument(2))));
    d.declareFunction("log", "i", "i", c -> log(c, Long.toString(c.integerArgument(1))));
    d.declareFunction(
        "log", "si", "i", c -> log(c, cstr(c, 1) + c.integerArgument(2)));
    d.declareFunction("log", "f", "i", c -> log(c, fmtFloat(c.floatArgument(1))));
    d.declareFunction(
        "log", "sf", "i", c -> log(c, cstr(c, 1) + fmtFloat(c.floatArgument(2))));
    d.declareFunction(
        "hex", "i", "i", c -> log(c, "0x" + Long.toHexString(c.integerArgument(1))));
    d.declareFunction(
        "hex",
        "si",
        "i",
        c -> log(c, cstr(c, 1) + "0x" + Long.toHexString(c.integerArgument(2))));
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {}
}
