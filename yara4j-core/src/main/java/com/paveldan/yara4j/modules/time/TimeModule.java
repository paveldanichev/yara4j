package com.paveldan.yara4j.modules.time;

import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YStructure;

/** The "time" module. Port of libyara/modules/time/time.c. */
public final class TimeModule implements YaraModule {
  @Override
  public String name() {
    return "time";
  }

  @Override
  public void declare(ModuleDeclarations d) {
    d.declareFunction("now", "", "i", c -> System.currentTimeMillis() / 1000);
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {}
}
