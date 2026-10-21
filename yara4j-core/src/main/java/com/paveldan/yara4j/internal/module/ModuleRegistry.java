package com.paveldan.yara4j.internal.module;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ServiceLoader;
import com.paveldan.yara4j.module.YaraModule;

/** Registry of available modules, discovered with ServiceLoader. */
public final class ModuleRegistry {
  private final Map<String, YaraModule> modules = new LinkedHashMap<>();

  private static volatile ModuleRegistry defaultRegistry;

  public static ModuleRegistry getDefault() {
    ModuleRegistry r = defaultRegistry;
    if (r == null) {
      synchronized (ModuleRegistry.class) {
        r = defaultRegistry;
        if (r == null) {
          r = new ModuleRegistry();
          r.loadServices(ModuleRegistry.class.getClassLoader());
          defaultRegistry = r;
        }
      }
    }
    return r;
  }

  public ModuleRegistry() {}

  public ModuleRegistry(ModuleRegistry other) {
    modules.putAll(other.modules);
  }

  public void loadServices(ClassLoader loader) {
    for (YaraModule m : ServiceLoader.load(YaraModule.class, loader)) {
      modules.putIfAbsent(m.name(), m);
    }
  }

  public void register(YaraModule module) {
    modules.put(module.name(), module);
  }

  public YaraModule get(String name) {
    return modules.get(name);
  }

  public Iterable<YaraModule> all() {
    return modules.values();
  }
}
