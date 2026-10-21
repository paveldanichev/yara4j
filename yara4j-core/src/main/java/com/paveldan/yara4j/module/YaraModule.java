package com.paveldan.yara4j.module;

import com.paveldan.yara4j.YaraException;
import com.paveldan.yara4j.object.YStructure;

/**
 * A YARA module. Modules declare a structure of objects (integers, strings, arrays, functions,
 * etc.) that become available to rule conditions after {@code import "name"}, and fill the
 * values for each scanned file in {@link #load}.
 *
 * <p>Modules are discovered with {@link java.util.ServiceLoader}, so third parties can provide
 * their own modules by registering an implementation of this interface in {@code
 * META-INF/services/com.paveldan.yara4j.module.YaraModule}.
 */
public interface YaraModule {

  /** Module name, as used in {@code import "name"}. */
  String name();

  /** Declares the module's objects. Equivalent to libyara's begin_declarations block. */
  void declare(ModuleDeclarations declarations);

  /**
   * Called once per scan for every module imported by the rules, before evaluating the
   * conditions.
   *
   * @param context the scan context, giving access to the scanned data.
   * @param module the module's structure, which must be populated with values.
   * @param moduleData optional data provided by the user for this module, or null.
   */
  void load(ScanContext context, YStructure module, byte[] moduleData) throws YaraException;

  /** Called after the scan finishes. */
  default void unload(YStructure module) {}
}
