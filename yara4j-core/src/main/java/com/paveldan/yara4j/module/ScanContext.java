package com.paveldan.yara4j.module;

import java.util.List;

/** Information about the current scan, available to modules. */
public interface ScanContext {
  /**
   * Size of the scanned file, or {@link com.paveldan.yara4j.object.YObject#UNDEFINED} if unknown.
   */
  long fileSize();

  /** Memory blocks being scanned. */
  List<MemoryBlock> blocks();

  /** The first memory block, or null if no data. */
  default MemoryBlock firstBlock() {
    List<MemoryBlock> b = blocks();
    return b.isEmpty() ? null : b.get(0);
  }

  /** True if scanning process memory rather than a file (always false in yara4j). */
  default boolean isProcessMemory() {
    return false;
  }

  /** Sends a message to the scan callback (used by the console module). */
  void consoleLog(String message);

  /** Returns the root structure of a module loaded in this scan, or null. */
  com.paveldan.yara4j.object.YStructure moduleObject(String name);

  /**
   * Aborts the scan with {@link com.paveldan.yara4j.ErrorCode#SCAN_TIMEOUT} if its timeout has
   * expired. A {@link com.paveldan.yara4j.util.BinaryReader} created with this context calls it
   * as it reads; modules should also call it, or {@link
   * com.paveldan.yara4j.util.BinaryReader#tick} which calls it every few hundred iterations, in
   * loops whose number of iterations depends on the scanned data and that can iterate without
   * reading it. The exception thrown is unchecked and must not be caught by the module.
   */
  default void checkTimeout() {}
}
