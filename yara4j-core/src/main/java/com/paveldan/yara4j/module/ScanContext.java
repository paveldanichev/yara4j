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
}
