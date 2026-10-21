package com.paveldan.yara4j.module;

import java.nio.ByteBuffer;

/** A block of scanned data. Files and buffers are usually scanned as a single block. */
public interface MemoryBlock {
  /** Base address (or offset) of the block. */
  long base();

  /** Size of the block in bytes. */
  int size();

  /**
   * Block data. The returned buffer is read-only, its position is 0 and its limit equals the
   * block size. Callers must use absolute get methods or duplicate the buffer.
   *
   * <p>The buffer is valid only during the scan: modules must not keep it (or views of it)
   * after {@link YaraModule#unload}, because a file mapping may be released when the scan ends,
   * and accessing an unmapped buffer crashes the JVM. Copy the bytes that must be kept.
   */
  ByteBuffer data();
}
