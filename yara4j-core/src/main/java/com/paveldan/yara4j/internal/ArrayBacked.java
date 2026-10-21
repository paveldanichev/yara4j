package com.paveldan.yara4j.internal;

/** Implemented by memory blocks backed by a byte array, used for faster scanning. */
public interface ArrayBacked {
  /** The backing array. It must not be modified. */
  byte[] array();

  /** Offset of the block data in the array. */
  int arrayOffset();
}
