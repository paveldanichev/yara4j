package com.paveldan.yara4j.util;

import java.nio.ByteBuffer;
import java.util.List;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ScanContext;

/**
 * Helpers for modules that process ranges of the scanned data spanning one or more memory
 * blocks, with the same semantics used by libyara's math and hash modules.
 */
public final class BlockData {
  private BlockData() {}

  /** Receives chunks of contiguous data. */
  @FunctionalInterface
  public interface Consumer {
    void accept(ByteBuffer data, int offset, int length);
  }

  /**
   * Feeds the data in [offset, offset + length) to the consumer. Returns false if the range is
   * undefined: invalid offset or length, or the range spans non contiguous blocks.
   */
  public static boolean forRange(ScanContext context, long offset, long length, Consumer consumer) {
    List<MemoryBlock> blocks = context.blocks();
    if (blocks.isEmpty()) {
      return false;
    }
    MemoryBlock first = blocks.get(0);
    if (offset < 0 || length < 0 || offset < first.base()) {
      return false;
    }
    boolean pastFirstBlock = false;
    for (MemoryBlock block : blocks) {
      long base = block.base();
      long size = block.size();
      if (offset >= base && offset < base + size) {
        long dataOffset = offset - base;
        long dataLen = Math.min(length, size - dataOffset);
        offset += dataLen;
        length -= dataLen;
        consumer.accept(block.data(), (int) dataOffset, (int) dataLen);
        pastFirstBlock = true;
      } else if (pastFirstBlock) {
        return false;
      }
      if (base + size >= offset + length) {
        break;
      }
    }
    return pastFirstBlock;
  }

  /** Feeds all the blocks, returns false if they are not contiguous starting at 0. */
  public static boolean forAll(ScanContext context, Consumer consumer) {
    long expectedNextOffset = 0;
    for (MemoryBlock block : context.blocks()) {
      if (expectedNextOffset != block.base()) {
        return false;
      }
      consumer.accept(block.data(), 0, block.size());
      expectedNextOffset = block.base() + block.size();
    }
    return true;
  }
}
