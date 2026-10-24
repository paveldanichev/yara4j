package com.paveldan.yara4j.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;
import org.junit.jupiter.api.Test;

class CopyCacheTest {

  @Test
  void strnlenMatchesBinaryReader() {
    // Every length found through the shared ranges, a few directly, and all directly.
    for (int maxUnsharedLength : new int[] {0, 8, CopyCache.MAX_UNSHARED_LENGTH}) {
      strnlenMatchesBinaryReader(maxUnsharedLength);
    }
  }

  private static void strnlenMatchesBinaryReader(int maxUnsharedLength) {
    Random r = new Random(3);
    for (int round = 0; round < 50; round++) {
      // Few NULs, so that the ranges found by the queries overlap and get joined.
      byte[] data = new byte[1 + r.nextInt(300)];
      for (int i = 0; i < data.length; i++) {
        data[i] = r.nextInt(20) == 0 ? 0 : (byte) (1 + r.nextInt(255));
      }
      BinaryReader reader = new BinaryReader(data);
      CopyCache cache = new CopyCache(reader, 0, maxUnsharedLength);
      for (int q = 0; q < 200; q++) {
        long offset = r.nextInt(data.length + 4) - 2;
        long max = r.nextInt(data.length + 4) - 2;
        assertEquals(reader.strnlen(offset, max), cache.strnlen(offset, max));
      }
    }
  }

  @Test
  void copiesAreSharedWithinTheBudget() {
    BinaryReader reader = new BinaryReader(new byte[100]);
    CopyCache cache = new CopyCache(reader, 40, 0);
    byte[] a = cache.bytes(10, 20);
    assertSame(a, cache.bytes(10, 20));
    assertEquals(19, cache.bytes(10, 19).length);
    assertFalse(cache.refused());
    // 39 bytes copied: the copy of 20 more bytes is refused, the shared one still returned.
    assertNull(cache.bytes(50, 20));
    assertTrue(cache.refused());
    assertSame(a, cache.bytes(10, 20));
  }

  @Test
  void shortCopiesAreOutsideTheBudget() {
    int n = CopyCache.MAX_UNSHARED_LENGTH;
    BinaryReader reader = new BinaryReader(new byte[4 * n]);
    CopyCache cache = new CopyCache(reader, n);
    assertEquals(n, cache.bytes(0, n).length);
    assertEquals(n, cache.bytes(n, n).length);
    assertFalse(cache.refused());
    assertNull(cache.bytes(0, 2 * n));
    assertTrue(cache.refused());
  }
}
