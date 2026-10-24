package com.paveldan.yara4j.util;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Copies of ranges of the scanned data for the values of a module, for formats where many
 * structures can reference the same data. A range copied before is shared instead of copied
 * again, and the total size of the copies is limited, so that a small file whose structures all
 * point to the same large range can't make the module allocate gigabytes. String lengths are
 * memoized for the same reason: finding the end of a long unterminated string for each of its
 * references would take quadratic time.
 *
 * <p>Ranges of up to {@link #MAX_UNSHARED_LENGTH} bytes are copied and scanned each time, outside
 * the budget: their copies take no more memory than the values that hold them, and sharing them
 * would cost more time than it saves in files with many short strings.
 */
public final class CopyCache {
  /** Length up to which ranges are copied and scanned without being shared. */
  public static final int MAX_UNSHARED_LENGTH = 256;

  private final BinaryReader r;
  private final int maxUnsharedLength;
  private long remaining;
  private boolean refused;
  /** The copies by offset (high 32 bits) and length (low 32 bits). */
  private final Map<Long, byte[]> copies = new HashMap<>();
  /** Ranges known to contain no NUL byte, mapped to the offset of the NUL that ends them. */
  private final TreeMap<Long, Long> nulAfter = new TreeMap<>();

  /** A cache allowing copies of more than {@link #MAX_UNSHARED_LENGTH} bytes up to budget. */
  public CopyCache(BinaryReader r, long budget) {
    this(r, budget, MAX_UNSHARED_LENGTH);
  }

  CopyCache(BinaryReader r, long budget, int maxUnsharedLength) {
    this.r = r;
    this.remaining = budget;
    this.maxUnsharedLength = maxUnsharedLength;
  }

  /**
   * A cache whose budget is a few times the size of the data, more than the copies needed by
   * the values of any well-formed file.
   */
  public static CopyCache forData(BinaryReader r) {
    return new CopyCache(r, budgetFor(r));
  }

  /** The budget of {@link #forData}, 4 times the size of the data plus 1 MiB. */
  public static long budgetFor(BinaryReader r) {
    return 4 * r.size() + (1 << 20);
  }

  /**
   * The bytes in [offset, offset + length), which must be within the data, or null if the copy
   * would exceed the budget. The returned array may be shared and must not be modified.
   */
  public byte[] bytes(long offset, int length) {
    if (length <= maxUnsharedLength) {
      return r.bytes(offset, length);
    }
    // Offsets and lengths are within the data, which a ByteBuffer limits to 2 GB.
    Long key = offset << 32 | (length & 0xFFFFFFFFL);
    byte[] b = copies.get(key);
    if (b == null) {
      if (length > remaining) {
        refused = true;
        return null;
      }
      b = r.bytes(offset, length);
      remaining -= length;
      copies.put(key, b);
    }
    return b;
  }

  /** True if {@link #bytes} returned null because the budget was exceeded. */
  public boolean refused() {
    return refused;
  }

  /** Same as {@link BinaryReader#strnlen}, in amortized constant time per call. */
  public int strnlen(long offset, long max) {
    if (offset < 0 || offset >= r.size()) {
      return -1;
    }
    long end = Math.min(r.size(), offset + max);
    long direct = Math.min(end - offset, maxUnsharedLength);
    int n = r.strnlen(offset, direct);
    if (n < direct || direct == end - offset) {
      return n;
    }
    long nul = nul(offset);
    return (int) (Math.min(nul, end) - offset);
  }

  /** Offset of the first NUL at or after offset, or the size of the data if there's none. */
  private long nul(long offset) {
    Map.Entry<Long, Long> e = nulAfter.floorEntry(offset);
    if (e != null && offset <= e.getValue()) {
      return e.getValue();
    }
    // Scan up to the next range found before, and join it instead of scanning it again.
    Long next = nulAfter.higherKey(offset);
    long limit = next == null ? r.size() : next;
    long p = offset + r.strnlen(offset, limit - offset);
    if (p == limit && next != null) {
      p = nulAfter.remove(next);
    }
    nulAfter.put(offset, p);
    return p;
  }
}
