package com.paveldan.yara4j.internal.exec;

/** A list of matches sorted by offset (libyara's YR_MATCHES). */
public final class MatchList {
  /**
   * Number of matches walked from the head before building the arrays, so that "$a at 0" or
   * "@a[1]" find their answer at the start of a long list without copying it.
   */
  private static final int LINEAR_SCAN = 16;

  public Match head;
  public Match tail;
  public int count;
  /**
   * The matches and their absolute offsets in arrays, built when conditions need matches past
   * the first few, so that "@a[i]" or "$a at x" in loops don't walk the list each time.
   */
  private Match[] array;

  private long[] offsets;

  void clear() {
    head = null;
    tail = null;
    count = 0;
    changed();
  }

  /** Called when matches are added or removed. */
  void changed() {
    array = null;
    offsets = null;
  }

  private void build() {
    if (array == null) {
      Match[] a = new Match[count];
      long[] o = new long[count];
      int i = 0;
      for (Match m = head; m != null && i < a.length; m = m.next, i++) {
        a[i] = m;
        o[i] = m.base + m.offset;
      }
      array = a;
      offsets = o;
    }
  }

  /** The i-th match (from 0), or null. */
  Match get(long i) {
    if (i < 0 || i >= count) {
      return null;
    }
    if (array == null && i < LINEAR_SCAN) {
      Match m = head;
      for (long k = 0; k < i && m != null; k++) {
        m = m.next;
      }
      return m;
    }
    build();
    return array[(int) i];
  }

  /** The index of the first match whose absolute offset is at least offset, or count. */
  int lowerBound(long offset) {
    if (array == null) {
      int i = 0;
      for (Match m = head; m != null && i < LINEAR_SCAN; m = m.next, i++) {
        if (m.base + m.offset >= offset) {
          return i;
        }
      }
      if (i < LINEAR_SCAN) {
        return i;
      }
      build();
    }
    int lo = 0;
    int hi = offsets.length;
    while (lo < hi) {
      int mid = (lo + hi) >>> 1;
      if (offsets[mid] < offset) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }

  /** The number of matches whose absolute offset is in [lo, hi]. */
  int countIn(long lo, long hi) {
    if (lo > hi) {
      return 0;
    }
    int start = lowerBound(lo);
    int end = hi == Long.MAX_VALUE ? count : lowerBound(hi + 1);
    return end - start;
  }

  /** True if a match has its absolute offset in [lo, hi]. */
  boolean anyIn(long lo, long hi) {
    Match m = get(lowerBound(lo));
    return m != null && m.base + m.offset <= hi;
  }
}
