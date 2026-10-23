package com.paveldan.yara4j.internal.exec;

/** A list of matches sorted by offset (libyara's YR_MATCHES). */
public final class MatchList {
  public Match head;
  public Match tail;
  public int count;
  /**
   * The matches and their absolute offsets in arrays, built when conditions need them, so that
   * "@a[i]" or "$a at x" in loops don't walk the list each time.
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
    build();
    return i >= 0 && i < array.length ? array[(int) i] : null;
  }

  /** The index of the first match whose absolute offset is at least offset, or count. */
  int lowerBound(long offset) {
    build();
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
    int end = hi == Long.MAX_VALUE ? offsets.length : lowerBound(hi + 1);
    return end - start;
  }

  /** True if a match has its absolute offset in [lo, hi]. */
  boolean anyIn(long lo, long hi) {
    int i = lowerBound(lo);
    return i < offsets.length && offsets[i] <= hi;
  }
}
