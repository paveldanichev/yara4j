package com.paveldan.yara4j.internal.exec;

/** A list of matches sorted by offset (libyara's YR_MATCHES). */
public final class MatchList {
  public Match head;
  public Match tail;
  public int count;

  void clear() {
    head = null;
    tail = null;
    count = 0;
  }
}
