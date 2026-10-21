package com.paveldan.yara4j.internal.exec;

/** A string match (libyara's YR_MATCH). Matches are kept in doubly linked lists. */
public final class Match {
  public long base;
  public long offset;
  public int matchLength;
  public byte[] data;
  public int chainLength;
  public boolean isPrivate;
  public int xorKey;
  Match prev;
  public Match next;

  public long absoluteOffset() {
    return base + offset;
  }
}
