package com.paveldan.yara4j.internal.rules;

/** A rule namespace (libyara's YR_NAMESPACE). */
public final class Namespace {
  public final String name;
  public final int idx;

  public Namespace(String name, int idx) {
    this.name = name;
    this.idx = idx;
  }
}
