package com.paveldan.yara4j.internal.ac;

import com.paveldan.yara4j.internal.rules.CompiledString;

/** An entry in the list of matches of an automaton state (libyara's YR_AC_MATCH). */
public final class AcMatch {
  public final CompiledString string;
  public final int backtrack;
  /** Offset of the forward regexp code, or -1. */
  public final int forwardCode;
  /** Offset of the backward regexp code, or -1. */
  public final int backwardCode;

  AcMatch next;

  AcMatch(CompiledString string, int backtrack, int forwardCode, int backwardCode) {
    this.string = string;
    this.backtrack = backtrack;
    this.forwardCode = forwardCode;
    this.backwardCode = backwardCode;
  }

  public AcMatch next() {
    return next;
  }
}
