package com.paveldan.yara4j.internal.re;

/** Node of a regular expression abstract syntax tree (libyara's RE_NODE). */
public final class ReNode {
  public static final int LITERAL = 1;
  public static final int MASKED_LITERAL = 2;
  public static final int ANY = 3;
  public static final int CONCAT = 4;
  public static final int ALT = 5;
  public static final int RANGE = 6;
  public static final int STAR = 7;
  public static final int PLUS = 8;
  public static final int CLASS = 9;
  public static final int WORD_CHAR = 10;
  public static final int NON_WORD_CHAR = 11;
  public static final int SPACE = 12;
  public static final int NON_SPACE = 13;
  public static final int DIGIT = 14;
  public static final int NON_DIGIT = 15;
  public static final int EMPTY = 16;
  public static final int ANCHOR_START = 17;
  public static final int ANCHOR_END = 18;
  public static final int WORD_BOUNDARY = 19;
  public static final int NON_WORD_BOUNDARY = 20;
  public static final int RANGE_ANY = 21;
  public static final int NOT_LITERAL = 22;
  public static final int MASKED_NOT_LITERAL = 23;

  public final int type;
  /** value, count or start depending on the node type. */
  public int value;
  /** mask or end depending on the node type. */
  public int mask;

  public boolean greedy = true;
  public ReClass reClass;

  public ReNode childrenHead;
  public ReNode childrenTail;
  public ReNode prevSibling;
  public ReNode nextSibling;

  /** Offset of the forward code for this node within the RE code buffer, or -1. */
  public int forwardCodeRef = -1;
  /** Offset of the backward code for this node within the RE code buffer, or -1. */
  public int backwardCodeRef = -1;

  public ReNode(int type) {
    this.type = type;
  }

  public int start() {
    return value;
  }

  public int end() {
    return mask;
  }

  public void appendChild(ReNode child) {
    if (childrenHead == null) {
      childrenHead = child;
    }
    if (childrenTail != null) {
      childrenTail.nextSibling = child;
    }
    child.prevSibling = childrenTail;
    childrenTail = child;
  }

  public void prependChild(ReNode child) {
    child.nextSibling = childrenHead;
    if (childrenHead != null) {
      childrenHead.prevSibling = child;
    }
    childrenHead = child;
    if (childrenTail == null) {
      childrenTail = child;
    }
  }
}
