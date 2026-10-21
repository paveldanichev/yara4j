package com.paveldan.yara4j.internal.re;

import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.internal.YaraError;

/** Emits code for regular expression ASTs. Port of the emitting functions in libyara's re.c. */
public final class ReEmitter {
  private static final int EMIT_BACKWARDS = 0x01;
  private static final int EMIT_DONT_SET_FORWARDS_CODE = 0x02;
  private static final int EMIT_DONT_SET_BACKWARDS_CODE = 0x04;

  private final ReCode code;
  private int nextSplitId;

  private ReEmitter(ReCode code) {
    this.code = code;
  }

  /**
   * Emits code for the AST, followed by a MATCH instruction.
   *
   * @return offset where the code starts.
   */
  public static int emit(ReAst ast, ReCode code, boolean backwards) {
    ReEmitter e = new ReEmitter(code);
    int start = code.offset();
    e.emitNode(ast.root, backwards ? EMIT_BACKWARDS : 0);
    code.u8(Re.OP_MATCH);
    return start;
  }

  private static YaraError tooLarge() {
    return new YaraError(ErrorCode.REGULAR_EXPRESSION_TOO_LARGE);
  }

  /** Emits a split instruction, returns the offset of its jump argument. */
  private int emitSplit(int opcode, int argument) {
    if (nextSplitId == Re.MAX_SPLIT_ID) {
      throw new YaraError(ErrorCode.REGULAR_EXPRESSION_TOO_COMPLEX);
    }
    code.u8(opcode);
    code.u8(nextSplitId++);
    int argRef = code.offset();
    code.u16(argument);
    return argRef;
  }

  /** Returns the offset of the first instruction emitted for the node. */
  private int emitNode(ReNode node, int flags) {
    int instructionRef = -1;
    switch (node.type) {
      case ReNode.LITERAL:
        instructionRef = code.offset();
        code.u8(Re.OP_LITERAL);
        code.u8(node.value);
        break;
      case ReNode.NOT_LITERAL:
        instructionRef = code.offset();
        code.u8(Re.OP_NOT_LITERAL);
        code.u8(node.value);
        break;
      case ReNode.MASKED_LITERAL:
        instructionRef = code.offset();
        code.u8(Re.OP_MASKED_LITERAL);
        code.u16(node.mask << 8 | node.value);
        break;
      case ReNode.MASKED_NOT_LITERAL:
        instructionRef = code.offset();
        code.u8(Re.OP_MASKED_NOT_LITERAL);
        code.u16(node.mask << 8 | node.value);
        break;
      case ReNode.WORD_CHAR:
        instructionRef = code.offset();
        code.u8(Re.OP_WORD_CHAR);
        break;
      case ReNode.NON_WORD_CHAR:
        instructionRef = code.offset();
        code.u8(Re.OP_NON_WORD_CHAR);
        break;
      case ReNode.WORD_BOUNDARY:
        instructionRef = code.offset();
        code.u8(Re.OP_WORD_BOUNDARY);
        break;
      case ReNode.NON_WORD_BOUNDARY:
        instructionRef = code.offset();
        code.u8(Re.OP_NON_WORD_BOUNDARY);
        break;
      case ReNode.SPACE:
        instructionRef = code.offset();
        code.u8(Re.OP_SPACE);
        break;
      case ReNode.NON_SPACE:
        instructionRef = code.offset();
        code.u8(Re.OP_NON_SPACE);
        break;
      case ReNode.DIGIT:
        instructionRef = code.offset();
        code.u8(Re.OP_DIGIT);
        break;
      case ReNode.NON_DIGIT:
        instructionRef = code.offset();
        code.u8(Re.OP_NON_DIGIT);
        break;
      case ReNode.ANY:
        instructionRef = code.offset();
        code.u8(Re.OP_ANY);
        break;
      case ReNode.CLASS:
        instructionRef = code.offset();
        code.u8(Re.OP_CLASS);
        code.u8(node.reClass.negated ? 1 : 0);
        code.bytes(node.reClass.bitmap);
        break;
      case ReNode.ANCHOR_START:
        instructionRef = code.offset();
        code.u8(Re.OP_MATCH_AT_START);
        break;
      case ReNode.ANCHOR_END:
        instructionRef = code.offset();
        code.u8(Re.OP_MATCH_AT_END);
        break;
      case ReNode.EMPTY:
        // No code is emitted for empty nodes, instructionRef remains null (-1).
        break;
      case ReNode.CONCAT:
        {
          boolean back = (flags & EMIT_BACKWARDS) != 0;
          instructionRef = emitNode(back ? node.childrenTail : node.childrenHead, flags);
          ReNode child = back ? node.childrenTail.prevSibling : node.childrenHead.nextSibling;
          while (child != null) {
            emitNode(child, flags);
            child = back ? child.prevSibling : child.nextSibling;
          }
          break;
        }
      case ReNode.PLUS:
        {
          instructionRef = emitNode(node.childrenHead, flags);
          int bookmark1 = code.offset();
          if (instructionRef - bookmark1 < Short.MIN_VALUE) {
            throw tooLarge();
          }
          emitSplit(node.greedy ? Re.OP_SPLIT_B : Re.OP_SPLIT_A, instructionRef - bookmark1);
          break;
        }
      case ReNode.STAR:
        {
          instructionRef = code.offset();
          int splitOffsetRef = emitSplit(node.greedy ? Re.OP_SPLIT_A : Re.OP_SPLIT_B, 0);
          emitNode(node.childrenHead, flags);
          int bookmark1 = code.offset();
          if (instructionRef - bookmark1 < Short.MIN_VALUE) {
            throw tooLarge();
          }
          code.u8(Re.OP_JUMP);
          code.u16(instructionRef - bookmark1);
          bookmark1 = code.offset();
          if (bookmark1 - instructionRef > Short.MAX_VALUE) {
            throw tooLarge();
          }
          code.putU16(splitOffsetRef, bookmark1 - instructionRef);
          break;
        }
      case ReNode.ALT:
        {
          instructionRef = code.offset();
          int splitOffsetRef = emitSplit(Re.OP_SPLIT_A, 0);
          emitNode(node.childrenHead, flags);
          int jmpInstructionRef = code.offset();
          code.u8(Re.OP_JUMP);
          int jmpOffsetRef = code.offset();
          code.u16(0);
          int bookmark1 = code.offset();
          if (bookmark1 - instructionRef > Short.MAX_VALUE) {
            throw tooLarge();
          }
          code.putU16(splitOffsetRef, bookmark1 - instructionRef);
          emitNode(node.childrenTail, flags);
          bookmark1 = code.offset();
          if (bookmark1 - jmpInstructionRef > Short.MAX_VALUE) {
            throw tooLarge();
          }
          code.putU16(jmpOffsetRef, bookmark1 - jmpInstructionRef);
          break;
        }
      case ReNode.RANGE_ANY:
        instructionRef = code.offset();
        code.u8(node.greedy ? Re.OP_REPEAT_ANY_GREEDY : Re.OP_REPEAT_ANY_UNGREEDY);
        code.u16(node.value);
        code.u16(node.mask);
        break;
      case ReNode.RANGE:
        {
          int start = node.value;
          int end = node.mask;
          boolean emitProlog = start > 0;
          boolean emitRepeat = end > start + 1 || end > 2;
          boolean emitSplit = end > start;
          boolean emitEpilog = end > start || end > 1;
          if (emitProlog) {
            instructionRef = emitNode(node.childrenHead, flags);
          }
          if (emitRepeat) {
            int min = start;
            int max = end;
            if (emitProlog) {
              max--;
              min--;
            }
            if (emitSplit) {
              max--;
            } else {
              min--;
              max--;
            }
            int bookmark1 = code.offset();
            if (!emitProlog) {
              instructionRef = bookmark1;
            }
            code.u8(node.greedy ? Re.OP_REPEAT_START_GREEDY : Re.OP_REPEAT_START_UNGREEDY);
            int repeatStartArgsRef = code.offset();
            code.u16(min);
            code.u16(max);
            code.i32(0);
            int bookmark2 = code.offset();
            emitNode(
                node.childrenHead,
                flags | EMIT_DONT_SET_FORWARDS_CODE | EMIT_DONT_SET_BACKWARDS_CODE);
            int bookmark3 = code.offset();
            code.u8(node.greedy ? Re.OP_REPEAT_END_GREEDY : Re.OP_REPEAT_END_UNGREEDY);
            code.u16(min);
            code.u16(max);
            code.i32(bookmark2 - bookmark3);
            int bookmark4 = code.offset();
            code.putI32(repeatStartArgsRef + 4, bookmark4 - bookmark1);
          }
          int splitOffsetRef = -1;
          int bookmark1 = 0;
          if (emitSplit) {
            bookmark1 = code.offset();
            splitOffsetRef = emitSplit(node.greedy ? Re.OP_SPLIT_A : Re.OP_SPLIT_B, 0);
          }
          if (emitEpilog) {
            int r =
                emitNode(
                    node.childrenHead, emitProlog ? flags | EMIT_DONT_SET_FORWARDS_CODE : flags);
            if (!(emitProlog || emitRepeat)) {
              instructionRef = r;
            }
          }
          if (emitSplit) {
            int bookmark2 = code.offset();
            if (bookmark2 - bookmark1 > Short.MAX_VALUE) {
              throw tooLarge();
            }
            code.putU16(splitOffsetRef, bookmark2 - bookmark1);
          }
          break;
        }
      default:
        throw new IllegalStateException("unexpected node type " + node.type);
    }

    if ((flags & EMIT_BACKWARDS) != 0) {
      if ((flags & EMIT_DONT_SET_BACKWARDS_CODE) == 0) {
        node.backwardCodeRef = code.offset();
      }
    } else {
      if ((flags & EMIT_DONT_SET_FORWARDS_CODE) == 0) {
        node.forwardCodeRef = instructionRef;
      }
    }
    return instructionRef;
  }

  // ---------------------------------------------------------------------------------------------
  // AST utilities

  /**
   * If the regexp is just a literal string returns its bytes, or null otherwise. Port of
   * yr_re_ast_extract_literal.
   */
  public static byte[] extractLiteral(ReAst ast) {
    ReNode root = ast.root;
    if (root.type == ReNode.LITERAL) {
      return new byte[] {(byte) root.value};
    }
    if (root.type != ReNode.CONCAT) {
      return null;
    }
    int length = 0;
    ReNode child = root.childrenTail;
    while (child != null && child.type == ReNode.LITERAL) {
      length++;
      child = child.prevSibling;
    }
    if (child != null) {
      return null;
    }
    byte[] r = new byte[length];
    child = root.childrenTail;
    while (child != null) {
      r[--length] = (byte) child.value;
      child = child.prevSibling;
    }
    return r;
  }

  private static boolean hasUnboundedQuantifierForDot(ReNode node) {
    if ((node.type == ReNode.STAR || node.type == ReNode.PLUS)
        && node.childrenHead.type == ReNode.ANY) {
      return true;
    }
    if (node.type == ReNode.RANGE_ANY && node.mask == Re.MAX_RANGE) {
      return true;
    }
    if (node.type == ReNode.CONCAT) {
      ReNode child = node.childrenTail;
      while (child != null) {
        if (hasUnboundedQuantifierForDot(child)) {
          return true;
        }
        child = child.prevSibling;
      }
    }
    return false;
  }

  /** Detects the use of .*, .+ or .{x,} in a regexp. */
  public static boolean hasUnboundedQuantifierForDot(ReAst ast) {
    return hasUnboundedQuantifierForDot(ast.root);
  }

  /** Result of {@link #splitAtChainingPoint}. */
  public static final class Split {
    public ReAst remainder;
    public int minGap;
    public int maxGap;
  }

  /** Port of yr_re_ast_split_at_chaining_point. Modifies ast in place. */
  public static Split splitAtChainingPoint(ReAst ast) {
    Split r = new Split();
    if (ast.root.type != ReNode.CONCAT) {
      return r;
    }
    ReNode child = ast.root.childrenHead;
    while (child != null) {
      if (!child.greedy
          && child.type == ReNode.RANGE_ANY
          && child.prevSibling != null
          && child.nextSibling != null
          && (child.value > Re.STRING_CHAINING_THRESHOLD
              || child.mask > Re.STRING_CHAINING_THRESHOLD)) {
        ReAst rem = new ReAst();
        ReNode concat = new ReNode(ReNode.CONCAT);
        concat.childrenHead = child.nextSibling;
        concat.childrenTail = ast.root.childrenTail;
        ast.root.childrenTail = child.prevSibling;
        child.prevSibling.nextSibling = null;
        child.nextSibling.prevSibling = null;
        r.minGap = child.value;
        r.maxGap = child.mask;
        rem.root = concat;
        rem.flags = ast.flags;
        r.remainder = rem;
        return r;
      }
      child = child.nextSibling;
    }
    return r;
  }
}
