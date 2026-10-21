package com.paveldan.yara4j.internal.exec;

import static com.paveldan.yara4j.object.YObject.UNDEFINED;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.YaraException;
import com.paveldan.yara4j.internal.YaraError;
import com.paveldan.yara4j.internal.re.Re;
import com.paveldan.yara4j.internal.rules.CompiledString;
import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.Regexp;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.object.YArray;
import com.paveldan.yara4j.object.YDictionary;
import com.paveldan.yara4j.object.YFloat;
import com.paveldan.yara4j.object.YFunction;
import com.paveldan.yara4j.object.YInteger;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YString;
import com.paveldan.yara4j.object.YStructure;

/**
 * Executable nodes for rule conditions. Each node reproduces the semantics of the corresponding
 * opcodes in libyara's exec.c, including the propagation of undefined values.
 */
public final class Nodes {
  private Nodes() {}

  static final double DBL_EPSILON = Math.ulp(1.0);

  public static long bits(double d) {
    return Double.doubleToRawLongBits(d);
  }

  public static double dbl(long bits) {
    return Double.longBitsToDouble(bits);
  }

  // ---------------------------------------------------------------------------------------------
  // Constants

  public static final class IntConst extends Node {
    final long value;

    public IntConst(long value) {
      this.value = value;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      return value;
    }
  }

  public static final class FloatConst extends Node {
    final long value;

    public FloatConst(double value) {
      this.value = bits(value);
    }

    @Override
    public long evalLong(ExecContext ctx) {
      return value;
    }
  }

  public static final class StringConst extends Node {
    final byte[] value;

    public StringConst(byte[] value) {
      this.value = value;
    }

    @Override
    public Object evalObj(ExecContext ctx) {
      return value;
    }
  }

  /** A compiled regular expression used in conditions and as function argument. */
  public static final class CompiledRegexp implements Regexp {
    final byte[] code;
    final int offset;
    final int flags;

    CompiledRegexp(byte[] code, int offset, int flags) {
      this.code = code;
      this.offset = offset;
      this.flags = flags;
    }

    @Override
    public boolean matches(ScanContext context, byte[] data) {
      return match(context, data) >= 0;
    }

    @Override
    public int match(ScanContext context, byte[] data) {
      com.paveldan.yara4j.internal.re.ReExec exec =
          context instanceof ExecContext
              ? ((ExecContext) context).reExec
              : new com.paveldan.yara4j.internal.re.ReExec();
      return exec.exec(
          code, offset, ByteBuffer.wrap(data), 0, data.length, 0, flags | Re.FLAGS_SCAN, null);
    }
  }

  public static final class RegexpConst extends Node {
    final int offset;
    final int flags;

    public RegexpConst(int offset, int flags) {
      this.offset = offset;
      this.flags = flags;
    }

    @Override
    public Object evalObj(ExecContext ctx) {
      return new CompiledRegexp(ctx.rules.reCode, offset, flags);
    }

    /** In boolean contexts libyara evaluates the pointer to the regexp, which is non-zero. */
    @Override
    public long evalLong(ExecContext ctx) {
      return 1;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Boolean operators

  public static final class And extends Node {
    final Node left;
    final Node right;

    public And(Node left, Node right) {
      this.left = left;
      this.right = right;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r1 = left.evalLong(ctx);
      if (r1 != UNDEFINED && r1 == 0) {
        return r1;
      }
      long r2 = right.evalLong(ctx);
      if (r1 == UNDEFINED) {
        r1 = 0;
      }
      if (r2 == UNDEFINED) {
        r2 = 0;
      }
      return (r1 != 0 && r2 != 0) ? 1 : 0;
    }
  }

  public static final class Or extends Node {
    final Node left;
    final Node right;

    public Or(Node left, Node right) {
      this.left = left;
      this.right = right;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r1 = left.evalLong(ctx);
      if (r1 != UNDEFINED && r1 != 0) {
        return r1;
      }
      long r2 = right.evalLong(ctx);
      if (r1 == UNDEFINED) {
        r1 = 0;
      }
      if (r2 == UNDEFINED) {
        r2 = 0;
      }
      return (r1 != 0 || r2 != 0) ? 1 : 0;
    }
  }

  public static final class Not extends Node {
    final Node child;

    public Not(Node child) {
      this.child = child;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r = child.evalLong(ctx);
      if (r == UNDEFINED) {
        return UNDEFINED;
      }
      return r == 0 ? 1 : 0;
    }
  }

  public static final class Defined extends Node {
    final Node child;

    public Defined(Node child) {
      this.child = child;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      return child.evalLong(ctx) != UNDEFINED ? 1 : 0;
    }
  }

  /** Defined for string-valued children (strings are undefined when null). */
  public static final class DefinedObj extends Node {
    final Node child;

    public DefinedObj(Node child) {
      this.child = child;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      return child.evalObj(ctx) != null ? 1 : 0;
    }
  }

  public static final class StrToBool extends Node {
    final Node child;

    public StrToBool(Node child) {
      this.child = child;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      byte[] s = (byte[]) child.evalObj(ctx);
      if (s == null) {
        return UNDEFINED;
      }
      return s.length > 0 ? 1 : 0;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Integer operators

  public static final int OP_ADD = 0;
  public static final int OP_SUB = 1;
  public static final int OP_MUL = 2;
  public static final int OP_DIV = 3;
  public static final int OP_MOD = 4;
  public static final int OP_SHL = 5;
  public static final int OP_SHR = 6;
  public static final int OP_AND = 7;
  public static final int OP_OR = 8;
  public static final int OP_XOR = 9;
  public static final int OP_EQ = 10;
  public static final int OP_NEQ = 11;
  public static final int OP_LT = 12;
  public static final int OP_LE = 13;
  public static final int OP_GT = 14;
  public static final int OP_GE = 15;

  public static final class IntBinary extends Node {
    final int op;
    final Node left;
    final Node right;

    public IntBinary(int op, Node left, Node right) {
      this.op = op;
      this.left = left;
      this.right = right;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r1 = left.evalLong(ctx);
      long r2 = right.evalLong(ctx);
      if (r2 == UNDEFINED || r1 == UNDEFINED) {
        return UNDEFINED;
      }
      switch (op) {
        case OP_ADD:
          return r1 + r2;
        case OP_SUB:
          return r1 - r2;
        case OP_MUL:
          return r1 * r2;
        case OP_DIV:
          if (r2 == 0 || (r1 == Long.MIN_VALUE && r2 == -1)) {
            return UNDEFINED;
          }
          return r1 / r2;
        case OP_MOD:
          if (r2 == 0 || (r1 == Long.MIN_VALUE && r2 == -1)) {
            return UNDEFINED;
          }
          return r1 % r2;
        case OP_SHL:
          if (r2 < 0) {
            return UNDEFINED;
          }
          return r2 < 64 ? r1 << r2 : 0;
        case OP_SHR:
          if (r2 < 0) {
            return UNDEFINED;
          }
          return r2 < 64 ? r1 >> r2 : 0;
        case OP_AND:
          return r1 & r2;
        case OP_OR:
          return r1 | r2;
        case OP_XOR:
          return r1 ^ r2;
        case OP_EQ:
          return r1 == r2 ? 1 : 0;
        case OP_NEQ:
          return r1 != r2 ? 1 : 0;
        case OP_LT:
          return r1 < r2 ? 1 : 0;
        case OP_LE:
          return r1 <= r2 ? 1 : 0;
        case OP_GT:
          return r1 > r2 ? 1 : 0;
        case OP_GE:
          return r1 >= r2 ? 1 : 0;
        default:
          throw new IllegalStateException();
      }
    }
  }

  public static final class IntMinus extends Node {
    final Node child;

    public IntMinus(Node child) {
      this.child = child;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r = child.evalLong(ctx);
      return r == UNDEFINED ? UNDEFINED : -r;
    }
  }

  public static final class BitNot extends Node {
    final Node child;

    public BitNot(Node child) {
      this.child = child;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r = child.evalLong(ctx);
      return r == UNDEFINED ? UNDEFINED : ~r;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Float operators

  public static final class IntToDbl extends Node {
    final Node child;

    public IntToDbl(Node child) {
      this.child = child;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r = child.evalLong(ctx);
      return r == UNDEFINED ? UNDEFINED : bits((double) r);
    }
  }

  public static final class DblBinary extends Node {
    final int op;
    final Node left;
    final Node right;

    public DblBinary(int op, Node left, Node right) {
      this.op = op;
      this.left = left;
      this.right = right;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long b1 = left.evalLong(ctx);
      long b2 = right.evalLong(ctx);
      if (op == OP_LT) {
        if (b1 == UNDEFINED || b2 == UNDEFINED) {
          return 0;
        }
        return dbl(b1) < dbl(b2) ? 1 : 0;
      }
      if (b2 == UNDEFINED || b1 == UNDEFINED) {
        return UNDEFINED;
      }
      double d1 = dbl(b1);
      double d2 = dbl(b2);
      switch (op) {
        case OP_ADD:
          return bits(d1 + d2);
        case OP_SUB:
          return bits(d1 - d2);
        case OP_MUL:
          return bits(d1 * d2);
        case OP_DIV:
          return bits(d1 / d2);
        case OP_EQ:
          return Math.abs(d1 - d2) < DBL_EPSILON ? 1 : 0;
        case OP_NEQ:
          return Math.abs(d1 - d2) >= DBL_EPSILON ? 1 : 0;
        case OP_LE:
          return d1 <= d2 ? 1 : 0;
        case OP_GT:
          return d1 > d2 ? 1 : 0;
        case OP_GE:
          return d1 >= d2 ? 1 : 0;
        default:
          throw new IllegalStateException();
      }
    }
  }

  public static final class DblMinus extends Node {
    final Node child;

    public DblMinus(Node child) {
      this.child = child;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r = child.evalLong(ctx);
      return r == UNDEFINED ? UNDEFINED : bits(-dbl(r));
    }
  }

  // ---------------------------------------------------------------------------------------------
  // String operators

  /** ss_compare: compares bytes as signed chars, like libyara does on most platforms. */
  public static int compare(byte[] s1, byte[] s2) {
    int i = 0;
    while (s1.length > i && s2.length > i && s1[i] == s2[i]) {
      i++;
    }
    if (i == s1.length && i == s2.length) {
      return 0;
    } else if (i == s1.length) {
      return -1;
    } else if (i == s2.length) {
      return 1;
    } else if (s1[i] < s2[i]) {
      return -1;
    } else {
      return 1;
    }
  }

  static int lower(byte b) {
    return Re.lower(b);
  }

  public static int icompare(byte[] s1, byte[] s2) {
    int i = 0;
    while (s1.length > i && s2.length > i && lower(s1[i]) == lower(s2[i])) {
      i++;
    }
    if (i == s1.length && i == s2.length) {
      return 0;
    } else if (i == s1.length) {
      return -1;
    } else if (i == s2.length) {
      return 1;
    } else if (s1[i] < s2[i]) {
      return -1;
    } else {
      return 1;
    }
  }

  public static boolean contains(byte[] s1, byte[] s2) {
    if (s2.length == 0) {
      return true;
    }
    outer:
    for (int i = 0; i + s2.length <= s1.length; i++) {
      for (int j = 0; j < s2.length; j++) {
        if (s1[i + j] != s2[j]) {
          continue outer;
        }
      }
      return true;
    }
    return false;
  }

  public static boolean icontains(byte[] s1, byte[] s2) {
    if (s1.length < s2.length) {
      return false;
    }
    for (int i = 0; i < s1.length - s2.length + 1; i++) {
      int j;
      for (j = 0; j < s2.length; j++) {
        if (lower(s1[i + j]) != lower(s2[j])) {
          break;
        }
      }
      if (j == s2.length) {
        return true;
      }
    }
    return false;
  }

  public static boolean startsWith(byte[] s1, byte[] s2, boolean nocase) {
    if (s1.length < s2.length) {
      return false;
    }
    for (int i = 0; i < s2.length; i++) {
      if (nocase ? lower(s1[i]) != lower(s2[i]) : s1[i] != s2[i]) {
        return false;
      }
    }
    return true;
  }

  public static boolean endsWith(byte[] s1, byte[] s2, boolean nocase) {
    if (s1.length < s2.length) {
      return false;
    }
    int off = s1.length - s2.length;
    for (int i = 0; i < s2.length; i++) {
      if (nocase ? lower(s1[off + i]) != lower(s2[i]) : s1[off + i] != s2[i]) {
        return false;
      }
    }
    return true;
  }

  public static final class StrCompare extends Node {
    final int op;
    final Node left;
    final Node right;

    public StrCompare(int op, Node left, Node right) {
      this.op = op;
      this.left = left;
      this.right = right;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      byte[] s1 = (byte[]) left.evalObj(ctx);
      byte[] s2 = (byte[]) right.evalObj(ctx);
      if (s2 == null || s1 == null) {
        return UNDEFINED;
      }
      int c = compare(s1, s2);
      boolean r;
      switch (op) {
        case OP_EQ:
          r = c == 0;
          break;
        case OP_NEQ:
          r = c != 0;
          break;
        case OP_LT:
          r = c < 0;
          break;
        case OP_LE:
          r = c <= 0;
          break;
        case OP_GT:
          r = c > 0;
          break;
        case OP_GE:
          r = c >= 0;
          break;
        default:
          throw new IllegalStateException();
      }
      return r ? 1 : 0;
    }
  }

  public static final int SOP_CONTAINS = 0;
  public static final int SOP_ICONTAINS = 1;
  public static final int SOP_STARTSWITH = 2;
  public static final int SOP_ISTARTSWITH = 3;
  public static final int SOP_ENDSWITH = 4;
  public static final int SOP_IENDSWITH = 5;
  public static final int SOP_IEQUALS = 6;

  public static final class StrOp extends Node {
    final int op;
    final Node left;
    final Node right;

    public StrOp(int op, Node left, Node right) {
      this.op = op;
      this.left = left;
      this.right = right;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      byte[] s1 = (byte[]) left.evalObj(ctx);
      byte[] s2 = (byte[]) right.evalObj(ctx);
      if (s1 == null || s2 == null) {
        return UNDEFINED;
      }
      boolean r;
      switch (op) {
        case SOP_CONTAINS:
          r = contains(s1, s2);
          break;
        case SOP_ICONTAINS:
          r = icontains(s1, s2);
          break;
        case SOP_STARTSWITH:
          r = startsWith(s1, s2, false);
          break;
        case SOP_ISTARTSWITH:
          r = startsWith(s1, s2, true);
          break;
        case SOP_ENDSWITH:
          r = endsWith(s1, s2, false);
          break;
        case SOP_IENDSWITH:
          r = endsWith(s1, s2, true);
          break;
        case SOP_IEQUALS:
          r = icompare(s1, s2) == 0;
          break;
        default:
          throw new IllegalStateException();
      }
      return r ? 1 : 0;
    }
  }

  public static final class Matches extends Node {
    final Node string;
    final RegexpConst regexp;

    public Matches(Node string, RegexpConst regexp) {
      this.string = string;
      this.regexp = regexp;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      byte[] s = (byte[]) string.evalObj(ctx);
      if (s == null) {
        return UNDEFINED;
      }
      int found =
          ctx.reExec.exec(
              ctx.rules.reCode,
              regexp.offset,
              ByteBuffer.wrap(s),
              0,
              s.length,
              0,
              regexp.flags | Re.FLAGS_SCAN,
              null);
      return found >= 0 ? 1 : 0;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Strings ($a, #a, @a, !a)

  /** Gives the string referenced by a node, which is fixed except for "$" inside loops. */
  public abstract static class StringRef {
    public abstract CompiledString get(ExecContext ctx);
  }

  public static final class FixedString extends StringRef {
    final CompiledString string;

    public FixedString(CompiledString string) {
      this.string = string;
    }

    @Override
    public CompiledString get(ExecContext ctx) {
      return string;
    }
  }

  public static final class LoopString extends StringRef {
    final int slot;

    public LoopString(int slot) {
      this.slot = slot;
    }

    @Override
    public CompiledString get(ExecContext ctx) {
      return (CompiledString) ctx.memObj[slot];
    }
  }

  public static final class Found extends Node {
    final StringRef s;

    public Found(StringRef s) {
      this.s = s;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      return ctx.matches[s.get(ctx).idx].tail != null ? 1 : 0;
    }
  }

  public static final class FoundAt extends Node {
    final StringRef s;
    final Node at;

    public FoundAt(StringRef s, Node at) {
      this.s = s;
      this.at = at;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r1 = at.evalLong(ctx);
      CompiledString str = s.get(ctx);
      if (r1 == UNDEFINED) {
        return UNDEFINED;
      }
      for (Match m = ctx.matches[str.idx].head; m != null; m = m.next) {
        long off = m.base + m.offset;
        if (r1 == off) {
          return 1;
        }
        if (r1 < off) {
          break;
        }
      }
      return 0;
    }
  }

  public static final class FoundIn extends Node {
    final StringRef s;
    final Node lo;
    final Node hi;

    public FoundIn(StringRef s, Node lo, Node hi) {
      this.s = s;
      this.lo = lo;
      this.hi = hi;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r1 = lo.evalLong(ctx);
      long r2 = hi.evalLong(ctx);
      CompiledString str = s.get(ctx);
      if (r1 == UNDEFINED || r2 == UNDEFINED) {
        return UNDEFINED;
      }
      for (Match m = ctx.matches[str.idx].head; m != null; m = m.next) {
        long off = m.base + m.offset;
        if (off >= r1 && off <= r2) {
          return 1;
        }
        if (off > r2) {
          break;
        }
      }
      return 0;
    }
  }

  public static final class Count extends Node {
    final StringRef s;

    public Count(StringRef s) {
      this.s = s;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      return ctx.matches[s.get(ctx).idx].count;
    }
  }

  public static final class CountIn extends Node {
    final StringRef s;
    final Node lo;
    final Node hi;

    public CountIn(StringRef s, Node lo, Node hi) {
      this.s = s;
      this.lo = lo;
      this.hi = hi;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r1 = lo.evalLong(ctx);
      long r2 = hi.evalLong(ctx);
      CompiledString str = s.get(ctx);
      if (r1 == UNDEFINED || r2 == UNDEFINED) {
        return UNDEFINED;
      }
      long count = 0;
      for (Match m = ctx.matches[str.idx].head; m != null; m = m.next) {
        long off = m.base + m.offset;
        if (off >= r1 && off <= r2) {
          count++;
        }
        if (off > r2) {
          break;
        }
      }
      return count;
    }
  }

  /** @a[i] when length is false, !a[i] when length is true. */
  public static final class OffsetOrLength extends Node {
    final StringRef s;
    final Node index;
    final boolean length;

    public OffsetOrLength(StringRef s, Node index, boolean length) {
      this.s = s;
      this.index = index;
      this.length = length;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long r1 = index.evalLong(ctx);
      CompiledString str = s.get(ctx);
      if (r1 == UNDEFINED) {
        return UNDEFINED;
      }
      long i = 1;
      for (Match m = ctx.matches[str.idx].head; m != null; m = m.next) {
        if (r1 == i) {
          return length ? m.matchLength : m.base + m.offset;
        }
        i++;
      }
      return UNDEFINED;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // "of" expressions

  static long quantifierResult(long quant, long found, long count) {
    if (quant == UNDEFINED) {
      return found >= count ? 1 : 0;
    } else if (quant == 0) {
      return found == 0 ? 1 : 0;
    } else {
      return found >= quant ? 1 : 0;
    }
  }

  public static final class OfStrings extends Node {
    final Node quant;
    final CompiledString[] strings;
    final boolean percent;

    public OfStrings(Node quant, List<CompiledString> strings, boolean percent) {
      this.quant = quant;
      this.strings = strings.toArray(new CompiledString[0]);
      this.percent = percent;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long q = quant.evalLong(ctx);
      long found = 0;
      long count = 0;
      for (CompiledString s : strings) {
        if (ctx.matches[s.idx].tail != null) {
          found++;
        }
        count++;
      }
      if (!percent) {
        return quantifierResult(q, found, count);
      }
      if (q == UNDEFINED || count == 0) {
        return UNDEFINED;
      }
      return (((double) found / count) * 100) >= q ? 1 : 0;
    }
  }

  public static final class OfRules extends Node {
    final Node quant;
    final int[] rules;
    final boolean percent;

    public OfRules(Node quant, List<Integer> rules, boolean percent) {
      this.quant = quant;
      this.rules = rules.stream().mapToInt(Integer::intValue).toArray();
      this.percent = percent;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long q = quant.evalLong(ctx);
      long found = 0;
      long count = 0;
      // libyara pops the rules from the stack (last first) and stops at the first undefined
      // value, which is what disabled rules produce.
      for (int i = rules.length - 1; i >= 0; i--) {
        if (ctx.ruleDisabled[rules[i]]) {
          break;
        }
        found += ctx.ruleMatches[rules[i]] ? 1 : 0;
        count++;
      }
      if (!percent) {
        return quantifierResult(q, found, count);
      }
      if (q == UNDEFINED || count == 0) {
        return UNDEFINED;
      }
      return (((double) found / count) * 100) >= q ? 1 : 0;
    }
  }

  public static final class OfFoundIn extends Node {
    final Node quant;
    final CompiledString[] strings;
    final Node lo;
    final Node hi;

    public OfFoundIn(Node quant, List<CompiledString> strings, Node lo, Node hi) {
      this.quant = quant;
      this.strings = strings.toArray(new CompiledString[0]);
      this.lo = lo;
      this.hi = hi;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long q = quant.evalLong(ctx);
      long r1 = lo.evalLong(ctx);
      long r2 = hi.evalLong(ctx);
      if (r1 == UNDEFINED || r2 == UNDEFINED) {
        return UNDEFINED;
      }
      long found = 0;
      long count = 0;
      for (CompiledString s : strings) {
        for (Match m = ctx.matches[s.idx].head; m != null; m = m.next) {
          long off = m.base + m.offset;
          if (off >= r1 && off <= r2) {
            found++;
            break;
          }
          if (off > r1) {
            break;
          }
        }
        count++;
      }
      return quantifierResult(q, found, count);
    }
  }

  public static final class OfFoundAt extends Node {
    final Node quant;
    final CompiledString[] strings;
    final Node at;

    public OfFoundAt(Node quant, List<CompiledString> strings, Node at) {
      this.quant = quant;
      this.strings = strings.toArray(new CompiledString[0]);
      this.at = at;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long q = quant.evalLong(ctx);
      long r2 = at.evalLong(ctx);
      if (r2 == UNDEFINED) {
        return UNDEFINED;
      }
      long found = 0;
      long count = 0;
      for (CompiledString s : strings) {
        for (Match m = ctx.matches[s.idx].head; m != null; m = m.next) {
          long off = m.base + m.offset;
          if (off == r2) {
            found++;
            break;
          }
          if (off > r2) {
            break;
          }
        }
        count++;
      }
      return quantifierResult(q, found, count);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Misc

  public static final class Filesize extends Node {
    @Override
    public long evalLong(ExecContext ctx) {
      return ctx.fileSize;
    }
  }

  public static final class Entrypoint extends Node {
    @Override
    public long evalLong(ExecContext ctx) {
      return ctx.entryPoint;
    }
  }

  /** int8, uint16be, etc. type index as computed by the lexer (0..11). */
  public static final class ReadInt extends Node {
    final Node offset;
    final int size;
    final boolean signed;
    final boolean bigEndian;

    public ReadInt(int type, Node offset) {
      this.offset = offset;
      this.bigEndian = type >= 6;
      int t = type % 6;
      this.signed = t < 3;
      this.size = 1 << (t % 3);
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long off = offset.evalLong(ctx);
      return ctx.readInt(off, size, signed, bigEndian);
    }
  }

  public static final class RuleRef extends Node {
    final int ruleIdx;

    public RuleRef(int ruleIdx) {
      this.ruleIdx = ruleIdx;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      if (ctx.ruleDisabled[ruleIdx]) {
        return UNDEFINED;
      }
      return ctx.ruleMatches[ruleIdx] ? 1 : 0;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Objects

  public static final class ObjLoad extends Node {
    final int index;

    public ObjLoad(int index) {
      this.index = index;
    }

    @Override
    public Object evalObj(ExecContext ctx) {
      return ctx.rootObjects[index];
    }
  }

  public static final class ObjField extends Node {
    final Node object;
    final String field;

    public ObjField(Node object, String field) {
      this.object = object;
      this.field = field;
    }

    @Override
    public Object evalObj(ExecContext ctx) {
      Object o = object.evalObj(ctx);
      if (o == null) {
        return null;
      }
      YObject f = ((YStructure) o).field(field);
      if (f == null) {
        throw new YaraError(ErrorCode.INVALID_FIELD_NAME);
      }
      return f;
    }
  }

  public static final class IndexArray extends Node {
    final Node array;
    final Node index;

    public IndexArray(Node array, Node index) {
      this.array = array;
      this.index = index;
    }

    @Override
    public Object evalObj(ExecContext ctx) {
      Object a = array.evalObj(ctx);
      long i = index.evalLong(ctx);
      if (i == UNDEFINED || a == null) {
        return null;
      }
      return ((YArray) a).get((int) i);
    }
  }

  public static final class LookupDict extends Node {
    final Node dict;
    final Node key;

    public LookupDict(Node dict, Node key) {
      this.dict = dict;
      this.key = key;
    }

    @Override
    public Object evalObj(ExecContext ctx) {
      Object d = dict.evalObj(ctx);
      byte[] k = (byte[]) key.evalObj(ctx);
      if (k == null || d == null) {
        return null;
      }
      return ((YDictionary) d).get(new String(k, StandardCharsets.ISO_8859_1));
    }
  }

  /** OP_OBJ_VALUE for integer objects. */
  public static final class ObjIntValue extends Node {
    final Node object;

    public ObjIntValue(Node object) {
      this.object = object;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      Object o = object.evalObj(ctx);
      if (o == null) {
        return UNDEFINED;
      }
      return ((YInteger) o).value();
    }
  }

  /** OP_OBJ_VALUE for float objects. */
  public static final class ObjFloatValue extends Node {
    final Node object;

    public ObjFloatValue(Node object) {
      this.object = object;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      Object o = object.evalObj(ctx);
      if (o == null) {
        return UNDEFINED;
      }
      double d = ((YFloat) o).value();
      return Double.isNaN(d) ? UNDEFINED : bits(d);
    }
  }

  /** OP_OBJ_VALUE for string objects. */
  public static final class ObjStringValue extends Node {
    final Node object;

    public ObjStringValue(Node object) {
      this.object = object;
    }

    @Override
    public Object evalObj(ExecContext ctx) {
      Object o = object.evalObj(ctx);
      if (o == null) {
        return null;
      }
      return ((YString) o).value();
    }
  }

  /** Function call, combined with OP_OBJ_VALUE on the returned object. */
  public static final class Call extends Node {
    final Node function;
    final Node[] args;
    final String argsFormat;
    final char returnType;

    public Call(Node function, List<Node> args, String argsFormat, char returnType) {
      this.function = function;
      this.args = args.toArray(new Node[0]);
      this.argsFormat = argsFormat;
      this.returnType = returnType;
    }

    private Object invoke(ExecContext ctx) {
      Object f = function.evalObj(ctx);
      Object[] values = new Object[args.length];
      boolean undefined = false;
      for (int i = 0; i < args.length; i++) {
        switch (argsFormat.charAt(i)) {
          case 'i':
          case 'b':
            {
              long v = args[i].evalLong(ctx);
              undefined |= v == UNDEFINED;
              values[i] = v;
              break;
            }
          case 'f':
            {
              long v = args[i].evalLong(ctx);
              undefined |= v == UNDEFINED;
              values[i] = dbl(v);
              break;
            }
          case 'r':
            values[i] = args[i].evalObj(ctx);
            break;
          default:
            {
              Object v = args[i].evalObj(ctx);
              undefined |= v == null;
              values[i] = v;
              break;
            }
        }
      }
      if (f == null || undefined) {
        return null;
      }
      YFunction fn = (YFunction) f;
      YFunction.Overload overload = fn.findOverload(argsFormat);
      if (overload == null) {
        throw new YaraError(ErrorCode.INTERNAL_FATAL_ERROR);
      }
      try {
        return overload.code.call(new FunctionCall(values, ctx, fn));
      } catch (YaraException e) {
        throw new YaraError(e.getErrorCode(), e.getMessage());
      }
    }

    @Override
    public long evalLong(ExecContext ctx) {
      Object r = invoke(ctx);
      if (r == null) {
        return UNDEFINED;
      }
      if (returnType == 'f') {
        double d = ((Number) r).doubleValue();
        return Double.isNaN(d) ? UNDEFINED : bits(d);
      }
      if (r instanceof Boolean) {
        return ((Boolean) r) ? 1 : 0;
      }
      return ((Number) r).longValue();
    }

    @Override
    public Object evalObj(ExecContext ctx) {
      Object r = invoke(ctx);
      if (r == null) {
        return null;
      }
      byte[] b =
          r instanceof String ? ((String) r).getBytes(StandardCharsets.ISO_8859_1) : (byte[]) r;
      // libyara's return_string uses strlen, so strings are truncated at the first NUL.
      for (int i = 0; i < b.length; i++) {
        if (b[i] == 0) {
          return java.util.Arrays.copyOf(b, i);
        }
      }
      return b;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Loops

  public static final class LoopVarLong extends Node {
    final int slot;

    public LoopVarLong(int slot) {
      this.slot = slot;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      return ctx.memLong[slot];
    }
  }

  public static final class LoopVarObj extends Node {
    final int slot;

    public LoopVarObj(int slot) {
      this.slot = slot;
    }

    @Override
    public Object evalObj(ExecContext ctx) {
      return ctx.memObj[slot];
    }
  }

  /** Iterator for "for" loops, sets the loop variables on each iteration. */
  public abstract static class LoopIterator {
    /** Initializes the iterator, evaluating its operands. */
    abstract void start(ExecContext ctx);

    /** Advances to the next item, returns false when exhausted. */
    abstract boolean next(ExecContext ctx);
  }

  public static final class RangeIterator extends LoopIterator {
    final Node lo;
    final Node hi;
    final int slot;
    long nextValue;
    long last;

    public RangeIterator(Node lo, Node hi, int slot) {
      this.lo = lo;
      this.hi = hi;
      this.slot = slot;
    }

    @Override
    void start(ExecContext ctx) {
      nextValue = lo.evalLong(ctx);
      last = hi.evalLong(ctx);
    }

    @Override
    boolean next(ExecContext ctx) {
      if (nextValue != UNDEFINED && last != UNDEFINED && nextValue <= last) {
        ctx.memLong[slot] = nextValue;
        nextValue++;
        return true;
      }
      return false;
    }
  }

  public static final class IntEnumIterator extends LoopIterator {
    final Node[] items;
    final int slot;
    long[] values;
    int index;

    public IntEnumIterator(List<Node> items, int slot) {
      this.items = items.toArray(new Node[0]);
      this.slot = slot;
    }

    @Override
    void start(ExecContext ctx) {
      values = new long[items.length];
      for (int i = 0; i < items.length; i++) {
        values[i] = items[i].evalLong(ctx);
      }
      index = 0;
    }

    @Override
    boolean next(ExecContext ctx) {
      if (index < values.length) {
        ctx.memLong[slot] = values[index++];
        return true;
      }
      return false;
    }
  }

  public static final class TextStringIterator extends LoopIterator {
    final Node[] items;
    final int slot;
    Object[] values;
    int index;

    public TextStringIterator(List<Node> items, int slot) {
      this.items = items.toArray(new Node[0]);
      this.slot = slot;
    }

    @Override
    void start(ExecContext ctx) {
      values = new Object[items.length];
      for (int i = 0; i < items.length; i++) {
        values[i] = items[i].evalObj(ctx);
      }
      index = 0;
    }

    @Override
    boolean next(ExecContext ctx) {
      if (index < values.length) {
        ctx.memObj[slot] = values[index++];
        return true;
      }
      return false;
    }
  }

  public static final class ArrayIterator extends LoopIterator {
    final Node array;
    final int slot;
    YArray value;
    int index;

    public ArrayIterator(Node array, int slot) {
      this.array = array;
      this.slot = slot;
    }

    @Override
    void start(ExecContext ctx) {
      value = (YArray) array.evalObj(ctx);
      index = 0;
    }

    @Override
    boolean next(ExecContext ctx) {
      if (value == null || index >= value.length()) {
        return false;
      }
      ctx.memObj[slot] = value.get(index);
      index++;
      return true;
    }
  }

  public static final class DictIterator extends LoopIterator {
    final Node dict;
    final int keySlot;
    final int valueSlot;
    YDictionary value;
    int index;

    public DictIterator(Node dict, int keySlot, int valueSlot) {
      this.dict = dict;
      this.keySlot = keySlot;
      this.valueSlot = valueSlot;
    }

    @Override
    void start(ExecContext ctx) {
      value = (YDictionary) dict.evalObj(ctx);
      index = 0;
    }

    @Override
    boolean next(ExecContext ctx) {
      if (value == null || index == value.size()) {
        return false;
      }
      ctx.memObj[keySlot] = value.keyAt(index).getBytes(StandardCharsets.ISO_8859_1);
      ctx.memObj[valueSlot] = value.valueAt(index);
      index++;
      return true;
    }
  }

  public static final class StringSetIterator extends LoopIterator {
    final CompiledString[] strings;
    final int slot;
    int index;

    public StringSetIterator(List<CompiledString> strings, int slot) {
      this.strings = strings.toArray(new CompiledString[0]);
      this.slot = slot;
    }

    @Override
    void start(ExecContext ctx) {
      index = 0;
    }

    @Override
    boolean next(ExecContext ctx) {
      if (index < strings.length) {
        ctx.memObj[slot] = strings[index++];
        return true;
      }
      return false;
    }
  }

  /**
   * A "for" loop. The iterator instance is created per evaluation because iterators are
   * stateful and loops can be nested or evaluated concurrently by different scanners.
   */
  public static final class For extends Node {
    final Node quant;
    final java.util.function.Supplier<LoopIterator> iteratorFactory;
    final Node body;

    public For(Node quant, java.util.function.Supplier<LoopIterator> iteratorFactory, Node body) {
      this.quant = quant;
      this.iteratorFactory = iteratorFactory;
      this.body = body;
    }

    @Override
    public long evalLong(ExecContext ctx) {
      long q = quant.evalLong(ctx);
      LoopIterator it = iteratorFactory.get();
      it.start(ctx);
      long trueCount = 0;
      long iterations = 0;
      while (it.next(ctx)) {
        long r = body.evalLong(ctx);
        iterations++;
        boolean cont;
        if (q == UNDEFINED) {
          cont = r != 0;
        } else if (q == 0) {
          cont = r != 1;
        } else {
          cont = trueCount + r < q;
        }
        if (r != UNDEFINED) {
          trueCount += r;
        }
        ctx.tick();
        if (!cont) {
          break;
        }
      }
      if (iterations == 0) {
        return 0;
      } else if (q == UNDEFINED) {
        return trueCount == iterations ? 1 : 0;
      } else if (q == 0) {
        return trueCount == 0 ? 1 : 0;
      } else {
        return trueCount >= q ? 1 : 0;
      }
    }
  }
}
