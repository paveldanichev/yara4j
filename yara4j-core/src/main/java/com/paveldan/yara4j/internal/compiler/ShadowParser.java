package com.paveldan.yara4j.internal.compiler;

import static com.paveldan.yara4j.internal.compiler.BisonTables.YYFINAL;
import static com.paveldan.yara4j.internal.compiler.BisonTables.YYLAST;
import static com.paveldan.yara4j.internal.compiler.BisonTables.YYNTOKENS;
import static com.paveldan.yara4j.internal.compiler.BisonTables.YYPACT_NINF;
import static com.paveldan.yara4j.internal.compiler.BisonTables.yycheck;
import static com.paveldan.yara4j.internal.compiler.BisonTables.yydefact;
import static com.paveldan.yara4j.internal.compiler.BisonTables.yydefgoto;
import static com.paveldan.yara4j.internal.compiler.BisonTables.yypact;
import static com.paveldan.yara4j.internal.compiler.BisonTables.yypgoto;
import static com.paveldan.yara4j.internal.compiler.BisonTables.yyr1;
import static com.paveldan.yara4j.internal.compiler.BisonTables.yyr2;
import static com.paveldan.yara4j.internal.compiler.BisonTables.yytable;
import static com.paveldan.yara4j.internal.compiler.BisonTables.yytname;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs libyara's Bison automaton (without semantic actions) over the tokens consumed by the
 * recursive descent parser. It provides what depends on Bison's internals:
 *
 * <ul>
 *   <li>The "expecting ..." part of syntax error messages, computed like Bison's
 *       yysyntax_error from the state in which the error is detected.
 *   <li>Whether a rule was reduced without reading a lookahead token. Bison performs default
 *       reductions without calling the lexer, so errors raised in their actions are reported at
 *       the line of the last token shifted instead of the line of the next token.
 * </ul>
 *
 * <p>The rule numbers used by the compiler are Bison's, see {@link BisonTables#yyrline}.
 */
final class ShadowParser {
  private static final int YYSYMBOL_YYEOF = 0;
  private static final int YYSYMBOL_YYERROR = 1;
  private static final int YYSYMBOL_YYUNDEF = 2;
  private static final int YYARGS_MAX = 5;

  private static final Map<String, Integer> SYMBOLS = new HashMap<>();

  static {
    for (int i = 0; i < YYNTOKENS; i++) {
      SYMBOLS.put(yytname[i], i);
    }
  }

  private int[] stack = new int[256];
  private int sp;
  /** Bison's yyerrstatus: tokens to shift before error messages are reported again. */
  private int errStatus;
  private boolean aborted;
  /** Rules reduced without lookahead after the last shift. */
  private final List<Integer> eager = new ArrayList<>();

  ShadowParser() {
    sp = 0;
    stack[0] = 0;
    reduceDefaults();
  }

  /** The Bison symbol number of a token. */
  static int symbol(Token t) {
    String name;
    switch (t.type) {
      case EOF:
        return YYSYMBOL_YYEOF;
      case CHAR:
        name = t.ch == '\\' ? "'\\\\'" : "'" + t.ch + "'";
        break;
      default:
        name = "\"" + t.type.display + "\"";
        break;
    }
    Integer s = SYMBOLS.get(name);
    return s == null ? YYSYMBOL_YYUNDEF : s;
  }

  private void push(int state) {
    if (sp + 1 == stack.length) {
      stack = Arrays.copyOf(stack, stack.length * 2);
    }
    stack[++sp] = state;
  }

  private static int gotoState(int top, int lhs) {
    int i = yypgoto[lhs - YYNTOKENS] + top;
    if (0 <= i && i <= YYLAST && yycheck[i] == top) {
      return yytable[i];
    }
    return yydefgoto[lhs - YYNTOKENS];
  }

  private static void reduce(int[] st, int[] spRef, int rule) {
    int s = spRef[0] - yyr2[rule];
    int state = gotoState(st[s], yyr1[rule]);
    st[++s] = state;
    spRef[0] = s;
  }

  private void reduce(int rule) {
    int[] spRef = {sp};
    if (sp + 1 >= stack.length) {
      stack = Arrays.copyOf(stack, stack.length * 2);
    }
    reduce(stack, spRef, rule);
    sp = spRef[0];
  }

  /** Reductions Bison performs before reading the next token (yypact_value_is_default). */
  private void reduceDefaults() {
    while (yypact[stack[sp]] == YYPACT_NINF && yydefact[stack[sp]] != 0) {
      int rule = yydefact[stack[sp]];
      eager.add(rule);
      reduce(rule);
    }
  }

  /**
   * The action for a lookahead symbol in a state: a positive state to shift to, a negative rule
   * number to reduce, or 0 for an error.
   */
  private static int action(int state, int sym) {
    int n = yypact[state];
    if (n != YYPACT_NINF) {
      n += sym;
      if (n >= 0 && n <= YYLAST && yycheck[n] == sym) {
        int v = yytable[n];
        return v > 0 ? v : (v < 0 ? v : 0);
      }
    }
    return -yydefact[state];
  }

  /** Feeds a token consumed (shifted) by the recursive descent parser. */
  void consume(Token t) {
    if (aborted) {
      return;
    }
    int sym = symbol(t);
    eager.clear();
    while (true) {
      int a = action(stack[sp], sym);
      if (a > 0) {
        push(a);
        if (errStatus > 0) {
          errStatus--;
        }
        if (a != YYFINAL) {
          reduceDefaults();
        }
        return;
      } else if (a < 0) {
        reduce(-a);
      } else {
        if (errStatus == 3) {
          // Bison discards the token while recovering from an error.
          if (sym == YYSYMBOL_YYEOF) {
            aborted = true;
          } else {
            recover();
          }
          return;
        }
        // The recursive descent parser accepted something Bison rejects: recover like Bison
        // would and retry the token.
        errStatus = 3;
        recover();
        if (aborted) {
          return;
        }
      }
    }
  }

  /** True while Bison is recovering from an error and doesn't report syntax errors. */
  boolean recovering() {
    return aborted || errStatus > 0;
  }

  /** True if the given rule was reduced without lookahead after the last consumed token. */
  boolean reducedWithoutLookahead(int rule) {
    return !aborted && eager.contains(rule);
  }

  /** Starts error recovery, after the parser reported an error (yyerrlab1). */
  void error() {
    if (aborted) {
      return;
    }
    errStatus = 3;
    eager.clear();
    recover();
  }

  private void recover() {
    while (true) {
      int n = yypact[stack[sp]];
      if (n != YYPACT_NINF) {
        n += YYSYMBOL_YYERROR;
        if (n >= 0 && n <= YYLAST && yycheck[n] == YYSYMBOL_YYERROR && yytable[n] > 0) {
          push(yytable[n]);
          reduceDefaults();
          return;
        }
      }
      if (sp == 0) {
        aborted = true;
        return;
      }
      sp--;
    }
  }

  /**
   * The message Bison produces when the token is a syntax error after the tokens consumed so
   * far, or null if Bison wouldn't detect an error there.
   */
  String syntaxErrorMessage(Token t) {
    if (aborted || errStatus > 0) {
      return null;
    }
    int sym = symbol(t);
    int[] st = Arrays.copyOf(stack, stack.length + 64);
    int[] spRef = {sp};
    for (int guard = 0; guard < 10000; guard++) {
      int a = action(st[spRef[0]], sym);
      if (a > 0) {
        return null;
      } else if (a < 0) {
        if (spRef[0] + 1 >= st.length) {
          st = Arrays.copyOf(st, st.length * 2);
        }
        reduce(st, spRef, -a);
      } else {
        return format(st[spRef[0]], sym);
      }
    }
    return null;
  }

  /** yysyntax_error. */
  private static String format(int state, int sym) {
    List<Integer> args = new ArrayList<>();
    args.add(sym);
    int n = yypact[state];
    if (n != YYPACT_NINF) {
      int xbegin = n < 0 ? -n : 0;
      int checklim = YYLAST - n + 1;
      int xend = Math.min(checklim, YYNTOKENS);
      for (int x = xbegin; x < xend; x++) {
        if (yycheck[x + n] == x && x != YYSYMBOL_YYERROR) {
          if (args.size() == YYARGS_MAX) {
            args.subList(1, args.size()).clear();
            break;
          }
          args.add(x);
        }
      }
    }
    StringBuilder sb = new StringBuilder("syntax error, unexpected ");
    sb.append(tnamerr(yytname[args.get(0)]));
    for (int i = 1; i < args.size(); i++) {
      sb.append(i == 1 ? ", expecting " : " or ").append(tnamerr(yytname[args.get(i)]));
    }
    return sb.toString();
  }

  /** yytnamerr: removes the double quotes from a token name when it's safe. */
  static String tnamerr(String name) {
    if (name.startsWith("\"")) {
      StringBuilder sb = new StringBuilder();
      for (int i = 1; i < name.length(); i++) {
        char c = name.charAt(i);
        switch (c) {
          case '\'':
          case ',':
            return name;
          case '\\':
            if (i + 1 < name.length() && name.charAt(i + 1) == '\\') {
              sb.append('\\');
              i++;
              break;
            }
            return name;
          case '"':
            return sb.toString();
          default:
            sb.append(c);
        }
      }
    }
    return name;
  }
}
