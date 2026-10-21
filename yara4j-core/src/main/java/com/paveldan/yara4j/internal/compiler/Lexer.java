package com.paveldan.yara4j.internal.compiler;

import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import com.paveldan.yara4j.ErrorCode;

/** Lexical analyzer for YARA rules. Hand-written equivalent of libyara's lexer.l. */
final class Lexer {
  static final int LEX_BUF_SIZE = 8192;

  private static final class Buffer {
    final byte[] data;
    final int len;
    int pos;
    int line = 1;

    Buffer(byte[] data) {
      int n = 0;
      // Rules are handled as C strings, anything past a NUL byte is ignored.
      while (n < data.length && data[n] != 0) {
        n++;
      }
      this.data = data;
      this.len = n;
    }
  }

  /** Callbacks into the compiler. */
  interface Host {
    /** Reports an error raised by the lexer (yyerror with an error code). */
    void lexerError(ErrorCode code, String extraInfo, int line);

    /** Reports a syntax error message (yyerror with a message). */
    void lexerSyntaxError(String message, int line);

    /** Handles an include directive, returns the included content or null on error. */
    byte[] include(String path, int line);
  }

  private final Deque<Buffer> stack = new ArrayDeque<>();
  private final Host host;
  private boolean terminated;

  Lexer(byte[] source, Host host) {
    this.host = host;
    stack.push(new Buffer(source));
  }


  int line() {
    Buffer b = stack.peek();
    // When the last buffer is popped flex has no current buffer and yyget_lineno returns 0.
    return b == null ? 0 : b.line;
  }

  private Buffer buf() {
    return stack.peek();
  }

  private int peek(int off) {
    Buffer b = buf();
    int p = b.pos + off;
    return p < b.len ? b.data[p] & 0xFF : -1;
  }

  private void advance(int n) {
    Buffer b = buf();
    for (int i = 0; i < n; i++) {
      if (b.data[b.pos] == '\n') {
        b.line++;
      }
      b.pos++;
    }
  }

  private static boolean isLetter(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  }

  private static boolean isDigit(int c) {
    return c >= '0' && c <= '9';
  }

  private static boolean isHexDigit(int c) {
    return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }

  private static boolean isIdentChar(int c) {
    return isLetter(c) || isDigit(c) || c == '_';
  }

  private Token tok(Token.Type t) {
    Token token = new Token(t);
    token.line = line();
    return token;
  }

  /** Lexer error followed by termination (equivalent of the error() macro in lexer.l). */
  private Token error(ErrorCode code, String extraInfo) {
    host.lexerError(code, extraInfo, line());
    terminated = true;
    return tok(Token.Type.EOF);
  }

  private Token syntaxError(String message) {
    return error(ErrorCode.SYNTAX_ERROR, message);
  }

  /** yyerror with a message followed by yyterminate. */
  private Token messageError(String message) {
    host.lexerSyntaxError(message, line());
    terminated = true;
    return tok(Token.Type.EOF);
  }

  private static final String[] KEYWORDS = {
    "private", "global", "rule", "meta", "strings", "ascii", "wide", "xor", "base64",
    "base64wide", "fullword", "nocase", "condition", "true", "false", "not", "and", "or", "at",
    "in", "of", "them", "for", "all", "any", "none", "entrypoint", "filesize", "matches",
    "contains", "startswith", "endswith", "icontains", "istartswith", "iendswith", "iequals",
    "import", "defined"
  };

  private static final Token.Type[] KEYWORD_TYPES = {
    Token.Type.PRIVATE, Token.Type.GLOBAL, Token.Type.RULE, Token.Type.META, Token.Type.STRINGS,
    Token.Type.ASCII, Token.Type.WIDE, Token.Type.XOR, Token.Type.BASE64, Token.Type.BASE64_WIDE,
    Token.Type.FULLWORD, Token.Type.NOCASE, Token.Type.CONDITION, Token.Type.TRUE,
    Token.Type.FALSE, Token.Type.NOT, Token.Type.AND, Token.Type.OR, Token.Type.AT, Token.Type.IN,
    Token.Type.OF, Token.Type.THEM, Token.Type.FOR, Token.Type.ALL, Token.Type.ANY,
    Token.Type.NONE, Token.Type.ENTRYPOINT, Token.Type.FILESIZE, Token.Type.MATCHES,
    Token.Type.CONTAINS, Token.Type.STARTSWITH, Token.Type.ENDSWITH, Token.Type.ICONTAINS,
    Token.Type.ISTARTSWITH, Token.Type.IENDSWITH, Token.Type.IEQUALS, Token.Type.IMPORT,
    Token.Type.DEFINED
  };

  Token next() {
    while (true) {
      if (terminated) {
        return tok(Token.Type.EOF);
      }
      Buffer b = buf();
      if (b.pos >= b.len) {
        stack.pop();
        if (stack.isEmpty()) {
          terminated = true;
          Token t = new Token(Token.Type.EOF);
          t.line = 0;
          return t;
        }
        return tok(Token.Type.END_OF_INCLUDED_FILE);
      }
      int c = peek(0);
      int c1 = peek(1);

      // whitespace
      if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
        advance(1);
        continue;
      }
      // comments
      if (c == '/' && c1 == '*') {
        advance(2);
        while (b.pos < b.len && !(peek(0) == '*' && peek(1) == '/')) {
          advance(1);
        }
        if (b.pos < b.len) {
          advance(2);
        }
        continue;
      }
      if (c == '/' && c1 == '/') {
        while (b.pos < b.len && peek(0) != '\n') {
          advance(1);
        }
        continue;
      }

      switch (c) {
        case '.':
          if (c1 == '.') {
            advance(2);
            return tok(Token.Type.DOT_DOT);
          }
          break;
        case '<':
          if (c1 == '=') {
            advance(2);
            return tok(Token.Type.LE);
          }
          if (c1 == '<') {
            advance(2);
            return tok(Token.Type.SHIFT_LEFT);
          }
          advance(1);
          return tok(Token.Type.LT);
        case '>':
          if (c1 == '=') {
            advance(2);
            return tok(Token.Type.GE);
          }
          if (c1 == '>') {
            advance(2);
            return tok(Token.Type.SHIFT_RIGHT);
          }
          advance(1);
          return tok(Token.Type.GT);
        case '=':
          if (c1 == '=') {
            advance(2);
            return tok(Token.Type.EQ);
          }
          break;
        case '!':
          if (c1 == '=') {
            advance(2);
            return tok(Token.Type.NEQ);
          }
          return stringRef(Token.Type.STRING_LENGTH);
        case '$':
          {
            int n = 1;
            while (isIdentChar(peek(n))) {
              n++;
            }
            if (peek(n) == '*') {
              Token t = tok(Token.Type.STRING_IDENTIFIER_WITH_WILDCARD);
              t.text = text(n + 1);
              advance(n + 1);
              return t;
            }
            Token t = tok(Token.Type.STRING_IDENTIFIER);
            t.text = text(n);
            advance(n);
            return t;
          }
        case '#':
          return stringRef(Token.Type.STRING_COUNT);
        case '@':
          return stringRef(Token.Type.STRING_OFFSET);
        case '"':
          return textString();
        case '/':
          return regexp();
        case '{':
          {
            int n = matchHexString();
            if (n > 0) {
              Token t = tok(Token.Type.HEX_STRING);
              t.bytes = new byte[n];
              System.arraycopy(b.data, b.pos, t.bytes, 0, n);
              advance(n);
              return t;
            }
            break;
          }
        default:
          break;
      }

      if (isLetter(c) || c == '_') {
        int n = 1;
        while (isIdentChar(peek(n))) {
          n++;
        }
        String word = text(n);
        if (word.equals("include") && (peek(n) == ' ' || peek(n) == '\t')) {
          int m = n;
          while (peek(m) == ' ' || peek(m) == '\t') {
            m++;
          }
          if (peek(m) == '"') {
            advance(m + 1);
            Token inc = include();
            if (inc != null) {
              return inc;
            }
            continue;
          }
        }
        for (int i = 0; i < KEYWORDS.length; i++) {
          if (KEYWORDS[i].equals(word)) {
            Token t = tok(KEYWORD_TYPES[i]);
            t.text = word;
            advance(n);
            return t;
          }
        }
        int intFunc = integerFunction(word);
        if (intFunc >= 0) {
          Token t = tok(Token.Type.INTEGER_FUNCTION);
          t.integer = intFunc;
          t.text = word;
          advance(n);
          return t;
        }
        Token t = tok(Token.Type.IDENTIFIER);
        t.text = word;
        advance(n);
        if (word.length() > 128) {
          return syntaxError("identifier too long");
        }
        return t;
      }

      if (isDigit(c)) {
        return number();
      }

      if (c >= 32 && c < 127) {
        Token t = tok(Token.Type.CHAR);
        t.ch = (char) c;
        advance(1);
        return t;
      }
      advance(1);
      return syntaxError("non-ascii character");
    }
  }

  private String text(int n) {
    Buffer b = buf();
    return new String(b.data, b.pos, n, java.nio.charset.StandardCharsets.ISO_8859_1);
  }

  private Token stringRef(Token.Type type) {
    int n = 1;
    while (isIdentChar(peek(n))) {
      n++;
    }
    Token t = tok(type);
    t.text = "$" + text(n).substring(1);
    advance(n);
    return t;
  }

  /** Returns the integer function index or -1 (u?int(8|16|32)(be)?). */
  private static int integerFunction(String w) {
    int v = 0;
    int i = 0;
    if (w.startsWith("u")) {
      v = 3;
      i = 1;
    }
    String rest = w.substring(i);
    if (rest.startsWith("int8")) {
      rest = rest.substring(4);
    } else if (rest.startsWith("int16")) {
      v += 1;
      rest = rest.substring(5);
    } else if (rest.startsWith("int32")) {
      v += 2;
      rest = rest.substring(5);
    } else {
      return -1;
    }
    if (rest.isEmpty()) {
      return v;
    }
    if (rest.equals("be")) {
      return v + 6;
    }
    return -1;
  }

  private Token number() {
    Buffer b = buf();
    int c1 = peek(1);
    if (peek(0) == '0' && c1 == 'x' && isHexDigit(peek(2))) {
      int n = 2;
      while (isHexDigit(peek(n))) {
        n++;
      }
      String s = text(n);
      Token t = tok(Token.Type.NUMBER);
      advance(n);
      try {
        t.integer = Long.parseLong(s.substring(2), 16);
      } catch (NumberFormatException e) {
        return error(ErrorCode.INTEGER_OVERFLOW, s);
      }
      return t;
    }
    if (peek(0) == '0' && c1 == 'o' && peek(2) >= '0' && peek(2) <= '7') {
      int n = 2;
      while (peek(n) >= '0' && peek(n) <= '7') {
        n++;
      }
      String s = text(n);
      Token t = tok(Token.Type.NUMBER);
      advance(n);
      try {
        t.integer = Long.parseLong(s.substring(2), 8);
      } catch (NumberFormatException e) {
        return error(ErrorCode.INTEGER_OVERFLOW, s);
      }
      return t;
    }
    int n = 0;
    while (isDigit(peek(n))) {
      n++;
    }
    if (peek(n) == '.' && isDigit(peek(n + 1))) {
      int m = n + 1;
      while (isDigit(peek(m))) {
        m++;
      }
      Token t = tok(Token.Type.DOUBLE);
      t.dbl = Double.parseDouble(text(m));
      advance(m);
      return t;
    }
    int suffix = 0;
    if ((peek(n) == 'M' || peek(n) == 'K') && peek(n + 1) == 'B') {
      suffix = peek(n) == 'M' ? 1048576 : 1024;
    }
    String digits = text(n);
    String full = text(n + (suffix != 0 ? 2 : 0));
    Token t = tok(Token.Type.NUMBER);
    advance(n + (suffix != 0 ? 2 : 0));
    long v;
    try {
      v = Long.parseLong(digits);
    } catch (NumberFormatException e) {
      return error(ErrorCode.INTEGER_OVERFLOW, full);
    }
    if (suffix != 0) {
      if (v > Long.MAX_VALUE / suffix) {
        return error(ErrorCode.INTEGER_OVERFLOW, full);
      }
      v *= suffix;
    }
    t.integer = v;
    return t;
  }

  private Token textString() {
    int startLine = line();
    advance(1);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    while (true) {
      int c = peek(0);
      if (c < 0) {
        // EOF inside a string: flex has no rule for it, the buffer ends.
        Token t = tok(Token.Type.EOF);
        terminated = true;
        return t;
      }
      if (c == '"') {
        advance(1);
        Token t = new Token(Token.Type.TEXT_STRING);
        t.line = startLine;
        t.bytes = out.toByteArray();
        return t;
      }
      if (c == '\n') {
        // The rule matches the newline, flex has already incremented yylineno.
        advance(1);
        return syntaxError("unterminated string");
      }
      if (out.size() + 1 >= LEX_BUF_SIZE - 1) {
        return messageError("out of space in lex_buf");
      }
      if (c == '\\') {
        int e = peek(1);
        switch (e) {
          case 't':
            out.write('\t');
            advance(2);
            continue;
          case 'r':
            out.write('\r');
            advance(2);
            continue;
          case 'n':
            out.write('\n');
            advance(2);
            continue;
          case '"':
            out.write('"');
            advance(2);
            continue;
          case '\\':
            out.write('\\');
            advance(2);
            continue;
          case 'x':
            if (isHexDigit(peek(2)) && isHexDigit(peek(3))) {
              out.write(Integer.parseInt(text(4).substring(2), 16));
              advance(4);
              continue;
            }
            return syntaxError("illegal escape sequence");
          default:
            return syntaxError("illegal escape sequence");
        }
      }
      out.write(c);
      advance(1);
    }
  }

  private Token regexp() {
    int startLine = line();
    advance(1);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    while (true) {
      int c = peek(0);
      if (c < 0) {
        terminated = true;
        return tok(Token.Type.EOF);
      }
      if (c == '/') {
        advance(1);
        boolean noCase = false;
        boolean dotAll = false;
        if (peek(0) == 'i') {
          noCase = true;
          advance(1);
        }
        if (peek(0) == 's') {
          dotAll = true;
          advance(1);
        }
        if (out.size() == 0) {
          return syntaxError("empty regular expression");
        }
        Token t = new Token(Token.Type.REGEXP);
        t.line = startLine;
        t.bytes = out.toByteArray();
        t.regexpNoCase = noCase;
        t.regexpDotAll = dotAll;
        return t;
      }
      if (c == '\n') {
        advance(1);
        return syntaxError("unterminated regular expression");
      }
      if (out.size() + 2 >= LEX_BUF_SIZE - 1) {
        return messageError("out of space in lex_buf");
      }
      if (c == '\\') {
        int e = peek(1);
        if (e == '/') {
          out.write('/');
          advance(2);
          continue;
        }
        if (e < 0 || e == '\n') {
          return syntaxError("unterminated regular expression");
        }
        out.write('\\');
        out.write(e);
        advance(2);
        continue;
      }
      out.write(c);
      advance(1);
    }
  }

  /**
   * Returns the length of a hex string starting at the current position (which is '{'), or 0
   * if the text at the current position is not a hex string.
   */
  private int matchHexString() {
    int n = 1;
    int elements = 0;
    while (true) {
      int c = peek(n);
      if (c < 0) {
        return 0;
      }
      if (c == '}') {
        return elements > 0 ? n + 1 : 0;
      }
      if (isHexDigit(c)
          || c == ' '
          || c == '-'
          || c == '|'
          || c == '~'
          || c == '?'
          || c == '['
          || c == ']'
          || c == '('
          || c == ')'
          || c == '\n'
          || c == '\r'
          || c == '\t') {
        n++;
        elements++;
        continue;
      }
      if (c == '/' && peek(n + 1) == '*') {
        int m = n + 2;
        boolean closed = false;
        while (peek(m) >= 0) {
          if (peek(m) == '*') {
            int k = m;
            while (peek(k) == '*') {
              k++;
            }
            if (peek(k) == '/') {
              m = k + 1;
              closed = true;
              break;
            }
            m = k;
          } else {
            m++;
          }
        }
        if (!closed) {
          return 0;
        }
        n = m;
        elements++;
        continue;
      }
      if (c == '/' && peek(n + 1) == '/') {
        int m = n + 2;
        while (peek(m) >= 0 && peek(m) != '\n') {
          m++;
        }
        if (peek(m) != '\n') {
          return 0;
        }
        n = m + 1;
        elements++;
        continue;
      }
      return 0;
    }
  }

  /** Handles an include directive, the opening quote has been consumed. */
  private Token include() {
    ByteArrayOutputStream path = new ByteArrayOutputStream();
    while (peek(0) >= 0 && peek(0) != '"') {
      path.write(peek(0));
      advance(1);
    }
    if (peek(0) != '"') {
      // EOF inside the include path, flex has no rule matching it.
      terminated = true;
      return tok(Token.Type.EOF);
    }
    advance(1);
    String p = new String(path.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
    byte[] content = host.include(p, line());
    if (content == null) {
      return null;
    }
    stack.push(new Buffer(content));
    return null;
  }

  /** Called by the host when an include error must terminate lexing. */
  void terminate() {
    terminated = true;
  }
}
