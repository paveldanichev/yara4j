package com.paveldan.yara4j.internal.compiler;

/** A token produced by the {@link Lexer}. */
final class Token {
  enum Type {
    EOF("end of file"),
    END_OF_INCLUDED_FILE("end of included file"),
    DOT_DOT(".."),
    RULE("<rule>"),
    PRIVATE("<private>"),
    GLOBAL("<global>"),
    META("<meta>"),
    STRINGS("<strings>"),
    CONDITION("<condition>"),
    IDENTIFIER("identifier"),
    STRING_IDENTIFIER("string identifier"),
    STRING_COUNT("string count"),
    STRING_OFFSET("string offset"),
    STRING_LENGTH("string length"),
    STRING_IDENTIFIER_WITH_WILDCARD("string identifier with wildcard"),
    NUMBER("integer number"),
    DOUBLE("floating point number"),
    INTEGER_FUNCTION("integer function"),
    TEXT_STRING("text string"),
    HEX_STRING("hex string"),
    REGEXP("regular expression"),
    ASCII("<ascii>"),
    WIDE("<wide>"),
    XOR("<xor>"),
    BASE64("<base64>"),
    BASE64_WIDE("<base64wide>"),
    NOCASE("<nocase>"),
    FULLWORD("<fullword>"),
    AT("<at>"),
    FILESIZE("<filesize>"),
    ENTRYPOINT("<entrypoint>"),
    ALL("<all>"),
    ANY("<any>"),
    NONE("<none>"),
    IN("<in>"),
    OF("<of>"),
    FOR("<for>"),
    THEM("<them>"),
    MATCHES("<matches>"),
    CONTAINS("<contains>"),
    STARTSWITH("<startswith>"),
    ENDSWITH("<endswith>"),
    ICONTAINS("<icontains>"),
    ISTARTSWITH("<istartswith>"),
    IENDSWITH("<iendswith>"),
    IEQUALS("<iequals>"),
    IMPORT("<import>"),
    TRUE("<true>"),
    FALSE("<false>"),
    OR("<or>"),
    AND("<and>"),
    NOT("<not>"),
    DEFINED("<defined>"),
    EQ("=="),
    NEQ("!="),
    LT("<"),
    LE("<="),
    GT(">"),
    GE(">="),
    SHIFT_LEFT("<<"),
    SHIFT_RIGHT(">>"),
    /** Any other single character, stored in {@link Token#ch}. */
    CHAR("char");

    final String display;

    Type(String display) {
      this.display = display;
    }
  }

  final Type type;
  /** Text for identifiers, string identifiers, etc. */
  String text;
  /** Value for NUMBER and INTEGER_FUNCTION tokens. */
  long integer;
  /** Value for DOUBLE tokens. */
  double dbl;
  /** Bytes for TEXT_STRING, HEX_STRING and REGEXP tokens. */
  byte[] bytes;
  /** Regexp flags for REGEXP tokens (SIZED_STRING_FLAGS_NO_CASE / DOT_ALL). */
  boolean regexpNoCase;

  boolean regexpDotAll;
  /** Character for CHAR tokens. */
  char ch;

  int line;

  Token(Type type) {
    this.type = type;
  }

  boolean isChar(char c) {
    return type == Type.CHAR && ch == c;
  }

  String describe() {
    if (type == Type.CHAR) {
      return "'" + ch + "'";
    }
    if (type == Type.EOF || type == Type.END_OF_INCLUDED_FILE) {
      return type.display;
    }
    return type.display;
  }
}
