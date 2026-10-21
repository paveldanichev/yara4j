package com.paveldan.yara4j.ported;

import static com.paveldan.yara4j.YaraAssert.*;

import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.ErrorCode;

/** Converted from YARA's test-rules.c. */
@SuppressWarnings("all")
class RulesTest {

  @Test
  void testBooleanOperators() throws Exception {
    assertTrueRule("rule test { condition: not false }", null);
    assertFalseRule("rule test { condition: not true }", null);
    assertFalseRule("rule test { condition: not (false or true) }", null);
    assertFalseRule("rule test { condition: not (true or false) }", null);
    assertTrueRule("rule test { condition: not (false and true) }", null);
    assertTrueRule("rule test { condition: not (true and false) }", null);
    assertTrueRule("rule test { condition: not (true and false) }", null);
    assertTrueRule("rule test { condition: true }", null);
    assertTrueRule("rule test { condition: true or false }", null);
    assertTrueRule("rule test { condition: true and true }", null);
    assertTrueRule("rule test { condition: 0x1 and 0x2}", null);
    assertFalseRule("rule test { condition: false }", null);
    assertFalseRule("rule test { condition: true and false }", null);
    assertFalseRule("rule test { condition: false or false }", null);
    assertTrueRule("rule test { condition: not var_false }", null);
    assertTrueRule("rule test { condition: var_true }", null);
    assertFalseRule("rule test { condition: var_false }", null);
    assertFalseRule("rule test { condition: not var_true }", null);
    assertFalseRule("import \"tests\" rule test { condition: not tests.undefined.i }", null);
    assertFalseRule("import \"tests\" rule test { condition: tests.undefined.i }", null);
    assertFalseRule("import \"tests\" rule test { condition: tests.undefined.i and true }", null);
    assertFalseRule("import \"tests\" rule test { condition: true and tests.undefined.i }", null);
    assertTrueRule("import \"tests\" rule test { condition: tests.undefined.i or true }", null);
    assertTrueRule("import \"tests\" rule test { condition: true or tests.undefined.i }", null);
    assertTrueRule("import \"tests\"       rule test {         condition:           not (tests.undefined.i and true)       }", null);
    assertTrueRule("import \"tests\"       rule test {         condition:           not (true and tests.undefined.i)       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           not tests.string_array[4] contains \"foo\"       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           not tests.string_dict[\"undefined\"] matches /foo/       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           not tests.undefined.i       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           not (tests.undefined.i)       }", null);
  }

  @Test
  void testComparisonOperators() throws Exception {
    assertTrueRule("rule test { condition: 2 > 1 }", null);
    assertTrueRule("rule test { condition: 1 < 2 }", null);
    assertTrueRule("rule test { condition: 2 >= 1 }", null);
    assertTrueRule("rule test { condition: 1 <= 1 }", null);
    assertTrueRule("rule test { condition: 1 == 1 }", null);
    assertTrueRule("rule test { condition: 1.5 == 1.5}", null);
    assertTrueRule("rule test { condition: 1.0 == 1}", null);
    assertTrueRule("rule test { condition: 1.5 >= 1.0}", null);
    assertTrueRule("rule test { condition: 1.0 != 1.000000000000001 }", null);
    assertTrueRule("rule test { condition: 1.0 < 1.000000000000001 }", null);
    assertFalseRule("rule test { condition: 1.0 >= 1.000000000000001 }", null);
    assertTrueRule("rule test { condition: 1.000000000000001 > 1 }", null);
    assertFalseRule("rule test { condition: 1.000000000000001 <= 1 }", null);
    assertTrueRule("rule test { condition: 1.0 == 1.0000000000000001 }", null);
    assertTrueRule("rule test { condition: 1.0 >= 1.0000000000000001 }", null);
    assertTrueRule("rule test { condition: 1.5 >= 1}", null);
    assertTrueRule("rule test { condition: 1.0 >= 1}", null);
    assertTrueRule("rule test { condition: 0.5 < 1}", null);
    assertTrueRule("rule test { condition: 0.5 <= 1}", null);
    assertTrueRule("rule test { condition: 1.0 <= 1}", null);
    assertTrueRule("rule test { condition: \"abc\" == \"abc\"}", null);
    assertTrueRule("rule test { condition: \"abc\" <= \"abc\"}", null);
    assertTrueRule("rule test { condition: \"abc\" >= \"abc\"}", null);
    assertTrueRule("rule test { condition: \"ab\" < \"abc\"}", null);
    assertTrueRule("rule test { condition: \"abc\" > \"ab\"}", null);
    assertTrueRule("rule test { condition: \"abc\" < \"abd\"}", null);
    assertTrueRule("rule test { condition: \"abd\" > \"abc\"}", null);
    assertFalseRule("rule test { condition: 1 != 1}", null);
    assertFalseRule("rule test { condition: 1 != 1.0}", null);
    assertFalseRule("rule test { condition: 2 > 3}", null);
    assertFalseRule("rule test { condition: 2.1 < 2}", null);
    assertFalseRule("rule test { condition: \"abc\" != \"abc\"}", null);
    assertFalseRule("rule test { condition: \"abc\" > \"abc\"}", null);
    assertFalseRule("rule test { condition: \"abc\" < \"abc\"}", null);
  }

  @Test
  void testArithmeticOperators() throws Exception {
    assertTrueRule("rule test { condition: (1 + 1) * 2 == (9 - 1) \\ 2 }", null);
    assertTrueRule("rule test { condition: 5 % 2 == 1 }", null);
    assertTrueRule("rule test { condition: 1.5 + 1.5 == 3}", null);
    assertTrueRule("rule test { condition: 3 \\ 2 == 1}", null);
    assertTrueRule("rule test { condition: 3.0 \\ 2 == 1.5}", null);
    assertTrueRule("rule test { condition: 1 + -1 == 0}", null);
    assertTrueRule("rule test { condition: -1 + -1 == -2}", null);
    assertTrueRule("rule test { condition: 4 --2 * 2 == 8}", null);
    assertTrueRule("rule test { condition: -1.0 * 1 == -1.0}", null);
    assertTrueRule("rule test { condition: 1-1 == 0}", null);
    assertTrueRule("rule test { condition: -2.0-3.0 == -5}", null);
    assertTrueRule("rule test { condition: --1 == 1}", null);
    assertTrueRule("rule test { condition: 1--1 == 2}", null);
    assertTrueRule("rule test { condition: 2 * -2 == -4}", null);
    assertTrueRule("rule test { condition: -4 * 2 == -8}", null);
    assertTrueRule("rule test { condition: -4 * -4 == 16}", null);
    assertTrueRule("rule test { condition: -0x01 == -1}", null);
    assertTrueRule("rule test { condition: 0o10 == 8 }", null);
    assertTrueRule("rule test { condition: 0o100 == 64 }", null);
    assertTrueRule("rule test { condition: 0o755 == 493 }", null);
    // Test cases for issue #1631.
    assertTrueRule("rule test { condition: var_one*3 == 3}", null);
    assertTrueRule("rule test { condition: var_zero*3 == 0}", null);
    // TODO: This should return ERROR_INTEGER_OVERFLOW, but right now it returns
    // ERROR_SYNTAX_ERROR because after the lexer aborts with
    // ERROR_INTEGER_OVERFLOW the parser finds an unexpected end fails with error:
    // unexpected $end.
    assertError("rule test { condition: 9223372036854775808 > 0 }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { condition: 9007199254740992KB > 0 }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { condition: 8796093022208MB > 0 }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { condition: 0x8000000000000000 > 0 }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { condition: 0o1000000000000000000000 > 0 }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { condition: 0x7FFFFFFFFFFFFFFF + 1 > 0 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: 9223372036854775807 + 1 > 0 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: -9223372036854775807 - 2 > 0 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: -2 + -9223372036854775807 > 0 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: 1 - -9223372036854775807 > 0 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: 0x4000000000000000 * 2 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: 4611686018427387904 * 2 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: 4611686018427387904 * -2 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: -4611686018427387904 * 2 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: -4611686018427387904 * -2 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: ~9223372036854775807 * 9223372036854775807 }", ErrorCode.INTEGER_OVERFLOW);
    assertError("rule test { condition: ~9223372036854775807 \\ -1 }", ErrorCode.INTEGER_OVERFLOW);
  }

  @Test
  void testBitwiseOperators() throws Exception {
    assertTrueRule("rule test { condition: 0x55 | 0xAA == 0xFF }", null);
    assertTrueRule("rule test { condition: ~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF) }", null);
    assertTrueRule("rule test { condition: ~0x55 & 0xFF == 0xAA }", null);
    assertTrueRule("rule test { condition: 8 >> 2 == 2 }", null);
    assertTrueRule("rule test { condition: 1 << 3 == 8 }", null);
    assertTrueRule("rule test { condition: 1 << 64 == 0 }", null);
    assertTrueRule("rule test { condition: 1 >> 64 == 0 }", null);
    assertError("rule test { condition: 1 << -1 == 0 }", ErrorCode.INVALID_OPERAND);
    assertError("rule test { condition: 1 >> -1 == 0 }", ErrorCode.INVALID_OPERAND);
    assertTrueRule("rule test { condition: 1 | 3 ^ 3 == 1 | (3 ^ 3) }", null);
    assertFalseRule("rule test { condition: ~0xAA ^ 0x5A & 0xFF == 0x0F }", null);
    assertFalseRule("rule test { condition: 1 | 3 ^ 3 == (1 | 3) ^ 3}", null);
  }

  @Test
  void testStringOperators() throws Exception {
    assertTrueRule("rule test { condition: \"foobarbaz\" contains \"bar\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" contains \"foo\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" contains \"baz\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" icontains \"BAR\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" icontains \"BaR\" }", null);
    assertTrueRule("rule test { condition: \"FooBarBaz\" icontains \"bar\" }", null);
    assertTrueRule("rule test { condition: \"FooBarBaz\" icontains \"baz\" }", null);
    assertTrueRule("rule test { condition: \"FooBarBaz\" icontains \"FOO\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" contains \"foo\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" contains \"baz\" }", null);
    assertFalseRule("rule test { condition: \"foobarbaz\" contains \"baq\" }", null);
    assertFalseRule("rule test { condition: \"foo\" contains \"foob\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" startswith \"foo\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" istartswith \"Foo\" }", null);
    assertTrueRule("rule test { condition: \"FooBarBaz\" istartswith \"fOO\" }", null);
    assertFalseRule("rule test { condition: \"foobarbaz\" startswith \"fob\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" endswith \"baz\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" iendswith \"baZ\" }", null);
    assertTrueRule("rule test { condition: \"foobarbaz\" iendswith \"BaZ\" }", null);
    assertFalseRule("rule test { condition: \"foobarbaz\" endswith \"ba\" }", null);
  }

  @Test
  void testSyntax() throws Exception {
    assertError("rule test { strings: $a = \"a\" $a = \"a\" condition: all of them }", ErrorCode.DUPLICATED_STRING_IDENTIFIER);
    assertError("rule test { strings: $a = /a.c/ xor condition: $a }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { strings: $a = /abc/ xor condition: $a }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { strings: $a = {01 02 ?? 03 04} xor condition: $a }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { strings: $a = {01 02 0? 03 04} xor condition: $a }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { strings: $a = {01 02 03 04} xor condition: $a }", ErrorCode.SYNTAX_ERROR);
    // Test case for issue #1295
    assertError("rule test rule test", ErrorCode.DUPLICATED_IDENTIFIER);
    assertError("rule test { strings: $a = \"a\" condition: -1 of them }", ErrorCode.INVALID_VALUE);
    assertError("rule test { strings: $a = \"a\" condition: 0 + -1 of them }", ErrorCode.INVALID_VALUE);
    assertError("rule test { strings: $a = \"a\" condition: for -1 of them: ($) }", ErrorCode.INVALID_VALUE);
    assertError("rule test { strings: $a = \"a\" condition: for 0 + -1 of them: ($) }", ErrorCode.INVALID_VALUE);
    assertError("rule test { strings: $a = \"a\" condition: \"foo\" of them }", ErrorCode.INVALID_VALUE);
    assertError("rule test { strings: $a = \"a\" condition: for \"foo\" of them: ($) }", ErrorCode.INVALID_VALUE);
    assertError("rule test { strings: $a = \"a\" condition: /foo/ of them }", ErrorCode.INVALID_VALUE);
    assertError("rule test { strings: $a = \"a\" condition: for /foo/ of them: ($) }", ErrorCode.INVALID_VALUE);
    assertError("rule test { strings: $a = \"a\" condition: for 3.14159 of them: ($) }", ErrorCode.INVALID_VALUE);
    assertError("rule test { strings: $a = \"a\" condition: true }", ErrorCode.UNREFERENCED_STRING);
    // String identifiers prefixed with '_' are allowed to be unreferenced.
    // Any unreferenced string must be searched for anywhere.
    assertStringCapture("rule test { strings: $a = \"AXS\" $_b = \"ERS\" condition: $a }", "AXSERS", "ERS");
  }

  @Test
  void testAnonymousStrings() throws Exception {
    assertTrueRule("rule test { strings: $ = \"a\" $ = \"b\" condition: all of them }", "ab");
    // Anonymous strings must be referenced.
    assertError("rule test { strings: $ = \"a\" condition: true }", ErrorCode.UNREFERENCED_STRING);
  }

  @Test
  void testWarnings() throws Exception {
    assertWarning("rule test {     strings:       $a = \"AXSERS\"       $b = \"WXSMTS\"     condition:       2 of them at 0     }");
    assertWarning("rule test {     strings:       $a = \"AXSERS\"       $b = \"WXSMTS\"     condition:       all of them at 0     }");
    assertWarning("rule test {     strings:       $a = \"AXSERS\"     condition:       0 of them     }");
    assertWarning("rule test {     strings:       $a = \"AXSERS\"     condition:       for 0 of ($a*): ($)     }");
    assertNoWarnings("rule test {     strings:       $a = \"AXSERS\"     condition:       none of them     }");
    assertNoWarnings("rule test {     strings:       $a = \"AXSERS\"     condition:       for none of ($a*): ($)     }");
    assertWarning("rule test {     strings:       $a = \"AXSERS\"     condition:       1 + -1 of them     }");
    assertWarning("rule test {     strings:       $a = \"AXSERS\"     condition:       2 of them     }");
    assertWarning("rule test {     strings:       $a = \"AXSERS\"     condition:       2 of ($a)     }");
    assertWarning("rule test {     strings:       $a = \"AXSERS\"     condition:       2 of ($a*)     }");
    assertWarning("rule test {     strings:       $a = \"AXSERS\"     condition:       2 of ($a*) in (0..10)     }");
    assertWarning("rule a {     condition:       true     }     rule b {       condition:         2 of (a)     }");
    assertWarning("rule a {     condition:       true     }     rule b {       condition:         2 of (a*)     }");
    assertWarning("rule test {     strings:       $a = \"AXSERS\"     condition:       2 of ($a*) at 0    }");
    assertError("rule test {       strings:         $a = \"AXSERS\"       condition:         1 of them at \"x\"    }", ErrorCode.INVALID_VALUE);
  }

  @Test
  void testStrings() throws Exception {
    String str = TEXT_1024_BYTES + "---- abc ---- xyz";
    byte[] blob = (TEXT_1024_BYTES + "---- a\0b\0c\0 -\0-\0-\0-\0x\0y\0z\0\0")
        .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    assertTrueRule("rule test { strings: $a = \"a\" condition: $a }", str);
    assertTrueRule("rule test { strings: $a = \"ab\" condition: $a }", str);
    assertTrueRule("rule test { strings: $a = \"abc\" condition: $a }", str);
    assertTrueRule("rule test { strings: $a = \"xyz\" condition: $a }", str);
    assertTrueRule("rule test { strings: $a = \"abc\" nocase fullword condition: $a }", str);
    assertTrueRule("rule test { strings: $a = \"aBc\" nocase  condition: $a }", str);
    assertTrueRule("rule test { strings: $a = \"abc\" fullword condition: $a }", str);
    assertFalseRule("rule test { strings: $a = \"a\" fullword condition: $a }", str);
    assertFalseRule("rule test { strings: $a = \"ab\" fullword condition: $a }", str);
    assertFalseRule("rule test { strings: $a = \"abc\" wide fullword condition: $a }", str);
    assertTrueRuleBlob("rule test { strings: $a = \"a\" wide condition: $a }", blob);
    assertTrueRuleBlob("rule test { strings: $a = \"a\" wide ascii condition: $a }", blob);
    assertTrueRuleBlob("rule test { strings: $a = \"ab\" wide condition: $a }", blob);
    assertTrueRuleBlob("rule test { strings: $a = \"ab\" wide ascii condition: $a }", blob);
    assertTrueRuleBlob("rule test { strings: $a = \"abc\" wide condition: $a }", blob);
    assertTrueRuleBlob("rule test { strings: $a = \"abc\" wide nocase fullword condition: $a }", blob);
    assertTrueRuleBlob("rule test { strings: $a = \"aBc\" wide nocase condition: $a }", blob);
    assertTrueRuleBlob("rule test { strings: $a = \"aBc\" wide ascii nocase condition: $a }", blob);
    assertTrueRuleBlob("rule test { strings: $a = \"---xyz\" wide nocase condition: $a }", blob);
    assertTrueRule("rule test { strings: $a = \"abc\" fullword condition: $a }", TEXT_1024_BYTES + "abc");
    assertFalseRule("rule test { strings: $a = \"abc\" fullword condition: $a }", TEXT_1024_BYTES + "xabcx");
    assertFalseRule("rule test { strings: $a = \"abc\" fullword condition: $a }", TEXT_1024_BYTES + "xabc");
    assertFalseRule("rule test { strings: $a = \"abc\" fullword condition: $a }", TEXT_1024_BYTES + "abcx");
    assertFalseRuleBlob("rule test { strings: $a = \"abc\" wide condition: $a }", TEXT_1024_BYTES + "a\u0001b\u0000c\u0000d\u0000e\u0000f\u0000");
    assertFalseRuleBlob("rule test { strings: $a = \"abcdef\" wide condition: $a }", TEXT_1024_BYTES + "a\u0000b\u0000c\u0000d\u0000e\u0000f\u0001");
    assertFalseRule("rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }", TEXT_1024_BYTES + "abcx");
    assertTrueRuleBlob("rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }", TEXT_1024_BYTES + "a\u0000abc");
    assertTrueRuleBlob("rule test { strings: $a = \"abc\" wide fullword condition: $a }", TEXT_1024_BYTES + "a\u0000b\u0000c\u0000");
    assertFalseRuleBlob("rule test { strings: $a = \"abc\" wide fullword condition: $a }", TEXT_1024_BYTES + "x\u0000a\u0000b\u0000c\u0000x\u0000");
    assertFalseRuleBlob("rule test { strings: $a = \"ab\" wide fullword condition: $a }", TEXT_1024_BYTES + "x\u0000a\u0000b\u0000");
    assertFalseRuleBlob("rule test { strings: $a = \"abc\" wide fullword condition: $a }", TEXT_1024_BYTES + "x\u0000a\u0000b\u0000c\u0000");
    assertTrueRuleBlob("rule test { strings: $a = \"abc\" wide fullword condition: $a }", TEXT_1024_BYTES + "x\u0001a\u0000b\u0000c\u0000");
    assertTrueRule("rule test { strings: $a = \"\\t\\r\\n\\\"\\\\\" condition: $a }", TEXT_1024_BYTES + "\t\r\n\"\\");
    assertTrueRule("rule test {\n         strings:\n             $a = \"abcdef\"\n             $b = \"cdef\"\n             $c = \"ef\"\n         condition:\n             all of them\n       }", TEXT_1024_BYTES + "abcdef");
    assertTrueRule("rule test {\n         strings:\n             $a = \"foo\"\n             $b = \"bar\"\n             $c = \"baz\"\n         condition:\n             all of them in (0..10)\n       }", "foobarbaz" + TEXT_1024_BYTES);
    // https://github.com/VirusTotal/yara/issues/1695
    assertFalseRule("rule test {\n         strings:\n             $a = \"AXS\"\n             $b = \"ERS\"\n         condition:\n             none of them in (0..10)\n       }", "AXSERS" + TEXT_1024_BYTES);
    // https://github.com/VirusTotal/yara/issues/1757
    assertFalseRule("rule test {\n         strings:\n             $a = \"foo\"\n             $b = \"foo\"\n         condition:\n             none of them in (0..1)\n       }", "foo");
    // https://github.com/VirusTotal/yara/issues/1660
    assertFalseRule("rule test {\n         strings:\n             $a = \"foo\"\n             $b = \"bar\"\n             $c = \"baz\"\n         condition:\n             all of them in (0..1)\n       }", TEXT_1024_BYTES);
    assertTrueRule("rule test {\n         strings:\n             $a = \"foo\"\n         condition:\n             #a == 3 and #a in (0..10) == 2\n       }", "foofoo" + TEXT_1024_BYTES + "foo");
    // xor by itself will match the plaintext version of the string too.
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" xor\n      condition:\n        #a == 256\n    }", "tests/data/xor.out");
    // Make sure the combination of xor and ascii behaves the same as just xor.
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" xor ascii\n      condition:\n        #a == 256\n    }", "tests/data/xor.out");
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" xor(1-0x10)\n      condition:\n        #a == 16\n    }", "tests/data/xor.out");
    // We should have no matches here because we are not generating the ascii
    // string, just the wide one, and the test data contains no wide strings.
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" xor wide\n      condition:\n        #a == 0\n    }", "tests/data/xor.out");
    // xor by itself is equivalent to xor(0-255).
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" xor wide\n      condition:\n        #a == 256\n    }", "tests/data/xorwide.out");
    // This DOES NOT look for the plaintext wide version by itself.
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" xor(1-16) wide\n      condition:\n        #a == 16\n    }", "tests/data/xorwide.out");
    // Check the location of the match to make sure we match on the correct one.
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" xor(1) wide\n      condition:\n        #a == 1 and @a == 0x2f\n    }", "tests/data/xorwide.out");
    assertError("rule test {\n      strings:\n        $a = \"This program cannot\" xor(300)\n      condition:\n        $a\n    }", ErrorCode.INVALID_MODIFIER);
    assertError("rule test {\n      strings:\n        $a = \"This program cannot\" xor(200-10)\n      condition:\n        $a\n    }", ErrorCode.INVALID_MODIFIER);
    assertError("rule test {\n      strings:\n        $a = {00 11 22 33} xor\n      condition:\n        $a\n    }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test {\n      strings:\n        $a = /foo(bar|baz)/ xor\n      condition:\n        $a\n    }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test {\n      strings:\n        $a = \"ab\" xor xor\n      condition:\n        $a\n    }", ErrorCode.DUPLICATED_MODIFIER);
    // We should have no matches here because we are not generating the wide
    // string, just the ascii one, and the test data contains no ascii strings.
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" xor ascii\n      condition:\n        #a == 0\n    }", "tests/data/xorwide.out");
    // This should match 512 times because we are looking for the wide and ascii
    // versions in plaintext and doing xor(0-255) (implicitly)
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" xor wide ascii\n      condition:\n        #a == 512\n    }", "tests/data/xorwideandascii.out");
    assertTrueRuleFile("rule test {\n      strings:\n        $a = \"This program cannot\" wide ascii\n      condition:\n        #a == 2\n    }", "tests/data/xorwideandascii.out");
    assertError("rule test {\n      strings:\n        $a = \"ab\" xor nocase\n      condition:\n        true\n    }", ErrorCode.INVALID_MODIFIER);
    assertTrueRule("rule test {         strings:          $a = \"AXS\" private      condition:        all of them      }", TEXT_1024_BYTES + "AXS");
    assertTrueRule("rule test {         strings:          $a = { 45 52 53 } private      condition:        all of them      }", TEXT_1024_BYTES + "ERS");
    assertTrueRule("rule test {         strings:          $a = /AXS[0-9]{4}ERS[0-9]{4}/ private      condition:        all of them      }", TEXT_1024_BYTES + "AXS1111ERS2222");
    assertError("rule test {\n      strings:\n        $a = \"ab\" base64 nocase\n      condition:\n        true\n    }", ErrorCode.INVALID_MODIFIER);
    assertError("rule test {\n      strings:\n        $a = \"ab\" base64 xor\n      condition:\n        true\n    }", ErrorCode.INVALID_MODIFIER);
    assertError("rule test {\n      strings:\n        $a = \"ab\" base64 fullword\n      condition:\n        true\n    }", ErrorCode.INVALID_MODIFIER);
    assertError("rule test {\n      strings:\n        $a = \"ab\" base64(\"AXS\")\n      condition:\n        true\n    }", ErrorCode.INVALID_MODIFIER);
    assertError("rule test {\n      strings:\n        $a = \"ab\" base64wide(\"ERS\")\n      condition:\n        true\n    }", ErrorCode.INVALID_MODIFIER);
    // Specifying different alphabets is an error.
    assertError("rule test {\n      strings:\n        $a = \"ab\" base64 base64wide(\"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ,.\")\n      condition:\n        true\n    }", ErrorCode.INVALID_MODIFIER);
    // Be specific about the offsets in these tests to make sure we are matching
    // the correct strings. Also be specific about the length because we want to
    // make sure the match is not the entire base64 string, but just the
    // substrings which are not dependent upon leading or trailing bytes.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64\n        condition:\n          #a == 6 and\n          @a[1] == 0x53 and\n          !a[1] == 25 and\n          @a[2] == 0x70 and\n          !a[2] == 25 and\n          @a[3] == 0xa2 and\n          !a[3] == 24 and\n          @a[4] == 0xbd and\n          !a[4] == 24 and\n          @a[5] == 0xef and\n          !a[5] == 25 and\n          @a[6] == 0x109 and\n          !a[6] == 25\n      }", "tests/data/base64");
    // This is identical to "base64" alone, but test it to make sure we don't
    // accidentally include the plaintext in the base64 search.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64 ascii\n        condition:\n          #a == 6 and\n          @a[1] == 0x53 and\n          !a[1] == 25 and\n          @a[2] == 0x70 and\n          !a[2] == 25 and\n          @a[3] == 0xa2 and\n          !a[3] == 24 and\n          @a[4] == 0xbd and\n          !a[4] == 24 and\n          @a[5] == 0xef and\n          !a[5] == 25 and\n          @a[6] == 0x109 and\n          !a[6] == 25\n      }", "tests/data/base64");
    // Make sure the wide modifier is applied BEFORE the base64 and we do NOT
    // include the wide plaintext string.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64 wide\n        condition:\n          #a == 6 and\n          @a[1] == 0x1b5 and\n          !a[1] == 50 and\n          @a[2] == 0x1ea and\n          !a[2] == 50 and\n          @a[3] == 0x248 and\n          !a[3] == 50 and\n          @a[4] == 0x27b and\n          !a[4] == 50 and\n          @a[5] == 0x2db and\n          !a[5] == 50 and\n          @a[6] == 0x311 and\n          !a[6] == 50\n      }", "tests/data/base64");
    // Make sure that both wide and ascii are base64 encoded. We can skip the
    // verbose length and offset checks, since the previous tests cover that.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64 wide ascii\n        condition:\n          #a == 12\n      }", "tests/data/base64");
    // Make sure that the two strings are generated when one ascii byte is
    // base64 encoded. When stripped, third base64 encoded is null.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"a\" base64\n          $b = \"a\" base64wide\n        condition:\n          @a[58] == 0x6ac and\n          @a[59] == 0x6b9 and\n          @b[15] == 0x6f7 and\n          @b[16] == 0x711\n      }", "tests/data/base64");
    // In the future, assert false if character classes are generated instead
    // of stripping the leading and trailing characters
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"Dhis program cannow\" base64\n        condition:\n          #a == 2 and\n          @a[1] == 0xa2 and\n          @a[2] == 0xbd\n      }", "tests/data/base64");
    // This checks for the ascii string in base64 form then widened.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64wide\n        condition:\n          #a == 3 and\n          @a[1] == 0x379 and\n          !a[1] == 50 and\n          @a[2] == 0x3b6 and\n          !a[2] == 48 and\n          @a[3] == 0x3f1 and\n          !a[3] == 50\n      }", "tests/data/base64");
    // Logically identical to the test above but include it to make sure we don't
    // accidentally include the plaintext in the future.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64wide ascii\n        condition:\n          #a == 3 and\n          @a[1] == 0x379 and\n          !a[1] == 50 and\n          @a[2] == 0x3b6 and\n          !a[2] == 48 and\n          @a[3] == 0x3f1 and\n          !a[3] == 50\n      }", "tests/data/base64");
    // Make sure the wide string is base64wide encoded.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64wide wide\n        condition:\n          #a == 3 and\n          @a[1] == 0x458 and\n          !a[1] == 100 and\n          @a[2] == 0x4c5 and\n          !a[2] == 100 and\n          @a[3] == 0x530 and\n          !a[3] == 100\n      }", "tests/data/base64");
    // Make sure both ascii and wide strings are base64wide encoded properly.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64wide wide ascii\n        condition:\n          #a == 6 and\n          @a[1] == 0x379 and\n          !a[1] == 50 and\n          @a[2] == 0x3b6 and\n          !a[2] == 48 and\n          @a[3] == 0x3f1 and\n          !a[3] == 50 and\n          @a[4] == 0x458 and\n          !a[4] == 100 and\n          @a[5] == 0x4c5 and\n          !a[5] == 100 and\n          @a[6] == 0x530 and\n          !a[6] == 100\n      }", "tests/data/base64");
    // Make sure base64 and base64wide together work.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64 base64wide\n        condition:\n          #a == 9 and\n          @a[1] == 0x53 and\n          !a[1] == 25 and\n          @a[2] == 0x70 and\n          !a[2] == 25 and\n          @a[3] == 0xa2 and\n          !a[3] == 24 and\n          @a[4] == 0xbd and\n          !a[4] == 24 and\n          @a[5] == 0xef and\n          !a[5] == 25 and\n          @a[6] == 0x109 and\n          !a[6] == 25 and\n          @a[7] == 0x379 and\n          !a[7] == 50 and\n          @a[8] == 0x3b6 and\n          !a[8] == 48 and\n          @a[9] == 0x3f1 and\n          !a[9] == 50\n      }", "tests/data/base64");
    // Identical to the test above but useful to make sure we don't accidentally
    // include the ascii plaintext in the future.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64 base64wide ascii\n        condition:\n          #a == 9\n      }", "tests/data/base64");
    // Making sure we don't accidentally include the wide plaintext in the future.
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64 base64wide wide\n        condition:\n          #a == 9\n      }", "tests/data/base64");
    assertTrueRuleFile("rule test {\n        strings:\n          $a = \"This program cannot\" base64(\"!@#$%^&*(){}[].,|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu\")\n        condition:\n          #a == 3 and\n          @a[1] == 0x619 and\n          !a[1] == 25 and\n          @a[2] == 0x638 and\n          !a[2] == 24 and\n          @a[3] == 0x656 and\n          !a[3] == 25\n      }", "tests/data/base64");
  }

  @Test
  void testWildcardStrings() throws Exception {
    assertTrueRuleBlob("rule test {\n         strings:\n             $s1 = \"abc\"\n             $s2 = \"xyz\"\n         condition:\n             for all of ($*) : ($)\n      }", TEXT_1024_BYTES + "---- abc ---- A\u0000B\u0000C\u0000 ---- xyz");
  }

  @Test
  void testHexStrings() throws Exception {
    assertTrueRuleBlob("rule test {         strings: $a = { 64 01 00 00 60 01 }         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { 64 0? 00 00 ?0 01 }         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { 6? 01 00 00 60 0? }         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { 64 01 [1-3] 60 01 }         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { 64 01 [1-3] (60|61) 01 }         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { 4D 5A [-] 6A 2A [-] 58 C3}         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { 4D 5A [300-] 6A 2A [-] 58 C3}         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { 2e 7? (65 | ?? ) 78 }         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertFalseRuleBlob("rule test {         strings: $a = { 4D 5A [0-300] 6A 2A }         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertFalseRuleBlob("rule test {         strings: $a = { 4D 5A [0-128] 45 [0-128] 01 [0-128]  C3 }         condition: $a }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRule("rule test {         strings: $a = { 31 32 [-] 38 39 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = {\n 31 32 [-] 38 39 \n\r}         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [-] 33 34 [-] 38 39 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [-] 33 34 [-] 38 39 } private         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [1] 34 35 [2] 38 39 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [1-] 34 35 [1-] 38 39 }          condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-3] 34 35 [1-] 38 39 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-2] 35 [1-] 37 38 39 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-1] 33 }         condition: !a == 3}", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-1] 34 }         condition: !a == 4}", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-2] 34 }         condition: !a == 4 }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [-] 38 39 }         condition: all of them }", TEXT_1024_BYTES + "1234567890");
    assertFalseRule("rule test {         strings: $a = { 31 32 [-] 32 33 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 ~32 34 35 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertFalseRule("rule test {         strings: $a = { 31 32 ~33 34 35 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { ( 31 32 ~32 34 35 | 31 32 ~33 34 35 ) }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 ~?2 34 35 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertFalseRule("rule test {         strings: $a = { 31 32 ~?3 34 35 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 ~4? 34 35 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertFalseRule("rule test {         strings: $a = { 31 32 ~3? 34 35 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { ( 31 32 ~3? 34 35 | 31 32 ~?2 34 35 ) }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertFalseRule("rule test {         strings: $a = { 35 36 [-] 31 32 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertFalseRule("rule test {         strings: $a = { 31 32 [2-] 34 35 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-1] 33 34 [0-2] 36 37 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-1] 34 35 [0-2] 36 37 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertFalseRule("rule test {         strings: $a = { 31 32 [0-3] 37 38 }         condition: $a }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [1] 33 34 }         condition: $a }", TEXT_1024_BYTES + "12\n34");
    assertTrueRule("rule test {         strings: $a = {31 32 [3-6] 32}         condition: !a == 6 }", TEXT_1024_BYTES + "12111222");
    assertTrueRule("rule test {         strings: $a = {31 [0-3] (32|33)}         condition: !a == 2 }", "122222222" + TEXT_1024_BYTES);
    assertTrueRule("rule test {         strings: $a = { 30 31 32 [0-5] 38 39 }         condition: $a }", "0123456789");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-5] 38 39 30 }         condition: $a }", "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-2] 34 [0-2] 34 }         condition: $a }", "1244");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-2] 34 [0-2] 34 }         condition: $a }", "12344");
    assertTrueRule("rule test {         strings: $a = { 31 32 [0-2] 34 [0-2] 34 [2-3] 34 }         condition: $a }", "123440004");
    assertTrueRule("rule test {         strings: $a = { 31[-][8-][-]30 }         condition: $a }", "1234567890");
    assertFalseRule("rule test {         strings: $a = { 31[-][9-][-]30 }         condition: $a }", "1234567890");
    // Test case for https://github.com/VirusTotal/yara/issues/2065
    byte[] ISSUE_2065 = {
      (byte) 0x81, (byte) 0xEC, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, (byte) 0xB8, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, (byte) 0xB8, 0x00, 0x00, 0x00, 0x00, 0x44, 0x55, 0x66, 0x77
    };
    assertTrueRuleBlob("rule test {         strings: $a = { 81 EC 38 01 [4-25] B8 ?? ?? ?? ?? [20-21] 44 55 66 77  }         condition: $a }", ISSUE_2065);
    assertError("rule test {         strings: $a = { 01 [0] 02 }         condition: $a }", ErrorCode.INVALID_HEX_STRING);
    assertError("rule test {         strings: $a = { [-] 01 02 } condition: $a }", ErrorCode.INVALID_HEX_STRING);
    assertError("rule test {         strings: $a = { 01 02 [-] }         condition: $a }", ErrorCode.INVALID_HEX_STRING);
    assertError("rule test {         strings: $a = { 01 02 ([-] 03 | 04) }         condition: $a }", ErrorCode.INVALID_HEX_STRING);
    assertError("rule test {         strings: $a = { 01 02 (03 [-] | 04) }         condition: $a }", ErrorCode.INVALID_HEX_STRING);
    assertError("rule test {         strings: $a = { 01 02 (03 | 04 [-]) }         condition: $a ", ErrorCode.INVALID_HEX_STRING);
    assertError("rule test {         strings: $a = { 01 02 ~ }         condition: $a ", ErrorCode.INVALID_HEX_STRING);
    assertError("rule test {         strings: $a = { 01 ~0 11 }         condition: $a ", ErrorCode.INVALID_HEX_STRING);
    assertError("rule test {         strings: $a = { 01 ~?? 11 }         condition: $a ", ErrorCode.INVALID_HEX_STRING);
    // Jump lengths that don't fit in an int must be rejected. 4294967297 used to
    // wrap around to 1, so this compiled as { 61 [0-1] 62 }.
    assertError("rule test {         strings: $a = { 61 [0-4294967297] 62 }         condition: $a }", ErrorCode.INVALID_HEX_STRING);
    assertError("rule test {         strings: $a = { 61 [0-2147483648] 62 }         condition: $a }", ErrorCode.INVALID_HEX_STRING);
    //  TODO: tests.py:551 ff. 
  }

  @Test
  void testCount() throws Exception {
    assertTrueRule("rule test { strings: $a = \"ssi\" condition: #a == 2 }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = \"ssi\" private condition: #a == 2 }", TEXT_1024_BYTES + "mississippi");
  }

  @Test
  void testAt() throws Exception {
    assertTrueRule("rule test {         strings: $a = \"miss\"         condition: any of them at 0}", "mississippi");
    assertTrueRule("rule test {         strings: $a = \"ssi\"         condition: $a at (1024+2) and $a at (1024+5) }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test {         strings: $a = \"ssi\" private         condition: $a at (1024+2) and $a at (1024+5) }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test {         strings: $a = \"mis\"         condition: $a at (1024+(~0xFF & 0xFF)) }", TEXT_1024_BYTES + "mississippi");
    assertTrueRuleBlob("rule test {         strings: $a = { 00 00 00 00 ?? 74 65 78 74 }         condition: $a at 308}", com.paveldan.yara4j.Blobs.PE32_FILE);
  }

  @Test
  void testIn() throws Exception {
    assertTrueRuleBlob("rule test {         strings: $a = { 6a 2a 58 c3 }         condition: $a in (entrypoint .. entrypoint + 1) }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { 6a 2a 58 c3 } private         condition: $a in (entrypoint .. entrypoint + 1) }", com.paveldan.yara4j.Blobs.PE32_FILE);
  }

  @Test
  void testOffset() throws Exception {
    assertTrueRule("rule test { strings: $a = \"ssi\" condition: @a == (1024+2) }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = \"ssi\" private condition: @a == (1024+2) }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = \"ssi\" condition: @a == @a[1] }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = \"ssi\" condition: @a[2] == (1024+5) }", TEXT_1024_BYTES + "mississippi");
  }

  @Test
  void testLength() throws Exception {
    assertTrueRule("rule test { strings: $a = /m.*?ssi/ condition: !a == 5 }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = /m.*?ssi/ private condition: !a == 5 }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = /m.*?ssi/ condition: !a[1] == 5 }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = /m.*ssi/ condition: !a == 8 }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = /m.*ssi/ condition: !a[1] == 8 }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = /ssi.*ppi/ condition: !a[1] == 9 }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = /ssi.*ppi/ condition: !a[2] == 6 }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = { 6D [1-3] 73 73 69 } condition: !a == 5}", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = { 6D [-] 73 73 69 } condition: !a == 5}", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = { 6D [-] 70 70 69 } condition: !a == 11}", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = { 6D 69 73 73 [-] 70 69 } condition: !a == 11}", TEXT_1024_BYTES + "mississippi");
  }

  @Test
  void testRuleOf() throws Exception {
    assertMatchCount("rule a { condition: true } rule b { condition: 1 of (a) }", null, 2);
    // https://github.com/VirusTotal/yara/issues/1695
    assertMatchCount("rule a { condition: false } rule b { condition: none of (a) }", null, 1);
    assertMatchCount("rule a1 { condition: true } rule a2 { condition: true } rule b { condition: 2 of (a*) }", null, 3);
    assertMatchCount("rule a1 { condition: true } rule a2 { condition: false } rule b { condition: 50% of (a*) }", null, 2);
    assertError("rule a { condition: all of (b*) }", ErrorCode.UNDEFINED_IDENTIFIER);
    assertError("rule a0 { condition: true } rule b { condition: 1 of (a*) } rule a1 { condition: true } ", ErrorCode.IDENTIFIER_MATCHES_WILDCARD);
    // Make sure repeating the rule set works
    assertMatchCount("rule a { condition: true } rule b { condition: 1 of (a*) } rule c { condition: 1 of (a*) }", null, 3);
    // This will compile but is false for the same reason that
    // "rule x { condition: x }" is compiles but is false.
    assertFalseRule("rule a { condition: 1 of (a*) }", null);
  }

  @Test
  void testOf() throws Exception {
    assertTrueRule("rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" condition: any of them }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" condition: none of them }", TEXT_1024_BYTES + "AXSERS");
    // https://github.com/VirusTotal/yara/issues/1695
    assertFalseRule("rule test { strings: $a = \"dummy1\" $b = \"dummy2\" $c = \"ssi\" condition: none of them }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = \"ssi\" $b = \"mis\" private $c = \"oops\" condition: 1 of them }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" condition: 2 of them }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\" condition: any of ($a*, $b*) }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\" condition: none of ($a*, $b*) }", TEXT_1024_BYTES + "AXSERS");
    // https://github.com/VirusTotal/yara/issues/1695
    assertFalseRule("rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy2\" $b2 = \"ssi\" condition: none of ($a*, $b*) }", TEXT_1024_BYTES + "mississippi");
    assertTrueRuleBlob("rule test {          strings:            $ = /abc/            $ = /def/            $ = /ghi/          condition:            for any of ($*) : ( for any i in (1..#): (uint8(@[i] - 1) == 0x00) )       }", TEXT_1024_BYTES + "abc\u0000def\u0000ghi");
    assertFalseRule("rule test {         strings:           $a = \"ssi\"           $b = \"mis\"           $c = \"oops\"         condition:           all of them       }", TEXT_1024_BYTES + "mississippi");
    assertError("rule test { condition: all of ($a*) }", ErrorCode.UNDEFINED_STRING);
    assertError("rule test { condition: all of them }", ErrorCode.UNDEFINED_STRING);
    assertError("rule test { strings: $a = \"AXS\" condition: 101% of them }", ErrorCode.INVALID_PERCENTAGE);
    assertError("rule test { strings: $a = \"ERS\" condition: 0% of them }", ErrorCode.INVALID_PERCENTAGE);
    assertTrueRule("rule test {         strings:           $a1 = \"dummy\"           $a2 = \"issi\"         condition:           50% of them       }", "mississippi");
    // This is equivalent to "50% of them" because 1050%50 == 50
    assertTrueRule("rule test {         strings:           $a1 = \"miss\"           $a2 = \"issi\"         condition:           1050%100% of them       }", "mississippi");
    assertTrueRule("rule test {         strings:           $a1 = \"miss\"           $a2 = \"issi\"         condition:           100% of them       }", "mississippi");
    assertTrueRule("import \"tests\"        rule test {          strings:            $a1 = \"miss\"            $a2 = \"issi\"          condition:            (25*tests.constants.two)% of them        }", "mississippi");
    // tests.integer_array[5] is undefined, so the following rule must evaluate
    // to false.
    assertFalseRule("import \"tests\"        rule test {          strings:            $a1 = \"miss\"            $a2 = \"issi\"          condition:            tests.integer_array[5]% of them        }", "mississippi");
    // If one of the bounds can not be determined statically it isn't an error.
    assertTrueRule("rule test {       strings:         $a = \"AXSERS\"       condition:         true or any of them in (0..filesize-100)     }", TEXT_1024_BYTES);
    // Lower bound can not be negative, if it can be determined statically.
    assertError("rule test {         strings:           $a = \"AXSERS\"         condition:           $a in (-1..10)       }", ErrorCode.INVALID_VALUE);
    // Make sure that an undefined range boundary returns an undefined value,
    // which translates to false.
    assertFalseRule("import \"tests\"         rule test { \t\t      strings: \t\t\t      $a = \"missi\" \t\t      condition: \t\t\t      any of them in (0..tests.undefined.i) \t    }", "mississippi");
  }

  @Test
  void testFor() throws Exception {
    assertTrueRule("rule test {         strings:           $a = \"ssi\"         condition:           for all i in (1..#a) : (@a[i] >= (1024+2) and @a[i] <= (1024+5))       }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test {         strings:           $a = \"ssi\"           $b = \"mi\"         condition:           for all i in (1..#a) : ( for all j in (1..#b) : (@a[i] >= @b[j]))       }", TEXT_1024_BYTES + "mississippi");
    assertFalseRule("rule test {         strings:           $a = \"ssi\"         condition:           for all i in (1..#a) : (@a[i] == (1024+5))       }", TEXT_1024_BYTES + "mississippi");
    assertTrueRule("rule test {         condition:           for any i in (1, 2, 3) : (i <= 1)       }", null);
    assertTrueRule("rule test {         condition:           for all i in (1, 2, 3) : (i >= 1)       }", null);
    assertFalseRule("rule test {         condition:           for all i in (1, 0) : (i != 1)       }", null);
    assertTrueRule("import \"tests\"       rule test {         condition:           for any item in tests.struct_array : (             item.i == 1           )       }", null);
    assertTrueRule("import \"tests\"       rule test {         condition:           for 0 item in tests.struct_array : (             item.i == 100           )       }", null);
    assertTrueRule("import \"tests\"       rule test {         condition:           for any item in tests.integer_array : (             item == 2           )       }", null);
    assertTrueRule("import \"tests\"       rule test {         condition:           for any item in tests.string_array : (             item == \"bar\"           )       }", null);
    assertTrueRule("rule test {         condition:           for all i in (3,5,4) : (             i >= 3 and i <= 5           )       }", null);
    assertTrueRule("rule test {         condition:           for all i in (3..5) : (             i >= 3 and i <= 5           )       }", null);
    assertTrueRule("rule test {         condition:           for 2 i in (5..10) : (             i == 6 or i == 7           )       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           for any k,v in tests.empty_struct_dict : (             true           )       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           for all i in (1..tests.undefined.i) : (             true           )       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           for all i in (tests.undefined.i..10) : (             true           )       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           for all i in (1..tests.undefined.i) : (             false           )       }", null);
    assertTrueRule("import \"tests\"       rule test {         condition:           for any k,v in tests.struct_dict : (             k == \"foo\" and v.s == \"foo\" and v.i == 1           )       }", null);
    assertError("import \"tests\"       rule test {         condition:           for any k,v in tests.integer_array : ( false )       }", ErrorCode.SYNTAX_ERROR);
    assertError("import \"tests\"       rule test {         condition:           for any a,b,c in tests.struct_dict : ( false )       }", ErrorCode.SYNTAX_ERROR);
    assertError("import \"tests\"       rule test {         condition:           for any i in tests.struct_dict : ( false )       }", ErrorCode.SYNTAX_ERROR);
    assertError("import \"tests\"       rule test {         condition:           for any i in tests.integer_array : ( undefined_ident )       }", ErrorCode.UNDEFINED_IDENTIFIER);
    assertError("import \"tests\"       rule test {         condition:           for any i in tests.integer_array : ( i == \"foo\" )       }", ErrorCode.WRONG_TYPE);
    assertFalseRule("rule test {         condition:           for any i in (0,1): (             for any j in (0,1): (               for any k in (0,1): (                 for any l in (0,1): (                  false                 )               )             )         )       }", null);
    // Lower bound must be less than upper bound, if it can be determined
    // statically.
    assertError("rule test {         condition:           for any i in (10..1): (i)       }", ErrorCode.INVALID_VALUE);
    // Test case for https://github.com/VirusTotal/yara/issues/1729
    assertTrueRule("rule test {         strings:           $a = \"abcde\"         condition:           for any n in (1..10) : ( n of ($a*) )       }", "abcde");
    assertTrueRule("rule test {         condition:           for all i in (\"a\", \"b\") : (i == \"a\" or i == \"b\")       }", null);
    assertError("rule test {         condition:           for any i in (\"a\"): (i == 0)       }", ErrorCode.WRONG_TYPE);
    assertError("rule test {         condition:           for any i in (\"a\", 0): (i == 0)       }", ErrorCode.WRONG_TYPE);
  }

  @Test
  void testRe() throws Exception {
    assertTrueRule("rule test { strings: $a = /ssi/ condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /ssi(s|p)/ condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /ssim*/ condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /ssa?/ condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /Miss/ nocase condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /(M|N)iss/ nocase condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /[M-N]iss/ nocase condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /(Mi|ssi)ssippi/ nocase condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /ppi\\tmi/ condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /ppi\\.mi/ condition: $a }", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertTrueRule("rule test { strings: $a = /^mississippi/ fullword condition: $a }", "mississippi\tmississippi.mississippi\nmississippi" + TEXT_1024_BYTES);
    assertTrueRule("rule test { strings: $a = /mississippi.*mississippi$/s condition: $a}", TEXT_1024_BYTES + "mississippi\tmississippi.mississippi\nmississippi");
    assertFalseRule("rule test { strings: $a = /^ssi/ condition: $a }", TEXT_1024_BYTES + "mississippi");
    assertFalseRule("rule test { strings: $a = /ssi$/ condition: $a }", TEXT_1024_BYTES + "mississippi");
    assertFalseRule("rule test { strings: $a = /ssissi/ fullword condition: $a }", TEXT_1024_BYTES + "mississippi");
    assertFalseRule("rule test { strings: $a = /^[isp]+/ condition: $a }", TEXT_1024_BYTES + "mississippi");
    assertTrueRuleBlob("rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 6 }", TEXT_1024_BYTES + "a\u0000x\u0000b\u0000");
    assertTrueRuleBlob("rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 8 }", TEXT_1024_BYTES + "a\u0000x\u0000x\u0000b\u0000");
    assertTrueRuleBlob("rule test { strings: $a = /\\babc/ wide condition: $a }", TEXT_1024_BYTES + "a\u0000b\u0000c\u0000");
    assertTrueRuleBlob("rule test { strings: $a = /\\babc/ wide condition: $a }", TEXT_1024_BYTES + "\u0000a\u0000b\u0000c\u0000");
    assertTrueRuleBlob("rule test { strings: $a = /\\babc/ wide condition: $a }", TEXT_1024_BYTES + "\ta\u0000b\u0000c\u0000");
    assertFalseRuleBlob("rule test { strings: $a = /\\babc/ wide condition: $a }", TEXT_1024_BYTES + "x\u0000a\u0000b\u0000c\u0000");
    assertTrueRuleBlob("rule test { strings: $a = /\\babc/ wide condition: $a }", TEXT_1024_BYTES + "x\ta\u0000b\u0000c\u0000");
    assertTrueRuleBlob("rule test { strings: $a = /abc\\b/ wide condition: $a }", TEXT_1024_BYTES + "a\u0000b\u0000c\u0000");
    assertTrueRuleBlob("rule test { strings: $a = /abc\\b/ wide condition: $a }", TEXT_1024_BYTES + "a\u0000b\u0000c\u0000\u0000");
    assertTrueRuleBlob("rule test { strings: $a = /abc\\b/ wide condition: $a }", TEXT_1024_BYTES + "a\u0000b\u0000c\u0000\t");
    assertFalseRuleBlob("rule test { strings: $a = /abc\\b/ wide condition: $a }", TEXT_1024_BYTES + "a\u0000b\u0000c\u0000x\u0000");
    assertTrueRuleBlob("rule test { strings: $a = /abc\\b/ wide condition: $a }", TEXT_1024_BYTES + "a\u0000b\u0000c\u0000b\t");
    assertFalseRule("rule test { strings: $a = /\\b/ wide condition: $a }", TEXT_1024_BYTES + "abc");
    assertTrueRule("rule test { condition: \"avb\" matches /a\\vb/ }", TEXT_1024_BYTES + "rule test { condition: \"avb\" matches /a\\vb/ }");
    assertFalseRule("rule test { condition: \"ab\" matches /a\\vb/ }", TEXT_1024_BYTES + "rule test { condition: \"ab\" matches /a\\vb/ }");
    assertRegexpSyntaxError(")");
    assertTrueRegexp("abc", "abc", "abc");
    assertFalseRegexp("abc", "xbc");
    assertFalseRegexp("abc", "axc");
    assertFalseRegexp("abc", "abx");
    assertTrueRegexp("abc", "xabcx", "abc");
    assertTrueRegexp("abc", "ababc", "abc");
    assertTrueRegexp("a.c", "abc", "abc");
    assertFalseRegexp("a.b", "a\nb");
    assertFalseRegexp("a.*b", "acc\nccb");
    assertFalseRegexp("a.{4,5}b", "acc\nccb");
    assertTrueRegexp("a.b", "a\rb", "a\rb");
    assertTrueRegexp("ab*c", "abc", "abc");
    assertTrueRegexp("ab*c", "ac", "ac");
    assertTrueRegexp("ab*bc", "abc", "abc");
    assertTrueRegexp("ab*bc", "abbc", "abbc");
    assertTrueRegexp("a.*bb", "abbbb", "abbbb");
    assertTrueRegexp("a.*?bbb", "abbbbbb", "abbb");
    assertTrueRegexp("a.*c", "ac", "ac");
    assertTrueRegexp("a.*c", "axyzc", "axyzc");
    assertTrueRegexp("ab+c", "abbc", "abbc");
    assertFalseRegexp("ab+c", "ac");
    assertTrueRegexp("ab+", "abbbb", "abbbb");
    assertTrueRegexp("ab+?", "abbbb", "ab");
    assertFalseRegexp("ab+bc", "abc");
    assertFalseRegexp("ab+bc", "abq");
    assertTrueRegexp("a+b+c", "aabbabc", "abc");
    assertFalseRegexp("ab?bc", "abbbbc");
    assertTrueRegexp("ab?c", "abc", "abc");
    assertTrueRegexp("ab*?", "abbb", "a");
    assertTrueRegexp("ab?c", "ac", "ac");
    assertTrueRegexp("ab??", "ab", "a");
    assertTrueRegexp("a(b|x)c", "abc", "abc");
    assertTrueRegexp("a(b|x)c", "axc", "axc");
    assertTrueRegexp("a(b|.)c", "axc", "axc");
    assertTrueRegexp("a(b|x|y)c", "ayc", "ayc");
    assertTrueRegexp("(a+|b)*", "ab", "ab");
    assertTrueRegexp("a|b|c|d|e", "e", "e");
    assertTrueRegexp("(a|b|c|d|e)f", "ef", "ef");
    assertTrueRegexp("a|b", "a", "a");
    assertTrueRegexp(".b{2}", "abb", "abb");
    assertTrueRegexp(".b{2,3}", "abbb", "abbb");
    assertTrueRegexp(".b{2,3}?", "abbb", "abb");
    assertTrueRegexp("ab{2,3}c", "abbbc", "abbbc");
    assertTrueRegexp("ab{2,3}?c", "abbbc", "abbbc");
    assertTrueRegexp(".b{2,3}cccc", "abbbcccc", "abbbcccc");
    assertTrueRegexp(".b{2,3}?cccc", "abbbcccc", "bbbcccc");
    assertTrueRegexp("a.b{2,3}cccc", "aabbbcccc", "aabbbcccc");
    assertTrueRegexp("ab{2,3}c", "abbbc", "abbbc");
    assertTrueRegexp("ab{2,3}?c", "abbbc", "abbbc");
    assertTrueRegexp("ab{2, 3}c", "abbbc", "abbbc");
    assertTrueRegexp("ab{2 ,3}c", "abbbc", "abbbc");
    assertTrueRegexp("ab{2  ,  3}c", "abbbc", "abbbc");
    assertTrueRegexp("ab{0,1}?c", "abc", "abc");
    assertTrueRegexp("a{0,1}?bc", "abc", "abc");
    assertTrueRegexp("a{0,1}bc", "bbc", "bc");
    assertTrueRegexp("a{0,1}?bc", "abc", "bc");
    assertTrueRegexp("a{,0}", "a", "");
    assertTrueRegexp("a{,0}", "x", "");
    assertTrueRegexp("aa{0,1}?bc", "abc", "abc");
    assertTrueRegexp("aa{0,1}?bc", "abc", "abc");
    assertTrueRegexp("aa{0,1}bc", "abc", "abc");
    assertTrueRegexp("ab{1}c", "abc", "abc");
    assertTrueRegexp("ab{1,2}c", "abbc", "abbc");
    assertFalseRegexp("ab{1,2}c", "abbbc");
    assertTrueRegexp("ab{1,}c", "abbbc", "abbbc");
    assertFalseRegexp("ab{1,}b", "ab");
    assertFalseRegexp("ab{1}c", "abbc");
    assertFalseRegexp("ab{1}c", "ac");
    assertTrueRegexp("ab{0,}c", "ac", "ac");
    assertTrueRegexp("ab{1,1}c", "abc", "abc");
    assertTrueRegexp("ab{0,}c", "abbbc", "abbbc");
    assertTrueRegexp("ab{,3}c", "abbbc", "abbbc");
    assertFalseRegexp("ab{,2}c", "abbbc");
    assertFalseRegexp("ab{4,5}bc", "abbbbc");
    assertFalseRegexp("ab{3}c", "abbbbc");
    // Issue #817
    assertFalseRegexp("ab{4}c", "abbbbbc");
    assertFalseRegexp("ab{5}c", "abbbbbbc");
    assertTrueRegexp("ab{0,1}", "abbbbb", "ab");
    assertTrueRegexp("ab{0,2}", "abbbbb", "abb");
    assertTrueRegexp("ab{0,3}", "abbbbb", "abbb");
    assertTrueRegexp("ab{0,4}", "abbbbb", "abbbb");
    assertTrueRegexp("ab{1,1}", "abbbbb", "ab");
    assertTrueRegexp("ab{1,2}", "abbbbb", "abb");
    assertTrueRegexp("ab{1,3}", "abbbbb", "abbb");
    assertTrueRegexp("ab{2,2}", "abbbbb", "abb");
    assertTrueRegexp("ab{2,3}", "abbbbb", "abbb");
    assertTrueRegexp("ab{2,4}", "abbbbc", "abbbb");
    assertTrueRegexp("ab{3,4}", "abbb", "abbb");
    assertTrueRegexp("ab{3,5}", "abbbbb", "abbbbb");
    assertFalseRegexp("ab{3,4}c", "abbbbbc");
    assertFalseRegexp("ab{3,4}c", "abbc");
    assertFalseRegexp("ab{3,5}c", "abbbbbbc");
    assertTrueRegexp("ab{1,3}?", "abbbbb", "ab");
    assertTrueRegexp("ab{0,1}?", "abbbbb", "a");
    assertTrueRegexp("ab{0,2}?", "abbbbb", "a");
    assertTrueRegexp("ab{0,3}?", "abbbbb", "a");
    assertTrueRegexp("ab{0,4}?", "abbbbb", "a");
    assertTrueRegexp("ab{1,1}?", "abbbbb", "ab");
    assertTrueRegexp("ab{1,2}?", "abbbbb", "ab");
    assertTrueRegexp("ab{1,3}?", "abbbbb", "ab");
    assertTrueRegexp("ab{2,2}?", "abbbbb", "abb");
    assertTrueRegexp("ab{2,3}?", "abbbbb", "abb");
    assertTrueRegexp("(a{2,3}b){2,3}", "aabaaabaab", "aabaaabaab");
    assertTrueRegexp("(a{2,3}?b){2,3}?", "aabaaabaab", "aabaaab");
    assertFalseRegexp("(a{4,5}b){4,5}", "aaaabaaaabaaaaab");
    assertTrueRegexp("(a{4,5}b){4,5}", "aaaabaaaabaaaaabaaaaab", "aaaabaaaabaaaaabaaaaab");
    assertTrueRegexp(".(abc){0,1}", "xabcabcabcabc", "xabc");
    assertTrueRegexp(".(abc){0,2}", "xabcabcabcabc", "xabcabc");
    assertTrueRegexp("x{1,2}abcd", "xxxxabcd", "xxabcd");
    assertTrueRegexp("x{1,2}abcd", "xxxxabcd", "xxabcd");
    assertTrueRegexp("ab{.*}", "ab{c}", "ab{c}");
    assertTrueRegexp(".(aa){1,2}", "aaaaaaaaaa", "aaaaa");
    assertTrueRegexp("a.(bc.){2}", "aabcabca", "aabcabca");
    assertTrueRegexp("(ab{1,2}c){1,3}", "abbcabc", "abbcabc");
    assertTrueRegexp("ab(c|cc){1,3}d", "abccccccd", "abccccccd");
    assertTrueRegexp("a[bx]c", "abc", "abc");
    assertTrueRegexp("a[bx]c", "axc", "axc");
    assertTrueRegexp("a[0-9]*b", "ab", "ab");
    assertTrueRegexp("a[0-9]*b", "a0123456789b", "a0123456789b");
    assertTrueRegexp("[0-9a-f]+", "0123456789abcdef", "0123456789abcdef");
    assertTrueRegexp("[0-9a-f]+", "xyz0123456789xyz", "0123456789");
    assertTrueRegexp("a[\\s\\S]b", "a b", "a b");
    assertTrueRegexp("a[\\d\\D]b", "a1b", "a1b");
    assertFalseRegexp("[x-z]+", "abc");
    assertTrueRegexp("a[-]?c", "ac", "ac");
    assertTrueRegexp("a[-b]", "a-", "a-");
    assertTrueRegexp("a[-b]", "ab", "ab");
    assertTrueRegexp("a[b-]", "a-", "a-");
    assertTrueRegexp("a[b-]", "ab", "ab");
    assertTrueRegexp("[a-c-e]", "b", "b");
    assertTrueRegexp("[a-c-e]+", "abc", "abc");
    assertTrueRegexp("[*-_]+", "ABC", "ABC");
    assertTrueRegexp("[a-c-e]", "-", "-");
    assertFalseRegexp("[a-c-e]", "d");
    assertRegexpSyntaxError("[b-a]");
    assertRegexpSyntaxError("(abc");
    assertRegexpSyntaxError("abc)");
    assertRegexpSyntaxError("a[]b");
    assertTrueRegexp("a[\\-b]", "a-", "a-");
    assertTrueRegexp("a[\\-b]", "ab", "ab");
    assertTrueRegexp("a]", "a]", "a]");
    assertTrueRegexp("a[]]b", "a]b", "a]b");
    assertTrueRegexp("[a-z]-b", "c-b-c", "c-b");
    // Issue #1690
    assertTrueRegexp("a[]-]b", "a]b", "a]b");
    assertTrueRegexp("a[]-]b", "a-b", "a-b");
    assertTrueRegexp("[\\.-z]*", "...abc", "...abc");
    assertTrueRegexp("[\\.-]*", "...abc", "...");
    assertTrueRegexp("a[\\]]b", "a]b", "a]b");
    assertTrueRegexp("a[^bc]d", "aed", "aed");
    assertFalseRegexp("a[^bc]d", "abd");
    assertTrueRegexp("a[^-b]c", "adc", "adc");
    assertFalseRegexp("a[^-b]c", "a-c");
    assertFalseRegexp("a[^]b]c", "a]c");
    assertTrueRegexp("a[^]b]c", "adc", "adc");
    assertTrueRegexp("[^ab]*", "cde", "cde");
    assertRegexpSyntaxError(")(");
    assertTrueRegexp("a\\sb", "a b", "a b");
    assertTrueRegexp("a\\sb", "a\tb", "a\tb");
    assertTrueRegexp("a\\sb", "a\rb", "a\rb");
    assertTrueRegexp("a\\sb", "a\nb", "a\nb");
    assertTrueRegexp("a\\sb", "a\u000bb", "a\u000bb");
    assertTrueRegexp("a\\sb", "a\u000cb", "a\u000cb");
    assertTrueRegexp("a[\\s]*b", "a \t\r\n\u000b\u000cb", "a \t\r\n\u000b\u000cb");
    assertTrueRegexp("a[^\\S]*b", "a \t\r\n\u000b\u000cb", "a \t\r\n\u000b\u000cb");
    assertFalseRegexp("a\\Sb", "a b");
    assertFalseRegexp("a\\Sb", "a\tb");
    assertFalseRegexp("a\\Sb", "a\rb");
    assertFalseRegexp("a\\Sb", "a\nb");
    assertFalseRegexp("a\\Sb", "a\u000bb");
    assertFalseRegexp("a\\Sb", "a\u000cb");
    assertTrueRegexp("foo([^\\s]*)", "foobar\n", "foobar");
    assertTrueRegexp("foo([^\\s]*)", "foobar\r\n", "foobar");
    assertTrueRegexp("\\n\\r\\t\\f\\a", "\n\r\t\u000c\u0007", "\n\r\t\u000c\u0007");
    assertTrueRegexp("[\\n][\\r][\\t][\\f][\\a]", "\n\r\t\u000c\u0007", "\n\r\t\u000c\u0007");
    assertTrueRegexp("\\x01\\x02\\x03", "\u0001\u0002\u0003", "\u0001\u0002\u0003");
    assertTrueRegexp("[\\x01-\\x03]+", "\u0001\u0002\u0003", "\u0001\u0002\u0003");
    assertFalseRegexp("[\\x00-\\x02]+", "\u0003\u0004\u0005");
    assertTrueRegexp("[\\x5D]", "]", "]");
    assertTrueRegexp("[\\x5A-\\x5D]", "[", "[");
    assertFalseRegexp("[\\x5A-\\x5D]", "O");
    assertTrueRegexp("[\\x5D-\\x5F]", "^", "^");
    assertTrueRegexp("[\\x5C-\\x5F]", "^", "^");
    assertTrueRegexp("[\\x5D-\\x5F]", "^", "^");
    assertTrueRegexp("a\\wc", "abc", "abc");
    assertTrueRegexp("a\\wc", "a_c", "a_c");
    assertTrueRegexp("a\\wc", "a0c", "a0c");
    assertFalseRegexp("a\\wc", "a*c");
    assertTrueRegexp("\\w+", "--ab_cd0123--", "ab_cd0123");
    assertTrueRegexp("[\\w]+", "--ab_cd0123--", "ab_cd0123");
    assertTrueRegexp("\\D+", "1234abc5678", "abc");
    assertTrueRegexp("[\\d]+", "0123456789", "0123456789");
    assertTrueRegexp("[\\D]+", "1234abc5678", "abc");
    assertTrueRegexp("[\\da-fA-F]+", "123abc", "123abc");
    assertFalseRegexp("^(ab|cd)e", "abcde");
    assertTrueRegexp("(abc|)ef", "abcdef", "ef");
    assertTrueRegexp("(abc|)ef", "abcef", "abcef");
    assertTrueRegexp("(abc|)", "foo", "");
    assertTrueRegexp("\\babc", "abc", "abc");
    assertTrueRegexp("abc\\b", "abc", "abc");
    assertTrueRegexp("\\b", "abc", "");
    assertFalseRegexp("\\babc", "1abc");
    assertFalseRegexp("abc\\b", "abc1");
    assertTrueRegexp("abc\\s\\b", "abc x", "abc ");
    assertFalseRegexp("abc\\s\\b", "abc  ");
    assertTrueRegexp("\\babc\\b", " abc ", "abc");
    assertTrueRegexp("\\b\\w\\w\\w\\b", " abc ", "abc");
    assertTrueRegexp("\\w\\w\\w\\b", "abcd", "bcd");
    assertTrueRegexp("\\b\\w\\w\\w", "abcd", "abc");
    assertFalseRegexp("\\b\\w\\w\\w\\b", "abcd");
    assertFalseRegexp("\\Babc", "abc");
    assertFalseRegexp("abc\\B", "abc");
    assertTrueRegexp("\\Babc", "1abc", "abc");
    assertTrueRegexp("abc\\B", "abc1", "abc");
    assertFalseRegexp("abc\\s\\B", "abc x");
    assertTrueRegexp("abc\\s\\B", "abc  ", "abc ");
    assertTrueRegexp("\\w\\w\\w\\B", "abcd", "abc");
    assertTrueRegexp("\\B\\w\\w\\w", "abcd", "bcd");
    assertFalseRegexp("\\B\\w\\w\\w\\B", "abcd");
    // This is allowed in most regexp engines but in order to keep the
    // grammar free of shift/reduce conflicts I've decided not supporting
    // it. Users can use the (abc|) form instead.
    assertRegexpSyntaxError("(|abc)ef");
    assertTrueRegexp("((a)(b)c)(d)", "abcd", "abcd");
    assertTrueRegexp("(a|b)c*d", "abcd", "bcd");
    assertTrueRegexp("(ab|ab*)bc", "abc", "abc");
    assertTrueRegexp("a([bc]*)c*", "abc", "abc");
    assertTrueRegexp("a([bc]*)c*", "ac", "ac");
    assertTrueRegexp("a([bc]*)c*", "a", "a");
    assertTrueRegexp("a([bc]*)(c*d)", "abcd", "abcd");
    assertTrueRegexp("a([bc]+)(c*d)", "abcd", "abcd");
    assertTrueRegexp("a([bc]*)(c+d)", "abcd", "abcd");
    assertTrueRegexp("a[bcd]*dcdcde", "adcdcde", "adcdcde");
    assertFalseRegexp("a[bcd]+dcdcde", "adcdcde");
    assertTrueRegexp("\\((.*), (.*)\\)", "(a, b)", "(a, b)");
    assertTrueRegexp("abc|123$", "abcx", "abc");
    assertFalseRegexp("abc|123$", "123x");
    assertTrueRegexp("abc|^123", "123", "123");
    assertFalseRegexp("abc|^123", "x123");
    assertTrueRegexp("^abc$", "abc", "abc");
    assertFalseRegexp("^abc$", "abcc");
    assertTrueRegexp("^abc", "abcc", "abc");
    assertFalseRegexp("^abc$", "aabc");
    assertFalseRegexp("abc^", "abc");
    assertFalseRegexp("ab^c", "abc");
    assertFalseRegexp("a^bcdef", "abcdef");
    assertTrueRegexp("abc$", "aabc", "abc");
    assertFalseRegexp("$abc", "abc");
    assertTrueRegexp("(a|a$)bcd", "abcd", "abcd");
    assertFalseRegexp("(a$|a$)bcd", "abcd");
    assertFalseRegexp("(abc$|ab$)", "abcd");
    assertTrueRegexp("^a(bc+|b[eh])g|.h$", "abhg", "abhg");
    assertTrueRegexp("(bc+d$|ef*g.|h?i(j|k))", "effgz", "effgz");
    assertTrueRegexp("(bc+d$|ef*g.|h?i(j|k))", "ij", "ij");
    assertFalseRegexp("(bc+d$|ef*g.|h?i(j|k))", "effg");
    assertFalseRegexp("(bc+d$|ef*g.|h?i(j|k))", "bcdd");
    assertTrueRegexp("(bc+d$|ef*g.|h?i(j|k))", "reffgz", "effgz");
    assertTrueRegexp("abcx{0,0}", "abcx", "abc");
    assertTrueRegexp("abcx{0}", "abcx", "abc");
    // Test case for issue #324
    assertTrueRegexp("whatever|   x.   x", "   xy   x", "   xy   x");
    // Test case for issue #503, \x without two following hex-digits
    assertRegexpSyntaxError("\\x0");
    assertRegexpSyntaxError("\\x");
    assertRegexpSyntaxError("\\xxy");
    // Test case for issue #682
    assertTrueRegexp("(a|\\b)[a]{1,}", "aaaa", "aaaa");
    // Test cases for issue #1018
    assertTrueRegexp("(ba{4}){4,10}", "baaaabaaaabaaaabaaaabaaaa", "baaaabaaaabaaaabaaaabaaaa");
    assertTrueRegexp("(ba{2}a{2}){5,10}", "baaaabaaaabaaaabaaaabaaaa", "baaaabaaaabaaaabaaaabaaaa");
    assertTrueRegexp("(ba{3}){4,10}", "baaabaaabaaabaaabaaa", "baaabaaabaaabaaabaaa");
    assertTrueRegexp("(ba{4}){5,10}", "baaaabaaaabaaaabaaaabaaaa", "baaaabaaaabaaaabaaaabaaaa");
    assertFalseRegexp("(ba{4}){4,10}", "baaaabaaaabaaaa");
    // Test for integer overflow in repeat interval
    assertRegexpSyntaxError("a{2977952116}");
    // Values that wrap around to a small positive number when truncated to an
    // int must be rejected too, not silently turned into a{0} and b{1,1}.
    assertRegexpSyntaxError("a{4294967296}");
    assertRegexpSyntaxError("b{1,4294967297}");
    assertRegexpSyntaxError("c{99999999999999999999}");
    assertError("rule test { strings: $a = /a\\/ condition: $a }", ErrorCode.SYNTAX_ERROR);
    assertError("rule test { strings: $a = /[a\\/ condition: $a }", ErrorCode.SYNTAX_ERROR);
    // Test case for issue #996
    assertError("rule test {strings:$=/.{,}? /", ErrorCode.SYNTAX_ERROR);
    assertTrueRuleBlob("rule test {         strings: $a = /MZ.{300,}t/         condition: !a == 317 }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = /MZ.{300,}?t/         condition: !a == 314 }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertFalseRule("rule test { strings: $a = /abc[^d]/ nocase condition: $a }", TEXT_1024_BYTES + "abcd");
    assertFalseRule("rule test { strings: $a = /abc[^d]/ condition: $a }", TEXT_1024_BYTES + "abcd");
    assertFalseRule("rule test { strings: $a = /abc[^D]/ nocase condition: $a }", TEXT_1024_BYTES + "abcd");
    assertTrueRule("rule test { strings: $a = /abc[^D]/ condition: $a }", TEXT_1024_BYTES + "abcd");
    assertTrueRule("rule test { strings: $a = /abc[^f]/ nocase condition: $a }", TEXT_1024_BYTES + "abcd");
    assertTrueRule("rule test { strings: $a = /abc[^f]/ condition: $a }", TEXT_1024_BYTES + "abcd");
    assertTrueRule("rule test { strings: $a = /abc[^F]/ nocase condition: $a }", TEXT_1024_BYTES + "abcd");
    assertTrueRule("rule test { strings: $a = /abc[^F]/ condition: $a }", TEXT_1024_BYTES + "abcd");
    assertTrueRule("rule test { strings: $a = /[*-_]+/ nocase condition: !a == 3 }", "abc");
    assertTrueRule("rule test { strings: $a = /([$&#*-_!().])+/ nocase condition: !a == 6 }", "ABCabc");
    // Test case for issue #1006
    assertFalseRuleBlob("rule test { strings: $a = \" cmd.exe \" nocase wide condition: $a }", com.paveldan.yara4j.Blobs.ISSUE_1006);
    // Test case for issue #1117
    assertTrueRuleBlob("rule test { strings: $a =/abc([^\"\\\\])*\"/ nocase condition: $a }", TEXT_1024_BYTES + "abc\u00e0\"");
    // Test case for issue #1933
    assertTrueRuleBlob("rule test { strings: $a = /a.{1}1/ ascii wide condition: $a }", "a\u0000b\u00001\u0000");
    // Test case for issue #1933
    assertTrueRuleBlob("rule test { strings: $a = /a.{1}1/ ascii wide condition: $a }", "ab1\u0000");
  }

  @Test
  void testEntrypoint() throws Exception {
    assertTrueRuleBlob("rule test {         strings: $a = { 6a 2a 58 c3 }         condition: $a at entrypoint }", com.paveldan.yara4j.Blobs.PE32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { b8 01 00 00 00 bb 2a }         condition: $a at entrypoint }", com.paveldan.yara4j.Blobs.ELF32_FILE);
    assertTrueRuleBlob("rule test {         strings: $a = { b8 01 00 00 00 bb 2a }         condition: $a at entrypoint }", com.paveldan.yara4j.Blobs.ELF64_FILE);
    assertFalseRule("rule test { condition: entrypoint >= 0 }", null);
  }

  @Test
  void testFilesize() throws Exception {
    String rule = "rule test { condition: filesize == " + com.paveldan.yara4j.Blobs.PE32_FILE.length + " }";
    assertTrueRuleBlob(rule, com.paveldan.yara4j.Blobs.PE32_FILE);
  }

  @Test
  void testComments() throws Exception {
    assertTrueRule("rule test {\n         condition:\n             //  this is a comment\n             /*** this is a comment ***/\n             /* /* /*\n                 this is a comment\n             */\n             true\n      }", null);
    assertTrueRule("rule test {         strings: $a = { 31 32 [-] // Inline comment\n\r           38 39 }         condition: !a == 9 }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 /* Inline comment */ [-] 38 39 }         condition: !a == 9 }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 /* Inline comment */ [-] 38 39 }                  $b = { 31 32 /* Inline comment */ [-] 35 36 }         condition: (!a == 9) and (!b == 6) }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 /* Inline comment with *asterisks* */ [-] 38 39 }         condition: !a == 9}", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { 31 32 /* Inline multi-line\n\r                                  comment */ [-] 38 39 }         condition: !a == 9 }", TEXT_1024_BYTES + "1234567890");
    assertTrueRule("rule test {         strings: $a = { /*Some*/ 31 /*interleaved*/ [-] /*comments*/ 38 39 }         condition: !a == 9 }", "1234567890" + TEXT_1024_BYTES);
    // Test case for https://github.com/VirusTotal/yara/issues/1819
    assertTrueRule("rule test {         // single line comment with brace }\n\r         strings:           $a = \"foo\" ascii         condition:           $a       }", "foo");
  }

  @Test
  void testMatchesOperator() throws Exception {
    assertTrueRule("rule test { condition: \"foo\" matches /foo/ }", null);
    assertFalseRule("rule test { condition: \"foo\" matches /bar/ }", null);
    assertTrueRule("rule test { condition: \"FoO\" matches /fOo/i }", null);
    assertTrueRule("rule test { condition: \"xxFoOxx\" matches /fOo/i }", null);
    assertFalseRule("rule test { condition: \"xxFoOxx\" matches /^fOo/i }", null);
    assertFalseRule("rule test { condition: \"xxFoOxx\" matches /fOo$/i }", null);
    assertTrueRule("rule test { condition: \"foo\" matches /^foo$/i }", null);
    assertTrueRule("rule test { condition: \"foo\\nbar\" matches /foo.*bar/s }", null);
    assertFalseRule("rule test { condition: \"foo\\nbar\" matches /foo.*bar/ }", null);
    assertTrueRule("rule test { condition: \"\" matches /foo|/ }", null);
    assertTrueRule("rule test { condition: \"\" matches /a||b/ }", null);
    assertFalseRule("rule test { condition: \"\" matches /foobar/ }", null);
  }

  @Test
  void testGlobalRules() throws Exception {
    assertTrueRule("global private rule global_rule {         condition:           true       }       rule test {         condition: true       }", null);
    assertFalseRule("global private rule global_rule {         condition:           false       }       rule test {         condition: true       }", null);
    assertFalseRule("global private rule global_rule {         strings:           $a = \"foo\"         condition:           $a       }       rule test {        strings:           $a = \"bar\"         condition:           $a       }", "bar");
    assertTrueRule("global private rule global_rule {         strings:           $a = \"foo\"         condition:           $a       }       rule test {        strings:           $a = \"bar\"         condition:           $a       }", "foobar");
  }

  @Test
  void testModules() throws Exception {
    assertTrueRule("import \"tests\"        rule test {         condition: tests.constants.one + 1 == tests.constants.two       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.constants.foo == \"foo\"       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.constants.empty == \"\"        }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.empty() == \"\"        }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.struct_array[1].i == 1        }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.struct_array[0].i == 1 or true       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.integer_array[0] == 0       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.integer_array[1] == 1       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.integer_array[256] == 256       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.string_array[0] == \"foo\"       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.string_array[2] == \"baz\"       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.string_dict[\"foo\"] == \"foo\"       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.string_dict[\"bar\"] == \"bar\"       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.isum(1,2) == 3       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.isum(1,2,3) == 6       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.fsum(1.0,2.0) == 3.0       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.fsum(1.0,2.0,3.0) == 6.0       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.foobar(1) == tests.foobar(1)       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.foobar(1) != tests.foobar(2)       }", null);
    assertTrueRule("import \"tests\"        rule test {         condition: tests.length(\"dummy\") == 5       }", null);
    assertFalseRule("import \"tests\"       rule test { condition: tests.struct_array[0].i == 1        }", null);
    assertFalseRule("import \"tests\"       rule test { condition: tests.isum(1,1) == 3       }", null);
    assertFalseRule("import \"tests\"       rule test { condition: tests.fsum(1.0,1.0) == 3.0       }", null);
    assertTrueRule("import \"tests\"       rule test { condition: tests.match(/foo/,\"foo\") == 3       }", null);
    assertTrueRule("import \"tests\"       rule test { condition: tests.match(/foo/,\"bar\") == -1       }", null);
    assertTrueRule("import \"tests\"       rule test { condition: tests.match(/foo.bar/i,\"FOO\\nBAR\") == -1       }", null);
    assertTrueRule("import \"tests\"       rule test { condition: tests.match(/foo.bar/is,\"FOO\\nBAR\") == 7       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           for any k,v in tests.empty_struct_array[0].struct_dict: (             v.unused == \"foo\"           )       }", null);
    assertFalseRule("import \"tests\"       rule test {         condition:           for any item in tests.empty_struct_array[0].struct_array: (             item.unused == \"foo\"           )       }", null);
    assertTrueRule("import \"tests\"       rule test {         condition:           for any item1 in tests.struct_array: (             item1.i == 1 and             for any item2 in tests.struct_array: (               item2.i == item1.i             )           )       }", null);
    assertError("import \"\\x00\"", ErrorCode.INVALID_MODULE_NAME);
    assertError("import \"\"", ErrorCode.INVALID_MODULE_NAME);
  }

  @Test
  void testTimeModule() throws Exception {
    assertTrueRule("import \"time\"         rule test { condition: time.now() > 0 }", null);
  }

  @Test
  void testHashModule() throws Exception {
    byte[] blob = {0x61, 0x62, 0x63, 0x64, 0x65};
    // abcde without trailing zero
    assertTrueRuleBlob("import \"hash\"        rule test {         condition:           hash.md5(0, filesize) ==             \"ab56b4d92b40713acc5af89985d4b786\"             and           hash.md5(1, filesize) ==             \"e02cfbe5502b64aa5ae9f2d0d69eaa8d\"             and           hash.sha1(0, filesize) ==             \"03de6c570bfe24bfc328ccd7ca46b76eadaf4334\"             and           hash.sha1(1, filesize) ==             \"a302d65ae4d9e768a1538d53605f203fd8e2d6e2\"             and           hash.sha256(0, filesize) ==             \"36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c\"             and           hash.sha256(1, filesize) ==             \"aaaaf2863e043b9df604158ad5c16ff1adaf3fd7e9fcea5dcb322b6762b3b59a\"             and           hash.crc32(0, filesize) == 0x8587d865             and           hash.checksum32(0, filesize) == 0x1ef       }", blob);
    assertTrueRule("import \"hash\"        rule test {         condition:           hash.md5(\"TEST STRING\") ==             \"2d7d687432758a8eeeca7b7e5d518e7f\"             and           hash.sha1(\"TEST STRING\") ==             \"d39d009c05797a93a79720952e99c7054a24e7c4\"             and           hash.sha256(\"TEST STRING\") ==             \"fb6ca29024bd42f1894620ffa45fd976217e72d988b04ee02bb4793ab9d0c862\"             and           hash.crc32(\"TEST STRING\") == 0x51f9be31             and           hash.checksum32(\"TEST STRING\") == 0x337       }", null);
    // Test hash caching mechanism
    assertTrueRuleBlob("import \"hash\"        rule test {         condition:           hash.md5(0, filesize) ==             \"ab56b4d92b40713acc5af89985d4b786\"             and           hash.md5(1, filesize) ==             \"e02cfbe5502b64aa5ae9f2d0d69eaa8d\"             and           hash.md5(0, filesize) ==             \"ab56b4d92b40713acc5af89985d4b786\"             and           hash.md5(1, filesize) ==             \"e02cfbe5502b64aa5ae9f2d0d69eaa8d\"       }", blob);
    byte[] multi_block_blob = (TEXT_1024_BYTES + TEXT_1024_BYTES + "\0")
        .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    assertTrueRuleBlob("import \"hash\"        rule test {         condition:           hash.md5(768, 8) ==             \"9edc35bab4510f115d0974fc3597d444\" /*    exact 1st block boundary - overlap */             and           hash.md5(1024, 8) ==             \"2b607f2bcdf01d2cc5484230c89f5e18\" /*    exact 1st block boundary */             and           hash.md5(764, 8) ==             \"0cdfa992f3a982b27c364ab7d4ae9aa2\" /* straddle 1st block boundary - overlap */             and           hash.md5(764, 8) ==             \"0cdfa992f3a982b27c364ab7d4ae9aa2\" /* straddle 1st block boundary - overlap; cache */             and           hash.md5(1020, 8) ==             \"478adcaee8dec0bf8d9425d6894e8672\" /* straddle 1st block boundary */             and           hash.md5(1020, 8) ==             \"478adcaee8dec0bf8d9425d6894e8672\" /* straddle 1st block boundary; cache */             and           hash.md5(0, filesize) ==             \"578848bccbd8294394864707e7f581e3\"             and           hash.md5(1, filesize) ==             \"633e48db55a5b477f9eeafad0ebbe108\"             and           hash.sha1(0, filesize) ==             \"0170d3bfb54b5ba2fc12df571ffb000fcb2a379d\"             and           hash.sha1(1, filesize) ==             \"89d614c846abe670f998ef02c4f5277ab76c0b4d\"             and           hash.sha256(0, filesize) ==             \"ebc7a22f28028552576eeef3c17182a7d635ddaefbc94fc6d85f099289fdf8a5\"             and           hash.sha256(1, filesize) ==             \"9c19006ade01c93f42949723f4ec8b1158e07fa43fd946f03e84a1ce25baa2c1\"             and           hash.crc32(0, filesize) == 0x2b11af72             and           hash.crc32(\"TEST STRING\") == 0x51f9be31       }", multi_block_blob);
  }

  @Test
  void testIntegerFunctions() throws Exception {
    assertTrueRule("rule test { condition: uint8(1024) == 0xAA}", TEXT_1024_BYTES + "\u00aa\u00bb\u00cc\u00dd");
    assertTrueRule("rule test { condition: uint16(1024) == 0xBBAA}", TEXT_1024_BYTES + "\u00aa\u00bb\u00cc\u00dd");
    assertTrueRule("rule test { condition: uint32(1024) == 0xDDCCBBAA}", TEXT_1024_BYTES + "\u00aa\u00bb\u00cc\u00dd");
    assertTrueRule("rule test { condition: uint8be(1024) == 0xAA}", TEXT_1024_BYTES + "\u00aa\u00bb\u00cc\u00dd");
    assertTrueRule("rule test { condition: uint16be(1024) == 0xAABB}", TEXT_1024_BYTES + "\u00aa\u00bb\u00cc\u00dd");
    assertTrueRule("rule test { condition: uint32be(1024) == 0xAABBCCDD}", TEXT_1024_BYTES + "\u00aa\u00bb\u00cc\u00dd");
  }

  @Test
  void testIncludeFiles() throws Exception {
    String rule = "include \"" + dataDir() + "/baz.yar\" rule t { condition: baz }";
    assertTrueRule(rule, null);
    rule = "include \"" + dataDir() + "/foo.yar\" rule t { condition: foo }";
    assertTrueRule(rule, null);
  }

  @Test
  void testTags() throws Exception {
    assertTrueRule("rule test : tag1 { condition: true}", null);
    assertTrueRule("rule test : tag1 tag2 { condition: true}", null);
    assertError("rule test : tag1 tag1 { condition: true}", ErrorCode.DUPLICATED_TAG_IDENTIFIER);
  }

  @Test
  void testInvalidEscapeSequencesWarnings() throws Exception {
    assertWarningStrictEscape("rule test { strings: $a = /ab\\cdef/ condition: $a }");
    assertWarningStrictEscape("rule test { strings: $a = /ab\\ def/ condition: $a }");
    assertWarningStrictEscape("rule test { strings: $a = /ab\\;def/ condition: $a }");
    assertNoWarnings("rule test { strings: $a = /ab\\*def/ condition: $a }");
    assertNoWarnings("rule test { strings: $a = /abcdef/ condition: $a }");
    assertWarningStrictEscape("rule test { strings: $a = /ab\\cdef/ condition: $a }");
    assertNoWarnings("rule test { strings: $a = /abcdef/ condition: $a }");
    assertWarningStrictEscape("rule test { strings: $a = /\\\\WINDOWS\\\\system32\\\\\\victim\\.exe\\.exe/ condition: $a }");
    assertNoWarnings("rule test { strings: $a = /\\\\WINDOWS\\\\system32\\\\victim\\.exe\\.exe/ condition: $a }");
    assertWarningStrictEscape("rule test { strings: $a = /AppData\\\\Roaming\\\\[0-9]{9,12}\\VMwareCplLauncher\\.exe/ condition: $a }");
    assertNoWarnings("rule test { strings: $a = /AppData\\\\Roaming\\\\[0-9]{9,12}\\\\VMwareCplLauncher\\.exe/ condition: $a }");
    assertWarningStrictEscape("rule test { strings: $a = /ab[\\000-\\343]/ condition: $a }");
    assertNoWarnings("rule test { strings: $a = /ab[\\x00-\\x43]/ condition: $a }");
    assertWarningStrictEscape("rule test { strings: $a = /C:\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\AzireVPN\\\\token\\.txt/ condition: $a }");
    assertNoWarnings("rule test { strings: $a = /C:\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\AzireVPN\\\\token\\.txt/ condition: $a }");
    assertWarningStrictEscape("rule test { condition: \"avb\" matches /a\\vb/ }");
  }

  @Test
  void testPerformanceWarnings() throws Exception {
    assertWarning("rule test {         strings: $a = { 01 }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 01 ?? }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 01 ?? ?? }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 01 ?? ?? 02 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 01 ?? ?2 03 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 01 ?? 02 1? }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 68 ?? 00 ?? 00 68 ?? 00 ?? 00}         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { (61 62 63 64 ?? | 65 ?? ?? 00 00 66)}         condition: $a }");
    assertWarning("rule test {         strings: $a = { 1? 2? 3? }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 1? 2? 3? 04 }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 1? ?? 03 }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 00 01 }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 01 00 }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 00 00 }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 00 00 00 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 00 00 01 }         condition: $a }");
    assertWarning("rule test {         strings: $a = { 00 00 00 00 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 00 00 00 01 }         condition: $a }");
    assertWarning("rule test {         strings: $a = { FF FF FF FF }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 00 00 01 02 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 00 01 02 03 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 01 02 03 04 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 01 02 03 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 20 01 02 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = { 01 02 }         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = \"foo\" wide         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = \"MZ\"         condition: $a }");
    assertNoWarnings("rule test {         strings: $a = \"ZZ\"         condition: $a }");
    assertWarning("rule test {         strings: $a = \"                    \" xor(0x20)         condition: $a }");
    // This will eventually xor with 0x41 and should cause a warning.
    assertWarning("rule test {         strings: $a = \"AAAAAAAAAAAAAAAAAAAA\" xor         condition: $a }");
    assertWarning("rule test {         strings: $a = /abcd.*efgh/         condition: $a }");
    assertWarning("rule test {         strings: $a = /abcd.+efgh/         condition: $a }");
    assertWarning("rule test {         strings: $a = /abcd.{1,}efgh/         condition: $a }");
    assertWarning("rule test {         strings: $a = /abcd.{10,}efgh/         condition: $a }");
  }

  @Test
  void testMeta() throws Exception {
    // Make sure that multiple metadata with the same identifier are allowed.
    // This was not intentionally designed like that, but users are alreay
    // relying on this.
    assertTrueRule("rule test {          meta:            foo = \"foo\"            foo = 1            foo = false          condition:           true       }", null);
  }

  @Test
  void testDefined() throws Exception {
    assertTrueRule("rule t { condition: defined 1 }", null);
    assertFalseRule("rule t { condition: defined true and false }", null);
    assertTrueRule("rule t { condition: defined (true and false) }", null);
    assertTrueRule("import \"pe\"       rule t {         condition:           defined (             for any x in (0..10) : (               pe.number_of_resources == 0             )           )       }", null);
    assertFalseRule("import \"pe\"       rule t {         condition:           defined pe.number_of_resources       }", null);
    assertTrueRule("import \"pe\"       rule t {         condition:           not defined pe.number_of_resources       }", null);
    assertFalseRule("import \"pe\"       rule t {         condition:           defined not pe.number_of_resources       }", null);
    assertFalseRule("import \"pe\"       rule t {         condition:           defined pe.number_of_resources and pe.number_of_resources == 0       }", null);
    assertTrueRule("import \"pe\"       rule t {         condition:           defined (pe.number_of_resources and pe.number_of_resources == 0)       }", null);
    assertTrueRule("import \"pe\"       rule t {         condition:           defined \"foo\" contains \"f\"       }", null);
    // Test FOUND_IN and FOUND_AT propagates undefined values
    assertTrueRule("import \"pe\"       rule t {         strings:             $a = \"abc\"         condition:           not defined ($a in (0..pe.number_of_resources)) and           not defined ($a in (pe.number_of_resources..5)) and           not defined ($a at pe.number_of_resources)       }", null);
    // Test that operations that would trigger a SIGFPE are detected and
    // returns undefined
    assertTrueRule("rule t {         strings:           $a = /aaa/         condition:           (not defined (1 \\ #a)) and           (not defined (1 % #a)) and           (not defined ((#a + -0x7FFFFFFFFFFFFFFF - 1) \\ -1)) and           (not defined ((#a + -0x7FFFFFFFFFFFFFFF - 1) % -1))       }", null);
  }
}
