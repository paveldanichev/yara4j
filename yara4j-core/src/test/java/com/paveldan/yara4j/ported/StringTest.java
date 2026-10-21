package com.paveldan.yara4j.ported;

import static com.paveldan.yara4j.YaraAssert.*;

import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.ErrorCode;

/** Converted from YARA's test-string.c. */
@SuppressWarnings("all")
class StringTest {

  @Test
  void testMain() throws Exception {
    assertTrueRule("import \"string\"       rule test {         condition:           string.to_int(\"1234\") == 1234       }", null);
    assertTrueRule("import \"string\"       rule test {         condition:           string.to_int(\"-1\") == -1       }", null);
    // Leading spaces and + are allowed.
    assertTrueRule("import \"string\"       rule test {         condition:           string.to_int(\" +1\") == 1       }", null);
    // Strings can be prefixed with 0x and will be interpreted as hexadecimal.
    assertTrueRule("import \"string\"       rule test {         condition:           string.to_int(\"0x10\") == 16       }", null);
    // Strings prefixed with 0 will be interpreted as octal.
    assertTrueRule("import \"string\"       rule test {         condition:           string.to_int(\"010\") == 8       }", null);
    assertTrueRule("import \"string\"       rule test {         condition:           string.to_int(\"10\", 8) == 8       }", null);
    // Base 0 is a special case that tries to interpret the string by prefix, or
    // default to decimal. We aren't doing anything special to get this, it is
    // part of strtoll by default.
    assertTrueRule("import \"string\"       rule test {         condition:           string.to_int(\"010\", 0) == 8 and           string.to_int(\"0x10\", 0) == 16 and           string.to_int(\"10\", 0) == 10       }", null);
    // Test undefined cases
    // on invalid base value
    assertTrueRule("import \"string\"       rule test {         condition:           not defined string.to_int(\"1\", -1) and           not defined string.to_int(\"1\", 1) and           not defined string.to_int(\"1\", 37)       }", null);
    // on underflow or underflow
    assertTrueRule("import \"string\"       rule test {         condition:           not defined string.to_int(\"9223372036854775808\")       }", null);
    assertTrueRule("import \"string\"       rule test {         condition:           not defined string.to_int(\"-9223372036854775809\")       }", null);
    // if parsing does not use all the string
    assertTrueRule("import \"string\"       rule test {         condition:           not defined string.to_int(\"FOO\") and           not defined string.to_int(\"10A20\")       }", null);
    // if parsing does not consume any digits
    assertTrueRule("import \"string\"       rule test {         condition:           not defined string.to_int(\"\") and           not defined string.to_int(\"   -\") and           not defined string.to_int(\" +0x\")       }", null);
    assertTrueRule("import \"string\"       rule test {         condition:           string.length(\"AXS\\x00ERS\") == 7       }", null);
  }
}
