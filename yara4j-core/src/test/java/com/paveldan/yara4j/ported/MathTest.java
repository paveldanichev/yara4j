package com.paveldan.yara4j.ported;

import static com.paveldan.yara4j.YaraAssert.*;

import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.ErrorCode;

/** Converted from YARA's test-math.c. */
@SuppressWarnings("all")
class MathTest {

  @Test
  void testMain() throws Exception {
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.min(0, 1) == 0       }", "A");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.max(0, 1) == 1       }", "A");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.to_number(1 == 1)       }", "A");
    assertFalseRuleBlob("import \"math\"       rule test {         condition:           math.to_number(1 > 2)       }", "A");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.abs(-1) == 1       }", "A");
    assertTrueRuleBlob("import \"math\"       rule test {         strings:           $a = \"A\"           $b = \"B\"         condition:           math.abs(@a - @b) == 1       }", "AB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.count(0x41, 0, 3) == 2       }", "AABAAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.count(0x41, 4, 10) == 1        }", "AABAAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           not defined math.count(0x41, 10, 3)        }", "AABAAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           not defined math.count(0x41, 0, -3)        }", "AABAAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           not defined math.count(-1)        }", "AABAAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.count(0x41) == 2       }", "ABAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.percentage(0x41) > 0.39 and math.percentage(0x41) < 0.41       }", "ABAB");
    // Blob matching includes terminating zero byte
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.percentage(0x41, 0, 4) == 0.5       }", "ABABCDEF");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           not defined math.percentage(0x41, 0, 0)       }", "AABAAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           not defined math.percentage(0x41, 10, 3)        }", "AABAAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           not defined math.percentage(0x41, 0, -3)        }", "AABAAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           not defined math.percentage(-1)        }", "AABAAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.mode() == 0x41       }", "ABABA");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.mode() == 0x41       }", "ABAB");
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.mode(2, 3) == 0x41       }", "CCABACC");
    assertTrueRule("import \"math\"       rule test {         condition:           math.entropy(\"AAAAA\") == 0.0       }", null);
    assertTrueRule("import \"math\"       rule test {         condition:           math.entropy(\"\") == 0.0       }", null);
    assertTrueRule("import \"math\"       rule test {         condition:           math.entropy(\"AABB\") == 1.0       }", null);
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.entropy(2, 3) == 0.0       }", "CCAAACC");
    assertTrueRule("import \"math\"       rule test {         condition:           math.deviation(\"AAAAA\", 0.0) == 65.0       }", null);
    assertTrueRule("import \"math\"       rule test {         condition:           math.deviation(\"ABAB\", 65.0) == 0.5       }", null);
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.deviation(2, 4, 65.0) == 0.5       }", "ABABABAB");
    assertTrueRule("import \"math\"       rule test {         condition:           math.mean(\"ABCABC\") == 66.0       }", null);
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.mean(0, 3) == 66.0       }", "ABCABC");
    assertTrueRule("import \"math\"       rule test {         condition:           math.serial_correlation(\"BCA\") == -0.5       }", null);
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.serial_correlation(1, 3) == -0.5       }", "ABCABC");
    assertTrueRule("import \"math\"       rule test {         condition:           math.in_range(2.0, 1.0, 3.0)       }", null);
    assertFalseRule("import \"math\"       rule test {         condition:           math.in_range(6.0, 1.0, 3.0)       }", null);
    assertTrueRule("import \"math\"       rule test {         condition:           math.monte_carlo_pi(\"ABCDEF123456987\") < 0.3       }", null);
    assertTrueRuleBlob("import \"math\"       rule test {         condition:           math.monte_carlo_pi(3, 15) < 0.3       }", "123ABCDEF123456987DE");
    assertTrueRule("import \"math\"       rule test {         condition:           math.to_string(1234) == \"1234\"       }", null);
    // We use signed integers by default if no base is specified.
    assertTrueRule("import \"math\"       rule test {         condition:           math.to_string(-1) == \"-1\"       }", null);
    assertTrueRule("import \"math\"       rule test {         condition:           math.to_string(32, 16) == \"20\"       }", null);
    assertTrueRule("import \"math\"       rule test {         condition:           math.to_string(32, 8) == \"40\"       }", null);
    assertTrueRule("import \"math\"       rule test {         condition:           math.to_string(32, 10) == \"32\"       }", null);
    // Base 10 is always a signed integer, all other bases are unsigned.
    assertTrueRule("import \"math\"       rule test {         condition:           math.to_string(-1, 10) == \"-1\" and           math.to_string(-1, 16) == \"ffffffffffffffff\" and           math.to_string(-1, 8) == \"1777777777777777777777\"       }", null);
    // Passing a base that is not 10, 8 or 16 will result in UNDEFINED.
    assertTrueRule("import \"math\"       rule test {         condition:           not defined(math.to_string(32, 9))       }", null);
  }
}
