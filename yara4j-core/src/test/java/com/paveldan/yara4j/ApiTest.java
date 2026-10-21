package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** Port of the relevant parts of YARA's tests/test-api.c. */
class ApiTest {

  /** Equivalent of the "count" callback in tests/util.c. */
  static final class Counters implements ScanCallback {
    int matching;
    int notMatching;
    int warnings;

    @Override
    public CallbackResult ruleMatching(RuleMatch match) {
      matching++;
      return CallbackResult.CONTINUE;
    }

    @Override
    public CallbackResult ruleNotMatching(Rule rule) {
      notMatching++;
      return CallbackResult.CONTINUE;
    }

    @Override
    public boolean tooManyMatches(Rule rule, String stringIdentifier) {
      warnings++;
      return true;
    }
  }

  private static byte[] bytes(String s) {
    return s.getBytes(StandardCharsets.ISO_8859_1);
  }

  @Test
  void testDisabledRules() throws Exception {
    Rules rules =
        YaraCompiler.compile(
            "rule disabled_rule {condition: true} "
                + "rule false_rule {condition: true and disabled_rule} "
                + "rule true_rule {condition: true or disabled_rule}");
    Scanner scanner = rules.newScanner();
    for (Rule r : rules.getRules()) {
      if (r.getIdentifier().contains("disabled")) {
        scanner.setRuleEnabled(r.getIdentifier(), false);
      }
    }
    Counters c = new Counters();
    scanner.setCallback(c).scan(bytes("foo bar"));
    assertEquals(1, c.matching);
  }

  @Test
  void testIncludeCallback() {
    YaraCompiler compiler = new YaraCompiler();
    compiler.setIncludeResolver(
        (name, file, ns) -> name.equals("ok") ? bytes("rule test {condition: true}") : null);
    assertEquals(0, compiler.addSource("include \"ok\""));
    assertEquals(1, compiler.addSource("include \"fail\""));
  }

  @Test
  void testMaxStringsPerRule() {
    String rule =
        "rule test { strings: $ = \"uno\" $ = \"dos\" condition: all of them }";
    YaraCompiler c1 = new YaraCompiler().setMaxStringsPerRule(1);
    c1.addSource(rule);
    assertEquals(ErrorCode.TOO_MANY_STRINGS, c1.getLastError());
    YaraCompiler c2 = new YaraCompiler().setMaxStringsPerRule(2);
    assertEquals(0, c2.addSource(rule));
  }

  @Test
  void testMaxMatchData() throws Exception {
    Rules rules = YaraCompiler.compile("rule t { strings: $a = \"foobar\" condition: $a }");
    Scanner scanner = rules.newScanner().setMaxMatchData(0);
    scanner.setCallback(
        new ScanCallback() {
          @Override
          public CallbackResult ruleMatching(RuleMatch match) {
            for (StringMatch m : match.getStringMatches()) {
              if (m.getData().length > 0) {
                return CallbackResult.ERROR;
              }
            }
            return CallbackResult.CONTINUE;
          }
        });
    scanner.scan(bytes("foobar"));
  }

  @Test
  void testTooManyMatches() throws Exception {
    Rules rules =
        YaraCompiler.compile(
            "rule t { strings: $a = \"aa\" $b = { 61 61 [-] 61 61} condition: any of them }");
    byte[] buffer = new byte[2 * 1000000];
    Arrays.fill(buffer, (byte) 'a');
    YaraException e =
        assertThrows(
            YaraException.class,
            () ->
                rules
                    .newScanner()
                    .setCallback(
                        new ScanCallback() {
                          @Override
                          public boolean tooManyMatches(Rule rule, String s) {
                            return false;
                          }
                        })
                    .scan(buffer));
    assertEquals(ErrorCode.TOO_MANY_MATCHES, e.getErrorCode());
    rules.newScanner().setCallback(new ScanCallback() {}).scan(buffer);
  }

  @Test
  void testTooSlowScanningSlowStringMatches() throws Exception {
    Rules rules = YaraCompiler.compile("rule t { strings: $a = /a.{0,18}/ condition: $a }");
    byte[] buffer = new byte[600000 + 100];
    Arrays.fill(buffer, (byte) 'a');
    YaraException e =
        assertThrows(
            YaraException.class,
            () ->
                rules
                    .newScanner()
                    .setCallback(
                        new ScanCallback() {
                          @Override
                          public boolean tooSlowScanning(Rule rule, String s) {
                            return false;
                          }
                        })
                    .scan(buffer));
    assertEquals(ErrorCode.TOO_SLOW_SCANNING, e.getErrorCode());
    rules.newScanner().setCallback(new ScanCallback() {}).scan(buffer);
  }

  @Test
  void testTooSlowScanning() throws Exception {
    Rules rules = YaraCompiler.compile("rule t { strings: $a = /\\w+/ condition: $a }");
    byte[] buffer = new byte[2 * 200000];
    Arrays.fill(buffer, (byte) 'a');
    YaraException e =
        assertThrows(
            YaraException.class,
            () ->
                rules
                    .newScanner()
                    .setCallback(
                        new ScanCallback() {
                          @Override
                          public boolean tooSlowScanning(Rule rule, String s) {
                            return false;
                          }
                        })
                    .scan(buffer));
    assertEquals(ErrorCode.TOO_SLOW_SCANNING, e.getErrorCode());
    rules.newScanner().scan(Arrays.copyOf(buffer, 16));
  }

  @Test
  void testScanner() throws Exception {
    YaraCompiler compiler = new YaraCompiler();
    compiler.defineInteger("int_var", 0);
    compiler.defineBoolean("bool_var", false);
    compiler.defineString("str_var", "");
    YaraException dup =
        assertThrows(YaraException.class, () -> compiler.defineString("str_var", ""));
    assertEquals(ErrorCode.DUPLICATED_EXTERNAL_VARIABLE, dup.getErrorCode());
    compiler.addSourceOrThrow(
        "rule true_rule { condition: true } "
            + "rule false_rule { condition: false } "
            + "rule test { condition: bool_var and int_var == 1 and str_var == \"foo\" }",
        null);
    Rules rules = compiler.getRules();
    Scanner scanner1 = rules.newScanner();
    Scanner scanner2 = rules.newScanner();

    Counters c = new Counters();
    scanner1.setCallback(c).setReportRules(true, true);
    scanner1.defineInteger("int_var", 1);
    scanner1.defineBoolean("bool_var", true);
    scanner1.defineString("str_var", "foo");
    scanner2.defineInteger("int_var", 2);
    scanner2.defineBoolean("bool_var", false);
    scanner2.defineString("str_var", "bar");

    scanner1.scan(bytes("dummy"));
    assertEquals(2, c.matching);
    assertEquals(1, c.notMatching);

    c = new Counters();
    scanner1.setCallback(c).setReportRules(true, false).scan(bytes("dummy"));
    assertEquals(2, c.matching);
    assertEquals(0, c.notMatching);

    c = new Counters();
    scanner2.setCallback(c).setReportRules(false, true).scan(bytes("dummy"));
    assertEquals(2, c.notMatching);
    assertEquals(0, c.matching);
  }

  @Test
  void testXorKeyStringInAtom() throws Exception {
    Rules rules =
        YaraCompiler.compile(
            "rule test { strings: $a = \"This\" xor(1) $b = \"Th\" xor(1) wide "
                + "condition: any of them }");
    AtomicInteger checked = new AtomicInteger();
    rules
        .newScanner()
        .setCallback(
            new ScanCallback() {
              @Override
              public CallbackResult ruleMatching(RuleMatch match) {
                for (StringMatch m : match.getStringMatches()) {
                  assertEquals(1, m.getXorKey());
                  checked.incrementAndGet();
                }
                return CallbackResult.CONTINUE;
              }
            })
        .scan(bytes("UihrU\u0001i\u0001h\u0001r\u0001"));
    assertTrue(checked.get() > 0);
  }

  @Test
  void testIssue834() throws Exception {
    Rules rules = YaraCompiler.compile("import \"tests\" rule test { condition: true }");
    Scanner scanner = rules.newScanner();
    scanner.scan(bytes("dummy"));
    scanner.scan(bytes("dummy"));
  }

  @Test
  void testIssue920() throws Exception {
    YaraCompiler compiler = new YaraCompiler();
    compiler.defineBoolean("test", true);
    compiler.addSource("rule test { condition: true }");
    assertEquals(ErrorCode.DUPLICATED_IDENTIFIER, compiler.getLastError());
  }

  @Test
  void testRuntimeWarnings() throws Exception {
    Rules rules =
        YaraCompiler.compile("rule test { strings: $x = \"X\" condition: #x > 1000000 }");
    byte[] data = YaraAssert.readFile("tests/data/x.txt");
    for (int pass = 0; pass < 2; pass++) {
      Counters c = new Counters();
      Scanner s = rules.newScanner().setCallback(c).setReportRules(true, true);
      s.scan(data);
      assertEquals(1, c.warnings);
      assertEquals(0, c.matching);
      assertEquals(1, c.notMatching);
    }
  }
}
