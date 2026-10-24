package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.internal.rules.RulesSerializer;

/** Deeply nested and very long conditions, which used to overflow the stack. */
class CompilerLimitsTest {

  private static String nestedParens(int depth) {
    return "(".repeat(depth) + "true" + ")".repeat(depth);
  }

  /** Runs code in a thread with a small stack, where any recursion overflows soon. */
  private static <T> T withSmallStack(java.util.concurrent.Callable<T> code) throws Exception {
    return withSmallStack(code, 256 << 10);
  }

  private static <T> T withSmallStack(java.util.concurrent.Callable<T> code, long stackSize)
      throws Exception {
    AtomicReference<Object> result = new AtomicReference<>();
    Thread t =
        new Thread(
            null,
            () -> {
              try {
                result.set(code.call());
              } catch (Throwable e) {
                result.set(e);
              }
            },
            "small-stack",
            stackSize);
    t.start();
    t.join();
    if (result.get() instanceof Exception) {
      throw (Exception) result.get();
    }
    if (result.get() instanceof Error) {
      throw (Error) result.get();
    }
    @SuppressWarnings("unchecked")
    T r = (T) result.get();
    return r;
  }

  @Test
  void deeplyNestedConditionIsAnError() throws Exception {
    for (String condition : new String[] {nestedParens(50_000), "not ".repeat(50_000) + "true"}) {
      YaraCompiler c = new YaraCompiler();
      c.addSource("rule ok { condition: true }");
      assertEquals(1, c.addSource("rule deep { condition: " + condition + " }"));
      CompilerMessage m = c.getErrors().get(0);
      assertEquals("expression nested too deeply", m.getMessage());
      assertEquals("deep", m.getRuleIdentifier());
      // The compiler used to return the rule half compiled, failing every scan.
      assertThrows(YaraCompilationException.class, c::getRules);
    }
  }

  @Test
  void moderatelyNestedConditionCompiles() throws Exception {
    Rules rules = YaraCompiler.compile("rule r { condition: " + nestedParens(500) + " }");
    assertEquals(1, rules.scan(new byte[0]).size());
  }

  @Test
  void longArithmeticChainCompiles() throws Exception {
    // Not nested: libyara accepts chains of any length, and so does the parser. Evaluating the
    // tree recurses once per operator, so very long chains fail when scanning.
    for (String op : new String[] {" + ", " | ", " * "}) {
      String chain = "filesize" + (op + "filesize").repeat(100_000);
      Rules rules = YaraCompiler.compile("rule r { condition: (" + chain + ") > 0 }");
      YaraException e = assertThrows(YaraException.class, () -> rules.scan(new byte[1]));
      assertEquals(ErrorCode.EXEC_STACK_OVERFLOW, e.getErrorCode());
    }
    String chain = "filesize" + " + filesize".repeat(500);
    assertEquals(
        1, YaraCompiler.compile("rule r { condition: " + chain + " > 0 }").scan(new byte[1]).size());
  }

  /** The error message of compiling the source, or null if it compiles. */
  private static String error(String source) {
    YaraCompiler c = new YaraCompiler();
    return c.addSource(source) == 0 ? null : c.getErrors().get(0).getMessage();
  }

  @Test
  void deeplyNestedGroupsAreAnError() {
    for (int depth : new int[] {1000, 1001}) {
      String hex = "{ 41 " + "( ".repeat(depth) + "42" + " )".repeat(depth) + " }";
      String re = "/x" + "(".repeat(depth) + "a" + ")".repeat(depth) + "/";
      String hexError = error("rule r { strings: $a = " + hex + " condition: $a }");
      String reError = error("rule r { strings: $a = " + re + " condition: $a }");
      String conditionError = error("rule r { condition: \"a\" matches " + re + " }");
      if (depth == 1000) {
        assertEquals(null, hexError);
        assertEquals(null, reError);
        assertEquals(null, conditionError);
      } else {
        assertEquals("invalid hex string \"$a\": groups nested too deeply", hexError);
        assertEquals("invalid regular expression \"$a\": groups nested too deeply", reError);
        assertEquals("groups nested too deeply", conditionError);
      }
    }
  }

  @Test
  void stackOverflowIsAnError() throws Exception {
    // Within the limits, but too deep for a small stack.
    YaraCompiler c = new YaraCompiler();
    int errors =
        withSmallStack(
            () -> c.addSource("rule r { condition: " + nestedParens(999) + " }"), 128 << 10);
    assertEquals(1, errors);
    assertEquals("rules nested too deeply", c.getErrors().get(0).getMessage());
    assertThrows(YaraCompilationException.class, c::getRules);
  }

  @Test
  void deeplyNestedSavedRulesDontLoad() throws Exception {
    RulesSerializer.Journal journal = new RulesSerializer.Journal();
    journal.source(
        ("rule deep { condition: " + nestedParens(50_000) + " }").getBytes(StandardCharsets.UTF_8),
        null,
        null);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    RulesSerializer.save(journal, out);
    YaraException e =
        assertThrows(
            YaraException.class,
            () -> withSmallStack(() -> Rules.load(new ByteArrayInputStream(out.toByteArray()))));
    assertEquals(ErrorCode.CORRUPT_FILE, e.getErrorCode());
  }

  private static List<String> matching(String source, byte[] data) throws Exception {
    Scanner s = YaraCompiler.compile(source).newScanner().setTimeout(Duration.ofSeconds(30));
    return s.scan(data).stream().map(RuleMatch::getIdentifier).collect(Collectors.toList());
  }

  @Test
  void longAndOrChains() throws Exception {
    // uint8(100) is undefined for 4 bytes of data.
    StringBuilder and = new StringBuilder("rule and_chain { condition: true");
    StringBuilder or = new StringBuilder("rule or_chain { condition: false");
    for (int i = 0; i < 50_000; i++) {
      and.append(i % 1000 == 999 ? " and not (uint8(100) == 1 and true)" : " and true");
      or.append(i == 49_999 ? " or true" : " or uint8(100) == 1");
    }
    String source = and.append(" }\n").append(or).append(" }").toString();
    assertEquals(List.of("and_chain", "or_chain"), matching(source, new byte[4]));
  }

  @Test
  void andOrChainsWithUndefinedValues() throws Exception {
    // The results of ((a op b) op c) in libyara, where an undefined operand is false but
    // doesn't stop the evaluation of the right operand.
    String u = "uint8(100)";
    String source =
        String.join(
            "\n",
            "rule a1 { condition: " + u + " and true and true }",
            "rule a2 { condition: true and " + u + " and true }",
            "rule a3 { condition: true and true and " + u + " }",
            "rule a4 { condition: true and 2 and 3 }",
            "rule o1 { condition: " + u + " or false or true }",
            "rule o2 { condition: false or " + u + " or false }",
            "rule o3 { condition: " + u + " or " + u + " or " + u + " }",
            "rule o4 { condition: false or 0 or 7 }",
            "rule m1 { condition: (false or " + u + ") and true or true }",
            "rule m2 { condition: " + u + " and true or false and true }");
    assertEquals(List.of("a4", "o1", "o4", "m1"), matching(source, new byte[4]));
  }

  @Test
  void indexedMatchAccess() throws Exception {
    // 200000 matches: "@a[i]" and "!a[i]" used to walk the list of matches each time.
    byte[] data = new byte[200_000];
    java.util.Arrays.fill(data, (byte) 'a');
    assertEquals(
        List.of("r"),
        matching(
            "rule r { strings: $a = \"a\" condition: #a == 200000 and "
                + "for all i in (1..#a) : (@a[i] == i - 1 and !a[i] == 1 and $a at (i - 1) "
                + "and #a in (i - 1 .. i + 1) <= 3) }",
            data));
  }

  @Test
  void matchOffsetOperators() throws Exception {
    byte[] data = "xaxxab".getBytes(StandardCharsets.ISO_8859_1);
    String source =
        String.join(
            "\n",
            "rule s { strings: $a = \"a\" $b = \"b\" condition: $a and $b and",
            "  @a[1] == 1 and @a[2] == 4 and !a[2] == 1 and",
            "  not defined @a[0] and not defined @a[3] and not defined !a[-1] and",
            "  $a at 1 and $a at 4 and not $a at 2 and not $a at -1 and",
            "  $a in (0..1) and $a in (2..4) and not $a in (2..3) and",
            "  not $a in (filesize - 1 .. 0) and",
            "  #a in (0..1) == 1 and #a in (1..4) == 2 and #a in (filesize - 1 .. 1) == 0 and",
            "  #a in (6..100) == 0 and #a in (0..9223372036854775807) == 2 and",
            "  all of ($a, $b) in (1..5) and not all of ($a, $b) in (1..4) and",
            "  1 of ($a, $b) at 5 and not any of ($a, $b) at 3 }");
    assertEquals(List.of("s"), matching(source, data));
  }

  @Test
  void chainsShortCircuit() throws Exception {
    // A chain whose last operand would fail the scan if evaluated.
    assertTrue(
        matching(
                "rule r { condition: false and false and for all i in (0..1000000000) : (true) }",
                new byte[1])
            .isEmpty());
  }
}
