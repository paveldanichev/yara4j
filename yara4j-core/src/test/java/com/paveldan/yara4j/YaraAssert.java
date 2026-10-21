package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import com.paveldan.yara4j.module.MemoryBlock;

/**
 * Port of the helpers in YARA's tests/util.c and tests/util.h. Rules and data passed as Java
 * strings are interpreted as ISO-8859-1, so each char is a byte like in the original C tests,
 * and they are truncated at the first NUL character as C strings are.
 */
public final class YaraAssert {
  private YaraAssert() {}

  public static final String TEXT_0063_BYTES =
      "[ 987654321 987654321 987654321 987654321 987654321 987654321 ]";

  private static String text256(String prefix) {
    return prefix + TEXT_0063_BYTES + TEXT_0063_BYTES + TEXT_0063_BYTES + TEXT_0063_BYTES + "\n";
  }

  /** The TEXT_1024_BYTES macro from YARA's tests/util.h. */
  public static final String TEXT_1024_BYTES =
      text256("001") + text256("002") + text256("003") + text256("004");

  /**
   * Block size used for splitting scanned data in multiple blocks, emulating pass 3 of YARA's
   * test-rules (0 means a single block).
   */
  public static int blockSize = 0;

  public static int blockOverlap = 0;

  static byte[] bytes(String s) {
    if (s == null) {
      return null;
    }
    byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
    for (int i = 0; i < b.length; i++) {
      if (b[i] == 0) {
        return Arrays.copyOf(b, i);
      }
    }
    return b;
  }

  /** Result of compiling a rule. */
  public static final class Compiled {
    public final ErrorCode error;
    public final Rules rules;
    public final int warnings;
    public final String messages;

    Compiled(ErrorCode error, Rules rules, int warnings, String messages) {
      this.error = error;
      this.rules = rules;
      this.warnings = warnings;
      this.messages = messages;
    }
  }

  public static Compiled compileRule(String rule, boolean strictEscape) {
    YaraCompiler compiler = new YaraCompiler();
    compiler.setStrictEscape(strictEscape);
    try {
      compiler.defineInteger("var_zero", 0);
      compiler.defineInteger("var_one", 1);
      compiler.defineBoolean("var_true", true);
      compiler.defineBoolean("var_false", false);
    } catch (YaraException e) {
      throw new AssertionError(e);
    }
    int errors = compiler.addSource(bytes(rule), null);
    int warnings = compiler.getWarnings().size();
    StringBuilder msgs = new StringBuilder();
    for (CompilerMessage m : compiler.getMessages()) {
      msgs.append(m).append('\n');
    }
    if (errors != 0) {
      return new Compiled(compiler.getLastError(), null, warnings, msgs.toString());
    }
    try {
      return new Compiled(ErrorCode.SUCCESS, compiler.getRules(), warnings, msgs.toString());
    } catch (YaraCompilationException e) {
      return new Compiled(e.getErrorCode(), null, warnings, msgs.toString());
    }
  }

  static Rules compileOrFail(String rule) {
    Compiled c = compileRule(rule, false);
    if (c.error != ErrorCode.SUCCESS) {
      fail("failed to compile rule << " + rule + " >>: " + c.messages);
    }
    return c.rules;
  }

  private static List<MemoryBlock> blocks(byte[] data) {
    List<MemoryBlock> blocks = new ArrayList<>();
    if (blockSize == 0 || data.length <= blockSize) {
      blocks.add(MemoryBlocks.of(data, 0));
      return blocks;
    }
    // Split like YARA's test iterator: blocks of blockSize bytes overlapping blockOverlap bytes
    // with the previous block.
    long base = 0;
    while (base < data.length) {
      long start = base == 0 ? 0 : base - blockOverlap;
      int len = (int) Math.min(blockSize, data.length - start);
      blocks.add(MemoryBlocks.of(Arrays.copyOfRange(data, (int) start, (int) start + len), start));
      base = start + len;
    }
    return blocks;
  }

  /** Port of matches_blob: returns the number of matching rules. */
  public static int matchesBlob(String rule, byte[] blob, byte[] moduleData) {
    if (blob == null) {
      blob = "dummy".getBytes(StandardCharsets.ISO_8859_1);
    }
    Rules rules = compileOrFail(rule);
    final int[] count = new int[1];
    Scanner scanner = rules.newScanner();
    scanner.setCallback(
        new ScanCallback() {
          @Override
          public CallbackResult ruleMatching(RuleMatch match) {
            count[0]++;
            return CallbackResult.CONTINUE;
          }

          @Override
          public byte[] importModule(String moduleName) {
            return moduleData;
          }
        });
    try {
      if (blockSize == 0) {
        scanner.scan(blob);
      } else {
        scanner.scanBlocks(blocks(blob), blob.length);
      }
    } catch (YaraException e) {
      fail("failed to scan using rule << " + rule + " >>: error: " + e.getErrorCode(), e);
    }
    return count[0];
  }

  public static int matchesString(String rule, String string) {
    byte[] b = string == null ? new byte[0] : bytes(string);
    return matchesBlob(rule, string == null ? null : b, null);
  }

  /** Port of capture_string. */
  public static int captureString(String rule, String string, String expected) {
    Rules rules = compileOrFail(rule);
    byte[] exp = bytes(expected);
    final int[] found = new int[1];
    Scanner scanner = rules.newScanner();
    scanner.setCallback(
        new ScanCallback() {
          @Override
          public CallbackResult ruleMatching(RuleMatch match) {
            for (StringMatch m : match.getStringMatches()) {
              byte[] d = m.getData();
              int dataLength = d.length;
              if (exp.length == dataLength
                  && (dataLength == 0 || Arrays.equals(exp, Arrays.copyOf(d, dataLength)))) {
                found[0]++;
              }
            }
            return CallbackResult.CONTINUE;
          }
        });
    try {
      scanner.scan(bytes(string));
    } catch (YaraException e) {
      fail("failed to scan using rule << " + rule + " >>: error: " + e.getErrorCode(), e);
    }
    return found[0];
  }

  public static byte[] readFile(String path) {
    String res = path.startsWith("tests/") ? path.substring("tests".length()) : "/" + path;
    try (InputStream in = YaraAssert.class.getResourceAsStream(res)) {
      if (in == null) {
        throw new AssertionError("cannot read file '" + path + "'");
      }
      return in.readAllBytes();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  // ---------------------------------------------------------------------------------------------

  public static void assertTrueRule(String rule, String string) {
    if (matchesString(rule, string) == 0) {
      fail("rule does not match (but should): " + rule);
    }
  }

  public static void assertFalseRule(String rule, String string) {
    if (matchesString(rule, string) != 0) {
      fail("rule matches (but shouldn't): " + rule);
    }
  }

  public static void assertTrueRuleBlob(String rule, byte[] blob) {
    if (matchesBlob(rule, blob, null) == 0) {
      fail("rule does not match (but should): " + rule);
    }
  }

  public static void assertFalseRuleBlob(String rule, byte[] blob) {
    if (matchesBlob(rule, blob, null) != 0) {
      fail("rule matches (but shouldn't): " + rule);
    }
  }

  /** C string literal blob: sizeof() includes the terminating NUL. */
  static byte[] literalBlob(String s) {
    byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
    return Arrays.copyOf(b, b.length + 1);
  }

  public static void assertTrueRuleBlob(String rule, String blob) {
    assertTrueRuleBlob(rule, literalBlob(blob));
  }

  public static void assertFalseRuleBlob(String rule, String blob) {
    assertFalseRuleBlob(rule, literalBlob(blob));
  }

  public static void assertTrueRuleBlobSize(String rule, String blob, int size) {
    assertTrueRuleBlob(rule, Arrays.copyOf(literalBlob(blob), size));
  }

  public static void assertFalseRuleBlobSize(String rule, String blob, int size) {
    assertFalseRuleBlob(rule, Arrays.copyOf(literalBlob(blob), size));
  }

  public static void assertTrueRuleBlobSize(String rule, byte[] blob, int size) {
    assertTrueRuleBlob(rule, Arrays.copyOf(blob, size));
  }

  public static void assertFalseRuleBlobSize(String rule, byte[] blob, int size) {
    assertFalseRuleBlob(rule, Arrays.copyOf(blob, size));
  }

  public static void assertTrueRuleFile(String rule, String filename) {
    if (matchesBlob(rule, readFile(filename), null) == 0) {
      fail("rule does not match contents of '" + filename + "' (but should): " + rule);
    }
  }

  public static void assertFalseRuleFile(String rule, String filename) {
    if (matchesBlob(rule, readFile(filename), null) != 0) {
      fail("rule matches contents of '" + filename + "' (but shouldn't): " + rule);
    }
  }

  public static void assertTrueRuleModuleDataFile(String rule, String filename) {
    if (matchesBlob(rule, null, readFile(filename)) == 0) {
      fail("rule does not match (but should): " + rule);
    }
  }

  public static void assertError(String rule, ErrorCode error) {
    Compiled c = compileRule(rule, false);
    assertEquals(error, c.error, "unexpected result compiling << " + rule + " >>: " + c.messages);
  }

  public static void assertWarnings(String rule, int w) {
    Compiled c = compileRule(rule, false);
    if (c.error != ErrorCode.SUCCESS) {
      fail("failed to compile << " + rule + " >>: " + c.messages);
    }
    assertTrue(c.warnings >= w, "expecting warning: " + rule);
  }

  public static void assertWarningsStrictEscape(String rule, int w) {
    Compiled c = compileRule(rule, true);
    if (c.error != ErrorCode.SUCCESS) {
      fail("failed to compile << " + rule + " >>: " + c.messages);
    }
    assertTrue(c.warnings >= w, "expecting warning: " + rule);
  }

  public static void assertWarning(String rule) {
    assertWarnings(rule, 1);
  }

  public static void assertWarningStrictEscape(String rule) {
    assertWarningsStrictEscape(rule, 1);
  }

  public static void assertNoWarnings(String rule) {
    Compiled c = compileRule(rule, false);
    if (c.error != ErrorCode.SUCCESS) {
      fail("failed to compile << " + rule + " >>: " + c.messages);
    }
    assertEquals(0, c.warnings, "unexpected warning: " + rule + "\n" + c.messages);
  }

  public static void assertTrueRegexp(String regexp, String string, String expected) {
    String rule = "rule test { strings: $a = /" + regexp + "/ condition: $a }";
    if (captureString(rule, string, expected) == 0) {
      fail("regexp does not match: " + regexp);
    }
  }

  public static void assertFalseRegexp(String regexp, String string) {
    assertFalseRule("rule test { strings: $a = /" + regexp + "/ condition: $a }", string);
  }

  public static void assertRegexpSyntaxError(String regexp) {
    assertError(
        "rule test { strings: $a = /" + regexp + "/ condition: $a }",
        ErrorCode.INVALID_REGULAR_EXPRESSION);
  }

  public static void assertMatchCount(String rule, String string, int count) {
    assertEquals(count, matchesString(rule, string), "rule does not match count: " + rule);
  }

  public static void assertStringCapture(String rule, String string, String expected) {
    if (captureString(rule, string, expected) == 0) {
      fail("rule does not match: " + rule);
    }
  }

  /** Absolute path of the directory containing YARA's test data files. */
  public static String dataDir() {
    try {
      return java.nio.file.Paths.get(YaraAssert.class.getResource("/data").toURI()).toString();
    } catch (java.net.URISyntaxException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Converts a byte array into an ISO-8859-1 string. */
  public static String latin1(byte[] b) {
    return new String(b, StandardCharsets.ISO_8859_1);
  }
}
