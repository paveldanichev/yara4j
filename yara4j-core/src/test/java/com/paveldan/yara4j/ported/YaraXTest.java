package com.paveldan.yara4j.ported;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import com.paveldan.yara4j.CompilerMessage;
import com.paveldan.yara4j.RuleMatch;
import com.paveldan.yara4j.StringMatch;
import com.paveldan.yara4j.YaraCompiler;

/**
 * Tests taken from yara-x (https://github.com/VirusTotal/yara-x): the end-to-end condition,
 * rule and pattern tests of lib/src/tests/mod.rs, and the compiler error and warning test files
 * of lib/src/compiler/tests/testdata.
 *
 * <p>yara-x isn't fully compatible with libyara, so the expected results are not yara-x's but
 * those of libyara 4.5.8 built natively, which yara4j must reproduce exactly: matching rules,
 * matched data, and the text and line of every compiler error and warning. Test names show
 * yara-x's expectation when libyara behaves differently, and cases that use yara-x extensions
 * check that yara4j rejects them with the same errors as libyara.
 */
class YaraXTest {

  private static byte[] resource(String path) throws IOException {
    try (InputStream in = YaraXTest.class.getResourceAsStream("/yarax/" + path)) {
      return in.readAllBytes();
    }
  }

  private static byte[] unhex(String s) {
    byte[] b = new byte[s.length() / 2];
    for (int i = 0; i < b.length; i++) {
      b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
    }
    return b;
  }

  private static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder();
    for (byte x : b) {
      sb.append(String.format("%02x", x & 0xFF));
    }
    return sb.toString();
  }

  private static String unescape(String s) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '\\' && i + 1 < s.length()) {
        char n = s.charAt(++i);
        sb.append(n == 'n' ? '\n' : n == 't' ? '\t' : n);
      } else {
        sb.append(c);
      }
    }
    return sb.toString();
  }

  /**
   * Compiles and scans like the native test harness: "RESULT <matching rules> <hex of the first
   * match of the first matching rule, or ->", or the compiler messages.
   */
  static String run(byte[] rule, byte[] data, boolean warnings) throws Exception {
    YaraCompiler compiler = new YaraCompiler();
    compiler.addSource(rule, null);
    List<String> lines = new ArrayList<>();
    boolean error = false;
    for (CompilerMessage m : compiler.getMessages()) {
      if (m.getLevel() == CompilerMessage.Level.ERROR) {
        error = true;
        lines.add("ERROR: line " + m.getLine() + ": " + m.getMessage());
      } else if (warnings) {
        String rid = m.getRuleIdentifier() == null ? "" : m.getRuleIdentifier() + ": ";
        lines.add("WARNING: line " + m.getLine() + ": " + rid + m.getMessage());
      }
    }
    if (!error) {
      List<RuleMatch> matches = compiler.getRules().newScanner().scan(data);
      String first = "-";
      for (RuleMatch m : matches) {
        List<StringMatch> sm = m.getPublicStringMatches();
        if (!sm.isEmpty()) {
          first = hex(sm.get(0).getData());
          break;
        }
      }
      lines.add("RESULT " + matches.size() + " " + first);
    }
    return String.join("\n", lines);
  }

  @TestFactory
  Stream<DynamicTest> conditions() throws Exception {
    byte[] jumps = resource("jumps.bin");
    String tsv = new String(resource("conditions.tsv"), StandardCharsets.UTF_8);
    List<DynamicTest> tests = new ArrayList<>();
    for (String line : tsv.split("\n")) {
      if (line.startsWith("#") || line.isEmpty()) {
        continue;
      }
      String[] f = line.split("\t", -1);
      String yaraxLine = f[0];
      String fn = f[1];
      String kind = f[2];
      String yaraxExpected = f[3];
      String expected = unescape(f[4]);
      byte[] rule = unhex(f[5]);
      byte[] data = f[6].equals("@jumps") ? jumps : unhex(f[6]);
      String name = fn + " (mod.rs:" + yaraxLine + ")";
      if (expected.startsWith("RESULT")) {
        String[] r = expected.split(" ");
        boolean agrees =
            kind.equals("bool") ? r[1].equals(yaraxExpected) : r[2].equals(yaraxExpected);
        if (!agrees) {
          name += " [yara-x expects " + yaraxExpected + "]";
        }
      } else {
        name += " [rejected by libyara]";
      }
      tests.add(
          DynamicTest.dynamicTest(
              name,
              () ->
                  assertEquals(
                      expected,
                      run(rule, data, false),
                      new String(rule, StandardCharsets.UTF_8))));
    }
    return tests.stream();
  }

  private static Stream<DynamicTest> compilerTests(String dir) throws Exception {
    Path base = Paths.get(YaraXTest.class.getResource("/yarax/compiler/" + dir).toURI());
    List<Path> inputs;
    try (Stream<Path> s = Files.list(base)) {
      inputs =
          s.filter(p -> p.toString().endsWith(".in"))
              .sorted((a, b) -> {
                String x = a.getFileName().toString();
                String y = b.getFileName().toString();
                return x.length() != y.length() ? x.length() - y.length() : x.compareTo(y);
              })
              .collect(Collectors.toList());
    }
    List<DynamicTest> tests = new ArrayList<>();
    for (Path in : inputs) {
      String name = in.getFileName().toString();
      Path exp = in.resolveSibling(name.substring(0, name.length() - 3) + ".expected");
      tests.add(
          DynamicTest.dynamicTest(
              dir + "/" + name,
              () -> {
                String expected =
                    new String(Files.readAllBytes(exp), StandardCharsets.ISO_8859_1).strip();
                byte[] src = Files.readAllBytes(in);
                assertEquals(expected, run(src, new byte[0], true).strip());
              }));
    }
    return tests.stream();
  }

  @TestFactory
  Stream<DynamicTest> compilerErrors() throws Exception {
    return compilerTests("errors");
  }

  @TestFactory
  Stream<DynamicTest> compilerWarnings() throws Exception {
    return compilerTests("warnings");
  }
}
