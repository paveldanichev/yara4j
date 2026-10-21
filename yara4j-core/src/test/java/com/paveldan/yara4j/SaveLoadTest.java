package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Compiled rules save/load and concurrent use of shared Rules. */
class SaveLoadTest {

  private static byte[] bytes(String s) {
    return s.getBytes(StandardCharsets.ISO_8859_1);
  }

  private static List<String> names(List<RuleMatch> matches) {
    return matches.stream()
        .map(m -> m.getNamespace() + ":" + m.getIdentifier())
        .sorted()
        .collect(Collectors.toList());
  }

  private static Rules sample() throws Exception {
    YaraCompiler c = new YaraCompiler();
    c.defineInteger("threshold", 2);
    c.defineString("tag", "foo");
    c.setIncludeResolver(
        (name, file, ns) ->
            name.equals("inc.yar")
                ? bytes("rule included { strings: $a = \"inc\" condition: $a }")
                : null);
    c.addSourceOrThrow(
        "include \"inc.yar\" "
            + "private rule p { strings: $a = /fo+/ condition: #a >= threshold } "
            + "rule uses_p { condition: p and tag == \"foo\" } "
            + "global rule g { condition: filesize > 3 }",
        "ns1");
    c.addSourceOrThrow(
        "import \"pe\" rule hexy { strings: $h = { 62 61 [1-2] 72 } condition: $h and "
            + "not pe.is_pe }",
        "ns2");
    return c.getRules();
  }

  @Test
  void roundTrip() throws Exception {
    Rules rules = sample();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    rules.save(out);
    Rules loaded = Rules.load(new ByteArrayInputStream(out.toByteArray()));

    assertEquals(rules.getRules().size(), loaded.getRules().size());
    assertEquals(rules.getImports(), loaded.getImports());
    byte[] data = bytes("foo fooo bar baxr inc");
    assertEquals(names(rules.scan(data)), names(loaded.scan(data)));
    assertEquals(
        List.of("ns1:g", "ns1:included", "ns1:uses_p", "ns2:hexy"), names(loaded.scan(data)));
    // Externals keep their default values and can be overridden.
    Scanner s = loaded.newScanner();
    s.defineString("tag", "bar");
    assertEquals(List.of("ns1:g", "ns1:included", "ns2:hexy"), names(s.scan(data)));

    // Saving the loaded rules produces the same file.
    ByteArrayOutputStream out2 = new ByteArrayOutputStream();
    loaded.save(out2);
    assertArrayEquals(out.toByteArray(), out2.toByteArray());
  }

  @Test
  void invalidFiles() throws Exception {
    YaraException e =
        assertThrows(
            YaraException.class,
            () -> Rules.load(new ByteArrayInputStream(bytes("YARA compiled rules"))));
    assertEquals(ErrorCode.INVALID_FILE, e.getErrorCode());

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    sample().save(out);
    byte[] good = out.toByteArray();

    byte[] corrupt = good.clone();
    corrupt[corrupt.length / 2] ^= 0x55;
    e = assertThrows(YaraException.class, () -> Rules.load(new ByteArrayInputStream(corrupt)));
    assertEquals(ErrorCode.CORRUPT_FILE, e.getErrorCode());

    byte[] truncated = java.util.Arrays.copyOf(good, good.length - 20);
    e = assertThrows(YaraException.class, () -> Rules.load(new ByteArrayInputStream(truncated)));
    assertEquals(ErrorCode.CORRUPT_FILE, e.getErrorCode());

    byte[] version = good.clone();
    version[11] = 99;
    e = assertThrows(YaraException.class, () -> Rules.load(new ByteArrayInputStream(version)));
    assertEquals(ErrorCode.UNSUPPORTED_FILE_VERSION, e.getErrorCode());
  }

  @Test
  void concurrentScanners() throws Exception {
    Rules rules = sample();
    byte[] match = bytes("foo fooo bar baxr inc");
    byte[] noMatch = bytes("nothing here at all");
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try {
      List<Future<Boolean>> results = new ArrayList<>();
      for (int i = 0; i < 200; i++) {
        final boolean expectMatch = i % 2 == 0;
        results.add(
            pool.submit(
                () -> {
                  Scanner s = rules.newScanner();
                  List<RuleMatch> r = s.scan(expectMatch ? match : noMatch);
                  return expectMatch ? r.size() == 4 : names(r).equals(List.of("ns1:g"));
                }));
      }
      for (Future<Boolean> f : results) {
        assertEquals(Boolean.TRUE, f.get());
      }
    } finally {
      pool.shutdownNow();
    }
  }
}
