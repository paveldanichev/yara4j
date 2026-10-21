package com.paveldan.yara4j.magic.tika;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.Rules;
import com.paveldan.yara4j.YaraCompiler;

class TikaMagicProviderTest {

  private static boolean matches(String condition, byte[] data) throws Exception {
    Rules rules = YaraCompiler.compile("import \"magic\" rule t { condition: " + condition + " }");
    boolean[] matched = {false};
    rules
        .newScanner()
        .setCallback(
            new com.paveldan.yara4j.ScanCallback() {
              @Override
              public com.paveldan.yara4j.CallbackResult ruleMatching(
                  com.paveldan.yara4j.RuleMatch m) {
                matched[0] = true;
                return com.paveldan.yara4j.CallbackResult.CONTINUE;
              }
            })
        .scan(data);
    return matched[0];
  }

  @Test
  void detectsPdf() throws Exception {
    byte[] pdf = "%PDF-1.4\n%âã\n1 0 obj\n".getBytes(StandardCharsets.ISO_8859_1);
    assertTrue(matches("magic.mime_type() == \"application/pdf\"", pdf));
    assertTrue(matches("magic.type() == \"Portable Document Format\"", pdf));
  }

  @Test
  void detectsPng() throws Exception {
    byte[] png = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R'};
    assertTrue(matches("magic.mime_type() == \"image/png\"", png));
    assertFalse(matches("magic.mime_type() == \"application/pdf\"", png));
  }

  @Test
  void providerIsDiscovered() throws Exception {
    assertEquals(
        "text/plain",
        new TikaMagicProvider()
            .mimeType(java.nio.ByteBuffer.wrap("hello world\n".getBytes(StandardCharsets.US_ASCII))));
    assertTrue(matches("defined magic.mime_type()", "hello".getBytes(StandardCharsets.US_ASCII)));
  }
}
