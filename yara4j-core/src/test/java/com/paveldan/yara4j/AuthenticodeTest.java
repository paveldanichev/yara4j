package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import com.paveldan.yara4j.object.YStructure;

/**
 * Compares pe.signatures with the output of libyara 4.5.8 built with OpenSSL 3.0.13 on PE files
 * with generated Authenticode signatures covering unusual structures (see
 * tools/authenticode-samples). The .expected files contain the signature related part of
 * "yara -D" for each sample.
 */
class AuthenticodeTest {

  static List<Path> samples() throws Exception {
    Path dir = Paths.get(AuthenticodeTest.class.getResource("/authenticode").toURI());
    try (Stream<Path> s = Files.list(dir)) {
      return s.filter(p -> !p.toString().endsWith(".expected")).sorted().collect(Collectors.toList());
    }
  }

  /** The signature related lines of the module data, like the script used for the goldens. */
  static String extract(String data) {
    List<String> out = new ArrayList<>();
    int skip = -1;
    for (String line : data.split("\n", -1)) {
      int ind = 0;
      while (ind < line.length() && line.charAt(ind) == '\t') {
        ind++;
      }
      String s = line.strip();
      if (skip >= 0) {
        if (ind > skip && !s.isEmpty()) {
          out.add(line);
          continue;
        }
        skip = -1;
      }
      if (ind == 1 && s.equals("signatures")) {
        out.add(line);
        skip = 1;
      } else if (ind == 1
          && (s.startsWith("number_of_signatures ") || s.startsWith("is_signed "))) {
        out.add(line);
      }
    }
    return String.join("\n", out) + "\n";
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("samples")
  void sameAsLibyara(Path sample) throws Exception {
    Rules rules = YaraCompiler.compile("import \"pe\" rule r { condition: false }");
    StringBuilder sb = new StringBuilder();
    rules
        .newScanner()
        .setCallback(
            new ScanCallback() {
              @Override
              public void moduleImported(String name, YStructure module) {
                module.printData(sb, 0, true);
              }
            })
        .scan(sample);
    String expected =
        new String(
            Files.readAllBytes(Paths.get(sample + ".expected")), StandardCharsets.ISO_8859_1);
    assertTrue(expected.contains("number_of_signatures"), "bad golden file");
    assertEquals(expected, extract(sb.toString()));
  }
}
