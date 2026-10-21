package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import com.paveldan.yara4j.object.YStructure;

/**
 * Compares the complete output of the pe, elf, macho, dotnet and dex modules ("yara -D") for
 * every sample in YARA's tests/data with the output of native libyara 4.5.8 built with OpenSSL
 * 3.0.13. The module-output/*.txt.gz resources are produced by tools/module-output.
 */
class ModuleOutputTest {

  private static final String[] MODULES = {"pe", "elf", "macho", "dotnet", "dex"};

  /** Sample name to expected output, in the order of the resource. */
  private static Map<String, String> expected(String module) throws IOException {
    String text;
    try (InputStream in =
        new GZIPInputStream(
            ModuleOutputTest.class.getResourceAsStream("/module-output/" + module + ".txt.gz"))) {
      text = new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
    }
    Map<String, String> result = new LinkedHashMap<>();
    String name = null;
    StringBuilder sb = new StringBuilder();
    for (String line : text.split("(?<=\n)")) {
      if (line.startsWith("### ")) {
        if (name != null) {
          result.put(name, sb.toString());
        }
        name = line.substring(4).strip();
        sb.setLength(0);
      } else {
        sb.append(line);
      }
    }
    if (name != null) {
      result.put(name, sb.toString());
    }
    return result;
  }

  static String printModuleData(String module, Path sample) throws Exception {
    Rules rules = YaraCompiler.compile("import \"" + module + "\" rule r { condition: false }");
    StringBuilder sb = new StringBuilder();
    rules
        .newScanner()
        .setCallback(
            new ScanCallback() {
              @Override
              public void moduleImported(String name, YStructure data) {
                data.printData(sb, 0, true);
                sb.append('\n');
              }
            })
        .scan(sample);
    return sb.toString();
  }

  @TestFactory
  Stream<DynamicContainer> sameAsLibyara() throws Exception {
    Path data = Paths.get(ModuleOutputTest.class.getResource("/data").toURI());
    List<String> samples;
    try (Stream<Path> s = Files.list(data)) {
      samples =
          s.filter(Files::isRegularFile)
              .map(p -> p.getFileName().toString())
              .sorted()
              .collect(Collectors.toList());
    }
    List<DynamicContainer> containers = new ArrayList<>();
    for (String module : MODULES) {
      Map<String, String> expected = expected(module);
      List<DynamicTest> tests = new ArrayList<>();
      // A sample added to tests/data without regenerating the expected output fails here.
      tests.add(
          DynamicTest.dynamicTest(
              "samples",
              () -> assertEquals(samples, new ArrayList<>(expected.keySet()))));
      for (Map.Entry<String, String> e : expected.entrySet()) {
        tests.add(
            DynamicTest.dynamicTest(
                e.getKey(),
                () ->
                    assertEquals(
                        e.getValue(), printModuleData(module, data.resolve(e.getKey())))));
      }
      containers.add(DynamicContainer.dynamicContainer(module, tests));
    }
    return containers.stream();
  }
}
