package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Feeds truncated, bit-flipped and random versions of YARA's test samples to every module,
 * calling the module functions too. Malformed input must never make a module throw.
 */
class RobustnessTest {

  private static final String[] CONDITIONS = {
    "pe.is_pe", "pe.imphash() != \"\"", "pe.exports(\"x\")", "pe.exports(/x/)", "pe.exports(1)",
    "pe.exports_index(\"x\") == 0", "pe.exports_index(1) == 0", "pe.exports_index(/x/) == 0",
    "pe.imports(\"kernel32.dll\", \"x\")", "pe.imports(\"kernel32.dll\", 1)",
    "pe.imports(\"kernel32.dll\") == 0", "pe.imports(/k/, /x/) == 0",
    "pe.imports(pe.IMPORT_ANY, \"a.dll\", \"x\")", "pe.imports(pe.IMPORT_ANY, /./, /./) == 0",
    "pe.import_rva(\"a.dll\", \"b\") == 0", "pe.import_rva(\"a.dll\", 1) == 0",
    "pe.delayed_import_rva(\"a.dll\", \"b\") == 0", "pe.delayed_import_rva(\"a.dll\", 1) == 0",
    "pe.calculate_checksum() == 0", "pe.rich_signature.version(1) == 0",
    "pe.rich_signature.toolid(1, 1) == 0", "pe.locale(0x409)", "pe.language(9)",
    "pe.is_dll()", "pe.is_32bit()", "pe.is_64bit()", "pe.rva_to_offset(0x1000) == 0",
    "pe.section_index(\".text\") == 0", "pe.section_index(0x400) == 0",
    "for any s in pe.signatures : (s.valid_on(1500000000))",
    "for any s in pe.sections : (s.name == \".text\")", "pe.number_of_resources > 1",
    "pe.version_info[\"CompanyName\"] == \"x\"", "pe.pdb_path == \"x\"",
    "elf.number_of_sections > 0", "elf.telfhash() != \"\"", "elf.import_md5() != \"\"",
    "macho.number_of_segments > 0", "macho.file_index_for_arch(7) == 0",
    "macho.entry_point_for_arch(7) == 0",
    "dex.has_method(\"x\")", "dex.has_method(\"a\", \"x\")", "dex.has_class(\"x\")",
    "dex.number_of_fields > 0",
    "dotnet.is_dotnet", "dotnet.number_of_classes > 0", "dotnet.typelib == \"x\"",
    "for any c in dotnet.classes : (c.number_of_methods > 0)",
    "math.entropy(0, filesize) > 7", "hash.md5(0, filesize) == \"x\"",
    "hash.crc32(0, filesize) == 0", "hash.checksum32(0, filesize) == 0",
  };

  private static Rules rules() throws Exception {
    StringBuilder sb =
        new StringBuilder(
            "import \"pe\" import \"elf\" import \"macho\" import \"dex\" import \"dotnet\" "
                + "import \"math\" import \"hash\"\n");
    for (int i = 0; i < CONDITIONS.length; i++) {
      sb.append("rule r").append(i).append(" { condition: ").append(CONDITIONS[i]).append(" }\n");
    }
    return YaraCompiler.compile(sb.toString());
  }

  private static void scan(Scanner s, byte[] data, String what) {
    try {
      s.scan(data);
    } catch (Throwable t) {
      AssertionError e = new AssertionError("scan failed for " + what + ": " + t, t);
      throw e;
    }
  }

  private static List<Path> samples() throws IOException {
    try (Stream<Path> s = Files.list(Paths.get(YaraAssert.dataDir()))) {
      return s.filter(Files::isRegularFile).sorted().collect(Collectors.toList());
    }
  }

  @Test
  void mutatedSamples() throws Exception {
    Rules rules = rules();
    Scanner scanner = rules.newScanner().setReportRules(true, true);
    Random random = new Random(0x5eed);
    List<String> failures = new ArrayList<>();
    for (Path p : samples()) {
      byte[] data = Files.readAllBytes(p);
      String name = p.getFileName().toString();
      int[] cuts = {0, 1, 2, 63, 64, 65, 200, 512, 1024, 4096, data.length / 3, data.length / 2,
          data.length - 1};
      for (int cut : cuts) {
        if (cut >= 0 && cut < data.length) {
          try {
            scan(scanner, java.util.Arrays.copyOf(data, cut), name + " truncated to " + cut);
          } catch (AssertionError e) {
            failures.add(e.getMessage());
          }
        }
      }
      int variants = data.length > 512 * 1024 ? 6 : 30;
      for (int v = 0; v < variants; v++) {
        byte[] mutated = data.clone();
        int flips = 1 + random.nextInt(32);
        for (int f = 0; f < flips && mutated.length > 0; f++) {
          // Half of the variants mutate the headers, where parsers are most sensitive.
          int limit = v % 2 == 0 ? Math.min(mutated.length, 4096) : mutated.length;
          int pos = random.nextInt(limit);
          mutated[pos] =
              random.nextBoolean()
                  ? (byte) (mutated[pos] ^ (1 << random.nextInt(8)))
                  : (byte) (random.nextBoolean() ? 0xFF : random.nextInt(256));
        }
        try {
          scan(scanner, mutated, name + " variant " + v);
        } catch (AssertionError e) {
          failures.add(e.getMessage());
        }
      }
    }
    if (!failures.isEmpty()) {
      fail(failures.size() + " failures, first: " + failures.get(0));
    }
  }

  @Test
  void randomBuffersWithMagic() throws Exception {
    Rules rules = rules();
    Scanner scanner = rules.newScanner();
    Random random = new Random(42);
    byte[][] magics = {
      {'M', 'Z'}, {0x7f, 'E', 'L', 'F', 1, 1}, {0x7f, 'E', 'L', 'F', 2, 2},
      {(byte) 0xfe, (byte) 0xed, (byte) 0xfa, (byte) 0xce},
      {(byte) 0xcf, (byte) 0xfa, (byte) 0xed, (byte) 0xfe},
      {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe}, {'d', 'e', 'x', '\n', '0', '3', '5', 0}
    };
    for (int i = 0; i < 700; i++) {
      byte[] data = new byte[random.nextInt(8192)];
      random.nextBytes(data);
      byte[] magic = magics[i % magics.length];
      System.arraycopy(magic, 0, data, 0, Math.min(magic.length, data.length));
      if (data.length > 0x40 && i % magics.length == 0) {
        // Point e_lfanew to a PE header.
        int lfanew = 0x40 + random.nextInt(Math.min(512, data.length - 0x40));
        data[0x3c] = (byte) lfanew;
        data[0x3d] = (byte) (lfanew >> 8);
        data[0x3e] = 0;
        data[0x3f] = 0;
        if (lfanew + 4 <= data.length) {
          data[lfanew] = 'P';
          data[lfanew + 1] = 'E';
          data[lfanew + 2] = 0;
          data[lfanew + 3] = 0;
        }
      }
      scan(scanner, data, "random buffer " + i);
    }
  }
}
