package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Scanning files with {@link Scanner#scan(Path)}. On Windows a mapped file can't be modified or
 * deleted, so the mapping must be released when the scan ends. The surefire "unmap" execution
 * runs this test, ModuleOutputTest and AuthenticodeTest with yara4j.unmap=true to exercise that
 * code on every system.
 */
class ScanFileTest {

  @TempDir Path dir;

  private static final String RULES =
      "rule a { strings: $a = \"evil\" condition: $a }\n"
          + "rule b { strings: $b = \"good\" condition: $b }";

  @Test
  void fileCanBeModifiedAndDeletedAfterScan() throws Exception {
    Rules rules = YaraCompiler.compile(RULES);
    Scanner scanner = rules.newScanner();
    Path file = dir.resolve("sample.bin");
    for (int i = 0; i < 20; i++) {
      Files.write(file, ("xx evil " + i).getBytes(StandardCharsets.US_ASCII));
      assertEquals("a", scanner.scan(file).get(0).getIdentifier());
      // Fails on Windows if the file is still mapped.
      Files.write(file, "xx good".getBytes(StandardCharsets.US_ASCII));
      assertEquals("b", scanner.scan(file).get(0).getIdentifier());
      Files.delete(file);
    }
  }

  @Test
  void emptyFile() throws Exception {
    Path file = Files.createFile(dir.resolve("empty"));
    Rules rules = YaraCompiler.compile("rule r { condition: filesize == 0 }");
    assertEquals(1, rules.newScanner().scan(file).size());
    Files.delete(file);
  }

  @Test
  void matchDataSurvivesTheScan() throws Exception {
    Path file = dir.resolve("sample.bin");
    Files.write(file, "xx evil xx".getBytes(StandardCharsets.US_ASCII));
    StringMatch m = YaraCompiler.compile(RULES).newScanner().scan(file).get(0)
        .getPublicStringMatches().get(0);
    Files.delete(file);
    assertEquals("evil", new String(m.getData(), StandardCharsets.US_ASCII));
  }

  /** On Linux, checks in /proc/self/maps that the file isn't mapped any more. */
  @Test
  void mappingIsReleased() throws Exception {
    assumeTrue(MemoryBlocks.UNMAP_AFTER_SCAN, "mappings are released only on Windows");
    Path maps = Paths.get("/proc/self/maps");
    assumeTrue(Files.isReadable(maps), "needs /proc/self/maps");
    Path file = dir.resolve("mapped-sample.bin");
    Files.write(file, new byte[1 << 20]);
    YaraCompiler.compile(RULES).newScanner().scan(file);
    assertFalse(Files.readString(maps).contains(file.toRealPath().toString()));
  }
}
