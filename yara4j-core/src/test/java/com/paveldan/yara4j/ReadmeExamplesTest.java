package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YStructure;

/** Keeps the examples of README.md compiling and working. */
class ReadmeExamplesTest {

  public static final class MyModule implements YaraModule {
    @Override
    public String name() {
      return "my";
    }

    @Override
    public void declare(ModuleDeclarations d) {
      d.declareInteger("size");
      d.declareFunction("twice", "i", "i", call -> call.integerArgument(1) * 2);
    }

    @Override
    public void load(ScanContext ctx, YStructure module, byte[] moduleData) {
      module.setInteger(ctx.fileSize(), "size");
    }

    @Override
    public void unload(YStructure module) {}
  }

  @Test
  void customModuleAndScanner() throws Exception {
    YaraCompiler compiler = new YaraCompiler().registerModule(new MyModule());
    compiler.defineString("filename", "");
    compiler.addSourceOrThrow(
        "import \"my\" rule r { strings: $a = \"abc\" "
            + "condition: $a and my.size == 6 and my.twice(3) == 6 and filename == \"x\" }",
        null);
    Rules rules = compiler.getRules();
    Scanner scanner =
        rules.newScanner().setTimeout(Duration.ofSeconds(30)).defineString("filename", "x");
    assertEquals(1, scanner.scan("xxabcx".getBytes(StandardCharsets.US_ASCII)).size());
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    rules.save(out);
    Rules loaded = Rules.load(new java.io.ByteArrayInputStream(out.toByteArray()), new MyModule());
    assertEquals(
        1,
        loaded.newScanner()
            .defineString("filename", "x")
            .scan("xxabcx".getBytes(StandardCharsets.US_ASCII))
            .size());
  }

  @Test
  void rulesFromStrings() throws Exception {
    byte[] data = "MZ... evil ...".getBytes(StandardCharsets.US_ASCII);
    Rules rules = YaraCompiler.compile("rule evil { strings: $a = \"evil\" condition: $a }");
    assertEquals("evil", rules.scan(data).get(0).getIdentifier());

    YaraCompiler compiler = new YaraCompiler();
    compiler.addSourceOrThrow(
        """
        rule mz_header {
          condition: uint16(0) == 0x5A4D
        }
        """);
    compiler.addSourceOrThrow("rule evil { strings: $a = \"evil\" condition: $a }", "malware");
    List<RuleMatch> matches = compiler.getRules().scan(data);
    assertEquals(2, matches.size());
    assertEquals("default", matches.get(0).getNamespace());
    assertEquals("malware", matches.get(1).getNamespace());

    YaraCompiler bad = new YaraCompiler();
    assertEquals(1, bad.addSource("rule broken { condition: foo }"));
    CompilerMessage m = bad.getErrors().get(0);
    assertEquals(1, m.getLine());
    assertEquals("undefined identifier \"foo\"", m.getMessage());
  }

  @Test
  void externalVariables() throws Exception {
    byte[] data = "abc".getBytes(StandardCharsets.US_ASCII);
    YaraCompiler compiler = new YaraCompiler();
    compiler.defineString("filename", "");
    compiler.defineInteger("max_size", 100);
    compiler.defineBoolean("trusted", false);
    compiler.defineFloat("threshold", 0.5);
    compiler.addSourceOrThrow(
        "rule exe { condition: filename matches /\\.exe$/i }\n"
            + "rule small { condition: filesize < max_size and not trusted }\n"
            + "rule ratio { condition: threshold > 0.25 }");
    Rules rules = compiler.getRules();

    // The values given to the compiler are the defaults of every scanner.
    assertEquals(List.of("small", "ratio"), ids(rules.newScanner().scan(data)));

    Scanner scanner = rules.newScanner().defineString("filename", "setup.EXE");
    assertEquals(List.of("exe", "small", "ratio"), ids(scanner.scan(data)));
    // The value stays until changed again.
    assertEquals(List.of("exe", "small", "ratio"), ids(scanner.scan(data)));
    scanner.defineInteger("max_size", 2).defineBoolean("trusted", true);
    scanner.defineFloat("threshold", 0.1);
    assertEquals(List.of("exe"), ids(scanner.scan(data)));
    // Other scanners are not affected.
    assertEquals(List.of("small", "ratio"), ids(rules.newScanner().scan(data)));

    // Only variables defined in the compiler can be set, with the same type.
    YaraException e =
        assertThrows(YaraException.class, () -> rules.newScanner().defineString("other", "x"));
    assertEquals(ErrorCode.INVALID_ARGUMENT, e.getErrorCode());
    e = assertThrows(YaraException.class, () -> rules.newScanner().defineInteger("filename", 1));
    assertEquals(ErrorCode.INVALID_EXTERNAL_VARIABLE_TYPE, e.getErrorCode());
    e = assertThrows(YaraException.class, () -> compiler.defineString("filename", "x"));
    assertEquals(ErrorCode.DUPLICATED_EXTERNAL_VARIABLE, e.getErrorCode());

    // A variable must be defined before the rules using it are added.
    YaraCompilationException ce =
        assertThrows(
            YaraCompilationException.class,
            () -> new YaraCompiler().addSourceOrThrow("rule r { condition: filename == \"\" }"));
    assertEquals(ErrorCode.UNDEFINED_IDENTIFIER, ce.getMessages().get(0).getErrorCode());
  }

  @Test
  void stringExternalsEndAtNul() throws Exception {
    YaraCompiler compiler = new YaraCompiler();
    compiler.defineString("s", "ab\0cd");
    compiler.addSourceOrThrow("rule r { condition: s == \"ab\" }");
    Rules rules = compiler.getRules();
    assertEquals(1, rules.scan(new byte[0]).size());
    assertEquals(1, rules.newScanner().defineString("s", "ab\0xx").scan(new byte[0]).size());
  }

  private static List<String> ids(List<RuleMatch> matches) {
    List<String> ids = new ArrayList<>();
    for (RuleMatch m : matches) {
      ids.add(m.getIdentifier());
    }
    return ids;
  }
}
