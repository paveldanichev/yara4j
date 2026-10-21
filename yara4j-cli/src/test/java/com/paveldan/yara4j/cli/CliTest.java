package com.paveldan.yara4j.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class CliTest {

  @TempDir Path dir;

  private String yara(String... args) {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    PrintStream out = new PrintStream(bytes, true, StandardCharsets.ISO_8859_1);
    int rc = new CommandLine(new YaraCli(out)).execute(args);
    out.flush();
    return rc + "|" + bytes.toString(StandardCharsets.ISO_8859_1);
  }

  @Test
  void scanAndCompile() throws Exception {
    Path rules = dir.resolve("r.yar");
    Files.writeString(
        rules,
        "rule a : t { meta: n = 1 strings: $a = \"foo\" $h = { 62 61 } condition: any of them }\n"
            + "rule b { condition: ext == \"x\" }\n");
    Path target = dir.resolve("t.bin");
    Files.write(target, "xx foo ba".getBytes(StandardCharsets.ISO_8859_1));

    String t = target.toString();
    assertEquals(
        "0|a [t] [n =1] " + t + "\n0x3:$a: foo\n0x7:$h: 62 61\n",
        yara("-d", "ext=y", "-s", "-g", "-m", rules.toString(), t));
    assertEquals("0|1\n", yara("-d", "ext=y", "-c", rules.toString(), t));
    assertEquals("0|b " + t + "\n", yara("-d", "ext=y", "-n", rules.toString(), t));

    Path compiled = dir.resolve("r.y4j");
    int rc =
        new CommandLine(new YaracCli())
            .execute("-d", "ext=x", rules.toString(), compiled.toString());
    assertEquals(0, rc);
    assertEquals("0|a " + t + "\nb " + t + "\n", yara("-C", compiled.toString(), t));
    assertEquals("0|a " + t + "\n", yara("-C", "-d", "ext=z", compiled.toString(), t));
    assertEquals("1|", yara(rules.toString(), dir.resolve("missing").toString()));
  }

  @Test
  void directory() throws Exception {
    Path rules = dir.resolve("r.yar");
    Files.writeString(rules, "rule a { strings: $a = \"foo\" condition: $a }\n");
    Path sub = Files.createDirectory(dir.resolve("sub"));
    Files.writeString(sub.resolve("1.txt"), "foo");
    Files.writeString(sub.resolve("2.txt"), "bar");
    Path deeper = Files.createDirectory(sub.resolve("deeper"));
    Files.writeString(deeper.resolve("3.txt"), "foo");
    assertEquals("0|a " + sub.resolve("1.txt") + "\n", yara(rules.toString(), sub.toString()));
    String r = yara("-r", "-p", "2", rules.toString(), sub.toString());
    assertEquals(
        java.util.Set.of("0|a " + sub.resolve("1.txt"), "a " + deeper.resolve("3.txt")).size(),
        r.split("\n").length);
    org.junit.jupiter.api.Assertions.assertTrue(r.contains("a " + deeper.resolve("3.txt") + "\n"));
    org.junit.jupiter.api.Assertions.assertTrue(r.contains("a " + sub.resolve("1.txt") + "\n"));
  }

  @Test
  void namespacePrefix() throws Exception {
    Path rules = dir.resolve("r.yar");
    Files.writeString(rules, "rule a { strings: $a = \"foo\" condition: $a }\n");
    Path target = dir.resolve("t.bin");
    Files.writeString(target, "foo");
    // "ns:C:\\...\\r.yar" on Windows, which isn't a valid path there.
    assertEquals(
        "0|ns:a " + target + "\n", yara("-e", "ns:" + rules, target.toString()));
    assertEquals("0|1\n", yara("-c", "ns:" + rules, target.toString()));
    assertEquals("1|", yara("ns:" + dir.resolve("missing.yar"), target.toString()));
  }
}
