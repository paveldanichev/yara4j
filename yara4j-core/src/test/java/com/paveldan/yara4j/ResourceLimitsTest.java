package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BinaryReader;

/**
 * Small files whose structures reference each other used to make modules allocate gigabytes,
 * recurse until the stack overflowed or run for minutes ignoring the scan timeout.
 */
class ResourceLimitsTest {

  /** The identifiers of the rules matching data, scanned with a timeout. */
  private static List<String> matching(YaraCompiler compiler, String source, byte[] data)
      throws Exception {
    compiler.addSourceOrThrow(source);
    Scanner scanner = compiler.getRules().newScanner().setTimeout(Duration.ofSeconds(60));
    return scanner.scan(data).stream().map(RuleMatch::getIdentifier).collect(Collectors.toList());
  }

  private static List<String> matching(String source, byte[] data) throws Exception {
    return matching(new YaraCompiler(), source, data);
  }

  @Test
  void deeplyNestedSignatures() throws Exception {
    // 100000 levels in 20 MB: each level used to keep a copy of the levels below it.
    byte[] pe = CraftedFiles.peWithNestedSignatures(100_000, 0x200);
    assertEquals(
        List.of("r"),
        matching(
            "import \"pe\" rule r { condition: pe.number_of_signatures == 9 and "
                + "pe.signatures[0].file_digest == pe.signatures[8].file_digest }",
            pe));
  }

  @Test
  void signatureTree() throws Exception {
    // 1 + 16 + 256 signatures, only the first 64 are parsed.
    byte[] pe = CraftedFiles.peWithSignatureTree(16, 2);
    assertEquals(
        List.of("r"),
        matching("import \"pe\" rule r { condition: pe.number_of_signatures == 64 }", pe));
  }

  @Test
  void dexMethodsSharingCodeItem() throws Exception {
    // A million methods whose instructions are the whole 4 MB file: each method used to get
    // its own copy of them. The file has a single method id, so only the first 65536 methods
    // are parsed.
    int size = 4 << 20;
    byte[] dex = CraftedFiles.dexWithSharedCodeItem(size);
    int max = 0x10000;
    long insnsSize = (size - 0x88 - 16) / 2;
    assertEquals(
        List.of("r"),
        matching(
            "import \"dex\" rule r { condition: dex.number_of_methods == "
                + max
                + " and dex.method["
                + (max - 1)
                + "].code_item.insns_size == "
                + insnsSize
                + " and dex.method[0].code_item.insns == dex.method["
                + (max - 1)
                + "].code_item.insns }",
            dex));
  }

  @Test
  void elfSymbolsSharingName() throws Exception {
    // 20000 symbols named by the same 512 KB string, which used to be copied (and its length
    // computed) for each of them.
    byte[] elf = CraftedFiles.elfWithSharedSymbolName(20_000, 512 << 10);
    assertEquals(
        List.of("r"),
        matching(
            "import \"elf\" rule r { condition: elf.symtab_entries == 20000 and "
                + "elf.symtab[19999].name == elf.symtab[0].name and "
                + "elf.symtab[0].name startswith \"ffff\" and "
                + "not defined elf.telfhash() and not defined elf.import_md5() }",
            elf));
  }

  @Test
  void dexFieldsOverTheLimit() throws Exception {
    // The fields of the first class go past the limit (the file has a single field id), so its
    // methods can't be found; the method of the second class is still parsed.
    int max = 0x10000;
    byte[] dex = CraftedFiles.dexWithFieldsThenMethod(max + 1, 7, 9);
    assertEquals(
        List.of("r"),
        matching(
            "import \"dex\" rule r { condition: dex.number_of_fields == "
                + max
                + " and dex.number_of_methods == 1 and dex.method[0].access_flags == 9 }",
            dex));
  }

  @Test
  void elfUndefinedHashesInLoop() throws Exception {
    // The names joined are over the limit, which used to be found again at each call.
    byte[] elf = CraftedFiles.elfWithSharedSymbolName(20_000, 512 << 10);
    YaraCompiler compiler = new YaraCompiler();
    compiler.addSourceOrThrow(
        "import \"elf\" rule r { condition: for all i in (1..10000) : "
            + "(not defined elf.telfhash() and not defined elf.import_md5()) }");
    Scanner scanner = compiler.getRules().newScanner().setTimeout(Duration.ofSeconds(20));
    assertEquals(
        List.of("r"),
        scanner.scan(elf).stream().map(RuleMatch::getIdentifier).collect(Collectors.toList()));
  }

  @Test
  void elfShortSymbolNames() throws Exception {
    byte[] elf = CraftedFiles.elfWithSharedSymbolName(3, 4);
    assertEquals(
        List.of("r"),
        matching(
            "import \"elf\" import \"hash\" rule r { condition: elf.symtab[2].name == \"ffff\" "
                + "and elf.import_md5() == hash.md5(\"ffff,ffff,ffff\") }",
            elf));
  }

  /** A module whose load runs the given code. */
  private static YaraModule module(String name, java.util.function.Consumer<ScanContext> load) {
    return new YaraModule() {
      @Override
      public String name() {
        return name;
      }

      @Override
      public void declare(ModuleDeclarations d) {
        d.declareInteger("before");
        d.declareInteger("after");
      }

      @Override
      public void load(ScanContext context, YStructure module, byte[] moduleData) {
        module.setInteger(1, "before");
        load.accept(context);
        module.setInteger(1, "after");
      }
    };
  }

  @Test
  void modulesCanCheckTheTimeout() throws Exception {
    YaraCompiler compiler = new YaraCompiler();
    compiler.registerModule(
        module(
            "slow",
            ctx -> {
              long end = System.nanoTime() + Duration.ofSeconds(30).toNanos();
              while (System.nanoTime() < end) {
                ctx.checkTimeout();
              }
            }));
    compiler.addSourceOrThrow("import \"slow\" rule r { condition: slow.after == 1 }");
    Scanner scanner = compiler.getRules().newScanner().setTimeout(Duration.ofMillis(200));
    YaraException e = assertThrows(YaraException.class, () -> scanner.scan(new byte[16]));
    assertEquals(ErrorCode.SCAN_TIMEOUT, e.getErrorCode());
  }

  @Test
  void readersCheckTheTimeout() throws Exception {
    YaraCompiler compiler = new YaraCompiler();
    compiler.registerModule(
        module(
            "reading",
            ctx -> {
              // Reads the data over and over for 30 seconds without checking the timeout.
              BinaryReader r = new BinaryReader(ctx.blocks().get(0).data(), ctx);
              long end = System.nanoTime() + Duration.ofSeconds(30).toNanos();
              while (System.nanoTime() < end) {
                for (long i = 0; i < r.size(); i++) {
                  r.u8(i);
                }
              }
            }));
    compiler.addSourceOrThrow("import \"reading\" rule r { condition: reading.after == 1 }");
    Scanner scanner = compiler.getRules().newScanner().setTimeout(Duration.ofMillis(200));
    YaraException e = assertThrows(YaraException.class, () -> scanner.scan(new byte[16]));
    assertEquals(ErrorCode.SCAN_TIMEOUT, e.getErrorCode());
  }
}
