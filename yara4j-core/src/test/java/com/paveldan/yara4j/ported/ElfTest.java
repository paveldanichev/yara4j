package com.paveldan.yara4j.ported;

import static com.paveldan.yara4j.YaraAssert.*;

import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.ErrorCode;

/** Converted from YARA's test-elf.c. */
@SuppressWarnings("all")
class ElfTest {

  @Test
  void testMain() throws Exception {
    // Each newly exposed e_machine value, checked end to end: patch the value
    // into the ELF header and confirm elf.machine reports it under the new
    // constant. Catches both a wrong constant and a value the module drops.
    Object[][] machines = {
      {"EM_PARISC", 15}, {"EM_SPARC32PLUS", 18}, {"EM_S390", 22}, {"EM_MCORE", 39},
      {"EM_RCE", 39}, {"EM_SH", 42}, {"EM_SPARCV9", 43}, {"EM_ARC_COMPACT", 93},
      {"EM_BPF", 247}, {"EM_LOONGARCH", 258},
    };
    for (Object[] m : machines) {
      byte[] elf = com.paveldan.yara4j.Blobs.ELF32_FILE.clone();
      int value = (Integer) m[1];
      elf[18] = (byte) (value & 0xFF);
      elf[19] = (byte) (value >> 8);
      assertTrueRuleBlob(
          "import \"elf\" rule test { condition: elf.machine == elf." + m[0]
              + " and elf.machine == " + value + " }",
          elf);
    }
    assertTrueRuleBlob("import \"elf\" rule test { condition: elf.type }", com.paveldan.yara4j.Blobs.ELF32_FILE);
    assertTrueRuleBlob("import \"elf\" rule test { condition: elf.type }", com.paveldan.yara4j.Blobs.ELF64_FILE);
    assertTrueRuleBlob("import \"elf\" rule test { condition: elf.machine == elf.EM_386 }", com.paveldan.yara4j.Blobs.ELF32_FILE);
    assertTrueRuleBlob("import \"elf\" rule test { condition: elf.machine == elf.EM_X86_64 }", com.paveldan.yara4j.Blobs.ELF64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         strings: $a = { b8 01 00 00 00 bb 2a }         condition: $a at elf.entry_point       }", com.paveldan.yara4j.Blobs.ELF32_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         strings: $a = { b8 01 00 00 00 bb 2a }         condition: $a at elf.entry_point       }", com.paveldan.yara4j.Blobs.ELF64_FILE);
    assertTrueRuleBlob("import \"elf\" rule test { condition: elf.entry_point == 0xa0 }", com.paveldan.yara4j.Blobs.ELF32_NOSECTIONS);
    assertTrueRuleBlob("import \"elf\" rule test { condition: elf.entry_point == 0x1a0 }", com.paveldan.yara4j.Blobs.ELF32_SHAREDOBJ);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition: elf.sections[2].name == \".comment\"       }", com.paveldan.yara4j.Blobs.ELF64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition: elf.machine == elf.EM_MIPS       }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           elf.number_of_sections == 35 and elf.number_of_segments == 10       }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           for any i in (0..elf.number_of_sections): (             elf.sections[i].type == elf.SHT_PROGBITS and              elf.sections[i].address == 0x400600 and             elf.sections[i].name == \".text\")       }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"         rule test {           condition:             for any i in (0..elf.number_of_segments): (             elf.segments[i].type == elf.PT_LOAD and             elf.segments[i].virtual_address == 0x00400000 and             elf.segments[i].file_size == 0x95c)      }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           elf.dynamic_section_entries == 19 and           elf.symtab_entries == 80       }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           for any i in (0..elf.symtab_entries): (             elf.symtab[i].shndx == 9 and             elf.symtab[i].value == 0x400650 and             elf.symtab[i].name == \"_start_c\")       }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           elf.symtab[68].name == \"_start_c\" and           elf.symtab[68].type == elf.STT_FUNC and           elf.symtab[68].bind == elf.STB_GLOBAL and           elf.symtab[68].value == 0x400650 and           elf.symtab[68].size == 56       }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           for any i in (0..elf.dynsym_entries): (             elf.dynsym[i].shndx == 11 and             elf.dynsym[i].value == 0x400910 and             elf.dynsym[i].name == \"_fini\")       }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           elf.dynsym[9].name == \"__RLD_MAP\" and           elf.dynsym[9].type == elf.STT_OBJECT and           elf.dynsym[9].bind == elf.STB_GLOBAL and           elf.dynsym[9].value == 0x411000 and           elf.dynsym[9].size == 0       }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           elf.dynamic[4].type == elf.DT_STRTAB and           elf.dynamic[4].val == 0x400484      }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           for any i in (0..elf.dynamic_section_entries): (             elf.dynamic[i].type == 0x70000006 and             elf.dynamic[i].val == 0x400000)      }", com.paveldan.yara4j.Blobs.ELF32_MIPS_FILE);
    // A big-endian symtab whose sh_link is past the real section count must not
    // be parsed against an out-of-range section header. Before the e_shnum byte
    // swap fix a little-endian host accepted the bogus link and reported a
    // phantom symbol named "ABCD".
    assertFalseRuleBlob("import \"elf\"       rule test {         condition:           elf.symtab_entries == 1 and elf.symtab[0].name == \"ABCD\"       }", com.paveldan.yara4j.Blobs.ELF32_BE_BAD_SYMTAB_LINK);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition: elf.machine == elf.EM_X86_64       }", com.paveldan.yara4j.Blobs.ELF_x64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           elf.number_of_sections == 22 and           elf.number_of_segments == 7       }", com.paveldan.yara4j.Blobs.ELF_x64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           for any i in (0..elf.number_of_sections): (             elf.sections[i].type == elf.SHT_PROGBITS and             elf.sections[i].address == 0x601000 and             elf.sections[i].name == \".got.plt\")       }", com.paveldan.yara4j.Blobs.ELF_x64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {          condition:             for any i in (0..elf.number_of_segments): (               elf.segments[i].type == elf.PT_LOAD and               elf.segments[i].virtual_address == 0x600e78 and               elf.segments[i].file_size == 0x1b0)       }", com.paveldan.yara4j.Blobs.ELF_x64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {          condition:             elf.dynamic_section_entries == 18 and             elf.symtab_entries == 48        }", com.paveldan.yara4j.Blobs.ELF_x64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           for any i in (0..elf.symtab_entries): (             elf.symtab[i].shndx == 8 and             elf.symtab[i].value == 0x400400 and             elf.symtab[i].name == \"main\")      }", com.paveldan.yara4j.Blobs.ELF_x64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           elf.symtab[20].name == \"__JCR_LIST__\" and           elf.symtab[20].type == elf.STT_OBJECT and           elf.symtab[20].bind == elf.STB_LOCAL and           elf.symtab[20].value == 0x600e88 and           elf.symtab[20].size == 0       }", com.paveldan.yara4j.Blobs.ELF_x64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           elf.dynamic[13].type == elf.DT_PLTGOT and           elf.dynamic[13].val == 0x601000      }", com.paveldan.yara4j.Blobs.ELF_x64_FILE);
    assertTrueRuleBlob("import \"elf\"       rule test {         condition:           for any i in (0..elf.dynamic_section_entries): (             elf.dynamic[i].type == elf.DT_JMPREL and             elf.dynamic[i].val == 0x4003c0)       }", com.paveldan.yara4j.Blobs.ELF_x64_FILE);
    assertTrueRuleFile("import \"elf\"       rule test {         condition:           elf.telfhash() ==             \"T174B012188204F00184540770331E0B111373086019509C464D0ACE88181266C09774FA\"       }", "tests/data/elf_with_imports");
  }
}
