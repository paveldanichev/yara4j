package com.paveldan.yara4j.ported;

import static com.paveldan.yara4j.YaraAssert.*;

import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.ErrorCode;

/** Converted from YARA's test-macho.c. */
@SuppressWarnings("all")
class MachoTest {

  @Test
  void testMain() throws Exception {
    //  Tests for executable files
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.cputype == macho.CPU_TYPE_X86 }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.filetype == macho.MH_EXECUTE }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.flags & macho.MH_PIE }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    // Segments
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.number_of_segments == 4 }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.segments[0].segname == \"__PAGEZERO\" and     macho.segments[1].segname == \"__TEXT\" and     macho.segments[2].segname == \"__DATA\" and     macho.segments[3].segname == \"__LINKEDIT\" }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.segments[0].vmaddr == 0 and     macho.segments[0].vmsize == 0x1000 and     macho.segments[2].nsects == 2 and     macho.segments[3].fsize == 0x118 }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    assertTrueRuleFile("import \"macho\" rule test { condition:     macho.number_of_segments == 1 }", "tests/data/tiny-macho");
    // Sections
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.segments[1].sections[0].addr == 0x1e90 and     macho.segments[1].sections[0].size == 0xa6 and     macho.segments[1].sections[0].offset == 0x0e90 }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.segments[1].sections[0].sectname == \"__text\" and     macho.segments[1].sections[0].segname == \"__TEXT\" }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.segments[1].sections[1].sectname == \"__symbol_stub\" and     macho.segments[1].sections[2].sectname == \"__stub_helper\" and     macho.segments[1].sections[3].sectname == \"__cstring\" and     macho.segments[1].sections[4].sectname == \"__unwind_info\" and     macho.segments[2].sections[0].sectname == \"__nl_symbol_ptr\" and     macho.segments[2].sections[1].sectname == \"__la_symbol_ptr\" }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    // Entry point (LC_MAIN)
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.entry_point == 0xe90 }", com.paveldan.yara4j.Blobs.MACHO_X86_FILE);
    // Tests for object files
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.cputype == macho.CPU_TYPE_X86 }", com.paveldan.yara4j.Blobs.MACHO_X86_OBJECT_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.filetype == macho.MH_OBJECT }", com.paveldan.yara4j.Blobs.MACHO_X86_OBJECT_FILE);
    // Segments and sections
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.number_of_segments == 1 and macho.segments[0].segname == \"\" and     macho.segments[0].sections[0].sectname == \"__text\" and     macho.segments[0].sections[0].segname == \"__TEXT\" }", com.paveldan.yara4j.Blobs.MACHO_X86_OBJECT_FILE);
    // Tests for big-endian byte order
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.cputype == macho.CPU_TYPE_POWERPC }", com.paveldan.yara4j.Blobs.MACHO_PPC_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.filetype == macho.MH_EXECUTE }", com.paveldan.yara4j.Blobs.MACHO_PPC_FILE);
    // Segments
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.number_of_segments == 4 and     macho.segments[0].segname == \"__PAGEZERO\" and     macho.segments[2].segname == \"__DATA\" and     macho.segments[2].nsects == 6 and     macho.segments[0].vmaddr == 0 and     macho.segments[0].vmsize == 0x1000 and     macho.segments[3].fileoff == 65536 and     macho.segments[3].fsize == 46032 }", com.paveldan.yara4j.Blobs.MACHO_PPC_FILE);
    // Entry point (LC_UNIXTHREAD)
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.entry_point == 0xeb8 }", com.paveldan.yara4j.Blobs.MACHO_PPC_FILE);
    // Tests for 64-bit and shared library files
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.flags == 0x0000100085 }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.reserved == 0x00000001 }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.cputype == macho.CPU_TYPE_X86_64 }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.filetype == macho.MH_DYLIB }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.flags & macho.MH_DYLDLINK and     macho.flags & macho.MH_NOUNDEFS and     macho.flags & macho.MH_NO_REEXPORTED_DYLIBS and     macho.flags & macho.MH_TWOLEVEL }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    // Segments and sections
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.number_of_segments == 2 }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.segments[0].segname == \"__TEXT\" and     macho.segments[1].segname == \"__LINKEDIT\" }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.segments[1].vmaddr == 0x0000000000001000 and     macho.segments[1].vmsize == 0x0000000000001000 and     macho.segments[1].nsects == 0 and     macho.segments[1].fsize == 128 }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.segments[0].sections[0].sectname == \"__text\" and     macho.segments[0].sections[0].segname == \"__TEXT\" }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    assertTrueRuleBlob("import \"macho\" rule test { condition:     macho.segments[0].sections[1].addr == 0x0000000000000f98 and     macho.segments[0].sections[1].size == 0x0000000000000048 and     macho.segments[0].sections[1].offset == 3992 }", com.paveldan.yara4j.Blobs.MACHO_X86_64_DYLIB_FILE);
    // Mach-O Universal Binaries tests
    assertTrueRuleFile("import \"macho\" rule test { condition:     macho.fat_magic == macho.FAT_MAGIC and macho.nfat_arch == 2 }", "tests/data/tiny-universal");
    assertTrueRuleFile("import \"macho\" rule test { condition:     macho.fat_arch[0].cputype == macho.CPU_TYPE_I386 and     macho.fat_arch[0].cpusubtype == macho.CPU_SUBTYPE_I386_ALL and     macho.fat_arch[0].offset == 4096 and     macho.fat_arch[1].cputype == macho.CPU_TYPE_X86_64 and     macho.fat_arch[1].cpusubtype == macho.CPU_SUBTYPE_X86_64_ALL |     macho.CPU_SUBTYPE_LIB64 and macho.fat_arch[1].align == 12 }", "tests/data/tiny-universal");
    assertTrueRuleFile("import \"macho\" rule test { condition:     macho.file[0].cputype == macho.fat_arch[0].cputype and     macho.file[1].cputype == macho.fat_arch[1].cputype }", "tests/data/tiny-universal");
    assertTrueRuleFile("import \"macho\" rule test { condition:     macho.file[0].magic == 0xcefaedfe and     macho.file[1].magic == 0xcffaedfe }", "tests/data/tiny-universal");
    // Entry points for files (LC_MAIN)
    assertTrueRuleFile("import \"macho\" rule test {     strings: $1 = { 55 89 e5 56 83 ec 34 }     condition: $1 at macho.file[0].entry_point + macho.fat_arch[0].offset }", "tests/data/tiny-universal");
    assertTrueRuleFile("import \"macho\" rule test {     strings: $1 = { 55 48 89 e5 48 83 ec 20 }     condition: $1 at macho.file[1].entry_point + macho.fat_arch[1].offset }", "tests/data/tiny-universal");
    // Helper functions
    assertTrueRuleFile("import \"macho\" rule test { condition:     macho.file[macho.file_index_for_arch(macho.CPU_TYPE_I386)].entry_point ==     macho.file[0].entry_point }", "tests/data/tiny-universal");
    assertTrueRuleFile("import \"macho\" rule test { condition:     macho.file[macho.file_index_for_arch(macho.CPU_TYPE_X86_64)].entry_point ==     macho.file[1].entry_point }", "tests/data/tiny-universal");
    assertTrueRuleFile("import \"macho\" rule test { condition:     macho.file[macho.file_index_for_arch(macho.CPU_TYPE_I386,                macho.CPU_SUBTYPE_I386_ALL)].entry_point ==     macho.file[0].entry_point }", "tests/data/tiny-universal");
    assertTrueRuleFile("import \"macho\" rule test { condition:     macho.file[macho.file_index_for_arch(macho.CPU_TYPE_X86_64,                macho.CPU_SUBTYPE_X86_64_ALL |                macho.CPU_SUBTYPE_LIB64)].entry_point ==     macho.file[1].entry_point }", "tests/data/tiny-universal");
    // Entry point for specific architecture
    assertTrueRuleFile("import \"macho\" rule test {     strings: $1 = { 55 89 e5 56 83 ec 34 }     condition: $1 at macho.entry_point_for_arch(macho.CPU_TYPE_I386,                                        macho.CPU_SUBTYPE_I386_ALL) }", "tests/data/tiny-universal");
    assertTrueRuleFile("import \"macho\" rule test {     strings: $1 = { 55 48 89 e5 48 83 ec 20 }     condition: $1 at macho.entry_point_for_arch(macho.CPU_TYPE_X86_64) }", "tests/data/tiny-universal");
  }
}
