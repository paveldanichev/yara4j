package com.paveldan.yara4j.ported;

import static com.paveldan.yara4j.YaraAssert.*;

import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.ErrorCode;

/** Converted from YARA's test-dex.c. */
@SuppressWarnings("all")
class DexTest {

  @Test
  void testMain() throws Exception {
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.header.magic ==         dex.DEX_FILE_MAGIC_035 }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.header.checksum ==         0x3F9C602F }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.header.data_size ==         0x18C }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.string_ids[0].value ==      \"<clinit>\" }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.string_ids[8].value ==         \"com.google.helloyara\" }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.type_ids[0].descriptor_idx ==         0x2 }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.proto_ids[0].shorty_idx ==         0x6 }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.field_ids[0].class_idx ==         0x1 }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.method_ids[0].class_idx ==         0x1 }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.class_defs[0].class_idx ==         0x1 }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.number_of_fields == 2 }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.field[0].class_name ==         \"Lcom/android/tools/ir/server/AppInfo;\" }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.field[0].name ==         \"applicationId\" }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.number_of_methods == 2 }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.method[0].class_name ==         \"Lcom/android/tools/ir/server/AppInfo;\" }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.method[0].proto == \"V\" }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.method[0].name ==         \"<clinit>\" }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.method[1].name ==         \"<init>\" }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition: dex.map_list.size == 12 }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition:           dex.map_list.map_item[0].type == dex.TYPE_HEADER_ITEM         }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition:           dex.has_method(\"<init>\")         }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition:           dex.has_method(\"Lcom/android/tools/ir/server/AppInfo;\", \"<clinit>\")         }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition:           dex.has_method(/init/)         }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition:           dex.has_method(/AppInfo/, /init/)         }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition:           dex.has_class(\"Lcom/android/tools/ir/server/AppInfo;\")         }", com.paveldan.yara4j.Blobs.DEX_FILE);
    assertTrueRuleBlob("import \"dex\" rule test { condition:           dex.has_class(/AppInfo/)         }", com.paveldan.yara4j.Blobs.DEX_FILE);
  }
}
