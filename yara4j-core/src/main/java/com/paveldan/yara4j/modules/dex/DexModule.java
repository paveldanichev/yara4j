package com.paveldan.yara4j.modules.dex;

import java.nio.charset.StandardCharsets;
import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.Regexp;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BinaryReader;
import com.paveldan.yara4j.util.CStrings;

/** The "dex" module. Port of libyara/modules/dex/dex.c. */
public final class DexModule implements YaraModule {

  private static final String[] MAGICS = {
    "dex\n035\0", "dex\n036\0", "dex\n037\0", "dex\n038\0", "dex\n039\0"
  };

  private static final int HEADER_SIZE = 112;
  private static final int CODE_ITEM_SIZE = 16;

  @Override
  public String name() {
    return "dex";
  }

  // ---------------------------------------------------------------------------------------------
  // Functions

  /** strcmp on the C string part of both strings. */
  private static boolean cstrEquals(byte[] a, byte[] b) {
    return java.util.Arrays.equals(CStrings.cstr(a), CStrings.cstr(b));
  }

  private static Object hasMethodString(FunctionCall c) {
    byte[] methodName = c.stringArgument(1);
    YObject module = c.module();
    long n = module.getInteger("number_of_methods");
    if (n == YObject.UNDEFINED) {
      return YObject.UNDEFINED;
    }
    for (int i = 0; i < n; i++) {
      byte[] parsed = module.getString("method[%i].name", i);
      if (parsed != null && cstrEquals(parsed, methodName)) {
        return 1L;
      }
    }
    return 0L;
  }

  private static Object hasMethodAndClassString(FunctionCall c) {
    byte[] className = c.stringArgument(1);
    byte[] methodName = c.stringArgument(2);
    YObject module = c.module();
    long n = module.getInteger("number_of_methods");
    if (n == YObject.UNDEFINED) {
      return YObject.UNDEFINED;
    }
    for (int i = 0; i < n; i++) {
      byte[] parsedClass = module.getString("method[%i].class_name", i);
      if (parsedClass != null && !cstrEquals(parsedClass, className)) {
        continue;
      }
      byte[] parsed = module.getString("method[%i].name", i);
      if (parsed != null && cstrEquals(parsed, methodName)) {
        return 1L;
      }
    }
    return 0L;
  }

  private static boolean reMatch(FunctionCall c, Regexp re, byte[] s) {
    return re.match(c.context(), CStrings.cstr(s)) != -1;
  }

  private static Object hasMethodRegexp(FunctionCall c) {
    Regexp re = c.regexpArgument(1);
    YObject module = c.module();
    long n = module.getInteger("number_of_methods");
    if (n == YObject.UNDEFINED) {
      return YObject.UNDEFINED;
    }
    for (int i = 0; i < n; i++) {
      byte[] parsed = module.getString("method[%i].name", i);
      if (parsed != null && reMatch(c, re, parsed)) {
        return 1L;
      }
    }
    return 0L;
  }

  private static Object hasMethodAndClassRegexp(FunctionCall c) {
    Regexp classRe = c.regexpArgument(1);
    Regexp nameRe = c.regexpArgument(2);
    YObject module = c.module();
    long n = module.getInteger("number_of_methods");
    if (n == YObject.UNDEFINED) {
      return YObject.UNDEFINED;
    }
    for (int i = 0; i < n; i++) {
      byte[] parsedClass = module.getString("method[%i].class_name", i);
      if (parsedClass != null && !reMatch(c, classRe, parsedClass)) {
        continue;
      }
      byte[] parsed = module.getString("method[%i].name", i);
      if (parsed != null && reMatch(c, nameRe, parsed)) {
        return 1L;
      }
    }
    return 0L;
  }

  private static Object hasClassString(FunctionCall c) {
    byte[] className = c.stringArgument(1);
    YObject module = c.module();
    long n = module.getInteger("number_of_methods");
    if (n == YObject.UNDEFINED) {
      return YObject.UNDEFINED;
    }
    for (int i = 0; i < n; i++) {
      byte[] parsedClass = module.getString("method[%i].class_name", i);
      if (parsedClass != null && cstrEquals(parsedClass, className)) {
        return 1L;
      }
    }
    return 0L;
  }

  private static Object hasClassRegexp(FunctionCall c) {
    Regexp re = c.regexpArgument(1);
    YObject module = c.module();
    long n = module.getInteger("number_of_methods");
    if (n == YObject.UNDEFINED) {
      return YObject.UNDEFINED;
    }
    for (int i = 0; i < n; i++) {
      byte[] parsedClass = module.getString("method[%i].class_name", i);
      if (parsedClass != null && reMatch(c, re, parsedClass)) {
        return 1L;
      }
    }
    return 0L;
  }

  // ---------------------------------------------------------------------------------------------
  // Parsing

  private static final class Dex {
    final BinaryReader r;
    final long size;
    final YObject object;

    Dex(BinaryReader r, YObject object) {
      this.r = r;
      this.size = r.size();
      this.object = object;
    }

    /** fits_in_dex: offset and size are treated as unsigned. */
    boolean fits(long offset, long len) {
      return Long.compareUnsigned(len, size) <= 0
          && offset >= 0
          && Long.compareUnsigned(offset, size - len) <= 0;
    }

    long u32(long off) {
      return r.u32(off);
    }

    int u16(long off) {
      return r.u16(off);
    }
  }

  /** Result of read_uleb128_bounded. */
  private static final class Uleb {
    int value;
    long size;
    boolean error;
  }

  private static void readUleb128(Dex dex, long p, Uleb u) {
    long end = dex.size;
    u.error = false;
    int result;
    if (p >= end) {
      u.error = true;
      u.value = 0;
      return;
    }
    result = dex.r.u8(p++);
    u.size++;
    if (result > 0x7f) {
      if (p == end) {
        u.error = true;
        u.value = result;
        return;
      }
      int cur = dex.r.u8(p++);
      u.size++;
      result = (result & 0x7f) | ((cur & 0x7f) << 7);
      if (cur > 0x7f) {
        if (p == end) {
          u.error = true;
          u.value = result;
          return;
        }
        cur = dex.r.u8(p++);
        u.size++;
        result |= (cur & 0x7f) << 14;
        if (cur > 0x7f) {
          if (p == end) {
            u.error = true;
            u.value = result;
            return;
          }
          cur = dex.r.u8(p++);
          u.size++;
          result |= (cur & 0x7f) << 21;
          if (cur > 0x7f) {
            if (p == end) {
              u.error = true;
              u.value = result;
              return;
            }
            cur = dex.r.u8(p);
            u.size++;
            result |= cur << 28;
          }
        }
      }
    }
    u.value = result;
  }

  private static long dexGetInteger(YObject o, String pattern, long index) {
    if (index == YObject.UNDEFINED || index < 0) {
      return YObject.UNDEFINED;
    }
    if (index > 0x80000) {
      return YObject.UNDEFINED;
    }
    return o.getInteger(pattern, (int) index);
  }

  private static byte[] dexGetString(YObject o, String pattern, long index) {
    if (index == YObject.UNDEFINED || index < 0) {
      return null;
    }
    if (index > 0x80000) {
      return null;
    }
    return o.getString(pattern, (int) index);
  }

  private static void parseHeader(Dex dex, YObject o) {
    BinaryReader r = dex.r;
    o.setString(r.bytes(0, 8), "header.magic");
    o.setInteger(r.u32(8), "header.checksum");
    o.setString(r.bytes(12, 20), "header.signature");
    String[] names = {
      "file_size", "header_size", "endian_tag", "link_size", "link_offset", "map_offset",
      "string_ids_size", "string_ids_offset", "type_ids_size", "type_ids_offset",
      "proto_ids_size", "proto_ids_offset", "field_ids_size", "field_ids_offset",
      "method_ids_size", "method_ids_offset", "class_defs_size", "class_defs_offset",
      "data_size", "data_offset"
    };
    for (int i = 0; i < names.length; i++) {
      o.setInteger(r.u32(32 + i * 4L), "header." + names[i]);
    }
  }

  /** Returns the number of bytes consumed, or 0 on error. */
  private static long loadEncodedField(
      Dex dex, long start, long[] previousFieldIdx, int index, int staticField,
      int instanceField) {
    if (!dex.fits(start, 8)) {
      return 0;
    }
    Uleb u = new Uleb();
    readUleb128(dex, start + u.size, u);
    if (u.error) {
      return 0;
    }
    long fieldIdxDiff = u.value & 0xFFFFFFFFL;
    readUleb128(dex, start + u.size, u);
    if (u.error) {
      return 0;
    }
    long accessFlags = u.value & 0xFFFFFFFFL;
    YObject o = dex.object;
    o.setInteger(fieldIdxDiff, "field[%i].field_idx_diff", index);
    o.setInteger(accessFlags, "field[%i].access_flags", index);
    o.setInteger(staticField, "field[%i].static", index);
    o.setInteger(instanceField, "field[%i].instance", index);
    previousFieldIdx[0] = (fieldIdxDiff + previousFieldIdx[0]) & 0xFFFFFFFFL;
    long nameIdx = dexGetInteger(o, "field_ids[%i].name_idx", previousFieldIdx[0]);
    if (nameIdx == YObject.UNDEFINED) {
      return 0;
    }
    byte[] fieldName = dexGetString(o, "string_ids[%i].value", nameIdx);
    if (fieldName != null) {
      o.setString(fieldName, "field[%i].name", index);
    }
    long classIdx = dexGetInteger(o, "field_ids[%i].class_idx", previousFieldIdx[0]);
    long descriptorIdx = dexGetInteger(o, "type_ids[%i].descriptor_idx", classIdx);
    byte[] className = dexGetString(o, "string_ids[%i].value", descriptorIdx);
    if (className != null) {
      o.setString(className, "field[%i].class_name", index);
    }
    // libyara stores these two in ints, truncating undefined values.
    int typeIdx = (int) dexGetInteger(o, "field_ids[%i].type_idx", previousFieldIdx[0]);
    int shortyIdx = (int) dexGetInteger(o, "type_ids[%i].descriptor_idx", typeIdx);
    byte[] protoName = dexGetString(o, "string_ids[%i].value", shortyIdx);
    if (protoName != null) {
      o.setString(protoName, "field[%i].proto", index);
    }
    return u.size;
  }

  private static long loadEncodedMethod(
      Dex dex, long start, long[] previousMethodIdx, int index, int direct, int virtual) {
    if (!dex.fits(start, 12)) {
      return 0;
    }
    Uleb u = new Uleb();
    readUleb128(dex, start + u.size, u);
    if (u.error) {
      return 0;
    }
    long methodIdxDiff = u.value & 0xFFFFFFFFL;
    readUleb128(dex, start + u.size, u);
    if (u.error) {
      return 0;
    }
    long accessFlags = u.value & 0xFFFFFFFFL;
    readUleb128(dex, start + u.size, u);
    if (u.error) {
      return 0;
    }
    long codeOff = u.value & 0xFFFFFFFFL;
    YObject o = dex.object;
    o.setInteger(methodIdxDiff, "method[%i].method_idx_diff", index);
    o.setInteger(accessFlags, "method[%i].access_flags", index);
    o.setInteger(codeOff, "method[%i].code_off", index);
    o.setInteger(direct, "method[%i].direct", index);
    o.setInteger(virtual, "method[%i].virtual", index);
    previousMethodIdx[0] = (methodIdxDiff + previousMethodIdx[0]) & 0xFFFFFFFFL;
    long nameIdx = dexGetInteger(o, "method_ids[%i].name_idx", previousMethodIdx[0]);
    if (nameIdx == YObject.UNDEFINED) {
      return 0;
    }
    byte[] methodName = dexGetString(o, "string_ids[%i].value", nameIdx);
    if (methodName != null) {
      o.setString(methodName, "method[%i].name", index);
    }
    long classIdx = dexGetInteger(o, "method_ids[%i].class_idx", previousMethodIdx[0]);
    long descriptorIdx = dexGetInteger(o, "type_ids[%i].descriptor_idx", classIdx);
    byte[] className = dexGetString(o, "string_ids[%i].value", descriptorIdx);
    if (className != null) {
      o.setString(className, "method[%i].class_name", index);
    }
    long protoIdx = dexGetInteger(o, "method_ids[%i].proto_idx", previousMethodIdx[0]);
    long shortyIdx = dexGetInteger(o, "proto_ids[%i].shorty_idx", protoIdx);
    byte[] protoName = dexGetString(o, "string_ids[%i].value", shortyIdx);
    if (protoName != null) {
      o.setString(protoName, "method[%i].proto", index);
    }
    if (codeOff != 0 && dex.fits(codeOff, CODE_ITEM_SIZE)) {
      o.setInteger(dex.u16(codeOff), "method[%i].code_item.registers_size", index);
      o.setInteger(dex.u16(codeOff + 2), "method[%i].code_item.ins_size", index);
      o.setInteger(dex.u16(codeOff + 4), "method[%i].code_item.outs_size", index);
      o.setInteger(dex.u16(codeOff + 6), "method[%i].code_item.tries_size", index);
      o.setInteger(dex.u32(codeOff + 8), "method[%i].code_item.debug_info_off", index);
      long insnsSize = dex.u32(codeOff + 12);
      o.setInteger(insnsSize, "method[%i].code_item.insns_size", index);
      long insnsLen = (insnsSize * 2) & 0xFFFFFFFFL;
      if (dex.fits(codeOff + CODE_ITEM_SIZE, insnsLen)) {
        o.setString(
            dex.r.bytes(codeOff + CODE_ITEM_SIZE, (int) insnsLen),
            "method[%i].code_item.insns",
            index);
      }
    }
    return u.size;
  }

  private static void parse(Dex dex) {
    YObject o = dex.object;
    if (!dex.fits(0, HEADER_SIZE)) {
      return;
    }
    parseHeader(dex, o);
    long stringIdsSize = dex.u32(56);
    long stringIdsOffset = dex.u32(60);
    long typeIdsSize = dex.u32(64);
    long typeIdsOffset = dex.u32(68);
    long protoIdsSize = dex.u32(72);
    long protoIdsOffset = dex.u32(76);
    long fieldIdsSize = dex.u32(80);
    long fieldIdsOffset = dex.u32(84);
    long methodIdsSize = dex.u32(88);
    long methodIdsOffset = dex.u32(92);
    long classDefsSize = dex.u32(96);
    long classDefsOffset = dex.u32(100);
    long mapOffset = dex.u32(52);

    if (!dex.fits(stringIdsOffset, stringIdsSize * 4)) {
      return;
    }
    for (int i = 0; i < stringIdsSize; i++) {
      long item = stringIdsOffset + i * 4L;
      if (!dex.fits(item, 4)) {
        break;
      }
      long dataOffset = dex.u32(item);
      if (!dex.fits(dataOffset, 4)) {
        continue;
      }
      Uleb u = new Uleb();
      readUleb128(dex, dataOffset, u);
      if (u.error) {
        continue;
      }
      long value = u.value & 0xFFFFFFFFL;
      if (!dex.fits(dataOffset + 1, value)) {
        continue;
      }
      o.setInteger(dataOffset, "string_ids[%i].offset", i);
      o.setInteger(value, "string_ids[%i].size", i);
      o.setString(dex.r.bytes(dataOffset + 1, (int) value), "string_ids[%i].value", i);
    }

    if (!dex.fits(typeIdsOffset, typeIdsSize * 4)) {
      return;
    }
    for (int i = 0; i < typeIdsSize; i++) {
      long item = typeIdsOffset + i * 4L;
      if (!dex.fits(item, 4)) {
        break;
      }
      o.setInteger(dex.u32(item), "type_ids[%i].descriptor_idx", i);
    }

    if (!dex.fits(protoIdsOffset, protoIdsSize * 12)) {
      return;
    }
    for (int i = 0; i < protoIdsSize; i++) {
      long item = protoIdsOffset + i * 12L;
      if (!dex.fits(item, 12)) {
        break;
      }
      o.setInteger(dex.u32(item), "proto_ids[%i].shorty_idx", i);
      o.setInteger(dex.u32(item + 4), "proto_ids[%i].return_type_idx", i);
      o.setInteger(dex.u32(item + 8), "proto_ids[%i].parameters_offset", i);
    }

    if (!dex.fits(fieldIdsOffset, fieldIdsSize * 8)) {
      return;
    }
    for (int i = 0; i < fieldIdsSize; i++) {
      long item = fieldIdsOffset + i * 8L;
      if (!dex.fits(item, 8)) {
        break;
      }
      o.setInteger(dex.u16(item), "field_ids[%i].class_idx", i);
      o.setInteger(dex.u16(item + 2), "field_ids[%i].type_idx", i);
      o.setInteger(dex.u32(item + 4), "field_ids[%i].name_idx", i);
    }

    if (!dex.fits(methodIdsOffset, methodIdsSize * 8)) {
      return;
    }
    for (int i = 0; i < methodIdsSize; i++) {
      long item = methodIdsOffset + i * 8L;
      if (!dex.fits(item, 8)) {
        break;
      }
      o.setInteger(dex.u16(item), "method_ids[%i].class_idx", i);
      o.setInteger(dex.u16(item + 2), "method_ids[%i].proto_idx", i);
      o.setInteger(dex.u32(item + 4), "method_ids[%i].name_idx", i);
    }

    if (mapOffset != 0 && dex.fits(mapOffset, 4)) {
      long mapListSize = dex.u32(mapOffset);
      o.setInteger(mapListSize, "map_list.size");
      if (!dex.fits(mapOffset, 4 + mapListSize * 12)) {
        return;
      }
      for (int i = 0; i < mapListSize; i++) {
        long item = mapOffset + 4 + i * 12L;
        if (!dex.fits(item, 12)) {
          return;
        }
        o.setInteger(dex.u16(item), "map_list.map_item[%i].type", i);
        o.setInteger(dex.u16(item + 2), "map_list.map_item[%i].unused", i);
        o.setInteger(dex.u32(item + 4), "map_list.map_item[%i].size", i);
        o.setInteger(dex.u32(item + 8), "map_list.map_item[%i].offset", i);
      }
    }

    int indexClassDataItem = 0;
    int indexEncodedMethod = 0;
    int indexEncodedField = 0;
    {
      if (!dex.fits(classDefsOffset, classDefsSize * 32)) {
        return;
      }
      for (int i = 0; i < classDefsSize; i++) {
        long item = classDefsOffset + i * 32L;
        if (!dex.fits(item, 32)) {
          break;
        }
        o.setInteger(dex.u32(item), "class_defs[%i].class_idx", i);
        o.setInteger(dex.u32(item + 4), "class_defs[%i].access_flags", i);
        o.setInteger(dex.u32(item + 8), "class_defs[%i].super_class_idx", i);
        o.setInteger(dex.u32(item + 12), "class_defs[%i].interfaces_offset", i);
        o.setInteger(dex.u32(item + 16), "class_defs[%i].source_file_idx", i);
        o.setInteger(dex.u32(item + 20), "class_defs[%i].annotations_offset", i);
        long classDataOffset = dex.u32(item + 24);
        o.setInteger(classDataOffset, "class_defs[%i].class_data_offset", i);
        o.setInteger(dex.u32(item + 28), "class_defs[%i].static_values_offset", i);
        if (classDataOffset == 0) {
          continue;
        }
        if (!dex.fits(classDataOffset, 16)) {
          return;
        }
        Uleb u = new Uleb();
        readUleb128(dex, classDataOffset, u);
        if (u.error) {
          return;
        }
        long staticFieldsSize = u.value & 0xFFFFFFFFL;
        readUleb128(dex, classDataOffset + u.size, u);
        if (u.error) {
          return;
        }
        long instanceFieldsSize = u.value & 0xFFFFFFFFL;
        readUleb128(dex, classDataOffset + u.size, u);
        if (u.error) {
          return;
        }
        long directMethodsSize = u.value & 0xFFFFFFFFL;
        readUleb128(dex, classDataOffset + u.size, u);
        if (u.error) {
          return;
        }
        long virtualMethodsSize = u.value & 0xFFFFFFFFL;
        long ulebSize = u.size;
        o.setInteger(
            staticFieldsSize, "class_data_item[%i].static_fields_size", indexClassDataItem);
        o.setInteger(
            instanceFieldsSize, "class_data_item[%i].instance_fields_size", indexClassDataItem);
        o.setInteger(
            directMethodsSize, "class_data_item[%i].direct_methods_size", indexClassDataItem);
        o.setInteger(
            virtualMethodsSize, "class_data_item[%i].virtual_methods_size", indexClassDataItem);
        long[] previous = {0};
        for (long j = 0; j < staticFieldsSize; j++) {
          long n =
              loadEncodedField(
                  dex, classDataOffset + ulebSize, previous, indexEncodedField, 1, 0);
          if (n == 0) {
            break;
          }
          ulebSize += n;
          indexEncodedField++;
        }
        previous[0] = 0;
        for (long j = 0; j < instanceFieldsSize; j++) {
          long n =
              loadEncodedField(
                  dex, classDataOffset + ulebSize, previous, indexEncodedField, 0, 1);
          if (n == 0) {
            break;
          }
          ulebSize += n;
          indexEncodedField++;
        }
        previous[0] = 0;
        for (long j = 0; j < directMethodsSize; j++) {
          long n =
              loadEncodedMethod(
                  dex, classDataOffset + ulebSize, previous, indexEncodedMethod, 1, 0);
          if (n == 0) {
            break;
          }
          ulebSize += n;
          indexEncodedMethod++;
        }
        previous[0] = 0;
        for (long j = 0; j < virtualMethodsSize; j++) {
          long n =
              loadEncodedMethod(
                  dex, classDataOffset + ulebSize, previous, indexEncodedMethod, 0, 1);
          if (n == 0) {
            break;
          }
          ulebSize += n;
          indexEncodedMethod++;
        }
        indexClassDataItem++;
      }
      o.setInteger(indexEncodedMethod, "number_of_methods");
      o.setInteger(indexEncodedField, "number_of_fields");
    }
  }

  // ---------------------------------------------------------------------------------------------

  @Override
  public void declare(ModuleDeclarations d) {
    for (String m : new String[] {"035", "036", "037", "038", "039"}) {
      d.declareString("DEX_FILE_MAGIC_" + m);
    }
    for (String n :
        new String[] {"ENDIAN_CONSTANT", "REVERSE_ENDIAN_CONSTANT", "NO_INDEX", "ACC_PUBLIC",
          "ACC_PRIVATE", "ACC_PROTECTED", "ACC_STATIC", "ACC_FINAL", "ACC_SYNCHRONIZED",
          "ACC_VOLATILE", "ACC_BRIDGE", "ACC_TRANSIENT", "ACC_VARARGS", "ACC_NATIVE",
          "ACC_INTERFACE", "ACC_ABSTRACT", "ACC_STRICT", "ACC_SYNTHETIC", "ACC_ANNOTATION",
          "ACC_ENUM", "ACC_CONSTRUCTOR", "ACC_DECLARED_SYNCHRONIZED", "TYPE_HEADER_ITEM",
          "TYPE_STRING_ID_ITEM", "TYPE_TYPE_ID_ITEM", "TYPE_PROTO_ID_ITEM", "TYPE_FIELD_ID_ITEM",
          "TYPE_METHOD_ID_ITEM", "TYPE_CLASS_DEF_ITEM", "TYPE_CALL_SITE_ID_ITEM",
          "TYPE_METHOD_HANDLE_ITEM", "TYPE_MAP_LIST", "TYPE_TYPE_LIST",
          "TYPE_ANNOTATION_SET_REF_LIST", "TYPE_ANNOTATION_SET_ITEM", "TYPE_CLASS_DATA_ITEM",
          "TYPE_CODE_ITEM", "TYPE_STRING_DATA_ITEM", "TYPE_DEBUG_INFO_ITEM",
          "TYPE_ANNOTATION_ITEM", "TYPE_ENCODED_ARRAY_ITEM", "TYPE_ANNOTATIONS_DIRECTORY_ITEM"}) {
      d.declareInteger(n);
    }
    d.beginStruct("header")
        .declareString("magic")
        .declareInteger("checksum")
        .declareString("signature");
    for (String n :
        new String[] {"file_size", "header_size", "endian_tag", "link_size", "link_offset",
          "map_offset", "string_ids_size", "string_ids_offset", "type_ids_size",
          "type_ids_offset", "proto_ids_size", "proto_ids_offset", "field_ids_size",
          "field_ids_offset", "method_ids_size", "method_ids_offset", "class_defs_size",
          "class_defs_offset", "data_size", "data_offset"}) {
      d.declareInteger(n);
    }
    d.endStruct("header");
    d.beginStructArray("string_ids")
        .declareInteger("offset")
        .declareInteger("size")
        .declareString("value")
        .endStructArray("string_ids");
    d.beginStructArray("type_ids").declareInteger("descriptor_idx").endStructArray("type_ids");
    d.beginStructArray("proto_ids")
        .declareInteger("shorty_idx")
        .declareInteger("return_type_idx")
        .declareInteger("parameters_offset")
        .endStructArray("proto_ids");
    d.beginStructArray("field_ids")
        .declareInteger("class_idx")
        .declareInteger("type_idx")
        .declareInteger("name_idx")
        .endStructArray("field_ids");
    d.beginStructArray("method_ids")
        .declareInteger("class_idx")
        .declareInteger("proto_idx")
        .declareInteger("name_idx")
        .endStructArray("method_ids");
    d.beginStructArray("class_defs");
    for (String n :
        new String[] {"class_idx", "access_flags", "super_class_idx", "interfaces_offset",
          "source_file_idx", "annotations_offset", "class_data_offset", "static_values_offset"}) {
      d.declareInteger(n);
    }
    d.endStructArray("class_defs");
    d.beginStructArray("class_data_item")
        .declareInteger("static_fields_size")
        .declareInteger("instance_fields_size")
        .declareInteger("direct_methods_size")
        .declareInteger("virtual_methods_size")
        .endStructArray("class_data_item");
    d.beginStruct("map_list").declareInteger("size");
    d.beginStructArray("map_item")
        .declareInteger("type")
        .declareInteger("unused")
        .declareInteger("size")
        .declareInteger("offset")
        .endStructArray("map_item");
    d.endStruct("map_list");
    d.declareInteger("number_of_fields");
    d.beginStructArray("field")
        .declareString("class_name")
        .declareString("name")
        .declareString("proto")
        .declareInteger("static")
        .declareInteger("instance")
        .declareInteger("field_idx_diff")
        .declareInteger("access_flags")
        .endStructArray("field");
    d.declareFunction("has_method", "s", "i", DexModule::hasMethodString);
    d.declareFunction("has_method", "ss", "i", DexModule::hasMethodAndClassString);
    d.declareFunction("has_method", "r", "i", DexModule::hasMethodRegexp);
    d.declareFunction("has_method", "rr", "i", DexModule::hasMethodAndClassRegexp);
    d.declareFunction("has_class", "s", "i", DexModule::hasClassString);
    d.declareFunction("has_class", "r", "i", DexModule::hasClassRegexp);
    d.declareInteger("number_of_methods");
    d.beginStructArray("method")
        .declareString("class_name")
        .declareString("name")
        .declareString("proto")
        .declareInteger("direct")
        .declareInteger("virtual")
        .declareInteger("method_idx_diff")
        .declareInteger("access_flags")
        .declareInteger("code_off");
    d.beginStruct("code_item")
        .declareInteger("registers_size")
        .declareInteger("ins_size")
        .declareInteger("outs_size")
        .declareInteger("tries_size")
        .declareInteger("debug_info_off")
        .declareInteger("insns_size")
        .declareString("insns")
        .endStruct("code_item");
    d.endStructArray("method");
  }

  private static final Object[][] CONSTANTS = {
    {"ENDIAN_CONSTANT", 0x12345678L}, {"REVERSE_ENDIAN_CONSTANT", 0x78563412L},
    {"NO_INDEX", 0xffffffffL}, {"ACC_PUBLIC", 0x1L}, {"ACC_PRIVATE", 0x2L},
    {"ACC_PROTECTED", 0x4L}, {"ACC_STATIC", 0x8L}, {"ACC_FINAL", 0x10L},
    {"ACC_SYNCHRONIZED", 0x20L}, {"ACC_VOLATILE", 0x40L}, {"ACC_BRIDGE", 0x40L},
    {"ACC_TRANSIENT", 0x80L}, {"ACC_VARARGS", 0x80L}, {"ACC_NATIVE", 0x100L},
    {"ACC_INTERFACE", 0x200L}, {"ACC_ABSTRACT", 0x400L}, {"ACC_STRICT", 0x800L},
    {"ACC_SYNTHETIC", 0x1000L}, {"ACC_ANNOTATION", 0x2000L}, {"ACC_ENUM", 0x4000L},
    {"ACC_CONSTRUCTOR", 0x10000L}, {"ACC_DECLARED_SYNCHRONIZED", 0x20000L},
    {"TYPE_HEADER_ITEM", 0x0000L}, {"TYPE_STRING_ID_ITEM", 0x0001L},
    {"TYPE_TYPE_ID_ITEM", 0x0002L}, {"TYPE_PROTO_ID_ITEM", 0x0003L},
    {"TYPE_FIELD_ID_ITEM", 0x0004L}, {"TYPE_METHOD_ID_ITEM", 0x0005L},
    {"TYPE_CLASS_DEF_ITEM", 0x0006L}, {"TYPE_CALL_SITE_ID_ITEM", 0x0007L},
    {"TYPE_METHOD_HANDLE_ITEM", 0x0008L}, {"TYPE_MAP_LIST", 0x1000L},
    {"TYPE_TYPE_LIST", 0x1001L}, {"TYPE_ANNOTATION_SET_REF_LIST", 0x1002L},
    {"TYPE_ANNOTATION_SET_ITEM", 0x1003L}, {"TYPE_CLASS_DATA_ITEM", 0x2000L},
    {"TYPE_CODE_ITEM", 0x2001L}, {"TYPE_STRING_DATA_ITEM", 0x2002L},
    {"TYPE_DEBUG_INFO_ITEM", 0x2003L}, {"TYPE_ANNOTATION_ITEM", 0x2004L},
    {"TYPE_ENCODED_ARRAY_ITEM", 0x2005L}, {"TYPE_ANNOTATIONS_DIRECTORY_ITEM", 0x2006L},
  };

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {
    for (String m : MAGICS) {
      module.setString(m.getBytes(StandardCharsets.ISO_8859_1), "DEX_FILE_MAGIC_" + m.substring(4, 7));
    }
    for (Object[] c : CONSTANTS) {
      module.setInteger((Long) c[1], (String) c[0]);
    }
    for (MemoryBlock block : context.blocks()) {
      BinaryReader r = new BinaryReader(block.data());
      if (r.size() < HEADER_SIZE) {
        continue;
      }
      byte[] magic = r.bytes(0, 8);
      boolean valid = false;
      for (String m : MAGICS) {
        if (java.util.Arrays.equals(magic, m.getBytes(StandardCharsets.ISO_8859_1))) {
          valid = true;
          break;
        }
      }
      if (valid) {
        parse(new Dex(r, module));
        break;
      }
    }
  }
}
