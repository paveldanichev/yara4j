package com.paveldan.yara4j.modules.dotnet;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.modules.pe.PeModule;
import com.paveldan.yara4j.modules.pe.PeModule.Pe;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BinaryReader;

/** The "dotnet" module. Port of libyara/modules/dotnet/dotnet.c. */
public final class DotnetModule implements YaraModule {

  static final int IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;
  static final long NET_METADATA_MAGIC = 0x424a5342L;
  static final int DOTNET_STREAM_NAME_SIZE = 32;
  static final int HEAP_EXTRA_DATA = 0x40;
  static final int SIG_FLAG_GENERIC = 0x10;

  static final int SIZEOF_CLI_HEADER = 72;
  static final int SIZEOF_NET_METADATA = 16;
  static final int SIZEOF_STREAM_HEADER = 8;
  static final int SIZEOF_TILDE_HEADER = 24;
  static final int SIZEOF_MODULE_TABLE = 18;
  static final int SIZEOF_MODULEREF_TABLE = 4;
  static final int SIZEOF_FIELDRVA_TABLE = 8;

  static final int BIT_MODULE = 0x00;
  static final int BIT_TYPEREF = 0x01;
  static final int BIT_TYPEDEF = 0x02;
  static final int BIT_FIELDPTR = 0x03;
  static final int BIT_FIELD = 0x04;
  static final int BIT_METHODDEFPTR = 0x05;
  static final int BIT_METHODDEF = 0x06;
  static final int BIT_PARAM = 0x08;
  static final int BIT_INTERFACEIMPL = 0x09;
  static final int BIT_MEMBERREF = 0x0A;
  static final int BIT_CONSTANT = 0x0B;
  static final int BIT_CUSTOMATTRIBUTE = 0x0C;
  static final int BIT_FIELDMARSHAL = 0x0D;
  static final int BIT_DECLSECURITY = 0x0E;
  static final int BIT_CLASSLAYOUT = 0x0F;
  static final int BIT_FIELDLAYOUT = 0x10;
  static final int BIT_STANDALONESIG = 0x11;
  static final int BIT_EVENTMAP = 0x12;
  static final int BIT_EVENTPTR = 0x13;
  static final int BIT_EVENT = 0x14;
  static final int BIT_PROPERTYMAP = 0x15;
  static final int BIT_PROPERTYPTR = 0x16;
  static final int BIT_PROPERTY = 0x17;
  static final int BIT_METHODSEMANTICS = 0x18;
  static final int BIT_METHODIMPL = 0x19;
  static final int BIT_MODULEREF = 0x1A;
  static final int BIT_TYPESPEC = 0x1B;
  static final int BIT_IMPLMAP = 0x1C;
  static final int BIT_FIELDRVA = 0x1D;
  static final int BIT_ENCLOG = 0x1E;
  static final int BIT_ENCMAP = 0x1F;
  static final int BIT_ASSEMBLY = 0x20;
  static final int BIT_ASSEMBLYPROCESSOR = 0x21;
  static final int BIT_ASSEMBLYOS = 0x22;
  static final int BIT_ASSEMBLYREF = 0x23;
  static final int BIT_ASSEMBLYREFPROCESSOR = 0x24;
  static final int BIT_ASSEMBLYREFOS = 0x25;
  static final int BIT_FILE = 0x26;
  static final int BIT_EXPORTEDTYPE = 0x27;
  static final int BIT_MANIFESTRESOURCE = 0x28;
  static final int BIT_NESTEDCLASS = 0x29;
  static final int BIT_GENERICPARAM = 0x2A;
  static final int BIT_METHODSPEC = 0x2B;
  static final int BIT_GENERICPARAMCONSTRAINT = 0x2C;

  static final int MAX_TYPELIB_SIZE = 0xFF;

  static final int TYPE_ATTR_CLASS_SEMANTIC_MASK = 0x20;
  static final int TYPE_ATTR_CLASS = 0x0;
  static final int TYPE_ATTR_INTERFACE = 0x20;
  static final int TYPE_ATTR_VISIBILITY_MASK = 0x7;
  static final int TYPE_ATTR_NOT_PUBLIC = 0x0;
  static final int TYPE_ATTR_PUBLIC = 0x1;
  static final int TYPE_ATTR_NESTED_PUBLIC = 0x2;
  static final int TYPE_ATTR_NESTED_PRIVATE = 0x3;
  static final int TYPE_ATTR_NESTED_FAMILY = 0x4;
  static final int TYPE_ATTR_NESTED_ASSEMBLY = 0x5;
  static final int TYPE_ATTR_NESTED_FAM_AND_ASSEM = 0x6;
  static final int TYPE_ATTR_NESTED_FAM_OR_ASSEM = 0x7;
  static final int TYPE_ATTR_ABSTRACT = 0x80;
  static final int TYPE_ATTR_SEALED = 0x100;

  static final int METHOD_ATTR_ACCESS_MASK = 0x7;
  static final int METHOD_ATTR_PRIVATE = 0x1;
  static final int METHOD_ATTR_FAM_AND_ASSEM = 0x2;
  static final int METHOD_ATTR_ASSEM = 0x3;
  static final int METHOD_ATTR_FAMILY = 0x4;
  static final int METHOD_ATTR_FAM_OR_ASSEM = 0x5;
  static final int METHOD_ATTR_PUBLIC = 0x6;
  static final int METHOD_ATTR_STATIC = 0x10;
  static final int METHOD_ATTR_FINAL = 0x20;
  static final int METHOD_ATTR_VIRTUAL = 0x40;
  static final int METHOD_ATTR_ABSTRACT = 0x400;

  static final int TYPE_VOID = 0x1;
  static final int TYPE_BOOL = 0x2;
  static final int TYPE_CHAR = 0x3;
  static final int TYPE_I1 = 0x4;
  static final int TYPE_U1 = 0x5;
  static final int TYPE_I2 = 0x6;
  static final int TYPE_U2 = 0x7;
  static final int TYPE_I4 = 0x8;
  static final int TYPE_U4 = 0x9;
  static final int TYPE_I8 = 0xa;
  static final int TYPE_U8 = 0xb;
  static final int TYPE_R4 = 0xc;
  static final int TYPE_R8 = 0xd;
  static final int TYPE_STRING = 0xe;
  static final int TYPE_PTR = 0xf;
  static final int TYPE_BYREF = 0x10;
  static final int TYPE_VALUETYPE = 0x11;
  static final int TYPE_CLASS = 0x12;
  static final int TYPE_VAR = 0x13;
  static final int TYPE_ARRAY = 0x14;
  static final int TYPE_GENERICINST = 0x15;
  static final int TYPE_TYPEDREF = 0x16;
  static final int TYPE_I = 0x18;
  static final int TYPE_U = 0x19;
  static final int TYPE_FNPTR = 0x1b;
  static final int TYPE_OBJECT = 0x1c;
  static final int TYPE_SZARRAY = 0x1d;
  static final int TYPE_MVAR = 0x1e;
  static final int TYPE_CMOD_REQD = 0x1f;
  static final int TYPE_CMOD_OPT = 0x20;

  static final int MAX_ARRAY_RANK = 50;
  static final int MAX_PARAM_COUNT = 2000;
  static final int MAX_GEN_PARAM_COUNT = 1000;
  static final int MAX_METHOD_COUNT = 20000;
  static final int MAX_TYPE_DEPTH = 0x10;
  static final int MAX_NAMESPACE_DEPTH = 0x0a;

  /** NULL pointer in the C code. */
  static final long NULL = Long.MIN_VALUE;

  // ---------------------------------------------------------------------------------------------
  // Data access helpers. Reads beyond the data return 0 instead of failing; the C code performs
  // the corresponding bounds checks before every read that matters.

  private static final class Data {
    final Pe pe;
    final BinaryReader r;
    final long size;
    final YStructure object;

    Data(Pe pe, YStructure object) {
      this.pe = pe;
      this.r = pe.r;
      this.size = pe.size;
      this.object = object;
    }

    boolean fits(long ptr, long len) {
      return ptr != NULL && pe.fits(ptr, len);
    }

    int u8(long o) {
      return o >= 0 && o < size ? r.u8(o) : 0;
    }

    int u16(long o) {
      return u8(o) | u8(o + 1) << 8;
    }

    long u32(long o) {
      return (u16(o) & 0xFFFFL) | (u16(o + 2) & 0xFFFFL) << 16;
    }

    long index(long o, int len) {
      return len == 2 ? u16(o) : u32(o);
    }

    /** pe_get_dotnet_string: the string or null. */
    String dotnetString(long heapOffset, long heapSize, long index) {
      long start = heapOffset + index;
      if (!(start >= 0 && start < size && index < heapSize)) {
        return null;
      }
      long remaining = size - start;
      long eos = -1;
      for (long p = start; p < start + remaining; p++) {
        if (r.u8(p) == 0) {
          eos = p;
          break;
        }
        if (p - start > 1024) {
          return null;
        }
      }
      if (eos < 0 || eos - start > 1024) {
        return null;
      }
      return new String(r.bytes(start, (int) (eos - start)), StandardCharsets.ISO_8859_1);
    }

    /** dotnet_parse_blob_entry: {size, length}. */
    long[] blobEntry(long offset) {
      long[] result = {0, 0};
      if (!fits(offset, 1)) {
        return result;
      }
      int b = u8(offset);
      if ((b & 0x80) == 0x00) {
        result[1] = b;
        result[0] = 1;
      } else if ((b & 0xC0) == 0x80) {
        if (!fits(offset, 2)) {
          return result;
        }
        result[1] = ((b & 0x3F) << 8) | u8(offset + 1);
        result[0] = 2;
      } else if (offset + 4 < size && (b & 0xE0) == 0xC0) {
        if (!fits(offset, 4)) {
          return result;
        }
        result[1] =
            ((long) (b & 0x1F) << 24) | (u8(offset + 1) << 16) | (u8(offset + 2) << 8)
                | u8(offset + 3);
        result[0] = 4;
      } else {
        return result;
      }
      if (!fits(offset, result[0] + result[1])) {
        result[0] = 0;
        return result;
      }
      return result;
    }
  }

  private static final class TableInfo {
    long offset = NULL;
    long rowCount;
    long rowSize;

    /** get_table_offset. */
    long row(long index) {
      if (index < 1 || index > rowCount) {
        return NULL;
      }
      return offset + rowSize * (index - 1);
    }

    void set(long offset, long rowCount, long rowSize) {
      this.offset = offset;
      this.rowCount = rowCount;
      this.rowSize = rowSize;
    }
  }

  private static final class Tables {
    final TableInfo typedef = new TableInfo();
    final TableInfo typespec = new TableInfo();
    final TableInfo typeref = new TableInfo();
    final TableInfo methoddef = new TableInfo();
    final TableInfo param = new TableInfo();
    final TableInfo module = new TableInfo();
    final TableInfo moduleref = new TableInfo();
    final TableInfo assemblyref = new TableInfo();
    final TableInfo interfaceimpl = new TableInfo();
    final TableInfo genericparam = new TableInfo();
    final TableInfo nestedclass = new TableInfo();
  }

  private static final class Rows {
    long module;
    long moduleref;
    long assemblyref;
    long typeref;
    long methoddef;
    long memberref;
    long typedef;
    long typespec;
    long field;
    long param;
    long property;
    long interfaceimpl;
    long event;
    long standalonesig;
    long assembly;
    long file;
    long exportedtype;
    long manifestresource;
    long genericparam;
    long genericparamconstraint;
    long methodspec;
    long assemblyrefprocessor;
  }

  private static final class IndexSizes {
    int string = 2;
    int guid = 2;
    int blob = 2;
    int field = 2;
    int methoddef = 2;
    int methodspec = 2;
    int memberref = 2;
    int param = 2;
    int event = 2;
    int typedef = 2;
    int typeref = 2;
    int typespec = 2;
    int interfaceimpl = 2;
    int property = 2;
    int moduleref = 2;
    int module = 2;
    int assemblyrefprocessor = 2;
    int assemblyref = 2;
    int assembly = 2;
    int genericparam = 2;
  }

  private static final class Ctx {
    Data d;
    Tables tables;
    IndexSizes indexSizes;
    long strHeap;
    long strSize;
    long blobHeap;
    long blobSize;
  }

  private static long maxRows(long... rows) {
    long biggest = 0;
    for (int i = 0; i < rows.length; i++) {
      if (i == 0 || rows[i] > biggest) {
        biggest = rows[i];
      }
    }
    return biggest;
  }

  // ---------------------------------------------------------------------------------------------
  // Row readers

  private static final class TypedefRow {
    long flags;
    long name;
    long namespace;
    long extends_;
    long field;
    long method;
  }

  private static TypedefRow readTypedef(Ctx ctx, long data) {
    if (!ctx.d.fits(data, ctx.tables.typedef.rowSize)) {
      return null;
    }
    int extSize = 2;
    long rowCount =
        maxRows(ctx.tables.typedef.rowCount, ctx.tables.typeref.rowCount,
            ctx.tables.typespec.rowCount);
    if (rowCount > (0xFFFF >> 0x02)) {
      extSize = 4;
    }
    TypedefRow r = new TypedefRow();
    long p = data;
    r.flags = ctx.d.u32(p);
    p += 4;
    r.name = ctx.d.index(p, ctx.indexSizes.string);
    p += ctx.indexSizes.string;
    r.namespace = ctx.d.index(p, ctx.indexSizes.string);
    p += ctx.indexSizes.string;
    r.extends_ = ctx.d.index(p, extSize);
    p += extSize;
    r.field = ctx.d.index(p, ctx.indexSizes.field);
    p += ctx.indexSizes.field;
    r.method = ctx.d.index(p, ctx.indexSizes.methoddef);
    return r;
  }

  private static long[] readTyperef(Ctx ctx, long data) {
    if (!ctx.d.fits(data, ctx.tables.typeref.rowSize)) {
      return null;
    }
    // The resolution scope index size is computed but only the name and namespace are used.
    long rowCount =
        maxRows(ctx.tables.module.rowCount, ctx.tables.moduleref.rowCount,
            ctx.tables.assemblyref.rowCount, ctx.tables.typeref.rowCount);
    int resSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
    long p = data + resSize;
    long name = ctx.d.index(p, ctx.indexSizes.string);
    p += ctx.indexSizes.string;
    long namespace = ctx.d.index(p, ctx.indexSizes.string);
    return new long[] {name, namespace};
  }

  private static long[] readInterfaceimpl(Ctx ctx, long data) {
    if (!ctx.d.fits(data, ctx.tables.interfaceimpl.rowSize)) {
      return null;
    }
    long rowCount =
        maxRows(ctx.tables.typedef.rowCount, ctx.tables.typeref.rowCount,
            ctx.tables.typespec.rowCount);
    int interfaceSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
    long cls = ctx.d.index(data, ctx.indexSizes.typedef);
    long itf = ctx.d.index(data + ctx.indexSizes.typedef, interfaceSize);
    return new long[] {cls, itf};
  }

  private static final class MethoddefRow {
    int flags;
    long name;
    long signature;
    long paramList;
  }

  private static MethoddefRow readMethoddef(Ctx ctx, long data) {
    if (!ctx.d.fits(data, ctx.tables.methoddef.rowSize)) {
      return null;
    }
    MethoddefRow r = new MethoddefRow();
    long p = data + 4 + 2;
    r.flags = ctx.d.u16(p);
    p += 2;
    r.name = ctx.d.index(p, ctx.indexSizes.string);
    p += ctx.indexSizes.string;
    r.signature = ctx.d.index(p, ctx.indexSizes.blob);
    p += ctx.indexSizes.blob;
    r.paramList = ctx.d.index(p, ctx.indexSizes.param);
    return r;
  }

  /** Returns the param name index, or -1 if the row doesn't fit. */
  private static long readParamName(Ctx ctx, long data) {
    if (!ctx.d.fits(data, ctx.tables.param.rowSize)) {
      return -1;
    }
    return ctx.d.index(data + 4, ctx.indexSizes.string);
  }

  /** {owner, name} or null. */
  private static long[] readGenericparam(Ctx ctx, long data) {
    if (!ctx.d.fits(data, ctx.tables.genericparam.rowSize)) {
      return null;
    }
    long rowCount = maxRows(ctx.tables.typedef.rowCount, ctx.tables.methoddef.rowCount);
    int ownerSize = rowCount > (0xFFFF >> 0x01) ? 4 : 2;
    long owner = ctx.d.index(data + 4, ownerSize);
    long name = ctx.d.index(data + 4 + ownerSize, ctx.indexSizes.string);
    return new long[] {owner, name};
  }

  private static long readTypespec(Ctx ctx, long data) {
    if (!ctx.d.fits(data, ctx.tables.typespec.rowSize)) {
      return -1;
    }
    return ctx.d.index(data, ctx.indexSizes.blob);
  }

  private static long[] readNestedclass(Ctx ctx, long data) {
    if (!ctx.d.fits(data, ctx.tables.nestedclass.rowSize)) {
      return null;
    }
    long nested = ctx.d.index(data, ctx.indexSizes.typedef);
    long enclosing = ctx.d.index(data + ctx.indexSizes.typedef, ctx.indexSizes.typedef);
    return new long[] {nested, enclosing};
  }

  // ---------------------------------------------------------------------------------------------
  // Blob signatures

  /** A cursor over signature data (the data pointer and remaining length in the C code). */
  private static final class Sig {
    long data;
    long len;

    Sig(long data, long len) {
      this.data = data;
      this.len = len;
    }
  }

  private static long readBlobUnsigned(Data d, Sig s) {
    if (s.len < 1) {
      return 0;
    }
    int first = d.u8(s.data);
    if ((first & 0x80) == 0) {
      s.data += 1;
      s.len -= 1;
      return first;
    }
    if (s.len < 2) {
      return 0;
    }
    if ((first & 0xC0) == 0x80) {
      long result = (d.u8(s.data) << 8) | d.u8(s.data + 1);
      s.data += 2;
      s.len -= 2;
      return result & 0x3FFF;
    }
    if (s.len < 4) {
      return 0;
    }
    if ((first & 0xE0) == 0xC0) {
      long result =
          ((long) d.u8(s.data) << 24) | (d.u8(s.data + 1) << 16) | (d.u8(s.data + 2) << 8)
              | d.u8(s.data + 3);
      s.data += 4;
      s.len -= 4;
      return result & 0x1FFFFFFF;
    }
    return 0;
  }

  private static int readBlobSigned(Data d, Sig s) {
    if (s.len < 1) {
      return 0;
    }
    byte first = (byte) d.u8(s.data);
    if ((first & 0x80) == 0) {
      byte tmp = (byte) (first >> 1);
      if ((first & 0x1) != 0) {
        tmp |= (byte) 0xC0;
      }
      s.data += 1;
      s.len -= 1;
      return tmp;
    }
    if (s.len < 2) {
      return 0;
    }
    if ((first & 0xC0) == 0x80) {
      int tmp1 = (d.u8(s.data) << 8) | d.u8(s.data + 1);
      short tmp2 = (short) ((tmp1 >> 1) & 0x3FFF);
      if ((tmp1 & 0x1) != 0) {
        tmp2 |= (short) 0xE000;
      }
      s.data += 2;
      s.len -= 2;
      return tmp2;
    }
    if (s.len < 4) {
      return 0;
    }
    if ((first & 0xE0) == 0xC0) {
      long tmp1 =
          ((long) d.u8(s.data) << 24) | (d.u8(s.data + 1) << 16) | (d.u8(s.data + 2) << 8)
              | d.u8(s.data + 3);
      int tmp2 = (int) ((tmp1 >> 1) & 0x1FFFFFFF);
      if ((tmp1 & 0x1) != 0) {
        tmp2 |= 0xF0000000;
      }
      s.data += 4;
      s.len -= 4;
      return tmp2;
    }
    return 0;
  }

  private static String cut(String s) {
    int end = s.indexOf('`');
    return end >= 0 ? s.substring(0, end) : s;
  }

  /** create_full_name(name, namespace). */
  static String createFullName(String name, String namespace) {
    if (name == null || name.isEmpty()) {
      return namespace;
    }
    if (namespace == null || namespace.isEmpty()) {
      return cut(name);
    }
    return cut(namespace + "." + name);
  }

  private static String getTypeDefOrRefFullname(
      Ctx ctx, long codedIndex, List<String> classGenParams, List<String> methodGenParams,
      int depth) {
    long index = codedIndex >>> 2;
    if (index == 0) {
      return null;
    }
    int table = (int) (codedIndex & 0x3);
    if (table == 0) {
      long data = ctx.tables.typedef.row(index);
      if (data == NULL) {
        return null;
      }
      TypedefRow row = readTypedef(ctx, data);
      if (row != null) {
        String name = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, row.name);
        String namespace = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, row.namespace);
        if (isNested(row.flags)) {
          String nestedNamespace = parseEnclosingTypes(ctx, index, 1);
          String tmp = createFullName(namespace, nestedNamespace);
          return createFullName(name, tmp);
        }
        return createFullName(name, namespace);
      }
    } else if (table == 1) {
      long data = ctx.tables.typeref.row(index);
      if (data == NULL) {
        return null;
      }
      long[] row = readTyperef(ctx, data);
      if (row != null) {
        String name = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, row[0]);
        String namespace = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, row[1]);
        return createFullName(name, namespace);
      }
    } else if (table == 2) {
      long data = ctx.tables.typespec.row(index);
      if (data == NULL) {
        return null;
      }
      long signature = readTypespec(ctx, data);
      if (signature >= 0 && signature < ctx.blobSize) {
        long sigData = ctx.blobHeap + signature;
        long[] blob = ctx.d.blobEntry(sigData);
        sigData += blob[0];
        if (blob[0] != 0) {
          return parseSignatureType(
              ctx, new Sig(sigData, blob[1]), classGenParams, null, depth);
        }
      }
    }
    return null;
  }

  private static String parseSignatureType(
      Ctx ctx, Sig s, List<String> classGenParams, List<String> methodGenParams, int depth) {
    Data d = ctx.d;
    if (s.len < 1 || !d.fits(s.data, 1) || depth > MAX_TYPE_DEPTH) {
      return null;
    }
    int type = d.u8(s.data);
    s.data++;
    s.len--;
    String tmp;
    switch (type) {
      case TYPE_VOID:
        return "void";
      case TYPE_BOOL:
        return "bool";
      case TYPE_CHAR:
        return "char";
      case TYPE_I1:
        return "sbyte";
      case TYPE_U1:
        return "byte";
      case TYPE_I2:
        return "short";
      case TYPE_U2:
        return "ushort";
      case TYPE_I4:
        return "int";
      case TYPE_U4:
        return "uint";
      case TYPE_I8:
        return "long";
      case TYPE_U8:
        return "ulong";
      case TYPE_R4:
        return "float";
      case TYPE_R8:
        return "double";
      case TYPE_STRING:
        return "string";
      case TYPE_TYPEDREF:
        return "TypedReference";
      case TYPE_I:
        return "IntPtr";
      case TYPE_U:
        return "UIntPtr";
      case TYPE_PTR:
        tmp = parseSignatureType(ctx, s, classGenParams, methodGenParams, depth + 1);
        return tmp == null ? null : "Ptr<" + tmp + ">";
      case TYPE_BYREF:
        tmp = parseSignatureType(ctx, s, classGenParams, methodGenParams, depth + 1);
        return tmp == null ? null : "ref " + tmp;
      case TYPE_VALUETYPE:
      case TYPE_CLASS:
        {
          long codedIndex = readBlobUnsigned(d, s);
          return getTypeDefOrRefFullname(
              ctx, codedIndex, classGenParams, methodGenParams, depth + 1);
        }
      case TYPE_VAR:
      case TYPE_MVAR:
        {
          long index = readBlobUnsigned(d, s);
          boolean cls = type == TYPE_VAR;
          if (cls && classGenParams != null && index < classGenParams.size()) {
            return classGenParams.get((int) index);
          } else if (!cls && methodGenParams != null && index < methodGenParams.size()) {
            return methodGenParams.get((int) index);
          }
          return null;
        }
      case TYPE_ARRAY:
        {
          tmp = parseSignatureType(ctx, s, classGenParams, methodGenParams, depth + 1);
          if (tmp == null) {
            return null;
          }
          long rank = readBlobUnsigned(d, s);
          if (rank == 0 || rank > MAX_ARRAY_RANK) {
            return null;
          }
          long numSizes = readBlobUnsigned(d, s);
          if (numSizes > rank) {
            return null;
          }
          int[] sizes = new int[(int) numSizes];
          for (int i = 0; i < numSizes; ++i) {
            sizes[i] = (int) readBlobUnsigned(d, s);
          }
          long numLowbounds = readBlobUnsigned(d, s);
          if (numLowbounds > rank) {
            return null;
          }
          int[] loBounds = new int[(int) numLowbounds];
          for (int i = 0; i < numLowbounds; ++i) {
            loBounds[i] = readBlobSigned(d, s);
            if (numSizes > i && loBounds[i] != 0) {
              sizes[i] += loBounds[i] - 1;
            }
          }
          StringBuilder sb = new StringBuilder(tmp).append('[');
          for (int i = 0; i < rank; ++i) {
            if (numSizes > i || numLowbounds > i) {
              if (numLowbounds > i && loBounds[i] != 0) {
                sb.append(loBounds[i]).append("...");
              }
              if (numSizes > i) {
                sb.append(sizes[i]);
              }
            }
            if (i + 1 != rank) {
              sb.append(',');
            }
          }
          return sb.append(']').toString();
        }
      case TYPE_GENERICINST:
        {
          tmp = parseSignatureType(ctx, s, classGenParams, methodGenParams, depth + 1);
          if (tmp == null) {
            return null;
          }
          long genCount = readBlobUnsigned(d, s);
          if (genCount > MAX_GEN_PARAM_COUNT) {
            return null;
          }
          StringBuilder sb = new StringBuilder(tmp).append('<');
          for (int i = 0; i < genCount; i++) {
            String paramType =
                parseSignatureType(ctx, s, classGenParams, methodGenParams, depth + 1);
            if (paramType != null) {
              if (i > 0) {
                sb.append(',');
              }
              sb.append(paramType);
            }
          }
          return sb.append('>').toString();
        }
      case TYPE_FNPTR:
        {
          if (s.len > 0) {
            s.data++;
            s.len--;
            long paramCount = readBlobUnsigned(d, s);
            if (paramCount > MAX_PARAM_COUNT) {
              return null;
            }
            tmp = parseSignatureType(ctx, s, classGenParams, methodGenParams, depth + 1);
            if (tmp == null) {
              return null;
            }
            StringBuilder sb = new StringBuilder("FnPtr<").append(tmp).append('(');
            for (int i = 0; i < paramCount; i++) {
              String paramType =
                  parseSignatureType(ctx, s, classGenParams, methodGenParams, depth + 1);
              if (paramType != null) {
                if (i > 0) {
                  sb.append(", ");
                }
                sb.append(paramType);
              }
            }
            return sb.append(")>").toString();
          }
          return null;
        }
      case TYPE_OBJECT:
        return "object";
      case TYPE_SZARRAY:
        tmp = parseSignatureType(ctx, s, classGenParams, methodGenParams, depth + 1);
        return tmp == null ? null : tmp + "[]";
      case TYPE_CMOD_REQD:
      case TYPE_CMOD_OPT:
        readBlobUnsigned(d, s);
        return parseSignatureType(ctx, s, classGenParams, methodGenParams, depth + 1);
      default:
        return null;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Types

  static boolean isNested(long flags) {
    switch ((int) (flags & TYPE_ATTR_VISIBILITY_MASK)) {
      case TYPE_ATTR_NESTED_PRIVATE:
      case TYPE_ATTR_NESTED_PUBLIC:
      case TYPE_ATTR_NESTED_FAMILY:
      case TYPE_ATTR_NESTED_ASSEMBLY:
      case TYPE_ATTR_NESTED_FAM_AND_ASSEM:
      case TYPE_ATTR_NESTED_FAM_OR_ASSEM:
        return true;
      default:
        return false;
    }
  }

  static String typeVisibility(long flags) {
    switch ((int) (flags & TYPE_ATTR_VISIBILITY_MASK)) {
      case TYPE_ATTR_NESTED_PRIVATE:
        return "private";
      case TYPE_ATTR_PUBLIC:
      case TYPE_ATTR_NESTED_PUBLIC:
        return "public";
      case TYPE_ATTR_NESTED_FAMILY:
        return "protected";
      case TYPE_ATTR_NOT_PUBLIC:
      case TYPE_ATTR_NESTED_ASSEMBLY:
        return "internal";
      case TYPE_ATTR_NESTED_FAM_AND_ASSEM:
        return "private protected";
      case TYPE_ATTR_NESTED_FAM_OR_ASSEM:
        return "protected internal";
      default:
        return "private";
    }
  }

  static String methodVisibility(long flags) {
    switch ((int) (flags & METHOD_ATTR_ACCESS_MASK)) {
      case METHOD_ATTR_PRIVATE:
        return "private";
      case METHOD_ATTR_FAM_AND_ASSEM:
        return "private protected";
      case METHOD_ATTR_ASSEM:
        return "internal";
      case METHOD_ATTR_FAMILY:
        return "protected";
      case METHOD_ATTR_FAM_OR_ASSEM:
        return "protected internal";
      case METHOD_ATTR_PUBLIC:
        return "public";
      default:
        return "private";
    }
  }

  static String typedefType(long flags) {
    switch ((int) (flags & TYPE_ATTR_CLASS_SEMANTIC_MASK)) {
      case TYPE_ATTR_CLASS:
        return "class";
      case TYPE_ATTR_INTERFACE:
        return "interface";
      default:
        return null;
    }
  }

  private static void parseTypeParents(
      Ctx ctx, long extends_, long typeIdx, int outIdx, List<String> classGenParams) {
    YStructure o = ctx.d.object;
    String parent = getTypeDefOrRefFullname(ctx, extends_, classGenParams, null, 0);
    int baseTypeIdx = 0;
    if (parent != null) {
      o.setString(parent, "classes[%i].base_types[%i]", outIdx, baseTypeIdx++);
    }
    for (long idx = 0; idx < ctx.tables.interfaceimpl.rowCount; ++idx) {
      long data = ctx.tables.interfaceimpl.row(idx + 1);
      if (data == NULL) {
        break;
      }
      long[] row = readInterfaceimpl(ctx, data);
      if (row == null) {
        continue;
      }
      if (row[0] == typeIdx) {
        String itf = getTypeDefOrRefFullname(ctx, row[1], classGenParams, null, 0);
        if (itf != null) {
          o.setString(itf, "classes[%i].base_types[%i]", outIdx, baseTypeIdx++);
        }
      }
    }
    o.setInteger(baseTypeIdx, "classes[%i].number_of_base_types", outIdx);
  }

  private static boolean parseMethodParams(
      Ctx ctx,
      long paramList,
      int methodIdx,
      int classIdx,
      long paramCount,
      Sig sig,
      List<String> classGenParams,
      List<String> methodGenParams) {
    if (paramList == 0) {
      return true;
    }
    String[] names = new String[(int) paramCount];
    String[] types = new String[(int) paramCount];
    for (int idx = 0; idx < paramCount; ++idx) {
      long data = ctx.tables.param.row(paramList + idx);
      String name;
      if (data != NULL) {
        long nameIndex = readParamName(ctx, data);
        if (nameIndex < 0) {
          return false;
        }
        name = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, nameIndex);
      } else {
        name = "P_" + idx;
      }
      String type = parseSignatureType(ctx, sig, classGenParams, methodGenParams, 0);
      names[idx] = name;
      types[idx] = type;
      if (type == null) {
        return false;
      }
    }
    YStructure o = ctx.d.object;
    o.setInteger(paramCount, "classes[%i].methods[%i].number_of_parameters", classIdx, methodIdx);
    for (int i = 0; i < paramCount; ++i) {
      o.setString(names[i], "classes[%i].methods[%i].parameters[%i].name", classIdx, methodIdx, i);
      o.setString(types[i], "classes[%i].methods[%i].parameters[%i].type", classIdx, methodIdx, i);
    }
    return true;
  }

  private static List<String> parseGenericParams(Ctx ctx, boolean method, long genIdx) {
    List<String> result = new ArrayList<>();
    for (long idx = 0; idx < ctx.tables.genericparam.rowCount; ++idx) {
      long data = ctx.tables.genericparam.row(idx + 1);
      if (data == NULL) {
        return new ArrayList<>();
      }
      long[] row = readGenericparam(ctx, data);
      if (row == null) {
        continue;
      }
      long table = row[0] & 0x1;
      if (table == (method ? 1 : 0) && (row[0] >>> 1) == genIdx) {
        String name = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, row[1]);
        if (name == null || name.isEmpty()) {
          return new ArrayList<>();
        }
        result.add(name);
      }
    }
    return result;
  }

  private static void parseMethods(
      Ctx ctx, long methodlist, long methodCount, int classIdx, List<String> classGenParams) {
    if (methodlist == 0) {
      return;
    }
    YStructure o = ctx.d.object;
    int outIdx = 0;
    for (long idx = 0; idx < methodCount; ++idx) {
      long data = ctx.tables.methoddef.row(methodlist + idx);
      if (data == NULL) {
        break;
      }
      MethoddefRow row = readMethoddef(ctx, data);
      if (row == null) {
        continue;
      }
      if (row.signature >= ctx.blobSize) {
        continue;
      }
      String name = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, row.name);
      if (name == null || name.isEmpty()) {
        continue;
      }
      List<String> methodGenParams = parseGenericParams(ctx, true, methodlist + idx);
      long sigData = ctx.blobHeap + row.signature;
      long[] blob = ctx.d.blobEntry(sigData);
      sigData += blob[0];
      Sig sig = new Sig(sigData, blob[1]);
      long paramCount = 0;
      String returnType = null;
      if (blob[0] != 0 && sig.len >= 3) {
        int flags = ctx.d.u8(sig.data);
        sig.data++;
        sig.len--;
        if ((flags & SIG_FLAG_GENERIC) != 0) {
          readBlobUnsigned(ctx.d, sig);
        }
        paramCount = readBlobUnsigned(ctx.d, sig);
        returnType = parseSignatureType(ctx, sig, classGenParams, methodGenParams, 0);
      } else {
        continue;
      }
      if (returnType == null || paramCount > MAX_PARAM_COUNT) {
        continue;
      }
      if (!parseMethodParams(
          ctx, row.paramList, outIdx, classIdx, paramCount, sig, classGenParams,
          methodGenParams)) {
        continue;
      }
      o.setString(name, "classes[%i].methods[%i].name", classIdx, outIdx);
      o.setString(methodVisibility(row.flags), "classes[%i].methods[%i].visibility", classIdx,
          outIdx);
      o.setInteger((row.flags & METHOD_ATTR_STATIC) != 0 ? 1 : 0,
          "classes[%i].methods[%i].static", classIdx, outIdx);
      o.setInteger((row.flags & METHOD_ATTR_VIRTUAL) != 0 ? 1 : 0,
          "classes[%i].methods[%i].virtual", classIdx, outIdx);
      o.setInteger((row.flags & METHOD_ATTR_FINAL) != 0 ? 1 : 0,
          "classes[%i].methods[%i].final", classIdx, outIdx);
      o.setInteger((row.flags & METHOD_ATTR_ABSTRACT) != 0 ? 1 : 0,
          "classes[%i].methods[%i].abstract", classIdx, outIdx);
      o.setInteger(methodGenParams.size(),
          "classes[%i].methods[%i].number_of_generic_parameters", classIdx, outIdx);
      for (int i = 0; i < methodGenParams.size(); ++i) {
        o.setString(methodGenParams.get(i), "classes[%i].methods[%i].generic_parameters[%i]",
            classIdx, outIdx, i);
      }
      if (!name.equals(".ctor") && !name.equals(".cctor")) {
        o.setString(returnType, "classes[%i].methods[%i].return_type", classIdx, outIdx);
      }
      outIdx++;
    }
    o.setInteger(outIdx, "classes[%i].number_of_methods", classIdx);
  }

  private static String parseEnclosingTypes(Ctx ctx, long nestedIdx, int depth) {
    if (depth > MAX_NAMESPACE_DEPTH) {
      return null;
    }
    for (long idx = 0; idx < ctx.tables.nestedclass.rowCount; ++idx) {
      long nestedData = ctx.tables.nestedclass.row(idx + 1);
      long[] nestedRow = readNestedclass(ctx, nestedData);
      if (nestedRow == null) {
        continue;
      }
      if (nestedRow[0] == nestedIdx) {
        long typedefData = ctx.tables.typedef.row(nestedRow[1]);
        TypedefRow typedefRow = readTypedef(ctx, typedefData);
        if (typedefRow == null) {
          break;
        }
        String name = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, typedefRow.name);
        if (name != null && name.equals("<Module>")) {
          break;
        }
        String namespace = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, typedefRow.namespace);
        if (isNested(typedefRow.flags) && nestedRow[1] != nestedRow[0]) {
          String nestedNamespace = parseEnclosingTypes(ctx, nestedRow[1], depth + 1);
          String tmp = createFullName(namespace, nestedNamespace);
          return createFullName(name, tmp);
        }
        return createFullName(name, namespace);
      }
    }
    return null;
  }

  private static void parseUserTypes(Ctx ctx) {
    YStructure o = ctx.d.object;
    int outIdx = 0;
    for (long idx = 0; idx < ctx.tables.typedef.rowCount; ++idx) {
      long data = ctx.tables.typedef.row(idx + 1);
      TypedefRow row = readTypedef(ctx, data);
      if (row == null) {
        continue;
      }
      String name = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, row.name);
      String type = typedefType(row.flags);
      if (name == null || name.isEmpty() || type == null) {
        continue;
      }
      int end = name.indexOf('`');
      if (end == 0 || name.equals("<Module>")) {
        continue;
      }
      o.setString(end > 0 ? name.substring(0, end) : name, "classes[%i].name", outIdx);
      String fullname;
      String namespace = ctx.d.dotnetString(ctx.strHeap, ctx.strSize, row.namespace);
      if (isNested(row.flags)) {
        String nestedNamespace = parseEnclosingTypes(ctx, idx + 1, 1);
        namespace = createFullName(namespace, nestedNamespace);
        o.setString(namespace, "classes[%i].namespace", outIdx);
        fullname = createFullName(name, namespace);
      } else {
        o.setString(namespace, "classes[%i].namespace", outIdx);
        fullname = createFullName(name, namespace);
      }
      o.setString(fullname, "classes[%i].fullname", outIdx);
      o.setString(typeVisibility(row.flags), "classes[%i].visibility", outIdx);
      o.setString(type, "classes[%i].type", outIdx);
      o.setInteger((row.flags & TYPE_ATTR_ABSTRACT) != 0 ? 1 : 0, "classes[%i].abstract", outIdx);
      o.setInteger((row.flags & TYPE_ATTR_SEALED) != 0 ? 1 : 0, "classes[%i].sealed", outIdx);
      List<String> genParams = parseGenericParams(ctx, false, idx + 1);
      o.setInteger(genParams.size(), "classes[%i].number_of_generic_parameters", outIdx);
      for (int i = 0; i < genParams.size(); ++i) {
        o.setString(genParams.get(i), "classes[%i].generic_parameters[%i]", outIdx, i);
      }
      parseTypeParents(ctx, row.extends_, idx + 1, outIdx, genParams);
      long methodCount = 0;
      if (idx + 1 < ctx.tables.typedef.rowCount) {
        long next = ctx.tables.typedef.row(idx + 2);
        TypedefRow nextRow = readTypedef(ctx, next);
        if (nextRow != null && nextRow.method >= row.method) {
          methodCount = nextRow.method - row.method;
        }
      } else if (ctx.tables.methoddef.rowCount >= row.method) {
        methodCount = (ctx.tables.methoddef.rowCount + 1 - row.method) & 0xffffffffL;
      }
      if (methodCount <= MAX_METHOD_COUNT) {
        parseMethods(ctx, row.method, methodCount, outIdx, genParams);
      }
      outIdx++;
    }
    o.setInteger(outIdx, "number_of_classes");
  }

  // ---------------------------------------------------------------------------------------------
  // Streams

  private static final class Streams {
    long metadataRoot;
    long guid = NULL;
    long tilde = NULL;
    long string = NULL;
    long blob = NULL;
    long us = NULL;
  }

  private static void parseGuid(Data d, long metadataRoot, long guidHeader) {
    long guidOffset = metadataRoot + d.u32(guidHeader);
    long guidSize = Math.min(d.u32(guidHeader + 4), 256);
    int i = 0;
    while (guidSize >= 16 && d.fits(guidOffset, 16)) {
      String guid =
          String.format(
              "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              d.u32(guidOffset), d.u16(guidOffset + 4), d.u16(guidOffset + 6),
              d.u8(guidOffset + 8), d.u8(guidOffset + 9), d.u8(guidOffset + 10),
              d.u8(guidOffset + 11), d.u8(guidOffset + 12), d.u8(guidOffset + 13),
              d.u8(guidOffset + 14), d.u8(guidOffset + 15));
      d.object.setString(guid, "guids[%i]", i);
      i++;
      guidSize -= 16;
      guidOffset += 16;
    }
    d.object.setInteger(i, "number_of_guids");
  }

  private static void parseUs(Data d, long metadataRoot, long usHeader) {
    long ushSz = d.u32(usHeader + 4);
    long offset = metadataRoot + d.u32(usHeader);
    long endOfHeader = offset + ushSz;
    int i = 0;
    if (ushSz == 0 || !d.fits(offset, ushSz)) {
      return;
    }
    if (d.u8(offset) != 0x00) {
      return;
    }
    offset++;
    while (offset < endOfHeader) {
      long[] blob = d.blobEntry(offset);
      if (blob[0] == 0) {
        break;
      }
      offset += blob[0];
      long length = blob[1];
      if (length > 0) {
        length--;
      }
      if (length > 0 && d.fits(offset, length)) {
        d.object.setString(d.r.bytes(offset, (int) length), "user_strings[%i]", i);
        offset += length;
        i++;
      }
    }
    d.object.setInteger(i, "number_of_user_strings");
  }

  private static Streams parseStreamHeaders(
      Data d, long offset, long metadataRoot, int numStreams) {
    Streams headers = new Streams();
    headers.metadataRoot = metadataRoot;
    long streamHeader = offset;
    int i;
    for (i = 0; i < numStreams; i++) {
      if (!d.fits(streamHeader, SIZEOF_STREAM_HEADER)) {
        break;
      }
      long start = streamHeader + 8;
      if (!d.fits(start, DOTNET_STREAM_NAME_SIZE)) {
        break;
      }
      int len = -1;
      for (int k = 0; k < DOTNET_STREAM_NAME_SIZE; k++) {
        if (d.u8(start + k) == 0) {
          len = k;
          break;
        }
      }
      if (len < 0) {
        break;
      }
      String name = new String(d.r.bytes(start, len), StandardCharsets.ISO_8859_1);
      d.object.setString(name, "streams[%i].name", i);
      d.object.setInteger(metadataRoot + d.u32(streamHeader), "streams[%i].offset", i);
      d.object.setInteger(d.u32(streamHeader + 4), "streams[%i].size", i);
      if ((name.startsWith("#~") || name.startsWith("#-")) && headers.tilde == NULL) {
        headers.tilde = streamHeader;
      } else if (name.startsWith("#GUID")) {
        headers.guid = streamHeader;
      } else if (name.startsWith("#Strings") && headers.string == NULL) {
        headers.string = streamHeader;
      } else if (name.startsWith("#Blob") && headers.blob == NULL) {
        headers.blob = streamHeader;
      } else if (name.startsWith("#US") && headers.us == NULL) {
        headers.us = streamHeader;
      }
      streamHeader += SIZEOF_STREAM_HEADER + len + 4 - (len % 4);
    }
    d.object.setInteger(i, "number_of_streams");
    return headers;
  }

  private static void parseTilde2(
      Data d, long tildeHeader, long resourceBase, Rows rows, IndexSizes indexSizes,
      Streams streams) {
    YStructure o = d.object;
    Tables tables = new Tables();
    long metadataRoot = streams.metadataRoot;
    long tildeStreamEnd = metadataRoot + d.u32(streams.tilde) + d.u32(streams.tilde + 4);
    long valid = d.u32(tildeHeader + 8) | d.u32(tildeHeader + 12) << 32;
    int validRows = Long.bitCount(valid);
    long rowOffset = tildeHeader + SIZEOF_TILDE_HEADER;
    long tableOffset = rowOffset + 4L * validRows;
    if ((d.u8(tildeHeader + 6) & HEAP_EXTRA_DATA) != 0) {
      tableOffset += 4;
    }
    long stringOffset = metadataRoot + d.u32(streams.string);
    long strHeapSize = d.u32(streams.string + 4);
    long blobBase = metadataRoot + d.u32(streams.blob);
    int matchedBits = 0;
    long typerefPtr = NULL;
    long memberrefPtr = NULL;
    long typerefRowSize = 0;
    long memberrefRowSize = 0;
    for (int bitCheck = 0; bitCheck < 64; bitCheck++) {
      if (((valid >>> bitCheck) & 0x01) == 0) {
        continue;
      }
      long rowPtrAddr = rowOffset + 4L * matchedBits;
      if (!d.fits(rowPtrAddr, 4) || rowPtrAddr + 4 > tildeStreamEnd) {
        return;
      }
      long numRows = d.u32(rowPtrAddr);
      if (numRows > 15000) {
        return;
      }
      int indexSize;
      long rowSize;
      long rowCount;
      switch (bitCheck) {
        case BIT_MODULE:
          if (!d.fits(tableOffset, SIZEOF_MODULE_TABLE)) {
            break;
          }
          {
            String name =
                d.dotnetString(stringOffset, strHeapSize,
                    d.index(tableOffset + 2, indexSizes.string));
            if (name != null) {
              o.setString(name, "module_name");
            }
          }
          rowSize = 2 + indexSizes.string + (indexSizes.guid * 3L);
          tables.module.set(tableOffset, numRows, rowSize);
          tableOffset += rowSize * numRows;
          break;
        case BIT_TYPEREF:
          rowCount = maxRows(rows.module, rows.moduleref, rows.assemblyref, rows.typeref);
          indexSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
          rowSize = indexSize + indexSizes.string * 2L;
          typerefRowSize = rowSize;
          typerefPtr = tableOffset;
          tables.typeref.set(tableOffset, numRows, rowSize);
          tableOffset += rowSize * numRows;
          break;
        case BIT_TYPEDEF:
          rowCount = maxRows(rows.typedef, rows.typeref, rows.typespec);
          indexSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
          rowSize =
              4 + indexSizes.string * 2L + indexSize + indexSizes.field + indexSizes.methoddef;
          tables.typedef.set(tableOffset, numRows, rowSize);
          tableOffset += rowSize * numRows;
          break;
        case BIT_FIELDPTR:
          tableOffset += indexSizes.field * numRows;
          break;
        case BIT_FIELD:
          tableOffset += (2L + indexSizes.string + indexSizes.blob) * numRows;
          break;
        case BIT_METHODDEFPTR:
          tableOffset += indexSizes.methoddef * numRows;
          break;
        case BIT_METHODDEF:
          rowSize = 4 + 2 + 2 + indexSizes.string + indexSizes.blob + indexSizes.param;
          tables.methoddef.set(tableOffset, numRows, rowSize);
          tableOffset += rowSize * numRows;
          break;
        case BIT_PARAM:
          rowSize = 2 + 2 + indexSizes.string;
          tables.param.set(tableOffset, numRows, rowSize);
          tableOffset += rowSize * numRows;
          break;
        case BIT_INTERFACEIMPL:
          rowCount = maxRows(rows.typedef, rows.typeref, rows.typespec);
          indexSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
          rowSize = indexSizes.typedef + indexSize;
          tables.interfaceimpl.set(tableOffset, numRows, rowSize);
          tableOffset += rowSize * numRows;
          break;
        case BIT_MEMBERREF:
          rowCount = maxRows(rows.methoddef, rows.moduleref, rows.typeref, rows.typespec);
          indexSize = rowCount > (0xFFFF >> 0x03) ? 4 : 2;
          rowSize = indexSize + indexSizes.string + indexSizes.blob;
          memberrefRowSize = rowSize;
          memberrefPtr = tableOffset;
          tableOffset += rowSize * numRows;
          break;
        case BIT_CONSTANT:
          {
            rowCount = maxRows(rows.param, rows.field, rows.property);
            indexSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
            int counter = 0;
            rowSize = 1 + 1 + indexSize + indexSizes.blob;
            long rowPtr = tableOffset;
            for (long i = 0; i < numRows; i++) {
              if (!d.fits(rowPtr, rowSize)) {
                break;
              }
              if (d.u16(rowPtr) != TYPE_STRING) {
                rowPtr += rowSize;
                continue;
              }
              long blobIndex = d.index(rowPtr + 2 + indexSize, indexSizes.blob);
              long blobOffset = blobBase + blobIndex;
              long[] blob = d.blobEntry(blobOffset);
              if (blob[0] == 0) {
                rowPtr += rowSize;
                continue;
              }
              blobOffset += blob[0];
              if (blobOffset + blob[1] >= d.size) {
                rowPtr += rowSize;
                continue;
              }
              o.setString(d.r.bytes(blobOffset, (int) blob[1]), "constants[%i]", counter);
              counter++;
              rowPtr += rowSize;
            }
            o.setInteger(counter, "number_of_constants");
            tableOffset += rowSize * numRows;
          }
          break;
        case BIT_CUSTOMATTRIBUTE:
          {
            rowCount =
                maxRows(rows.methoddef, rows.field, rows.typeref, rows.typedef, rows.param,
                    rows.interfaceimpl, rows.memberref, rows.module, rows.property, rows.event,
                    rows.standalonesig, rows.moduleref, rows.typespec, rows.assembly,
                    rows.assemblyref, rows.file, rows.exportedtype, rows.manifestresource,
                    rows.genericparam, rows.genericparamconstraint, rows.methodspec);
            indexSize = rowCount > (0xFFFF >> 0x05) ? 4 : 2;
            rowCount = maxRows(rows.methoddef, rows.memberref);
            int indexSize2 = rowCount > (0xFFFF >> 0x03) ? 4 : 2;
            rowSize = indexSize + indexSize2 + indexSizes.blob;
            if (typerefPtr != NULL && memberrefPtr != NULL) {
              parseCustomAttributes(d, tableOffset, numRows, rowSize, indexSize, indexSize2,
                  memberrefPtr, memberrefRowSize, typerefPtr, typerefRowSize, rows, indexSizes,
                  stringOffset, strHeapSize, blobBase);
            }
            tableOffset += rowSize * numRows;
          }
          break;
        case BIT_FIELDMARSHAL:
          rowCount = maxRows(rows.field, rows.param);
          indexSize = rowCount > (0xFFFF >> 0x01) ? 4 : 2;
          tableOffset += (long) (indexSize + indexSizes.blob) * numRows;
          break;
        case BIT_DECLSECURITY:
          rowCount = maxRows(rows.typedef, rows.methoddef, rows.assembly);
          indexSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
          tableOffset += (2L + indexSize + indexSizes.blob) * numRows;
          break;
        case BIT_CLASSLAYOUT:
          tableOffset += (2L + 4 + indexSizes.typedef) * numRows;
          break;
        case BIT_FIELDLAYOUT:
          tableOffset += (4L + indexSizes.field) * numRows;
          break;
        case BIT_STANDALONESIG:
          tableOffset += indexSizes.blob * numRows;
          break;
        case BIT_EVENTMAP:
          tableOffset += (long) (indexSizes.typedef + indexSizes.event) * numRows;
          break;
        case BIT_EVENTPTR:
          tableOffset += indexSizes.event * numRows;
          break;
        case BIT_EVENT:
          rowCount = maxRows(rows.typedef, rows.typeref, rows.typespec);
          indexSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
          tableOffset += (2L + indexSizes.string + indexSize) * numRows;
          break;
        case BIT_PROPERTYMAP:
          tableOffset += (long) (indexSizes.typedef + indexSizes.property) * numRows;
          break;
        case BIT_PROPERTYPTR:
          tableOffset += indexSizes.property * numRows;
          break;
        case BIT_PROPERTY:
          tableOffset += (2L + indexSizes.string + indexSizes.blob) * numRows;
          break;
        case BIT_METHODSEMANTICS:
          rowCount = maxRows(rows.event, rows.property);
          indexSize = rowCount > (0xFFFF >> 0x01) ? 4 : 2;
          tableOffset += (2L + indexSizes.methoddef + indexSize) * numRows;
          break;
        case BIT_METHODIMPL:
          rowCount = maxRows(rows.methoddef, rows.memberref);
          indexSize = rowCount > (0xFFFF >> 0x01) ? 4 : 2;
          tableOffset += (long) (indexSizes.typedef + indexSize * 2) * numRows;
          break;
        case BIT_MODULEREF:
          {
            long rowPtr = tableOffset;
            int counter = 0;
            for (long i = 0; i < numRows; i++) {
              if (!d.fits(rowPtr, SIZEOF_MODULEREF_TABLE)) {
                break;
              }
              String name =
                  d.dotnetString(stringOffset, strHeapSize, d.index(rowPtr, indexSizes.string));
              if (name != null) {
                o.setString(name, "modulerefs[%i]", counter);
                counter++;
              }
              rowPtr += indexSizes.string;
            }
            o.setInteger(counter, "number_of_modulerefs");
            rowSize = indexSizes.string;
            tables.moduleref.set(tableOffset, numRows, rowSize);
            tableOffset += rowSize * numRows;
          }
          break;
        case BIT_TYPESPEC:
          rowSize = indexSizes.blob;
          tables.typespec.set(tableOffset, numRows, rowSize);
          tableOffset += rowSize * numRows;
          break;
        case BIT_IMPLMAP:
          rowCount = maxRows(rows.field, rows.methoddef);
          indexSize = rowCount > (0xFFFF >> 0x01) ? 4 : 2;
          tableOffset += (2L + indexSize + indexSizes.string + indexSizes.moduleref) * numRows;
          break;
        case BIT_FIELDRVA:
          {
            rowSize = 4 + indexSizes.field;
            long rowPtr = tableOffset;
            int counter = 0;
            for (long i = 0; i < numRows; i++) {
              if (!d.fits(rowPtr, SIZEOF_FIELDRVA_TABLE)) {
                break;
              }
              long fieldOffset = d.pe.rvaToOffset(d.u32(rowPtr));
              if (fieldOffset >= 0) {
                o.setInteger(fieldOffset, "field_offsets[%i]", counter);
                counter++;
              }
              rowPtr += rowSize;
            }
            o.setInteger(counter, "number_of_field_offsets");
            tableOffset += rowSize * numRows;
          }
          break;
        case BIT_ENCLOG:
          tableOffset += 8 * numRows;
          break;
        case BIT_ENCMAP:
          tableOffset += 4 * numRows;
          break;
        case BIT_ASSEMBLY:
          rowSize = 4 + 2 + 2 + 2 + 2 + 4 + indexSizes.blob + indexSizes.string * 2L;
          if (!d.fits(tableOffset, rowSize)) {
            break;
          }
          {
            long rowPtr = tableOffset;
            o.setInteger(d.u16(rowPtr + 4), "assembly.version.major");
            o.setInteger(d.u16(rowPtr + 6), "assembly.version.minor");
            o.setInteger(d.u16(rowPtr + 8), "assembly.version.build_number");
            o.setInteger(d.u16(rowPtr + 10), "assembly.version.revision_number");
            long nameOff = rowPtr + 4 + 2 + 2 + 2 + 2 + 4 + indexSizes.blob;
            String name =
                d.dotnetString(stringOffset, strHeapSize, d.index(nameOff, indexSizes.string));
            if (name != null) {
              o.setString(name, "assembly.name");
            }
            name =
                d.dotnetString(stringOffset, strHeapSize,
                    d.index(nameOff + indexSizes.string, indexSizes.string));
            if (name != null && !name.isEmpty()) {
              o.setString(name, "assembly.culture");
            }
          }
          tableOffset += rowSize * numRows;
          break;
        case BIT_ASSEMBLYPROCESSOR:
          tableOffset += 4 * numRows;
          break;
        case BIT_ASSEMBLYOS:
          tableOffset += 12 * numRows;
          break;
        case BIT_ASSEMBLYREF:
          {
            rowSize = 2 + 2 + 2 + 2 + 4 + indexSizes.blob * 2L + indexSizes.string * 2L;
            long rowPtr = tableOffset;
            long i;
            for (i = 0; i < numRows; i++) {
              if (!d.fits(rowPtr, rowSize)) {
                break;
              }
              o.setInteger(d.u16(rowPtr), "assembly_refs[%i].version.major", i);
              o.setInteger(d.u16(rowPtr + 2), "assembly_refs[%i].version.minor", i);
              o.setInteger(d.u16(rowPtr + 4), "assembly_refs[%i].version.build_number", i);
              o.setInteger(d.u16(rowPtr + 6), "assembly_refs[%i].version.revision_number", i);
              long blobOffset = blobBase + d.index(rowPtr + 12, indexSizes.blob);
              long[] blob = d.blobEntry(blobOffset);
              blobOffset += blob[0];
              if (blob[0] == 0 || !d.fits(blobOffset, blob[1])) {
                rowPtr += rowSize;
                continue;
              }
              if (blob[1] > 0) {
                o.setString(d.r.bytes(blobOffset, (int) blob[1]),
                    "assembly_refs[%i].public_key_or_token", i);
              }
              String name =
                  d.dotnetString(stringOffset, strHeapSize,
                      d.index(rowPtr + 2 + 2 + 2 + 2 + 4 + indexSizes.blob, indexSizes.string));
              if (name != null) {
                o.setString(name, "assembly_refs[%i].name", i);
              }
              rowPtr += rowSize;
            }
            tables.assemblyref.set(tableOffset, numRows, rowSize);
            o.setInteger(i, "number_of_assembly_refs");
            tableOffset += rowSize * numRows;
          }
          break;
        case BIT_ASSEMBLYREFPROCESSOR:
          tableOffset += (4L + indexSizes.assemblyrefprocessor) * numRows;
          break;
        case BIT_ASSEMBLYREFOS:
          tableOffset += (12L + indexSizes.assemblyref) * numRows;
          break;
        case BIT_FILE:
          tableOffset += (4L + indexSizes.string + indexSizes.blob) * numRows;
          break;
        case BIT_EXPORTEDTYPE:
          rowCount = maxRows(rows.file, rows.assemblyref, rows.exportedtype);
          indexSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
          tableOffset += (8L + indexSizes.string * 2L + indexSize) * numRows;
          break;
        case BIT_MANIFESTRESOURCE:
          {
            rowCount = maxRows(rows.file, rows.assemblyref);
            indexSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
            rowSize = 4 + 4 + indexSizes.string + indexSize;
            long rowPtr = tableOffset;
            long i;
            for (i = 0; i < numRows; i++) {
              if (!d.fits(rowPtr, rowSize)) {
                break;
              }
              long table = rowPtr;
              long implementation = d.index(rowPtr + 4 + 4 + indexSizes.string, indexSize);
              rowPtr += rowSize;
              String name =
                  d.dotnetString(stringOffset, strHeapSize, d.index(table + 8, indexSizes.string));
              if (name != null) {
                o.setString(name, "resources[%i].name", i);
              }
              if (implementation != 0) {
                continue;
              }
              long resourceOffset = d.u32(table);
              if (!d.fits(resourceBase + resourceOffset, 4)) {
                continue;
              }
              long resourceSize = d.u32(resourceBase + resourceOffset);
              o.setInteger(resourceBase + resourceOffset + 4, "resources[%i].offset", i);
              o.setInteger(resourceSize, "resources[%i].length", i);
            }
            o.setInteger(i, "number_of_resources");
            tableOffset += rowSize * numRows;
          }
          break;
        case BIT_NESTEDCLASS:
          rowSize = indexSizes.typedef * 2L;
          tables.nestedclass.set(tableOffset, numRows, rowSize);
          tableOffset += rowSize * numRows;
          break;
        case BIT_GENERICPARAM:
          rowCount = maxRows(rows.typedef, rows.methoddef);
          indexSize = rowCount > (0xFFFF >> 0x01) ? 4 : 2;
          rowSize = 2 + 2 + indexSize + indexSizes.string;
          tables.genericparam.set(tableOffset, numRows, rowSize);
          tableOffset += rowSize * numRows;
          break;
        case BIT_METHODSPEC:
          rowCount = maxRows(rows.methoddef, rows.memberref);
          indexSize = rowCount > (0xFFFF >> 0x01) ? 4 : 2;
          tableOffset += (long) (indexSize + indexSizes.blob) * numRows;
          break;
        case BIT_GENERICPARAMCONSTRAINT:
          rowCount = maxRows(rows.typedef, rows.typeref, rows.typespec);
          indexSize = rowCount > (0xFFFF >> 0x02) ? 4 : 2;
          tableOffset += (long) (indexSizes.genericparam + indexSize) * numRows;
          break;
        default:
          return;
      }
      matchedBits++;
    }
    Ctx ctx = new Ctx();
    ctx.d = d;
    ctx.tables = tables;
    ctx.indexSizes = indexSizes;
    ctx.strHeap = stringOffset;
    ctx.strSize = strHeapSize;
    ctx.blobHeap = blobBase;
    ctx.blobSize = d.u32(streams.blob + 4);
    parseUserTypes(ctx);
  }

  private static void parseCustomAttributes(
      Data d, long tableOffset, long numRows, long rowSize, int indexSize, int indexSize2,
      long memberrefPtr, long memberrefRowSize, long typerefPtr, long typerefRowSize, Rows rows,
      IndexSizes indexSizes, long stringOffset, long strHeapSize, long blobBase) {
    long rowPtr = tableOffset;
    for (long i = 0; i < numRows; i++) {
      if (!d.fits(rowPtr, rowSize)) {
        break;
      }
      long parent = indexSize == 4 ? d.u32(rowPtr) : d.u16(rowPtr);
      if ((parent & 0x1F) != 0x0E) {
        rowPtr += rowSize;
        continue;
      }
      long typeField = indexSize2 == 4 ? d.u32(rowPtr + indexSize) : d.u16(rowPtr + indexSize);
      if ((typeField & 0x07) != 0x03) {
        rowPtr += rowSize;
        continue;
      }
      long typeIndex = typeField >>> 3;
      if (typeIndex > 0) {
        typeIndex--;
      }
      long memberrefRow = memberrefPtr + memberrefRowSize * typeIndex;
      if (!d.fits(memberrefRow, memberrefRowSize)) {
        break;
      }
      long cls = indexSizes.memberref == 4 ? d.u32(memberrefRow) : d.u16(memberrefRow);
      if ((cls & 0x07) != 0x01) {
        rowPtr += rowSize;
        continue;
      }
      long classIndex = cls >>> 3;
      if (classIndex > 0) {
        classIndex--;
      }
      long typerefRow = typerefPtr + typerefRowSize * classIndex;
      if (!d.fits(typerefRow, typerefRowSize)) {
        break;
      }
      long rowCount = maxRows(rows.module, rows.moduleref, rows.assemblyref, rows.typeref);
      typerefRow += rowCount > (0xFFFF >> 0x02) ? 4 : 2;
      String name =
          d.dotnetString(stringOffset, strHeapSize,
              indexSizes.string == 4 ? d.u32(typerefRow) : d.u16(typerefRow));
      if (name != null && !name.startsWith("GuidAttribute")) {
        rowPtr += rowSize;
        continue;
      }
      long blobIndex = d.index(rowPtr + indexSize + indexSize2, indexSizes.blob);
      long blobOffset = blobBase + blobIndex;
      if (blobIndex == 0x00 || blobOffset >= d.size) {
        rowPtr += rowSize;
        continue;
      }
      long[] blob = d.blobEntry(blobOffset);
      if (blob[0] == 0) {
        rowPtr += rowSize;
        continue;
      }
      long blobLength = blob[1];
      blobOffset += blob[0];
      if (blobLength < 3 || blobOffset + blobLength >= d.size) {
        rowPtr += rowSize;
        continue;
      }
      if (d.u16(blobOffset) != 0x0001) {
        rowPtr += rowSize;
        continue;
      }
      blobOffset += 2;
      int strLen = d.u8(blobOffset);
      blobOffset += 1;
      if (blobOffset + strLen > d.size) {
        rowPtr += rowSize;
        continue;
      }
      String typelib;
      int first = d.u8(blobOffset);
      if (first == 0xFF || first == 0x00) {
        typelib = "";
      } else {
        // strncpy stops at the first NUL.
        int n = 0;
        while (n < strLen && d.u8(blobOffset + n) != 0) {
          n++;
        }
        typelib = new String(d.r.bytes(blobOffset, n), StandardCharsets.ISO_8859_1);
      }
      d.object.setString(typelib, "typelib");
      rowPtr += rowSize;
    }
  }

  private static void parseTilde(Data d, long cliHeader, Streams streams) {
    long metadataRoot = streams.metadataRoot;
    Rows rows = new Rows();
    IndexSizes indexSizes = new IndexSizes();
    long tildeHeader = metadataRoot + d.u32(streams.tilde);
    long tildeStreamEnd = tildeHeader + d.u32(streams.tilde + 4);
    if (!d.fits(tildeHeader, SIZEOF_TILDE_HEADER)) {
      return;
    }
    int heapSizes = d.u8(tildeHeader + 6);
    if ((heapSizes & 0x01) != 0) {
      indexSizes.string = 4;
    }
    if ((heapSizes & 0x02) != 0) {
      indexSizes.guid = 4;
    }
    if ((heapSizes & 0x04) != 0) {
      indexSizes.blob = 4;
    }
    long rowOffset = tildeHeader + SIZEOF_TILDE_HEADER;
    long valid = d.u32(tildeHeader + 8) | d.u32(tildeHeader + 12) << 32;
    int validCount = Long.bitCount(valid);
    if (!d.fits(rowOffset, (validCount * 4L) & 0xffffffffL)) {
      return;
    }
    int matchedBits = 0;
    for (int bitCheck = 0; bitCheck < 64; bitCheck++) {
      if (((valid >>> bitCheck) & 0x01) == 0) {
        continue;
      }
      long p = rowOffset + 4L * matchedBits;
      boolean ok = p + 4 <= tildeStreamEnd;
      long v = ok ? d.u32(p) : 0;
      boolean big = v > 0xFFFF;
      switch (bitCheck) {
        case BIT_MODULE:
          if (ok) {
            rows.module = v;
            if (big) {
              indexSizes.module = 4;
            }
          }
          break;
        case BIT_MODULEREF:
          if (ok) {
            rows.moduleref = v;
            if (big) {
              indexSizes.moduleref = 4;
            }
          }
          break;
        case BIT_ASSEMBLYREF:
          if (ok) {
            rows.assemblyref = v;
            if (big) {
              indexSizes.assemblyref = 4;
            }
          }
          break;
        case BIT_ASSEMBLYREFPROCESSOR:
          if (ok) {
            rows.assemblyrefprocessor = v;
            if (big) {
              indexSizes.assemblyrefprocessor = 4;
            }
          }
          break;
        case BIT_TYPEREF:
          if (ok) {
            rows.typeref = v;
            if (big) {
              indexSizes.typeref = 4;
            }
          }
          break;
        case BIT_METHODDEF:
          if (ok) {
            rows.methoddef = v;
            if (big) {
              indexSizes.methoddef = 4;
            }
          }
          break;
        case BIT_MEMBERREF:
          if (ok) {
            rows.memberref = v;
            if (big) {
              indexSizes.memberref = 4;
            }
          }
          break;
        case BIT_TYPEDEF:
          if (ok) {
            rows.typedef = v;
            if (big) {
              indexSizes.typedef = 4;
            }
          }
          break;
        case BIT_TYPESPEC:
          if (ok) {
            rows.typespec = v;
            if (big) {
              indexSizes.typespec = 4;
            }
          }
          break;
        case BIT_FIELD:
          if (ok) {
            rows.field = v;
            if (big) {
              indexSizes.field = 4;
            }
          }
          break;
        case BIT_PARAM:
          if (ok) {
            rows.param = v;
            if (big) {
              indexSizes.param = 4;
            }
          }
          break;
        case BIT_PROPERTY:
          if (ok) {
            rows.property = v;
            if (big) {
              indexSizes.property = 4;
            }
          }
          break;
        case BIT_INTERFACEIMPL:
          if (ok) {
            rows.interfaceimpl = v;
            if (big) {
              indexSizes.interfaceimpl = 4;
            }
          }
          break;
        case BIT_EVENT:
          if (ok) {
            rows.event = v;
            if (big) {
              indexSizes.event = 4;
            }
          }
          break;
        case BIT_STANDALONESIG:
          if (ok) {
            rows.standalonesig = v;
          }
          break;
        case BIT_ASSEMBLY:
          if (ok) {
            rows.assembly = v;
            if (big) {
              indexSizes.assembly = 4;
            }
          }
          break;
        case BIT_FILE:
          if (ok) {
            rows.file = v;
          }
          break;
        case BIT_EXPORTEDTYPE:
          if (ok) {
            rows.exportedtype = v;
          }
          break;
        case BIT_MANIFESTRESOURCE:
          if (ok) {
            rows.manifestresource = v;
          }
          break;
        case BIT_GENERICPARAM:
          if (ok) {
            rows.genericparam = v;
            if (big) {
              indexSizes.genericparam = 4;
            }
          }
          break;
        case BIT_GENERICPARAMCONSTRAINT:
          if (ok) {
            rows.genericparamconstraint = v;
          }
          break;
        case BIT_METHODSPEC:
          if (ok) {
            rows.methodspec = v;
            if (big) {
              indexSizes.methodspec = 4;
            }
          }
          break;
        default:
          break;
      }
      matchedBits++;
    }
    long resourceBase = d.pe.rvaToOffset(d.u32(cliHeader + 24));
    parseTilde2(d, tildeHeader, resourceBase, rows, indexSizes, streams);
  }

  private static boolean isDotnet(Data d) {
    Pe pe = d.pe;
    long directory = pe.directoryEntry(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if (directory < 0) {
      return false;
    }
    long offset = pe.rvaToOffset(d.u32(directory));
    if (offset < 0 || !d.fits(offset, SIZEOF_CLI_HEADER)) {
      return false;
    }
    long cliHeader = offset;
    if (d.u32(cliHeader) != SIZEOF_CLI_HEADER) {
      return false;
    }
    long metadataRoot = pe.rvaToOffset(d.u32(cliHeader + 8));
    if (!d.fits(metadataRoot, SIZEOF_NET_METADATA)) {
      return false;
    }
    if (d.u32(metadataRoot) != NET_METADATA_MAGIC) {
      return false;
    }
    long mdLen = d.u32(metadataRoot + 12);
    if (mdLen == 0 || mdLen > 255 || mdLen % 4 != 0
        || !d.fits(metadataRoot + SIZEOF_NET_METADATA, mdLen)) {
      return false;
    }
    if (pe.is64) {
      if (pe.numberOfRvaAndSizes() < IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
        return false;
      }
    }
    return true;
  }

  private static void parseCom(Data d) {
    YStructure o = d.object;
    if (!isDotnet(d)) {
      o.setInteger(0, "is_dotnet");
      return;
    }
    o.setInteger(1, "is_dotnet");
    Pe pe = d.pe;
    long directory = pe.directoryEntry(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if (directory < 0) {
      return;
    }
    long offset = pe.rvaToOffset(d.u32(directory));
    if (offset < 0 || !d.fits(offset, SIZEOF_CLI_HEADER)) {
      return;
    }
    long cliHeader = offset;
    long metadataRoot = pe.rvaToOffset(d.u32(cliHeader + 8));
    offset = metadataRoot;
    if (!d.fits(offset, SIZEOF_NET_METADATA)) {
      return;
    }
    long mdLen = d.u32(offset + 12);
    if (mdLen == 0 || mdLen > 255 || mdLen % 4 != 0
        || !d.fits(offset + SIZEOF_NET_METADATA, mdLen)) {
      return;
    }
    long version = offset + SIZEOF_NET_METADATA;
    for (long k = 0; k < mdLen; k++) {
      if (d.u8(version + k) == 0) {
        o.setString(d.r.bytes(version, (int) k), "version");
        break;
      }
    }
    offset += SIZEOF_NET_METADATA + mdLen + 2;
    if (!d.fits(offset, 2)) {
      return;
    }
    int numStreams = d.u8(offset);
    offset += 2;
    Streams headers = parseStreamHeaders(d, offset, metadataRoot, numStreams);
    if (headers.guid != NULL) {
      parseGuid(d, metadataRoot, headers.guid);
    }
    if (headers.tilde != NULL && headers.string != NULL && headers.blob != NULL) {
      parseTilde(d, cliHeader, headers);
    }
    if (headers.us != NULL) {
      parseUs(d, metadataRoot, headers.us);
    }
  }

  // ---------------------------------------------------------------------------------------------

  @Override
  public String name() {
    return "dotnet";
  }

  @Override
  public void declare(ModuleDeclarations d) {
    d.declareInteger("is_dotnet")
        .declareString("version")
        .declareString("module_name")
        .beginStructArray("streams")
        .declareString("name")
        .declareInteger("offset")
        .declareInteger("size")
        .endStructArray("streams")
        .declareInteger("number_of_streams")
        .declareStringArray("guids")
        .declareInteger("number_of_guids")
        .beginStructArray("resources")
        .declareInteger("offset")
        .declareInteger("length")
        .declareString("name")
        .endStructArray("resources")
        .declareInteger("number_of_resources")
        .beginStructArray("classes")
        .declareString("fullname")
        .declareString("name")
        .declareString("namespace")
        .declareString("visibility")
        .declareString("type")
        .declareInteger("abstract")
        .declareInteger("sealed")
        .declareInteger("number_of_generic_parameters")
        .declareStringArray("generic_parameters")
        .declareInteger("number_of_base_types")
        .declareStringArray("base_types")
        .declareInteger("number_of_methods")
        .beginStructArray("methods")
        .declareStringArray("generic_parameters")
        .declareInteger("number_of_generic_parameters")
        .beginStructArray("parameters")
        .declareString("name")
        .declareString("type")
        .endStructArray("parameters")
        .declareInteger("number_of_parameters")
        .declareString("return_type")
        .declareInteger("abstract")
        .declareInteger("final")
        .declareInteger("virtual")
        .declareInteger("static")
        .declareString("visibility")
        .declareString("name")
        .endStructArray("methods")
        .endStructArray("classes")
        .declareInteger("number_of_classes")
        .beginStructArray("assembly_refs")
        .beginStruct("version")
        .declareInteger("major")
        .declareInteger("minor")
        .declareInteger("build_number")
        .declareInteger("revision_number")
        .endStruct("version")
        .declareString("public_key_or_token")
        .declareString("name")
        .endStructArray("assembly_refs")
        .declareInteger("number_of_assembly_refs")
        .beginStruct("assembly")
        .beginStruct("version")
        .declareInteger("major")
        .declareInteger("minor")
        .declareInteger("build_number")
        .declareInteger("revision_number")
        .endStruct("version")
        .declareString("name")
        .declareString("culture")
        .endStruct("assembly")
        .declareStringArray("modulerefs")
        .declareInteger("number_of_modulerefs")
        .declareStringArray("user_strings")
        .declareInteger("number_of_user_strings")
        .declareString("typelib")
        .declareStringArray("constants")
        .declareInteger("number_of_constants")
        .declareIntegerArray("field_offsets")
        .declareInteger("number_of_field_offsets");
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {
    for (MemoryBlock block : context.blocks()) {
      BinaryReader r = new BinaryReader(block.data());
      long header = PeModule.getHeader(r);
      if (header < 0) {
        continue;
      }
      Pe pe = new Pe(r, header, module);
      module.setData(pe);
      parseCom(new Data(pe, module));
      break;
    }
  }

  @Override
  public void unload(YStructure module) {
    module.setData(null);
  }
}
