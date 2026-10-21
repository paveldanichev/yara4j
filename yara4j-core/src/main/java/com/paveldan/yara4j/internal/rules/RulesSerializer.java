package com.paveldan.yara4j.internal.rules;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.zip.CRC32;

/**
 * yara4j's compiled rules format.
 *
 * <p>libyara's .yarc files are dumps of its internal arena and can't be shared with yara4j.
 * Instead, a yara4j compiled rules file records the inputs of the compilation: compiler options,
 * external variables, sources (in order, with their namespaces) and the content of every
 * included file. Loading replays the compilation, which is deterministic, so the loaded rules
 * are identical to the saved ones and don't depend on include files being available. The
 * format is a simple versioned binary encoding with a CRC32; no Java serialization is involved,
 * so loading untrusted files is no more dangerous than compiling untrusted rules.
 *
 * <pre>
 *   "YARA4JR\0"  version:int  count:int  op*  crc32:long
 * </pre>
 */
public final class RulesSerializer {
  private RulesSerializer() {}

  private static final byte[] MAGIC = "YARA4JR\0".getBytes(StandardCharsets.US_ASCII);
  public static final int VERSION = 1;

  static final int OP_STRICT_ESCAPE = 1;
  static final int OP_MAX_STRINGS = 2;
  static final int OP_ATOM_TABLE = 3;
  static final int OP_DEFINE = 4;
  static final int OP_SOURCE = 5;

  /** Thrown when a file can't be loaded. */
  public static final class FormatException extends Exception {
    private static final long serialVersionUID = 1L;
    public final boolean unsupportedVersion;

    FormatException(String message, boolean unsupportedVersion) {
      super(message);
      this.unsupportedVersion = unsupportedVersion;
    }
  }

  /** One recorded compiler call. */
  public static final class Op {
    public final int type;
    public boolean flag;
    public int number;
    public byte[] data;
    public ExternalDef external;
    public String namespace;
    public String fileName;
    public List<byte[]> includes = new ArrayList<>();

    Op(int type) {
      this.type = type;
    }
  }

  /** The recorded compilation. Only accessed by the thread using the compiler. */
  public static final class Journal {
    private final List<Op> ops = new ArrayList<>();

    public void strictEscape(boolean strict) {
      Op op = new Op(OP_STRICT_ESCAPE);
      op.flag = strict;
      ops.add(op);
    }

    public void maxStrings(int max) {
      Op op = new Op(OP_MAX_STRINGS);
      op.number = max;
      ops.add(op);
    }

    public void atomTable(byte[] table, int threshold) {
      Op op = new Op(OP_ATOM_TABLE);
      op.data = table.clone();
      op.number = threshold;
      ops.add(op);
    }

    public void define(ExternalDef def) {
      Op op = new Op(OP_DEFINE);
      op.external = def;
      ops.add(op);
    }

    /** Records a source; the returned list must receive the content of its includes. */
    public List<byte[]> source(byte[] source, String namespace, String fileName) {
      Op op = new Op(OP_SOURCE);
      op.data = source.clone();
      op.namespace = namespace;
      op.fileName = fileName;
      ops.add(op);
      return op.includes;
    }

    public List<Op> ops() {
      return Collections.unmodifiableList(ops);
    }

    public Journal copy() {
      Journal j = new Journal();
      j.ops.addAll(ops);
      return j;
    }
  }

  private static void writeBytes(DataOutputStream out, byte[] b) throws IOException {
    if (b == null) {
      out.writeInt(-1);
      return;
    }
    out.writeInt(b.length);
    out.write(b);
  }

  private static void writeString(DataOutputStream out, String s) throws IOException {
    writeBytes(out, s == null ? null : s.getBytes(StandardCharsets.UTF_8));
  }

  public static void save(Journal journal, OutputStream os) throws IOException {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(buf);
    out.write(MAGIC);
    out.writeInt(VERSION);
    out.writeInt(journal.ops.size());
    for (Op op : journal.ops) {
      out.writeByte(op.type);
      switch (op.type) {
        case OP_STRICT_ESCAPE:
          out.writeBoolean(op.flag);
          break;
        case OP_MAX_STRINGS:
          out.writeInt(op.number);
          break;
        case OP_ATOM_TABLE:
          writeBytes(out, op.data);
          out.writeInt(op.number);
          break;
        case OP_DEFINE:
          out.writeByte(op.external.type);
          writeString(out, op.external.identifier);
          out.writeLong(op.external.integer);
          out.writeDouble(op.external.dbl);
          writeBytes(out, op.external.string);
          break;
        case OP_SOURCE:
          writeString(out, op.namespace);
          writeString(out, op.fileName);
          writeBytes(out, op.data);
          out.writeInt(op.includes.size());
          for (byte[] inc : op.includes) {
            writeBytes(out, inc);
          }
          break;
        default:
          throw new IllegalStateException();
      }
    }
    out.flush();
    byte[] content = buf.toByteArray();
    CRC32 crc = new CRC32();
    crc.update(content);
    os.write(content);
    DataOutputStream tail = new DataOutputStream(os);
    tail.writeLong(crc.getValue());
    tail.flush();
  }

  private static byte[] readBytes(DataInputStream in, boolean nullable) throws IOException,
      FormatException {
    int n = in.readInt();
    if (n == -1 && nullable) {
      return null;
    }
    if (n < 0) {
      throw new FormatException("invalid length", false);
    }
    // readNBytes allocates incrementally, so a corrupt length can't exhaust the memory.
    byte[] b = in.readNBytes(n);
    if (b.length != n) {
      throw new EOFException();
    }
    return b;
  }

  private static String readString(DataInputStream in) throws IOException, FormatException {
    byte[] b = readBytes(in, true);
    return b == null ? null : new String(b, StandardCharsets.UTF_8);
  }

  public static Journal load(InputStream is) throws IOException, FormatException {
    byte[] all = is.readAllBytes();
    if (all.length < MAGIC.length + 16
        || !Arrays.equals(Arrays.copyOf(all, MAGIC.length), MAGIC)) {
      throw new FormatException("not a yara4j compiled rules file", false);
    }
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(all));
    in.skipBytes(MAGIC.length);
    int version = in.readInt();
    if (version != VERSION) {
      throw new FormatException("unsupported version " + version, true);
    }
    CRC32 crc = new CRC32();
    crc.update(all, 0, all.length - 8);
    long stored =
        new DataInputStream(new ByteArrayInputStream(all, all.length - 8, 8)).readLong();
    if (stored != crc.getValue()) {
      throw new FormatException("checksum mismatch", false);
    }
    in = new DataInputStream(new ByteArrayInputStream(all, 0, all.length - 8));
    in.skipBytes(MAGIC.length + 4);
    Journal j = new Journal();
    try {
      int count = in.readInt();
      if (count < 0) {
        throw new FormatException("invalid count", false);
      }
      for (int i = 0; i < count; i++) {
        Op op = new Op(in.readUnsignedByte());
        switch (op.type) {
          case OP_STRICT_ESCAPE:
            op.flag = in.readBoolean();
            break;
          case OP_MAX_STRINGS:
            op.number = in.readInt();
            break;
          case OP_ATOM_TABLE:
            op.data = readBytes(in, false);
            op.number = in.readInt();
            break;
          case OP_DEFINE:
            {
              int type = in.readUnsignedByte();
              String id = readString(in);
              long integer = in.readLong();
              double dbl = in.readDouble();
              byte[] s = readBytes(in, true);
              if (id == null || type < ExternalDef.TYPE_FLOAT || type > ExternalDef.TYPE_STRING
                  || (type == ExternalDef.TYPE_STRING) != (s != null)) {
                throw new FormatException("invalid external variable", false);
              }
              op.external = new ExternalDef(id, type, integer, dbl, s);
            }
            break;
          case OP_SOURCE:
            {
              op.namespace = readString(in);
              op.fileName = readString(in);
              op.data = readBytes(in, false);
              int n = in.readInt();
              if (n < 0) {
                throw new FormatException("invalid include count", false);
              }
              for (int k = 0; k < n; k++) {
                op.includes.add(readBytes(in, false));
              }
            }
            break;
          default:
            throw new FormatException("unknown record type " + op.type, false);
        }
        j.ops.add(op);
      }
      if (in.available() != 0) {
        throw new FormatException("trailing data", false);
      }
    } catch (EOFException e) {
      throw new FormatException("truncated file", false);
    }
    return j;
  }
}
