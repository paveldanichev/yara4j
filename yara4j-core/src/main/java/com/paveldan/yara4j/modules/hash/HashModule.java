package com.paveldan.yara4j.modules.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BlockData;

/** The "hash" module. Port of libyara/modules/hash/hash.c. */
public final class HashModule implements YaraModule {

  @Override
  public String name() {
    return "hash";
  }

  private static final char[] HEX = "0123456789abcdef".toCharArray();

  /** Lowercase hex representation of a digest. */
  public static String hex(byte[] digest) {
    char[] c = new char[digest.length * 2];
    for (int i = 0; i < digest.length; i++) {
      c[i * 2] = HEX[(digest[i] >> 4) & 0xF];
      c[i * 2 + 1] = HEX[digest[i] & 0xF];
    }
    return new String(c);
  }

  static MessageDigest digest(String algorithm) {
    try {
      return MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, String> cache(FunctionCall c) {
    return (Map<String, String>) c.module().getData();
  }

  private static Object stringDigest(FunctionCall c, String algorithm) {
    MessageDigest md = digest(algorithm);
    md.update(c.stringArgument(1));
    return hex(md.digest());
  }

  private static Object dataDigest(FunctionCall c, String algorithm, String ns) {
    long offset = c.integerArgument(1);
    long length = c.integerArgument(2);
    ScanContext ctx = c.context();
    if (ctx.blocks().isEmpty()) {
      return null;
    }
    if (offset < 0 || length < 0 || offset < ctx.blocks().get(0).base()) {
      return null;
    }
    Map<String, String> cache = cache(c);
    String key = ns + ":" + offset + ":" + length;
    String cached = cache == null ? null : cache.get(key);
    if (cached != null) {
      return cached;
    }
    MessageDigest md = digest(algorithm);
    boolean ok =
        BlockData.forRange(
            ctx,
            offset,
            length,
            (buf, off, len) -> {
              java.nio.ByteBuffer b = buf.duplicate();
              b.limit(off + len);
              b.position(off);
              md.update(b);
            });
    if (!ok) {
      return null;
    }
    String result = hex(md.digest());
    if (cache != null) {
      cache.put(key, result);
    }
    return result;
  }

  private static final int[] CRC32_TAB = new int[256];

  static {
    for (int n = 0; n < 256; n++) {
      int c = n;
      for (int k = 0; k < 8; k++) {
        c = (c & 1) != 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      }
      CRC32_TAB[n] = c;
    }
  }

  private static Object dataChecksum32(FunctionCall c) {
    final int[] checksum = new int[1];
    boolean ok =
        BlockData.forRange(
            c.context(),
            c.integerArgument(1),
            c.integerArgument(2),
            (buf, off, len) -> {
              for (int i = 0; i < len; i++) {
                checksum[0] += buf.get(off + i) & 0xFF;
              }
            });
    return ok ? (checksum[0] & 0xFFFFFFFFL) : YObject.UNDEFINED;
  }

  private static Object stringChecksum32(FunctionCall c) {
    int checksum = 0;
    for (byte b : c.stringArgument(1)) {
      checksum += b & 0xFF;
    }
    return checksum & 0xFFFFFFFFL;
  }

  private static Object dataCrc32(FunctionCall c) {
    final int[] checksum = {0xFFFFFFFF};
    boolean ok =
        BlockData.forRange(
            c.context(),
            c.integerArgument(1),
            c.integerArgument(2),
            (buf, off, len) -> {
              int crc = checksum[0];
              for (int i = 0; i < len; i++) {
                crc = CRC32_TAB[(crc ^ buf.get(off + i)) & 0xFF] ^ (crc >>> 8);
              }
              checksum[0] = crc;
            });
    return ok ? ((checksum[0] ^ 0xFFFFFFFF) & 0xFFFFFFFFL) : YObject.UNDEFINED;
  }

  private static Object stringCrc32(FunctionCall c) {
    int crc = 0xFFFFFFFF;
    for (byte b : c.stringArgument(1)) {
      crc = CRC32_TAB[(crc ^ b) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFFL;
  }

  @Override
  public void declare(ModuleDeclarations d) {
    d.declareFunction("md5", "ii", "s", c -> dataDigest(c, "MD5", "md5"));
    d.declareFunction("md5", "s", "s", c -> stringDigest(c, "MD5"));
    d.declareFunction("sha1", "ii", "s", c -> dataDigest(c, "SHA-1", "sha1"));
    d.declareFunction("sha1", "s", "s", c -> stringDigest(c, "SHA-1"));
    d.declareFunction("sha256", "ii", "s", c -> dataDigest(c, "SHA-256", "sha256"));
    d.declareFunction("sha256", "s", "s", c -> stringDigest(c, "SHA-256"));
    d.declareFunction("checksum32", "ii", "i", HashModule::dataChecksum32);
    d.declareFunction("checksum32", "s", "i", HashModule::stringChecksum32);
    d.declareFunction("crc32", "ii", "i", HashModule::dataCrc32);
    d.declareFunction("crc32", "s", "i", HashModule::stringCrc32);
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {
    module.setData(new HashMap<String, String>());
  }

  @Override
  public void unload(YStructure module) {
    module.setData(null);
  }
}
