package com.paveldan.yara4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/** Binary test samples from YARA's tests/blob.h. */
public final class Blobs {
  private Blobs() {}

  static byte[] load(String name) {
    try (InputStream in = Blobs.class.getResourceAsStream("/blobs/" + name + ".bin")) {
      return in.readAllBytes();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  public static final byte[] PE32_FILE = load("PE32_FILE");
  public static final byte[] ELF32_FILE = load("ELF32_FILE");
  public static final byte[] ELF64_FILE = load("ELF64_FILE");
  public static final byte[] ELF32_NOSECTIONS = load("ELF32_NOSECTIONS");
  public static final byte[] ELF32_SHAREDOBJ = load("ELF32_SHAREDOBJ");
  public static final byte[] MACHO_X86_FILE = load("MACHO_X86_FILE");
  public static final byte[] MACHO_PPC_FILE = load("MACHO_PPC_FILE");
  public static final byte[] MACHO_X86_OBJECT_FILE = load("MACHO_X86_OBJECT_FILE");
  public static final byte[] MACHO_X86_64_DYLIB_FILE = load("MACHO_X86_64_DYLIB_FILE");
  public static final byte[] DEX_FILE = load("DEX_FILE");
  public static final byte[] ISSUE_1006 = load("ISSUE_1006");
  public static final byte[] ELF32_MIPS_FILE = load("ELF32_MIPS_FILE");
  public static final byte[] ELF_x64_FILE = load("ELF_x64_FILE");
  public static final byte[] ELF32_BE_BAD_SYMTAB_LINK = load("ELF32_BE_BAD_SYMTAB_LINK");
}
