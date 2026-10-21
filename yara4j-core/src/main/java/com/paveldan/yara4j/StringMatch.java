package com.paveldan.yara4j;

/** A match of a string in the scanned data. */
public final class StringMatch {
  private final String identifier;
  private final long offset;
  private final long base;
  private final int length;
  private final byte[] data;
  private final int xorKey;
  private final boolean isPrivate;
  private final boolean isHex;

  StringMatch(
      String identifier,
      long base,
      long offset,
      int length,
      byte[] data,
      int xorKey,
      boolean isPrivate,
      boolean isHex) {
    this.identifier = identifier;
    this.base = base;
    this.offset = offset;
    this.length = length;
    this.data = data;
    this.xorKey = xorKey;
    this.isPrivate = isPrivate;
    this.isHex = isHex;
  }

  /** True if the string is a hex string (like { 4D 5A }). */
  public boolean isHex() {
    return isHex;
  }

  /** Identifier of the matching string, like "$a". */
  public String getIdentifier() {
    return identifier;
  }

  /** Offset of the match (base + offset within the block). */
  public long getOffset() {
    return base + offset;
  }

  /** Base address of the memory block containing the match. */
  public long getBase() {
    return base;
  }

  /** Length of the match in bytes. */
  public int getLength() {
    return length;
  }

  /** Matching data, truncated to the maximum match data length (512 bytes by default). */
  public byte[] getData() {
    return data == null ? new byte[0] : data.clone();
  }

  /** XOR key for strings with the xor modifier, 0 otherwise. */
  public int getXorKey() {
    return xorKey;
  }

  public boolean isPrivate() {
    return isPrivate;
  }

  @Override
  public String toString() {
    return "0x" + Long.toHexString(getOffset()) + ":" + identifier;
  }
}
