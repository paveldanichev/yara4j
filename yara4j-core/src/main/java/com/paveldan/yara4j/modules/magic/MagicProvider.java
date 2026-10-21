package com.paveldan.yara4j.modules.magic;

import java.nio.ByteBuffer;

/**
 * Service provider used by the "magic" module to identify file types. libyara uses libmagic,
 * which isn't available in pure Java; implementations are discovered with {@link
 * java.util.ServiceLoader} (the yara4j-magic-tika artifact provides one based on Apache Tika) or
 * can be set explicitly with {@link MagicModule#setProvider}. Without a provider {@code
 * magic.type()} and {@code magic.mime_type()} are undefined.
 *
 * <p>Implementations must be thread-safe.
 */
public interface MagicProvider {
  /**
   * Returns a human readable description of the data (the equivalent of {@code file -b}), or
   * null if unknown. The buffer must not be modified.
   */
  String type(ByteBuffer data);

  /** Returns the MIME type of the data (like {@code file -b --mime-type}), or null. */
  String mimeType(ByteBuffer data);
}
