package com.paveldan.yara4j.magic.tika;

import java.io.IOException;
import java.nio.ByteBuffer;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.mime.MediaType;
import org.apache.tika.mime.MimeType;
import org.apache.tika.mime.MimeTypeException;
import org.apache.tika.mime.MimeTypes;
import org.apache.tika.parser.ParseContext;

/**
 * {@link com.paveldan.yara4j.modules.magic.MagicProvider} based on the MIME type detection of
 * Apache Tika (tika-core). MIME types are usually the same as libmagic's for common formats, but
 * the descriptions returned by {@code magic.type()} come from Tika's type registry and differ from
 * libmagic's strings.
 */
public final class TikaMagicProvider implements com.paveldan.yara4j.modules.magic.MagicProvider {

  private final MimeTypes mimeTypes;

  public TikaMagicProvider() {
    this(MimeTypes.getDefaultMimeTypes());
  }

  public TikaMagicProvider(MimeTypes mimeTypes) {
    this.mimeTypes = mimeTypes;
  }

  private MediaType detect(ByteBuffer data) {
    int n = Math.min(data.remaining(), Math.max(mimeTypes.getMinLength(), 64 * 1024));
    byte[] prefix = new byte[n];
    data.duplicate().get(prefix);
    try (TikaInputStream in = TikaInputStream.get(prefix)) {
      return mimeTypes.detect(in, new Metadata(), new ParseContext());
    } catch (IOException e) {
      return null;
    }
  }

  @Override
  public String mimeType(ByteBuffer data) {
    MediaType type = detect(data);
    return type == null ? null : type.getBaseType().toString();
  }

  @Override
  public String type(ByteBuffer data) {
    MediaType type = detect(data);
    if (type == null) {
      return null;
    }
    try {
      MimeType mt = mimeTypes.forName(type.getBaseType().toString());
      String description = mt.getDescription();
      if (description != null && !description.isEmpty()) {
        return description;
      }
    } catch (MimeTypeException e) {
      // Fall back to the MIME type.
    }
    return type.getBaseType().toString();
  }
}
