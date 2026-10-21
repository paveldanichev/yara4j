package com.paveldan.yara4j.modules.magic;

import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YStructure;

/**
 * The "magic" module. Port of libyara/modules/magic/magic.c with libmagic replaced by a {@link
 * MagicProvider}. Results are cached for the duration of a scan, like libyara does.
 */
public final class MagicModule implements YaraModule {

  private static volatile MagicProvider defaultProvider;
  private static volatile boolean defaultLoaded;

  private final MagicProvider provider;

  /** Creates the module using the provider found with ServiceLoader, if any. */
  public MagicModule() {
    this(null);
  }

  /** Creates the module with an explicit provider (null to use the default one). */
  public MagicModule(MagicProvider provider) {
    this.provider = provider;
  }

  /** Sets the provider used by modules created without an explicit one. */
  public static void setProvider(MagicProvider p) {
    defaultProvider = p;
    defaultLoaded = true;
  }

  private static MagicProvider loadDefault() {
    if (!defaultLoaded) {
      synchronized (MagicModule.class) {
        if (!defaultLoaded) {
          MagicProvider found = null;
          try {
            Iterator<MagicProvider> it =
                ServiceLoader.load(MagicProvider.class, MagicModule.class.getClassLoader())
                    .iterator();
            if (it.hasNext()) {
              found = it.next();
            }
          } catch (ServiceConfigurationError e) {
            found = null;
          }
          defaultProvider = found;
          defaultLoaded = true;
        }
      }
    }
    return defaultProvider;
  }

  private MagicProvider provider() {
    return provider != null ? provider : loadDefault();
  }

  /** Per scan cache (the MAGIC_CACHE of libyara). */
  private static final class Cache {
    String type;
    String mimeType;
  }

  private Object result(FunctionCall c, boolean mime) {
    ScanContext context = c.context();
    if (context.isProcessMemory()) {
      return null;
    }
    MagicProvider p = provider();
    if (p == null) {
      return null;
    }
    Cache cache = (Cache) c.module().getData();
    if (cache == null) {
      return null;
    }
    String cached = mime ? cache.mimeType : cache.type;
    if (cached == null) {
      MemoryBlock block = context.firstBlock();
      if (block == null) {
        return null;
      }
      String r;
      try {
        r = mime ? p.mimeType(block.data().duplicate()) : p.type(block.data().duplicate());
      } catch (RuntimeException e) {
        r = null;
      }
      if (mime) {
        cache.mimeType = r;
      } else {
        cache.type = r;
      }
      cached = r;
    }
    return cached;
  }

  @Override
  public String name() {
    return "magic";
  }

  @Override
  public void declare(ModuleDeclarations d) {
    d.declareFunction("mime_type", "", "s", c -> result(c, true));
    d.declareFunction("type", "", "s", c -> result(c, false));
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {
    module.setData(new Cache());
  }

  @Override
  public void unload(YStructure module) {
    module.setData(null);
  }
}
