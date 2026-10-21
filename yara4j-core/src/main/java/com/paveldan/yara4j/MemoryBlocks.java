package com.paveldan.yara4j;

import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import com.paveldan.yara4j.module.MemoryBlock;

/** Factory methods for memory blocks. */
public final class MemoryBlocks {
  private MemoryBlocks() {}

  /** Maximum size of a single block. Larger files are split in several blocks. */
  public static final int MAX_BLOCK_SIZE = Integer.MAX_VALUE - 8;

  /**
   * Whether {@link Scanner#scan(Path)} releases the file mapping as soon as the scan ends, like
   * libyara's yr_filemap_unmap, instead of leaving it to the garbage collector. Windows doesn't
   * allow deleting, renaming or writing a file while it's mapped, so this is the default there.
   * Other systems don't need it, and their scans are unchanged. The system property
   * {@code yara4j.unmap} ({@code true} or {@code false}) overrides the default.
   */
  static final boolean UNMAP_AFTER_SCAN =
      Boolean.parseBoolean(
          System.getProperty(
              "yara4j.unmap",
              String.valueOf(System.getProperty("os.name", "").startsWith("Windows"))));

  /**
   * sun.misc.Unsafe.invokeCleaner(ByteBuffer), which unmaps a mapped buffer immediately (the
   * standard API to do it, java.lang.foreign, needs Java 22). Null if not available.
   */
  private static final MethodHandle UNMAPPER = unmapper();

  private static MethodHandle unmapper() {
    try {
      Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
      Field f = unsafeClass.getDeclaredField("theUnsafe");
      f.setAccessible(true);
      return MethodHandles.lookup()
          .findVirtual(
              unsafeClass, "invokeCleaner", MethodType.methodType(void.class, ByteBuffer.class))
          .bindTo(f.get(null));
    } catch (ReflectiveOperationException | RuntimeException e) {
      return null;
    }
  }

  private static final class BufferBlock implements MemoryBlock {
    private final long base;
    private final ByteBuffer data;

    BufferBlock(long base, ByteBuffer data) {
      this.base = base;
      this.data = data;
    }

    @Override
    public long base() {
      return base;
    }

    @Override
    public int size() {
      return data.limit();
    }

    @Override
    public ByteBuffer data() {
      return data;
    }
  }

  /** Creates a block from a byte array. */
  public static MemoryBlock of(byte[] data, long base) {
    return new ArrayBlock(base, data);
  }

  /** A block backed by an array, which allows faster access during the scan. */
  private static final class ArrayBlock
      implements MemoryBlock, com.paveldan.yara4j.internal.ArrayBacked {
    private final long base;
    private final byte[] array;
    private final ByteBuffer data;

    ArrayBlock(long base, byte[] array) {
      this.base = base;
      this.array = array;
      this.data = ByteBuffer.wrap(array).asReadOnlyBuffer();
    }

    @Override
    public long base() {
      return base;
    }

    @Override
    public int size() {
      return array.length;
    }

    @Override
    public ByteBuffer data() {
      return data;
    }

    @Override
    public byte[] array() {
      return array;
    }

    @Override
    public int arrayOffset() {
      return 0;
    }
  }

  /** Creates a block from a buffer, from its position to its limit. */
  public static MemoryBlock of(ByteBuffer data, long base) {
    ByteBuffer b = data.slice().asReadOnlyBuffer();
    return new BufferBlock(base, b);
  }

  /**
   * Maps a file in memory. Files larger than {@link #MAX_BLOCK_SIZE} are split in multiple
   * blocks, as libyara does with process memory, so strings spanning two blocks won't match.
   *
   * <p>The mapping is released when the buffers are garbage collected. On Windows the file can't
   * be deleted, renamed or written until then; {@link Scanner#scan(Path)} doesn't have this
   * problem.
   */
  public static List<MemoryBlock> mapFile(Path path) throws IOException {
    try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
      long size = ch.size();
      if (size == 0) {
        return Collections.singletonList(of(new byte[0], 0));
      }
      List<MemoryBlock> blocks = new ArrayList<>();
      long pos = 0;
      while (pos < size) {
        long len = Math.min(MAX_BLOCK_SIZE, size - pos);
        ByteBuffer b = ch.map(FileChannel.MapMode.READ_ONLY, pos, len);
        blocks.add(new BufferBlock(pos, b));
        pos += len;
      }
      return blocks;
    }
  }

  /**
   * Opens a file for {@link Scanner#scan(Path)}: maps it, or reads it in memory when its mapping
   * must be released after the scan and that isn't possible with this JVM.
   */
  static List<MemoryBlock> openFile(Path path) throws IOException {
    if (!UNMAP_AFTER_SCAN || UNMAPPER != null) {
      return mapFile(path);
    }
    try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
      long size = ch.size();
      List<MemoryBlock> blocks = new ArrayList<>();
      long pos = 0;
      do {
        byte[] b = new byte[(int) Math.min(MAX_BLOCK_SIZE, size - pos)];
        ByteBuffer bb = ByteBuffer.wrap(b);
        while (bb.hasRemaining() && ch.read(bb, pos + bb.position()) >= 0) {}
        int n = bb.position();
        blocks.add(new ArrayBlock(pos, n == b.length ? b : Arrays.copyOf(b, n)));
        pos += b.length;
      } while (pos < size);
      return blocks;
    }
  }

  /**
   * Releases the mappings of blocks returned by {@link #openFile} if {@link #UNMAP_AFTER_SCAN}.
   * The blocks must not be used afterwards: accessing an unmapped buffer crashes the JVM.
   */
  static void closeFile(List<MemoryBlock> blocks) {
    if (!UNMAP_AFTER_SCAN || UNMAPPER == null) {
      return;
    }
    for (MemoryBlock block : blocks) {
      if (block instanceof BufferBlock && ((BufferBlock) block).data.isDirect()) {
        try {
          UNMAPPER.invokeExact(((BufferBlock) block).data);
        } catch (Throwable e) {
          // Left to the garbage collector.
        }
      }
    }
  }
}
