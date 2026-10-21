package com.paveldan.yara4j.internal.re;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.internal.YaraError;

/** Port of YARA's tests/test-re-split.c. */
class ReSplitTest {

  @Test
  void testSplitAtChainingPoint() {
    RegexParser.Result r =
        HexParser.parse(
            "{ 01 02 03 04 [0-300] 05 06 07 08 [1-400] 09 0A 0B 0C }"
                .getBytes(StandardCharsets.ISO_8859_1));
    ReAst ast = r.ast;
    assertNotNull(ast);
    ReEmitter.Split s = ReEmitter.splitAtChainingPoint(ast);
    assertNotNull(s.remainder);
    assertEquals(0, s.minGap);
    assertEquals(300, s.maxGap);
    ast = s.remainder;
    s = ReEmitter.splitAtChainingPoint(ast);
    assertNotNull(s.remainder);
    assertEquals(1, s.minGap);
    assertEquals(400, s.maxGap);
    ast = s.remainder;
    s = ReEmitter.splitAtChainingPoint(ast);
    assertNull(s.remainder);
  }

  private static ErrorCode exec(byte[] code) {
    ReExec exec = new ReExec();
    YaraError e =
        assertThrows(
            YaraError.class,
            () ->
                exec.exec(
                    code,
                    0,
                    ByteBuffer.wrap(new byte[1]),
                    0,
                    1,
                    0,
                    Re.FLAGS_SCAN,
                    (start, len, flags) -> {}));
    return e.code();
  }

  @Test
  void testSplitIdOverflow() {
    int count = Re.MAX_SPLIT_ID + 64;
    byte[] code = new byte[count * 4 + 1];
    for (int i = 0; i < count; i++) {
      int offset = (count - i) * 4;
      code[i * 4] = (byte) Re.OP_SPLIT_A;
      code[i * 4 + 1] = (byte) i;
      code[i * 4 + 2] = (byte) offset;
      code[i * 4 + 3] = (byte) (offset >> 8);
    }
    code[count * 4] = (byte) Re.OP_MATCH;
    assertEquals(ErrorCode.INTERNAL_FATAL_ERROR, exec(code));
  }

  @Test
  void testRepeatStackOverflow() {
    int instrSize = 9;
    int count = Re.MAX_STACK + 64;
    byte[] code = new byte[count * instrSize + 1];
    for (int i = 0; i < count; i++) {
      int p = i * instrSize;
      code[p] = (byte) Re.OP_REPEAT_START_GREEDY;
      code[p + 1] = 1;
      code[p + 3] = 2;
    }
    code[count * instrSize] = (byte) Re.OP_MATCH;
    assertEquals(ErrorCode.INTERNAL_FATAL_ERROR, exec(code));
  }

  @Test
  void testRepeatStackUnderflow() {
    byte[] code = new byte[10];
    code[0] = (byte) Re.OP_REPEAT_END_GREEDY;
    code[1] = 1;
    code[3] = 2;
    code[9] = (byte) Re.OP_MATCH;
    assertEquals(ErrorCode.INTERNAL_FATAL_ERROR, exec(code));
  }
}
