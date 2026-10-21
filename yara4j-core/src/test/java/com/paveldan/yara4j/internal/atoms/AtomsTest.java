package com.paveldan.yara4j.internal.atoms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.internal.re.HexParser;
import com.paveldan.yara4j.internal.re.ReAst;
import com.paveldan.yara4j.internal.re.RegexParser;

/** Port of YARA's tests/test-atoms.c. */
class AtomsTest {

  private static Atoms.Atom atom(int[] bytes, int[] mask) {
    Atoms.Atom a = new Atoms.Atom();
    a.length = bytes.length;
    for (int i = 0; i < bytes.length; i++) {
      a.bytes[i] = bytes[i];
      a.mask[i] = mask == null ? 0xFF : mask[i];
    }
    return a;
  }

  private static Atoms.Atom atom(int... bytes) {
    return atom(bytes, null);
  }

  private static byte[] table(int[][] entries) {
    byte[] t = new byte[entries.length * 5];
    for (int i = 0; i < entries.length; i++) {
      for (int j = 0; j < 5; j++) {
        t[i * 5 + j] = (byte) entries[i][j];
      }
    }
    return t;
  }

  @Test
  void testTableQuality() {
    Atoms.QualityFunction l1 =
        Atoms.tableQuality(table(new int[][] {{0, 0, 0, 0, 1}, {0, 0, 0, 1, 2}, {0, 0, 0, 2, 3}}));
    Atoms.QualityFunction l2 =
        Atoms.tableQuality(
            table(
                new int[][] {
                  {0, 0, 0, 0, 1}, {0, 0, 0, 1, 2}, {0, 0, 0, 2, 3}, {0, 0, 0, 3, 4}
                }));
    Atoms.Atom a0 = atom(0, 0, 0, 0);
    Atoms.Atom a1 = atom(0, 0, 0, 1);
    Atoms.Atom a2 = atom(0, 0, 0, 2);
    Atoms.Atom a3 = atom(0, 0, 0, 3);
    Atoms.Atom a4 = atom(new int[] {0, 0, 0, 0}, new int[] {0xFF, 0xFF, 0xFF, 0x00});
    assertEquals(1, l1.quality(a0));
    assertEquals(2, l1.quality(a1));
    assertEquals(3, l1.quality(a2));
    assertEquals(Atoms.MAX_ATOM_QUALITY, l1.quality(a3));
    assertEquals(1, l2.quality(a0));
    assertEquals(2, l2.quality(a1));
    assertEquals(3, l2.quality(a2));
    assertEquals(4, l2.quality(a3));
    assertEquals(1, l2.quality(a4));
  }

  private static int q(Atoms.Atom a) {
    return Atoms.heuristicQuality(a);
  }

  @Test
  void testHeuristicQuality() {
    int q00000000 = q(atom(0, 0, 0, 0));
    int q00000001 = q(atom(0, 0, 0, 1));
    int q00000102 = q(atom(0, 0, 1, 2));
    int q00010203 = q(atom(0, 1, 2, 3));
    int q01020304 = q(atom(1, 2, 3, 4));
    int q010203 = q(atom(1, 2, 3));
    int q0102 = q(atom(1, 2));
    int q01 = q(atom(1));
    int q0001 = q(atom(0, 1));
    int q000001 = q(atom(0, 0, 1));
    int q000102 = q(atom(0, 1, 2));
    int q01020000 = q(atom(1, 2, 0, 0));
    int q0102XX04 = q(atom(new int[] {1, 2, 3, 4}, new int[] {0xFF, 0xFF, 0x00, 0xFF}));
    int q01010101 = q(atom(1, 1, 1, 1));
    int q01020102 = q(atom(1, 2, 1, 2));
    int q20202020 = q(atom(0x20, 0x20, 0x20, 0x20));
    int q90909090 = q(atom(0x90, 0x90, 0x90, 0x90));
    int qCCCCCCCC = q(atom(0xCC, 0xCC, 0xCC, 0xCC));
    int qFFFFFFFF = q(atom(0xFF, 0xFF, 0xFF, 0xFF));
    int q61626364 = q(atom(0x61, 0x62, 0x63, 0x64));
    int q41424344 = q(atom(0x41, 0x42, 0x43, 0x44));
    int q6162632E = q(atom(0x61, 0x62, 0x63, 0x2E));
    int q01XX03 = q(atom(new int[] {1, 2, 3}, new int[] {0xFF, 0x00, 0xFF}));
    int q01X203 = q(atom(new int[] {1, 2, 3}, new int[] {0xFF, 0x0F, 0xFF}));
    int q010X03 = q(atom(new int[] {1, 2, 3}, new int[] {0xFF, 0x0F, 0xFF}));
    int q010X0X = q(atom(new int[] {1, 2, 3}, new int[] {0xFF, 0x0F, 0x0F}));

    assertTrue(q00000001 > q00000000);
    assertTrue(q00000001 > q000001);
    assertTrue(q000001 > q0001);
    assertTrue(q00000102 > q00000001);
    assertTrue(q00010203 > q00000102);
    assertTrue(q01020304 > q00010203);
    assertTrue(q000102 > q000001);
    assertTrue(q00010203 > q010203);
    assertTrue(q010203 > q0102);
    assertTrue(q010203 > q00000000);
    assertTrue(q0102 > q01);
    assertTrue(q01X203 > q0102);
    assertTrue(q01X203 > q0001);
    assertTrue(q01X203 < q010203);
    assertTrue(q01X203 == q010X03);
    assertTrue(q01XX03 <= q0102);
    assertTrue(q01XX03 < q010X03);
    assertTrue(q01XX03 < q010203);
    assertTrue(q010X0X > q01);
    assertTrue(q010X0X < q010203);
    assertTrue(q01020000 > q0102XX04);
    assertTrue(q01020102 > q01010101);
    assertTrue(q01020304 > q01020102);
    assertTrue(q01020102 > q010203);
    assertTrue(q01020304 > q61626364);
    assertTrue(q010203 < q61626364);
    assertTrue(q41424344 == q61626364);
    assertTrue(q6162632E > q61626364);
    assertTrue(q90909090 < q01010101);
    assertTrue(q20202020 < q01010101);
    assertTrue(qCCCCCCCC < q01010101);
    assertTrue(qFFFFFFFF < q01010101);
    assertEquals(Atoms.MAX_ATOM_QUALITY, q01020304);
  }

  /** Port of _assert_atoms: actual atoms must be a prefix of the expected ones. */
  private static void assertAtoms(ReAst ast, int[][] expected) {
    Atoms.Extraction e = Atoms.extractFromRe(Atoms.HEURISTIC, ast, 0);
    List<int[]> actual = new ArrayList<>();
    for (Atoms.AtomListItem a = e.atoms; a != null; a = a.next) {
      int[] b = new int[a.atom.length];
      System.arraycopy(a.atom.bytes, 0, b, 0, a.atom.length);
      actual.add(b);
    }
    assertTrue(actual.size() <= expected.length, "too many atoms: " + actual.size());
    for (int i = 0; i < actual.size(); i++) {
      assertArrayEquals(expected[i], actual.get(i), "atom " + i);
    }
  }

  private static void assertReAtoms(String re, int[]... expected) {
    RegexParser.Result r = RegexParser.parse(re.getBytes(StandardCharsets.ISO_8859_1), false);
    assertAtoms(r.ast, expected);
  }

  private static void assertHexAtoms(String hex, int[]... expected) {
    RegexParser.Result r = HexParser.parse(hex.getBytes(StandardCharsets.ISO_8859_1));
    assertAtoms(r.ast, expected);
  }

  private static int[] a(int... b) {
    return b;
  }

  @Test
  void testAtomChoose() {
    int[][] atoms61XX6364 = new int[256][];
    for (int i = 0; i < 256; i++) {
      atoms61XX6364[i] = a(0x61, i, 0x63, 0x64);
    }
    int[][] atoms61620X64 = new int[16][];
    int[][] atoms616X63 = new int[16][];
    for (int i = 0; i < 16; i++) {
      atoms61620X64[i] = a(0x61, 0x62, i, 0x64);
      atoms616X63[i] = a(0x61, 0x60 + i, 0x63);
    }
    assertReAtoms("abcd", a(0x61, 0x62, 0x63, 0x64));
    assertReAtoms("abcd1234", a(0x31, 0x32, 0x33, 0x34));
    assertReAtoms("a..d", a(0x61));
    assertReAtoms("a..de", a(0x64, 0x65));
    assertReAtoms("abcd.efgh", a(0x61, 0x62, 0x63, 0x64));
    assertReAtoms("(abcd|efgh)", a(0x65, 0x66, 0x67, 0x68), a(0x61, 0x62, 0x63, 0x64));
    assertReAtoms(
        "(abcd|efgh|ij)", a(0x69, 0x6A), a(0x65, 0x66, 0x67, 0x68), a(0x61, 0x62, 0x63, 0x64));
    assertReAtoms("a.cd", atoms61XX6364);
    assertHexAtoms("{61 62 63 64}", a(0x61, 0x62, 0x63, 0x64));
    assertHexAtoms("{61 62 63 64 [1-5] 65 66 67 68}", a(0x61, 0x62, 0x63, 0x64));
    assertHexAtoms("{61 62 63 [1-5] 65 66 67 68}", a(0x65, 0x66, 0x67, 0x68));
    assertHexAtoms("{61 62 63 [1-5] 65 66 }", a(0x61, 0x62, 0x63));
    assertHexAtoms("{61 6? 63 [1-5] 65 66}", atoms616X63);
    assertHexAtoms("{(61 62 63 | 65 66 67 68)}", a(0x65, 0x66, 0x67, 0x68), a(0x61, 0x62, 0x63));
    assertHexAtoms("{61 62 0? 64}", atoms61620X64);
    assertHexAtoms("{11 ?? 11 ?? 22 33 44 55 66}", a(0x22, 0x33, 0x44, 0x55));
    assertHexAtoms("{68 ?? ?? 00 00 58}", a(0x00, 0x00, 0x58));
    assertHexAtoms("{69 ?? a0 0d 00}", a(0xa0, 0x0d, 0x00));
    assertHexAtoms("{?? 11 22 33 ?? 55 66}", a(0x11, 0x22, 0x33));
    assertReAtoms("foobar\\.{128}", a(0x62, 0x61, 0x72, 0x2e));
    assertHexAtoms(
        "{(61 61 62 63 64 ?? | 65 ?? ?? 00 00 66)}", a(0x00, 0x00, 0x66), a(0x61, 0x62, 0x63, 0x64));
  }
}
