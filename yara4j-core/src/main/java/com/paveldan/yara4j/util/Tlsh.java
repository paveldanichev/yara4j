package com.paveldan.yara4j.util;

/**
 * TLSH (Trend Micro Locality Sensitive Hash) with 128 buckets and 1 byte checksum, the
 * configuration used by libyara for the ELF module's telfhash function. Port of libyara's
 * tlshc, which is derived from https://github.com/trendmicro/tlsh (Apache 2.0 / BSD).
 */
public final class Tlsh {
  private Tlsh() {}

  private static final int EFF_BUCKETS = 128;
  private static final int CODE_SIZE = 32;
  private static final int MIN_DATA_LENGTH = 50;

  private static final int[] V_TABLE = {
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84,
    249, 230, 44, 163, 14, 197, 213, 181, 161, 85, 218, 80,
    64, 239, 24, 226, 236, 142, 38, 200, 110, 177, 104, 103,
    141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214,
    244, 227, 149, 235, 97, 234, 57, 22, 60, 250, 82, 175,
    208, 5, 127, 199, 111, 62, 135, 248, 174, 169, 211, 58,
    66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13,
    153, 246, 216, 219, 119, 68, 223, 78, 83, 88, 201, 99,
    122, 11, 92, 32, 136, 114, 52, 10, 138, 30, 48, 183,
    156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220,
    90, 53, 23, 131, 125, 173, 15, 238, 79, 95, 89, 16,
    105, 137, 225, 224, 217, 160, 37, 123, 118, 73, 2, 157,
    46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247,
    19, 205, 39, 203, 233, 40, 186, 147, 198, 192, 155, 33,
    164, 191, 98, 204, 165, 180, 117, 76, 140, 36, 210, 172,
    41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43,
    71, 109, 184, 209,
  };

  private static final long[] TOPVAL = {
    1, 2, 3, 5, 7, 11,
    17, 25, 38, 57, 86, 129,
    194, 291, 437, 656, 854, 1110,
    1443, 1876, 2439, 3171, 3475, 3823,
    4205, 4626, 5088, 5597, 6157, 6772,
    7450, 8195, 9014, 9916, 10907, 11998,
    13198, 14518, 15970, 17567, 19323, 21256,
    23382, 25720, 28292, 31121, 34233, 37656,
    41422, 45564, 50121, 55133, 60646, 66711,
    73382, 80721, 88793, 97672, 107439, 118183,
    130002, 143002, 157302, 173032, 190335, 209369,
    230306, 253337, 278670, 306538, 337191, 370911,
    408002, 448802, 493682, 543050, 597356, 657091,
    722800, 795081, 874589, 962048, 1058252, 1164078,
    1280486, 1408534, 1549388, 1704327, 1874759, 2062236,
    2268459, 2495305, 2744836, 3019320, 3321252, 3653374,
    4018711, 4420582, 4862641, 5348905, 5883796, 6472176,
    7119394, 7831333, 8614467, 9475909, 10423501, 11465851,
    12612437, 13873681, 15261050, 16787154, 18465870, 20312458,
    22343706, 24578077, 27035886, 29739474, 32713425, 35984770,
    39583245, 43541573, 47895730, 52685306, 57953837, 63749221,
    70124148, 77136564, 84850228, 93335252, 102668779, 112935659,
    124229227, 136652151, 150317384, 165349128, 181884040, 200072456,
    220079703, 242087671, 266296456, 292926096, 322218735, 354440623,
    389884688, 428873168, 471760495, 518936559, 570830240, 627913311,
    690704607, 759775136, 835752671, 919327967, 1011260767, 1112386880,
    1223623232, 1345985727, 1480584256, 1628642751, 1791507135, 1970657856,
    2167723648L, 2384496256L, 2622945920L, 2885240448L, 3173764736L, 3491141248L,
    3840255616L, 4224281216L,
  };

  private static int b(int ms, int i, int j, int k) {
    return V_TABLE[V_TABLE[V_TABLE[ms ^ i] ^ j] ^ k];
  }

  private static int lCapturing(long len) {
    int bottom = 0;
    int top = 170;
    int idx = 85;
    while (true) {
      if (idx == 0) {
        return idx;
      }
      if (len <= TOPVAL[idx] && len > TOPVAL[idx - 1]) {
        return idx;
      }
      if (len < TOPVAL[idx]) {
        top = idx - 1;
      } else {
        bottom = idx + 1;
      }
      idx = ((bottom + top) / 2) & 0xFF;
    }
  }

  private static int swapByte(int in) {
    return ((in & 0xF0) >> 4) | ((in & 0x0F) << 4) & 0xF0;
  }

  /**
   * Computes the TLSH hash of the data, returns the hash with the "T1" version prefix or null
   * if the data doesn't produce a valid hash (too short or not enough variation).
   */
  public static String hash(byte[] data) {
    long[] bucket = new long[256];
    int[] window = new int[5];
    int checksum = 0;
    int len = data.length;
    for (int i = 0; i < len; i++) {
      int j = i % 5;
      window[j] = data[i] & 0xFF;
      if (i >= 4) {
        int j1 = (j + 4) % 5;
        int j2 = (j + 3) % 5;
        int j3 = (j + 2) % 5;
        int j4 = (j + 1) % 5;
        int w0 = window[j];
        checksum = b(1, w0, window[j1], checksum);
        bucket[b(49, w0, window[j1], window[j2])]++;
        bucket[b(12, w0, window[j1], window[j3])]++;
        bucket[b(178, w0, window[j2], window[j3])]++;
        bucket[b(166, w0, window[j2], window[j4])]++;
        bucket[b(84, w0, window[j1], window[j4])]++;
        bucket[b(230, w0, window[j3], window[j4])]++;
      }
    }
    if (len < MIN_DATA_LENGTH) {
      return null;
    }
    long[] copy = java.util.Arrays.copyOf(bucket, EFF_BUCKETS);
    java.util.Arrays.sort(copy);
    long q1 = copy[EFF_BUCKETS / 4 - 1];
    long q2 = copy[EFF_BUCKETS / 2 - 1];
    long q3 = copy[EFF_BUCKETS - EFF_BUCKETS / 4 - 1];
    if (q3 == 0) {
      return null;
    }
    int nonzero = 0;
    for (int i = 0; i < CODE_SIZE * 4; i++) {
      if (bucket[i] > 0) {
        nonzero++;
      }
    }
    if (nonzero <= 4 * CODE_SIZE / 2) {
      return null;
    }
    int[] code = new int[CODE_SIZE];
    for (int i = 0; i < CODE_SIZE; i++) {
      int h = 0;
      for (int j = 0; j < 4; j++) {
        long k = bucket[4 * i + j];
        if (q3 < k) {
          h += 3 << (j * 2);
        } else if (q2 < k) {
          h += 2 << (j * 2);
        } else if (q1 < k) {
          h += 1 << (j * 2);
        }
      }
      code[i] = h & 0xFF;
    }
    int lvalue = lCapturing(len);
    int q1ratio = (int) ((long) ((float) (q1 * 100) / (float) q3) % 16);
    int q2ratio = (int) ((long) ((float) (q2 * 100) / (float) q3) % 16);
    int qb = (q1ratio & 0xF) | (q2ratio & 0xF) << 4;
    StringBuilder sb = new StringBuilder("T1");
    hex(sb, swapByte(checksum));
    hex(sb, swapByte(lvalue));
    hex(sb, swapByte(qb));
    for (int i = 0; i < CODE_SIZE; i++) {
      hex(sb, code[CODE_SIZE - 1 - i]);
    }
    return sb.toString();
  }

  private static void hex(StringBuilder sb, int b) {
    sb.append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, 16)));
    sb.append(Character.toUpperCase(Character.forDigit(b & 0xF, 16)));
  }
}
