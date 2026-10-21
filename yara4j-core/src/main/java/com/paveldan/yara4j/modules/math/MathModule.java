package com.paveldan.yara4j.modules.math;

import java.util.Locale;
import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BlockData;

/** The "math" module. Port of libyara/modules/math/math.c. */
public final class MathModule implements YaraModule {
  private static final double PI = 3.141592653589793;

  @Override
  public String name() {
    return "math";
  }

  private static double log2(double x) {
    return Math.log(x) / Math.log(2.0);
  }

  private static long[] distribution(ScanContext ctx, long offset, long length) {
    long[] data = new long[256];
    boolean ok =
        BlockData.forRange(
            ctx,
            offset,
            length,
            (buf, off, len) -> {
              for (int i = 0; i < len; i++) {
                data[buf.get(off + i) & 0xFF]++;
              }
            });
    return ok ? data : null;
  }

  private static long[] distributionGlobal(ScanContext ctx) {
    long[] data = new long[256];
    boolean ok =
        BlockData.forAll(
            ctx,
            (buf, off, len) -> {
              for (int i = 0; i < len; i++) {
                data[buf.get(off + i) & 0xFF]++;
              }
            });
    return ok ? data : null;
  }

  private static double entropy(long[] data, long total) {
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
      if (data[i] != 0) {
        double x = (double) data[i] / total;
        entropy -= x * log2(x);
      }
    }
    return entropy;
  }

  private static Object stringEntropy(FunctionCall c) {
    byte[] s = c.stringArgument(1);
    long[] data = new long[256];
    for (byte b : s) {
      data[b & 0xFF]++;
    }
    return entropy(data, s.length);
  }

  private static Object dataEntropy(FunctionCall c) {
    long[] data = distribution(c.context(), c.integerArgument(1), c.integerArgument(2));
    if (data == null) {
      return null;
    }
    long total = 0;
    for (long v : data) {
      total += v;
    }
    return entropy(data, total);
  }

  private static Object stringDeviation(FunctionCall c) {
    byte[] s = c.stringArgument(1);
    double mean = c.floatArgument(2);
    double sum = 0.0;
    // libyara uses (signed) char values here.
    for (byte b : s) {
      sum += Math.abs(((double) b) - mean);
    }
    return sum / s.length;
  }

  private static Object dataDeviation(FunctionCall c) {
    long[] data = distribution(c.context(), c.integerArgument(1), c.integerArgument(2));
    if (data == null) {
      return null;
    }
    double mean = c.floatArgument(3);
    double sum = 0.0;
    long total = 0;
    for (int i = 0; i < 256; i++) {
      total += data[i];
      sum += Math.abs(((double) i) - mean) * data[i];
    }
    return sum / total;
  }

  private static Object stringMean(FunctionCall c) {
    byte[] s = c.stringArgument(1);
    double sum = 0.0;
    for (byte b : s) {
      sum += (double) b;
    }
    return sum / s.length;
  }

  private static Object dataMean(FunctionCall c) {
    long[] data = distribution(c.context(), c.integerArgument(1), c.integerArgument(2));
    if (data == null) {
      return null;
    }
    double sum = 0.0;
    long total = 0;
    for (int i = 0; i < 256; i++) {
      total += data[i];
      sum += ((double) i) * data[i];
    }
    return sum / total;
  }

  private static Object dataSerialCorrelation(FunctionCall c) {
    final double[] v = new double[6]; // sccfirst, scclast, scct1, scct2, scct3, totalLen
    long offset = c.integerArgument(1);
    long length = c.integerArgument(2);
    boolean ok =
        BlockData.forRange(
            c.context(),
            offset,
            length,
            (buf, off, len) -> {
              v[5] += len;
              for (int i = 0; i < len; i++) {
                double sccun = buf.get(off + i) & 0xFF;
                if (i == 0) {
                  v[0] = sccun;
                }
                v[2] += v[1] * sccun;
                v[3] += sccun;
                v[4] += sccun * sccun;
                v[1] = sccun;
              }
            });
    if (!ok) {
      return null;
    }
    double totalLen = v[5];
    double scct1 = v[2] + v[1] * v[0];
    double scct2 = v[3] * v[3];
    double scc = totalLen * v[4] - scct2;
    if (scc == 0) {
      scc = -100000;
    } else {
      scc = (totalLen * scct1 - scct2) / scc;
    }
    return scc;
  }

  private static Object stringSerialCorrelation(FunctionCall c) {
    byte[] s = c.stringArgument(1);
    double scclast = 0;
    double scct1 = 0;
    double scct2 = 0;
    double scct3 = 0;
    for (byte b : s) {
      double sccun = (double) b;
      scct1 += scclast * sccun;
      scct2 += sccun;
      scct3 += sccun * sccun;
      scclast = sccun;
    }
    if (s.length > 0) {
      scct1 += scclast * (double) s[0];
    }
    scct2 *= scct2;
    double scc = s.length * scct3 - scct2;
    if (scc == 0) {
      scc = -100000;
    } else {
      scc = (s.length * scct1 - scct2) / scc;
    }
    return scc;
  }

  private static final double INCIRC = Math.pow(Math.pow(256.0, 3.0) - 1, 2.0);

  private static Object dataMonteCarloPi(FunctionCall c) {
    final long[] monte = new long[6];
    final long[] counts = new long[2]; // mcount, inmont
    boolean ok =
        BlockData.forRange(
            c.context(),
            c.integerArgument(1),
            c.integerArgument(2),
            (buf, off, len) -> {
              for (int i = 0; i < len; i++) {
                monte[i % 6] = buf.get(off + i) & 0xFF;
                if (i % 6 == 5) {
                  double mx = 0;
                  double my = 0;
                  counts[0]++;
                  for (int j = 0; j < 3; j++) {
                    mx = (mx * 256.0) + monte[j];
                    my = (my * 256.0) + monte[j + 3];
                  }
                  if ((mx * mx + my * my) <= INCIRC) {
                    counts[1]++;
                  }
                }
              }
            });
    if (!ok || counts[0] == 0) {
      return null;
    }
    double mpi = 4.0 * ((double) counts[1] / counts[0]);
    return Math.abs((mpi - PI) / PI);
  }

  private static Object stringMonteCarloPi(FunctionCall c) {
    byte[] s = c.stringArgument(1);
    long[] monte = new long[6];
    int mcount = 0;
    int inmont = 0;
    for (int i = 0; i < s.length; i++) {
      // (unsigned int) of a signed char sign-extends.
      monte[i % 6] = ((long) s[i]) & 0xFFFFFFFFL;
      if (i % 6 == 5) {
        double mx = 0;
        double my = 0;
        mcount++;
        for (int j = 0; j < 3; j++) {
          mx = (mx * 256.0) + monte[j];
          my = (my * 256.0) + monte[j + 3];
        }
        if ((mx * mx + my * my) <= INCIRC) {
          inmont++;
        }
      }
    }
    if (mcount == 0) {
      return null;
    }
    double mpi = 4.0 * ((double) inmont / mcount);
    return Math.abs((mpi - PI) / PI);
  }

  private static long mode(long[] distribution) {
    int mostCommon = 0;
    for (int i = 0; i < 256; i++) {
      if (distribution[i] > distribution[mostCommon]) {
        mostCommon = i;
      }
    }
    return mostCommon;
  }

  private static Object percentage(long[] distribution, long b) {
    long count = distribution[(int) b];
    long total = 0;
    for (long v : distribution) {
      total += v;
    }
    return (double) (((float) count) / ((float) total));
  }

  @Override
  public void declare(ModuleDeclarations d) {
    d.declareFloat("MEAN_BYTES");
    d.declareFunction(
        "in_range",
        "fff",
        "i",
        c -> {
          double test = c.floatArgument(1);
          double lower = c.floatArgument(2);
          double upper = c.floatArgument(3);
          return (lower <= test && test <= upper) ? 1L : 0L;
        });
    d.declareFunction("deviation", "iif", "f", MathModule::dataDeviation);
    d.declareFunction("deviation", "sf", "f", MathModule::stringDeviation);
    d.declareFunction("mean", "ii", "f", MathModule::dataMean);
    d.declareFunction("mean", "s", "f", MathModule::stringMean);
    d.declareFunction("serial_correlation", "ii", "f", MathModule::dataSerialCorrelation);
    d.declareFunction("serial_correlation", "s", "f", MathModule::stringSerialCorrelation);
    d.declareFunction("monte_carlo_pi", "ii", "f", MathModule::dataMonteCarloPi);
    d.declareFunction("monte_carlo_pi", "s", "f", MathModule::stringMonteCarloPi);
    d.declareFunction("entropy", "ii", "f", MathModule::dataEntropy);
    d.declareFunction("entropy", "s", "f", MathModule::stringEntropy);
    d.declareFunction(
        "min",
        "ii",
        "i",
        c -> {
          long i = c.integerArgument(1);
          long j = c.integerArgument(2);
          return Long.compareUnsigned(i, j) < 0 ? i : j;
        });
    d.declareFunction(
        "max",
        "ii",
        "i",
        c -> {
          long i = c.integerArgument(1);
          long j = c.integerArgument(2);
          return Long.compareUnsigned(i, j) > 0 ? i : j;
        });
    d.declareFunction("to_number", "b", "i", c -> c.integerArgument(1) != 0 ? 1L : 0L);
    d.declareFunction("abs", "i", "i", c -> Math.abs(c.integerArgument(1)));
    d.declareFunction(
        "count",
        "iii",
        "i",
        c -> {
          long b = c.integerArgument(1);
          if (b < 0 || b > 255) {
            return YObject.UNDEFINED;
          }
          long[] dist = distribution(c.context(), c.integerArgument(2), c.integerArgument(3));
          return dist == null ? YObject.UNDEFINED : dist[(int) b];
        });
    d.declareFunction(
        "count",
        "i",
        "i",
        c -> {
          long b = c.integerArgument(1);
          if (b < 0 || b > 255) {
            return YObject.UNDEFINED;
          }
          long[] dist = distributionGlobal(c.context());
          return dist == null ? YObject.UNDEFINED : dist[(int) b];
        });
    d.declareFunction(
        "percentage",
        "iii",
        "f",
        c -> {
          long b = c.integerArgument(1);
          if (b < 0 || b > 255) {
            return null;
          }
          long[] dist = distribution(c.context(), c.integerArgument(2), c.integerArgument(3));
          return dist == null ? null : percentage(dist, b);
        });
    d.declareFunction(
        "percentage",
        "i",
        "f",
        c -> {
          long b = c.integerArgument(1);
          if (b < 0 || b > 255) {
            return null;
          }
          long[] dist = distributionGlobal(c.context());
          return dist == null ? null : percentage(dist, b);
        });
    d.declareFunction(
        "mode",
        "ii",
        "i",
        c -> {
          long[] dist = distribution(c.context(), c.integerArgument(1), c.integerArgument(2));
          return dist == null ? YObject.UNDEFINED : mode(dist);
        });
    d.declareFunction(
        "mode",
        "",
        "i",
        c -> {
          long[] dist = distributionGlobal(c.context());
          return dist == null ? YObject.UNDEFINED : mode(dist);
        });
    d.declareFunction("to_string", "i", "s", c -> Long.toString(c.integerArgument(1)));
    d.declareFunction(
        "to_string",
        "ii",
        "s",
        c -> {
          long i = c.integerArgument(1);
          long base = c.integerArgument(2);
          if (base == 10) {
            return Long.toString(i);
          } else if (base == 8) {
            return Long.toOctalString(i);
          } else if (base == 16) {
            return Long.toHexString(i).toLowerCase(Locale.ROOT);
          }
          return null;
        });
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {
    module.setFloat(127.5, "MEAN_BYTES");
  }
}
