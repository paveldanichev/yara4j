package com.paveldan.yara4j.internal.exec;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.internal.YaraError;
import com.paveldan.yara4j.internal.re.ReExec;
import com.paveldan.yara4j.internal.rules.RuleSet;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;

/**
 * Per-scan state: matches, rule results, loaded module objects, loop variables, etc. This is
 * the equivalent of libyara's YR_SCAN_CONTEXT (aka YR_SCANNER).
 */
public final class ExecContext implements ScanContext {
  public static final int MAX_LOOP_NESTING = 4;
  public static final int MAX_LOOP_VARS = 2;
  public static final int INTERNAL_LOOP_VARS = 3;
  public static final int MEM_SIZE = MAX_LOOP_NESTING * (MAX_LOOP_VARS + INTERNAL_LOOP_VARS);
  public static final int MAX_STRING_MATCHES = 1000000;
  public static final int SLOW_STRING_MATCHES = 600000;

  /** Receives console messages, used by the console module. */
  public interface ConsoleListener {
    void log(String message);
  }

  public final RuleSet rules;
  public final MatchList[] matches;
  public final MatchList[] unconfirmedMatches;
  public final boolean[] ruleMatches;
  public final boolean[] nsUnsatisfied;
  public final boolean[] requiredEval;
  public final boolean[] stringsTempDisabled;
  /** Disabled rules (yr_rule_disable), per scanner. */
  public final boolean[] ruleDisabled;

  public long fileSize = YObject.UNDEFINED;
  public long entryPoint = YObject.UNDEFINED;
  public List<MemoryBlock> blocks = Collections.emptyList();

  /** Root objects (externals and modules) indexed as in {@link RuleSet#rootObjects}. */
  public final YObject[] rootObjects;

  public final long[] memLong = new long[MEM_SIZE];
  public final Object[] memObj = new Object[MEM_SIZE];

  public final ReExec reExec = new ReExec();

  public boolean fastMode;
  public int maxMatchData = 512;
  /** Deadline in System.nanoTime() units, or 0 for no timeout. */
  public long deadline;

  private int cycle;
  public ConsoleListener consoleListener;
  public java.util.Map<String, YStructure> modules = new java.util.HashMap<>();

  public ExecContext(RuleSet rules) {
    this.rules = rules;
    int ns = rules.strings.size();
    matches = new MatchList[ns];
    unconfirmedMatches = new MatchList[ns];
    for (int i = 0; i < ns; i++) {
      matches[i] = new MatchList();
      unconfirmedMatches[i] = new MatchList();
    }
    ruleMatches = new boolean[rules.rules.size()];
    requiredEval = new boolean[rules.rules.size()];
    nsUnsatisfied = new boolean[rules.namespaces.size()];
    stringsTempDisabled = new boolean[ns];
    ruleDisabled = new boolean[rules.rules.size()];
    for (int i = 0; i < ruleDisabled.length; i++) {
      ruleDisabled[i] = rules.rules.get(i).isDisabled();
    }
    rootObjects = new YObject[rules.rootObjects.size()];
  }

  /** Resets the per-scan state (_yr_scanner_clean_matches). */
  public void clean() {
    Arrays.fill(ruleMatches, false);
    Arrays.fill(requiredEval, false);
    Arrays.fill(nsUnsatisfied, false);
    Arrays.fill(stringsTempDisabled, false);
    for (MatchList m : matches) {
      m.clear();
    }
    for (MatchList m : unconfirmedMatches) {
      m.clear();
    }
    Arrays.fill(memObj, null);
    entryPoint = YObject.UNDEFINED;
    // Don't keep the scanned data, which may be unmapped after the scan.
    blocks = Collections.emptyList();
  }

  /** Checks the timeout, called periodically during evaluation. */
  public void tick() {
    if (deadline != 0 && ++cycle >= 100) {
      cycle = 0;
      checkTimeout();
    }
  }

  @Override
  public void checkTimeout() {
    if (deadline != 0 && System.nanoTime() - deadline > 0) {
      throw new YaraError(ErrorCode.SCAN_TIMEOUT);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // ScanContext

  @Override
  public long fileSize() {
    return fileSize;
  }

  @Override
  public List<MemoryBlock> blocks() {
    return blocks;
  }

  @Override
  public void consoleLog(String message) {
    if (consoleListener != null) {
      consoleListener.log(message);
    }
  }

  @Override
  public YStructure moduleObject(String name) {
    return modules.get(name);
  }

  /** Reads an integer from the scanned data like libyara's read_int*_t functions. */
  public long readInt(long offset, int size, boolean signed, boolean bigEndian) {
    for (MemoryBlock block : blocks) {
      long base = block.base();
      long bsize = block.size();
      // offset is treated as unsigned (size_t) like in libyara.
      if (Long.compareUnsigned(offset, base) >= 0
          && bsize >= size
          && Long.compareUnsigned(offset, base + bsize - size) <= 0) {
        java.nio.ByteBuffer d = block.data();
        int at = (int) (offset - base);
        long v;
        switch (size) {
          case 1:
            v = signed ? d.get(at) : d.get(at) & 0xFF;
            break;
          case 2:
            {
              int b0 = d.get(at) & 0xFF;
              int b1 = d.get(at + 1) & 0xFF;
              int u = bigEndian ? (b0 << 8 | b1) : (b1 << 8 | b0);
              v = signed ? (short) u : u;
              break;
            }
          default:
            {
              int b0 = d.get(at) & 0xFF;
              int b1 = d.get(at + 1) & 0xFF;
              int b2 = d.get(at + 2) & 0xFF;
              int b3 = d.get(at + 3) & 0xFF;
              int u =
                  bigEndian
                      ? (b0 << 24 | b1 << 16 | b2 << 8 | b3)
                      : (b3 << 24 | b2 << 16 | b1 << 8 | b0);
              v = signed ? u : (u & 0xFFFFFFFFL);
              break;
            }
        }
        return v;
      }
    }
    return YObject.UNDEFINED;
  }
}
