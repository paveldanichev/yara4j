package com.paveldan.yara4j;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.paveldan.yara4j.internal.exec.ExecContext;
import com.paveldan.yara4j.internal.exec.Match;
import com.paveldan.yara4j.internal.exec.ScanRunner;
import com.paveldan.yara4j.internal.rules.CompiledRule;
import com.paveldan.yara4j.internal.rules.CompiledString;
import com.paveldan.yara4j.internal.rules.ExternalDef;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.object.YFloat;
import com.paveldan.yara4j.object.YInteger;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YString;
import com.paveldan.yara4j.object.YStructure;

/**
 * Scans data with a set of rules. A scanner holds per-scan state and is not thread-safe, but it
 * can be reused for scanning many files. This is the equivalent of libyara's YR_SCANNER.
 */
public final class Scanner {
  private final Rules rules;
  private final ScanRunner runner;
  private ScanCallback callback;
  private long timeoutNanos;
  private boolean fastMode;
  private boolean reportMatching = true;
  private boolean reportNotMatching = false;
  private final Map<String, byte[]> moduleData = new HashMap<>();

  Scanner(Rules rules) {
    this.rules = rules;
    this.runner = new ScanRunner(rules.set, rules.registry);
  }

  /** Sets the callback receiving scan events. */
  public Scanner setCallback(ScanCallback callback) {
    this.callback = callback;
    return this;
  }

  /** Sets the scan timeout, zero or null means no timeout. */
  public Scanner setTimeout(Duration timeout) {
    this.timeoutNanos = timeout == null ? 0 : timeout.toNanos();
    return this;
  }

  /** In fast mode a string is reported only once even if it matches several times. */
  public Scanner setFastMode(boolean fastMode) {
    this.fastMode = fastMode;
    return this;
  }

  /** Controls which rules are reported to the callback. By default only matching rules. */
  public Scanner setReportRules(boolean matching, boolean notMatching) {
    this.reportMatching = matching;
    this.reportNotMatching = notMatching;
    return this;
  }

  /** Sets the maximum number of bytes stored for each match (default 512). */
  public Scanner setMaxMatchData(int max) {
    runner.ctx.maxMatchData = max;
    return this;
  }

  /** Data passed to a module when loaded, like a cuckoo report. */
  public Scanner setModuleData(String moduleName, byte[] data) {
    if (data == null) {
      moduleData.remove(moduleName);
    } else {
      moduleData.put(moduleName, data);
    }
    return this;
  }

  /**
   * Enables or disables a rule for this scanner (libyara's yr_rule_enable/yr_rule_disable).
   * Disabled rules don't match, and rules referencing them see an undefined value.
   *
   * @return the number of rules affected (rules with this identifier in any namespace).
   */
  public int setRuleEnabled(String identifier, boolean enabled) {
    int n = 0;
    for (CompiledRule r : rules.set.rules) {
      if (r.identifier.equals(identifier)) {
        runner.ctx.ruleDisabled[r.idx] = !enabled;
        n++;
      }
    }
    return n;
  }

  /** Enables or disables a rule identified by its namespace and identifier. */
  public boolean setRuleEnabled(String namespace, String identifier, boolean enabled) {
    for (CompiledRule r : rules.set.rules) {
      if (r.identifier.equals(identifier) && r.ns.name.equals(namespace)) {
        runner.ctx.ruleDisabled[r.idx] = !enabled;
        return true;
      }
    }
    return false;
  }

  private YObject external(String identifier) throws YaraException {
    YObject o = runner.external(identifier);
    if (o == null) {
      throw new YaraException(ErrorCode.INVALID_ARGUMENT, "undefined external " + identifier);
    }
    return o;
  }

  /** Sets the value of an integer (or boolean) external variable for subsequent scans. */
  public Scanner defineInteger(String identifier, long value) throws YaraException {
    YObject o = external(identifier);
    if (!(o instanceof YInteger)) {
      throw new YaraException(ErrorCode.INVALID_EXTERNAL_VARIABLE_TYPE);
    }
    ((YInteger) o).set(value);
    return this;
  }

  public Scanner defineBoolean(String identifier, boolean value) throws YaraException {
    return defineInteger(identifier, value ? 1 : 0);
  }

  public Scanner defineFloat(String identifier, double value) throws YaraException {
    YObject o = external(identifier);
    if (!(o instanceof YFloat)) {
      throw new YaraException(ErrorCode.INVALID_EXTERNAL_VARIABLE_TYPE);
    }
    ((YFloat) o).set(value);
    return this;
  }

  public Scanner defineString(String identifier, String value) throws YaraException {
    YObject o = external(identifier);
    if (!(o instanceof YString)) {
      throw new YaraException(ErrorCode.INVALID_EXTERNAL_VARIABLE_TYPE);
    }
    byte[] b = value.getBytes(StandardCharsets.UTF_8);
    int z = 0;
    while (z < b.length && b[z] != 0) {
      z++;
    }
    ((YString) o).set(java.util.Arrays.copyOf(b, z));
    return this;
  }

  // ---------------------------------------------------------------------------------------------

  /** Scans a byte array. Returns the matching rules (if no callback is set). */
  public List<RuleMatch> scan(byte[] data) throws YaraException {
    MemoryBlock b = MemoryBlocks.of(data, 0);
    return scan(Collections.singletonList(b), data.length, true);
  }

  /** Scans a buffer from its position to its limit. */
  public List<RuleMatch> scan(ByteBuffer data) throws YaraException {
    MemoryBlock b = MemoryBlocks.of(data, 0);
    return scan(Collections.singletonList(b), b.size(), true);
  }

  /**
   * Scans a file, which is mapped in memory. On Windows the mapping is released when the scan
   * ends, so the file can be deleted or modified afterwards.
   */
  public List<RuleMatch> scan(Path file) throws YaraException, IOException {
    List<MemoryBlock> blocks = MemoryBlocks.openFile(file);
    try {
      long size = 0;
      for (MemoryBlock b : blocks) {
        size += b.size();
      }
      return scan(blocks, size, blocks.size() == 1);
    } finally {
      MemoryBlocks.closeFile(blocks);
    }
  }

  /** Reads a stream fully and scans its content. */
  public List<RuleMatch> scan(InputStream in) throws YaraException, IOException {
    return scan(in.readAllBytes());
  }

  /**
   * Scans a sequence of memory blocks, like libyara's yr_scanner_scan_mem_blocks.
   *
   * @param fileSize the value of "filesize" in conditions, or -1 if unknown (undefined).
   */
  public List<RuleMatch> scanBlocks(List<MemoryBlock> blocks, long fileSize)
      throws YaraException {
    return scan(blocks, fileSize < 0 ? YObject.UNDEFINED : fileSize, false);
  }

  private List<RuleMatch> scan(List<MemoryBlock> blocks, long fileSize, boolean singleBuffer)
      throws YaraException {
    final ScanCallback cb = callback != null ? callback : new ScanCallback() {};
    List<RuleMatch> results = new ArrayList<>();
    ScanRunner.Listener listener =
        new ScanRunner.Listener() {
          @Override
          public boolean tooManyMatches(CompiledString string) {
            return cb.tooManyMatches(rules.rule(string.ruleIdx), string.identifier);
          }

          @Override
          public boolean tooSlowScanning(CompiledString string) {
            return cb.tooSlowScanning(
                string == null ? null : rules.rule(string.ruleIdx),
                string == null ? null : string.identifier);
          }

          @Override
          public byte[] importModule(String moduleName) {
            byte[] d = cb.importModule(moduleName);
            return d != null ? d : moduleData.get(moduleName);
          }

          @Override
          public void moduleImported(String moduleName, YStructure module) {
            cb.moduleImported(moduleName, module);
          }

          @Override
          public void consoleLog(String message) {
            cb.consoleLog(message);
          }
        };
    try {
      runner.scan(blocks, fileSize, singleBuffer, timeoutNanos, fastMode, listener);
      ExecContext ctx = runner.ctx;
      for (CompiledRule rule : rules.set.rules) {
        boolean matched = runner.ruleMatched(rule);
        if (rule.isPrivate()) {
          continue;
        }
        CallbackResult r = CallbackResult.CONTINUE;
        if (matched && reportMatching) {
          RuleMatch m = buildMatch(ctx, rule);
          if (callback == null) {
            results.add(m);
          }
          r = cb.ruleMatching(m);
        } else if (!matched && reportNotMatching) {
          r = cb.ruleNotMatching(rules.rule(rule.idx));
        }
        if (r == CallbackResult.ABORT) {
          return results;
        }
        if (r == CallbackResult.ERROR) {
          throw new YaraException(ErrorCode.CALLBACK_ERROR);
        }
      }
      cb.scanFinished();
      return results;
    } finally {
      runner.ctx.clean();
    }
  }

  private RuleMatch buildMatch(ExecContext ctx, CompiledRule rule) {
    List<StringMatch> list = new ArrayList<>();
    for (CompiledString s : rule.strings) {
      for (Match m = ctx.matches[s.idx].head; m != null; m = m.next) {
        list.add(
            new StringMatch(
                s.identifier,
                m.base,
                m.offset,
                m.matchLength,
                m.data,
                m.xorKey,
                m.isPrivate,
                (s.flags & com.paveldan.yara4j.internal.compiler.StringFlags.HEXADECIMAL) != 0));
      }
    }
    return new RuleMatch(rules.rule(rule.idx), list);
  }

  /** Returns the definition of an external variable, used internally. */
  ExternalDef externalDef(String name) {
    return runner.externalDef(name);
  }
}
