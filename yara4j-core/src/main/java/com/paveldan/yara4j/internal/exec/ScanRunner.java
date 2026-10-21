package com.paveldan.yara4j.internal.exec;

import java.util.ArrayList;
import java.util.List;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.YaraException;
import com.paveldan.yara4j.internal.YaraError;
import com.paveldan.yara4j.internal.compiler.Compiler;
import com.paveldan.yara4j.internal.module.ModuleRegistry;
import com.paveldan.yara4j.internal.rules.CompiledRule;
import com.paveldan.yara4j.internal.rules.CompiledString;
import com.paveldan.yara4j.internal.rules.ExternalDef;
import com.paveldan.yara4j.internal.rules.RuleSet;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BinaryReader;

/**
 * Runs a scan: searches the strings, loads the modules and evaluates the rules. Port of
 * yr_scanner_scan_mem_blocks and yr_execute_code.
 */
public final class ScanRunner {

  /** Hooks for user callbacks. */
  public interface Listener extends ScanEngine.Events {
    /** Returns the module data for the module or null (CALLBACK_MSG_IMPORT_MODULE). */
    byte[] importModule(String moduleName);

    /** CALLBACK_MSG_MODULE_IMPORTED. */
    void moduleImported(String moduleName, YStructure module);

    void consoleLog(String message);
  }

  public static final int FILE_SIZE_THRESHOLD = 200000;

  private final RuleSet rules;
  private final ModuleRegistry registry;
  public final ExecContext ctx;
  /** External variables, which can be modified per scanner. */
  public final YObject[] externals;

  public ScanRunner(RuleSet rules, ModuleRegistry registry) {
    this.rules = rules;
    this.registry = registry;
    this.ctx = new ExecContext(rules);
    this.externals = new YObject[rules.externals.size()];
    for (int i = 0; i < externals.length; i++) {
      externals[i] = Compiler.objectFromExternal(rules.externals.get(i));
    }
  }

  public YObject external(String name) {
    for (int i = 0; i < externals.length; i++) {
      if (rules.externals.get(i).identifier.equals(name)) {
        return externals[i];
      }
    }
    return null;
  }

  public ExternalDef externalDef(String name) {
    for (ExternalDef d : rules.externals) {
      if (d.identifier.equals(name)) {
        return d;
      }
    }
    return null;
  }

  /**
   * Scans the given blocks and evaluates the rules. After this method returns, the results are
   * in {@link ExecContext#ruleMatches} and the matches, until {@link ExecContext#clean} is
   * called.
   *
   * @param fileSize file size or UNDEFINED.
   * @param singleBuffer true when scanning a single buffer (enables the slow scanning check).
   */
  public void scan(
      List<MemoryBlock> blocks,
      long fileSize,
      boolean singleBuffer,
      long timeoutNanos,
      boolean fastMode,
      Listener listener)
      throws YaraException {
    ExecContext c = ctx;
    c.clean();
    c.fastMode = fastMode;
    c.blocks = blocks;
    c.consoleListener = listener::consoleLog;
    try {
      if (singleBuffer
          && rules.ac.matches[0] != null
          && blocks.size() == 1
          && blocks.get(0).size() > FILE_SIZE_THRESHOLD) {
        CompiledString reportString = rules.ac.matches[0].string;
        if (!listener.tooSlowScanning(reportString)) {
          throw new YaraException(ErrorCode.TOO_SLOW_SCANNING);
        }
      }
      System.arraycopy(rules.noRequiredStrings, 0, c.requiredEval, 0, c.requiredEval.length);
      c.deadline = timeoutNanos > 0 ? System.nanoTime() + timeoutNanos : 0;
      if (c.deadline == 0 && timeoutNanos > 0) {
        c.deadline = 1;
      }
      ScanEngine engine = new ScanEngine(c, listener);
      for (MemoryBlock block : blocks) {
        if (c.entryPoint == YObject.UNDEFINED) {
          try {
            c.entryPoint = EntryPoint.offset(new BinaryReader(block.data()));
          } catch (IndexOutOfBoundsException e) {
            c.entryPoint = YObject.UNDEFINED;
          }
        }
        engine.scanBlock(block);
      }
      c.fileSize = fileSize;
      execute(listener);
    } catch (YaraError e) {
      throw e.toException();
    } catch (StackOverflowError e) {
      throw new YaraException(ErrorCode.EXEC_STACK_OVERFLOW);
    }
  }

  private void execute(Listener listener) throws YaraException {
    ExecContext c = ctx;
    // Root objects: externals first, then modules.
    for (int i = 0; i < c.rootObjects.length; i++) {
      c.rootObjects[i] = null;
    }
    c.modules.clear();
    List<String> roots = rules.rootObjects;
    for (int i = 0; i < externals.length; i++) {
      int idx = roots.indexOf(rules.externals.get(i).identifier);
      if (idx >= 0) {
        c.rootObjects[idx] = externals[i];
      }
    }
    List<YaraModule> loaded = new ArrayList<>();
    try {
      for (String moduleName : rules.imports) {
        int idx = roots.indexOf(moduleName);
        if (idx >= 0 && c.rootObjects[idx] != null) {
          continue;
        }
        YStructure structure = new YStructure(moduleName);
        byte[] moduleData = listener.importModule(moduleName);
        YaraModule module = registry.get(moduleName);
        if (module == null) {
          throw new YaraException(ErrorCode.UNKNOWN_MODULE, "unknown module " + moduleName);
        }
        module.declare(new ModuleDeclarations(structure));
        if (idx >= 0) {
          c.rootObjects[idx] = structure;
        }
        c.modules.put(moduleName, structure);
        loaded.add(module);
        try {
          module.load(c, structure, moduleData);
        } catch (RuntimeException e) {
          if (e instanceof YaraError) {
            throw e;
          }
          // Modules must never crash the scan on malformed input. A module that fails with
          // an unexpected exception leaves its remaining fields undefined.
        }
        listener.moduleImported(moduleName, structure);
      }
      for (CompiledRule rule : rules.rules) {
        int i = rule.idx;
        boolean skip = c.ruleDisabled[i] || !c.requiredEval[i];
        if (skip) {
          if (rule.isGlobal()) {
            c.nsUnsatisfied[rule.ns.idx] = true;
          }
          continue;
        }
        long r = rule.condition.evalLong(c);
        if (r != YObject.UNDEFINED && r != 0) {
          c.ruleMatches[i] = true;
        } else if (rule.isGlobal()) {
          c.nsUnsatisfied[rule.ns.idx] = true;
        }
        c.tick();
      }
    } finally {
      for (int k = loaded.size() - 1; k >= 0; k--) {
        YaraModule m = loaded.get(k);
        YStructure s = c.modules.get(m.name());
        try {
          m.unload(s);
        } catch (RuntimeException e) {
          // ignore
        }
      }
    }
  }

  /** True if the rule matched in the last scan, taking global rules into account. */
  public boolean ruleMatched(CompiledRule rule) {
    return ctx.ruleMatches[rule.idx] && !ctx.nsUnsatisfied[rule.ns.idx];
  }
}
