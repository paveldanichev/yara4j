package com.paveldan.yara4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import com.paveldan.yara4j.internal.module.ModuleRegistry;
import com.paveldan.yara4j.internal.rules.CompiledRule;
import com.paveldan.yara4j.internal.rules.RuleSet;
import com.paveldan.yara4j.internal.rules.RulesSerializer;
import com.paveldan.yara4j.module.YaraModule;

/**
 * A set of compiled rules. Instances are immutable and thread-safe; create a {@link Scanner}
 * per thread for scanning, or use the convenience scan methods which create a scanner each
 * time.
 */
public final class Rules {
  final RuleSet set;
  final ModuleRegistry registry;
  private final List<Rule> rules;
  private final RulesSerializer.Journal journal;

  Rules(RuleSet set, ModuleRegistry registry, RulesSerializer.Journal journal) {
    this.set = set;
    this.registry = registry;
    this.journal = journal;
    List<Rule> r = new ArrayList<>();
    for (CompiledRule cr : set.rules) {
      r.add(new Rule(cr));
    }
    this.rules = Collections.unmodifiableList(r);
  }

  /** All the rules in the set, including private ones. */
  public List<Rule> getRules() {
    return rules;
  }

  Rule rule(int idx) {
    return rules.get(idx);
  }

  /** Names of the modules imported by the rules. */
  public List<String> getImports() {
    return Collections.unmodifiableList(set.imports);
  }

  /** Creates a new scanner for these rules. */
  public Scanner newScanner() {
    return new Scanner(this);
  }

  /** Scans a buffer and returns the matching rules. */
  public List<RuleMatch> scan(byte[] data) throws YaraException {
    return newScanner().scan(data);
  }

  public List<RuleMatch> scan(ByteBuffer data) throws YaraException {
    return newScanner().scan(data);
  }

  /** Scans a file and returns the matching rules. */
  public List<RuleMatch> scan(Path file) throws YaraException, IOException {
    return newScanner().scan(file);
  }

  /**
   * Saves the compiled rules in yara4j's binary format. The format is not compatible with
   * libyara's .yarc files; see {@link RulesSerializer} for details.
   */
  public void save(OutputStream out) throws IOException {
    RulesSerializer.save(journal, out);
  }

  /** Saves the compiled rules to a file. */
  public void save(Path file) throws IOException {
    try (OutputStream out = java.nio.file.Files.newOutputStream(file)) {
      save(out);
    }
  }

  /**
   * Loads compiled rules saved with {@link #save}.
   *
   * @param extraModules modules that were registered in the compiler with {@link
   *     YaraCompiler#registerModule}, if any.
   * @throws YaraException with {@link ErrorCode#INVALID_FILE}, {@link
   *     ErrorCode#UNSUPPORTED_FILE_VERSION} or {@link ErrorCode#CORRUPT_FILE} if the data isn't
   *     valid.
   */
  public static Rules load(InputStream in, YaraModule... extraModules)
      throws IOException, YaraException {
    RulesSerializer.Journal journal;
    try {
      journal = RulesSerializer.load(in);
    } catch (RulesSerializer.FormatException e) {
      ErrorCode code =
          e.unsupportedVersion
              ? ErrorCode.UNSUPPORTED_FILE_VERSION
              : e.getMessage().startsWith("not a") ? ErrorCode.INVALID_FILE : ErrorCode.CORRUPT_FILE;
      throw new YaraException(code, e.getMessage());
    }
    ModuleRegistry registry = new ModuleRegistry(ModuleRegistry.getDefault());
    for (YaraModule m : extraModules) {
      registry.register(m);
    }
    return YaraCompiler.replay(journal, registry);
  }

  /** Loads compiled rules from a file. */
  public static Rules load(Path file, YaraModule... extraModules)
      throws IOException, YaraException {
    try (InputStream in = java.nio.file.Files.newInputStream(file)) {
      return load(in, extraModules);
    }
  }
}
