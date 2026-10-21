package com.paveldan.yara4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import com.paveldan.yara4j.internal.compiler.Compiler;
import com.paveldan.yara4j.internal.module.ModuleRegistry;
import com.paveldan.yara4j.internal.rules.ExternalDef;
import com.paveldan.yara4j.internal.rules.RulesSerializer;
import com.paveldan.yara4j.module.YaraModule;

/**
 * Compiles YARA rules. Equivalent to libyara's YR_COMPILER.
 *
 * <pre>{@code
 * YaraCompiler compiler = new YaraCompiler();
 * compiler.addSource("rule test { strings: $a = \"foo\" condition: $a }");
 * Rules rules = compiler.getRules();
 * for (RuleMatch m : rules.scan(data)) {
 *   System.out.println(m.getIdentifier());
 * }
 * }</pre>
 *
 * <p>Like in libyara, once a call to one of the {@code add*} methods fails no more rules can be
 * added, and {@link #getRules()} can be called only if no errors occurred.
 */
public final class YaraCompiler {
  private final ModuleRegistry registry;
  private final Compiler compiler;
  /** The inputs of the compilation, saved with the rules by {@link Rules#save}. */
  private final RulesSerializer.Journal journal = new RulesSerializer.Journal();

  public YaraCompiler() {
    this(new ModuleRegistry(ModuleRegistry.getDefault()));
  }

  private YaraCompiler(ModuleRegistry registry) {
    this.registry = registry;
    this.compiler = new Compiler(registry);
  }

  /** Compiles rules from a string, throwing an exception if they contain errors. */
  public static Rules compile(String source) throws YaraCompilationException {
    YaraCompiler c = new YaraCompiler();
    c.addSourceOrThrow(source, null);
    return c.getRules();
  }

  /** Registers an additional module, available to rules compiled by this compiler. */
  public YaraCompiler registerModule(YaraModule module) {
    registry.register(module);
    return this;
  }

  /**
   * Enables strict escape sequences in regexps: unknown escape sequences like \R produce a
   * warning.
   */
  public YaraCompiler setStrictEscape(boolean strict) {
    compiler.setStrictEscape(strict);
    journal.strictEscape(strict);
    return this;
  }

  /** Sets a custom resolver for include directives. */
  public YaraCompiler setIncludeResolver(IncludeResolver resolver) {
    if (resolver == null) {
      throw new NullPointerException();
    }
    compiler.setIncludeResolver(resolver);
    return this;
  }

  /** Disables include directives, which then produce an error. */
  public YaraCompiler disableIncludes() {
    compiler.setIncludeResolver(null);
    return this;
  }

  /** Sets the maximum number of strings per rule (default 10000). */
  public YaraCompiler setMaxStringsPerRule(int max) {
    compiler.setMaxStringsPerRule(max);
    journal.maxStrings(max);
    return this;
  }

  /**
   * Uses an atom quality table instead of the default heuristic (see
   * yr_compiler_set_atom_quality_table). Each entry has 4 bytes for the atom plus 1 byte for its
   * quality, and entries must be sorted by atom.
   */
  public YaraCompiler setAtomQualityTable(byte[] table, int warningThreshold) {
    compiler.setAtomQualityTable(table, warningThreshold);
    journal.atomTable(table, warningThreshold);
    return this;
  }

  private YaraCompiler define(ExternalDef def) throws YaraException {
    ErrorCode ec = compiler.defineExternal(def);
    if (ec != ErrorCode.SUCCESS) {
      throw new YaraException(ec, "duplicated external variable \"" + def.identifier + "\"");
    }
    journal.define(def);
    return this;
  }

  public YaraCompiler defineInteger(String identifier, long value) throws YaraException {
    return define(new ExternalDef(identifier, ExternalDef.TYPE_INTEGER, value, 0, null));
  }

  public YaraCompiler defineBoolean(String identifier, boolean value) throws YaraException {
    return define(new ExternalDef(identifier, ExternalDef.TYPE_BOOLEAN, value ? 1 : 0, 0, null));
  }

  public YaraCompiler defineFloat(String identifier, double value) throws YaraException {
    return define(new ExternalDef(identifier, ExternalDef.TYPE_FLOAT, 0, value, null));
  }

  public YaraCompiler defineString(String identifier, String value) throws YaraException {
    return define(
        new ExternalDef(
            identifier, ExternalDef.TYPE_STRING, 0, 0, value.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Compiles rules from a string in the default namespace.
   *
   * @return the number of errors, check {@link #getMessages()} for details.
   */
  public int addSource(String source) {
    return addSource(source, null);
  }

  /** Compiles rules from a string in the given namespace (null for "default"). */
  public int addSource(String source, String namespace) {
    return add(source.getBytes(StandardCharsets.UTF_8), namespace, null);
  }

  /** Compiles rules from raw bytes in the given namespace (null for "default"). */
  public int addSource(byte[] source, String namespace) {
    return add(source, namespace, null);
  }

  /**
   * Compiles rules from raw bytes. The file name (which may be null) is used in messages and
   * for resolving relative includes with the default include resolver.
   */
  public int addSource(byte[] source, String namespace, String fileName) {
    return add(source, namespace, fileName);
  }

  /** Compiles rules from a file. Relative includes are resolved from the file's directory. */
  public int addFile(Path file, String namespace) throws IOException {
    byte[] content = Files.readAllBytes(file);
    return add(content, namespace, file.toString());
  }

  private int add(byte[] source, String namespace, String fileName) {
    compiler.setIncludeLog(journal.source(source, namespace, fileName));
    try {
      return compiler.addSource(source, namespace, fileName);
    } finally {
      compiler.setIncludeLog(null);
    }
  }

  /** Replays a compilation recorded by {@link Rules#save}. */
  static Rules replay(RulesSerializer.Journal recorded, ModuleRegistry registry)
      throws YaraException {
    YaraCompiler c = new YaraCompiler(registry);
    for (RulesSerializer.Op op : recorded.ops()) {
      switch (op.type) {
        case 1:
          c.setStrictEscape(op.flag);
          break;
        case 2:
          c.setMaxStringsPerRule(op.number);
          break;
        case 3:
          c.setAtomQualityTable(op.data, op.number);
          break;
        case 4:
          c.define(op.external);
          break;
        default:
          c.compiler.setIncludeReplay(new java.util.ArrayDeque<>(op.includes));
          try {
            c.add(op.data, op.namespace, op.fileName);
          } finally {
            c.compiler.setIncludeReplay(null);
          }
          break;
      }
    }
    try {
      return c.getRules();
    } catch (YaraCompilationException e) {
      throw new YaraException(ErrorCode.CORRUPT_FILE, "compiled rules can't be rebuilt");
    }
  }

  /** Like {@link #addSource(String)} but throws if there are errors. */
  public YaraCompiler addSourceOrThrow(String source) throws YaraCompilationException {
    return addSourceOrThrow(source, null);
  }

  /** Like {@link #addSource(String, String)} but throws if there are errors. */
  public YaraCompiler addSourceOrThrow(String source, String namespace)
      throws YaraCompilationException {
    if (addSource(source, namespace) != 0) {
      throw new YaraCompilationException(compiler.lastError(), getMessages());
    }
    return this;
  }

  /** Like {@link #addFile(Path, String)} but throws if there are errors. */
  public YaraCompiler addFileOrThrow(Path file, String namespace)
      throws YaraCompilationException, IOException {
    if (addFile(file, namespace) != 0) {
      throw new YaraCompilationException(compiler.lastError(), getMessages());
    }
    return this;
  }

  /** All errors and warnings produced so far. */
  public List<CompilerMessage> getMessages() {
    return Collections.unmodifiableList(compiler.messages());
  }

  public List<CompilerMessage> getErrors() {
    return compiler.messages().stream()
        .filter(m -> m.getLevel() == CompilerMessage.Level.ERROR)
        .collect(Collectors.toList());
  }

  public List<CompilerMessage> getWarnings() {
    return compiler.messages().stream()
        .filter(m -> m.getLevel() == CompilerMessage.Level.WARNING)
        .collect(Collectors.toList());
  }

  /** The last error code (libyara's compiler->last_error). */
  public ErrorCode getLastError() {
    return compiler.lastError();
  }

  /** Returns the compiled rules. */
  public Rules getRules() throws YaraCompilationException {
    if (compiler.errors() != 0) {
      throw new YaraCompilationException(compiler.lastError(), getMessages());
    }
    return new Rules(compiler.getRules(), registry, journal.copy());
  }
}
