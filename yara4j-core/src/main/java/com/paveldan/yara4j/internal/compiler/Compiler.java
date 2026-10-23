package com.paveldan.yara4j.internal.compiler;

import static com.paveldan.yara4j.object.YObject.UNDEFINED;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.paveldan.yara4j.CompilerMessage;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.IncludeResolver;
import com.paveldan.yara4j.internal.YaraError;
import com.paveldan.yara4j.internal.ac.AhoCorasick;
import com.paveldan.yara4j.internal.atoms.Atoms;
import com.paveldan.yara4j.internal.exec.Node;
import com.paveldan.yara4j.internal.exec.Nodes;
import com.paveldan.yara4j.internal.module.ModuleRegistry;
import com.paveldan.yara4j.internal.re.Base64;
import com.paveldan.yara4j.internal.re.HexParser;
import com.paveldan.yara4j.internal.re.Re;
import com.paveldan.yara4j.internal.re.ReAst;
import com.paveldan.yara4j.internal.re.ReCode;
import com.paveldan.yara4j.internal.re.ReEmitter;
import com.paveldan.yara4j.internal.re.RegexParser;
import com.paveldan.yara4j.internal.rules.CompiledMeta;
import com.paveldan.yara4j.internal.rules.CompiledRule;
import com.paveldan.yara4j.internal.rules.CompiledString;
import com.paveldan.yara4j.internal.rules.ExternalDef;
import com.paveldan.yara4j.internal.rules.Namespace;
import com.paveldan.yara4j.internal.rules.RuleSet;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YArray;
import com.paveldan.yara4j.object.YDictionary;
import com.paveldan.yara4j.object.YFloat;
import com.paveldan.yara4j.object.YFunction;
import com.paveldan.yara4j.object.YInteger;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YString;
import com.paveldan.yara4j.object.YStructure;

/**
 * The YARA rules compiler. It parses rules and produces a {@link RuleSet}. The parser is a
 * hand-written recursive descent parser equivalent to libyara's grammar.y, and the semantic
 * actions are ports of the actions in grammar.y, parser.c and compiler.c.
 */
public final class Compiler implements Lexer.Host {
  // Expression types (EXPRESSION_TYPE_* in libyara)
  static final int T_UNKNOWN = 0;
  static final int T_BOOLEAN = 1;
  static final int T_INTEGER = 2;
  static final int T_STRING = 4;
  static final int T_REGEXP = 8;
  static final int T_OBJECT = 16;
  static final int T_FLOAT = 32;
  static final int T_QUANTIFIER = 64;

  static final int FOR_ALL = 1;
  static final int FOR_ANY = 2;
  static final int FOR_NONE = 3;

  static final int MAX_FUNCTION_ARGS = 128;
  static final int MAX_INCLUDE_DEPTH = 16;
  static final int ATOMS_PER_RULE_WARNING_THRESHOLD = 12000;

  /** Compile-time information about an expression (libyara's YR_EXPRESSION). */
  static final class Expr {
    int type;
    /** value.integer: compile time value for integers, UNDEFINED if unknown. */
    long intValue = UNDEFINED;
    /** Literal value for string literals (value.sized_string_ref), null otherwise. */
    byte[] literal;

    double dblValue;
    YObject object;
    String identifier;
    int requiredStrings;
    Node node;
    /** True if the expression is a primary_expression in the grammar. */
    boolean primary;

    Expr(int type, Node node) {
      this.type = type;
      this.node = node;
    }
  }

  /** Thrown for aborting the parsing of the current rule after an error. */
  private static final class ParseError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    ParseError() {
      super(null, null, false, false);
    }
  }

  /** Thrown for aborting the whole parsing (YYABORT). */
  private static final class FatalError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    FatalError() {
      super(null, null, false, false);
    }
  }

  private static final class LoopContext {
    int varsCount;
    int varsInternalCount;
    final String[] varNames = new String[ExecLimits.MAX_LOOP_VARS];
    final Expr[] vars = new Expr[ExecLimits.MAX_LOOP_VARS];
  }

  /** Limits shared with the execution engine. */
  static final class ExecLimits {
    static final int MAX_LOOP_NESTING =
        com.paveldan.yara4j.internal.exec.ExecContext.MAX_LOOP_NESTING;
    static final int MAX_LOOP_VARS = com.paveldan.yara4j.internal.exec.ExecContext.MAX_LOOP_VARS;
    static final int INTERNAL_LOOP_VARS =
        com.paveldan.yara4j.internal.exec.ExecContext.INTERNAL_LOOP_VARS;
  }

  // ---------------------------------------------------------------------------------------------
  // Configuration

  private boolean strictEscape;
  private IncludeResolver includeResolver = Compiler::defaultInclude;
  private boolean usingDefaultIncludeResolver = true;
  private Atoms.QualityFunction atomQuality = Atoms.HEURISTIC;
  private int atomQualityWarningThreshold = Atoms.QUALITY_WARNING_THRESHOLD;
  private int maxStringsPerRule = 10000;
  private final ModuleRegistry registry;
  /** When not null, the content returned for every include is appended (used to save rules). */
  private List<byte[]> includeLog;
  /** When not null, include contents are taken from here instead of the resolver. */
  private java.util.Deque<byte[]> includeReplay;

  // ---------------------------------------------------------------------------------------------
  // State

  private final List<CompilerMessage> messages = new ArrayList<>();
  private int errors;
  private ErrorCode lastError = ErrorCode.SUCCESS;
  private String lastErrorExtraInfo = "";
  private int currentLine;

  private final List<Namespace> namespaces = new ArrayList<>();
  private Namespace currentNs;
  /** External variables (objects_table with NULL namespace). */
  private final Map<String, YObject> globalObjects = new HashMap<>();
  /** Modules imported in each namespace. */
  private final Map<String, Map<String, YObject>> nsObjects = new HashMap<>();
  private final Map<String, Map<String, Integer>> rulesTable = new HashMap<>();
  private final Map<String, Set<String>> wildcardIdentifiers = new HashMap<>();
  private final List<CompiledRule> rules = new ArrayList<>();
  private final List<CompiledString> strings = new ArrayList<>();
  private final ReCode reCode = new ReCode();
  private final AhoCorasick automaton = new AhoCorasick();
  private final List<ExternalDef> externals = new ArrayList<>();
  private final List<String> imports = new ArrayList<>();
  private final List<String> rootObjects = new ArrayList<>();
  private final Map<String, Integer> rootObjectIndex = new HashMap<>();
  private final Deque<String> fileNames = new ArrayDeque<>();
  private RuleSet result;

  // Per-rule parsing state
  private CompiledRule currentRule;
  private final Map<String, Integer> stringsTable = new HashMap<>();
  private final LoopContext[] loops = new LoopContext[ExecLimits.MAX_LOOP_NESTING];
  private int loopIndex = -1;
  private int loopForOfVarIndex = -1;

  // Lexer state
  private Lexer lexer;
  private Token tok;
  /** libyara's Bison automaton, fed with the consumed tokens. */
  private ShadowParser shadow;
  /** Line of the last consumed token. */
  private int lastConsumedLine;

  public Compiler(ModuleRegistry registry) {
    this.registry = registry;
    for (int i = 0; i < loops.length; i++) {
      loops[i] = new LoopContext();
    }
  }

  public void setStrictEscape(boolean strictEscape) {
    this.strictEscape = strictEscape;
  }

  /** Sets the include resolver, null disables includes. */
  public void setIncludeResolver(IncludeResolver resolver) {
    this.includeResolver = resolver;
    this.usingDefaultIncludeResolver = false;
  }

  public void setIncludeLog(List<byte[]> log) {
    this.includeLog = log;
  }

  public void setIncludeReplay(java.util.Deque<byte[]> replay) {
    this.includeReplay = replay;
  }

  public void setAtomQualityTable(byte[] table, int warningThreshold) {
    this.atomQuality = Atoms.tableQuality(table);
    this.atomQualityWarningThreshold = warningThreshold;
  }

  public void setMaxStringsPerRule(int max) {
    this.maxStringsPerRule = max;
  }

  public List<CompilerMessage> messages() {
    return messages;
  }

  public int errors() {
    return errors;
  }

  public ErrorCode lastError() {
    return lastError;
  }

  // ---------------------------------------------------------------------------------------------
  // External variables

  /** Defines an external variable (_yr_compiler_define_variable). */
  public ErrorCode defineExternal(ExternalDef def) {
    if (globalObjects.containsKey(def.identifier)) {
      return ErrorCode.DUPLICATED_EXTERNAL_VARIABLE;
    }
    externals.add(def);
    globalObjects.put(def.identifier, objectFromExternal(def));
    return ErrorCode.SUCCESS;
  }

  /** Creates the object representing an external variable (yr_object_from_external_variable). */
  public static YObject objectFromExternal(ExternalDef def) {
    switch (def.type) {
      case ExternalDef.TYPE_INTEGER:
      case ExternalDef.TYPE_BOOLEAN:
        {
          YInteger o = new YInteger(def.identifier);
          o.set(def.integer);
          return o;
        }
      case ExternalDef.TYPE_FLOAT:
        {
          YFloat o = new YFloat(def.identifier);
          o.set(def.dbl);
          return o;
        }
      default:
        {
          YString o = new YString(def.identifier);
          o.set(cstring(def.string));
          return o;
        }
    }
  }

  /** Truncates a byte array at the first NUL, like a C string. */
  static byte[] cstring(byte[] b) {
    for (int i = 0; i < b.length; i++) {
      if (b[i] == 0) {
        return java.util.Arrays.copyOf(b, i);
      }
    }
    return b;
  }

  private int rootIndex(String name) {
    Integer idx = rootObjectIndex.get(name);
    if (idx == null) {
      idx = rootObjects.size();
      rootObjects.add(name);
      rootObjectIndex.put(name, idx);
    }
    return idx;
  }

  // ---------------------------------------------------------------------------------------------
  // Errors and warnings

  private String currentRuleIdentifier() {
    return currentRule == null ? null : currentRule.identifier;
  }

  private int errorLine() {
    if (currentLine != 0) {
      return currentLine;
    }
    return lexer != null ? lexer.line() : 0;
  }

  /** yyerror(NULL) after setting last_error. */
  private void reportError(ErrorCode code, String extra, int line) {
    errors++;
    lastError = code;
    lastErrorExtraInfo = extra == null ? "" : extra;
    currentLine = 0;
    messages.add(
        new CompilerMessage(
            CompilerMessage.Level.ERROR,
            code,
            fileNames.peek(),
            line,
            currentRuleIdentifier(),
            errorMessage(code, lastErrorExtraInfo)));
  }

  /** yyerror(message), which sets last_error to ERROR_SYNTAX_ERROR. */
  private void reportSyntax(String message, int line) {
    errors++;
    lastError = ErrorCode.SYNTAX_ERROR;
    lastErrorExtraInfo = message;
    currentLine = 0;
    messages.add(
        new CompilerMessage(
            CompilerMessage.Level.ERROR,
            ErrorCode.SYNTAX_ERROR,
            fileNames.peek(),
            line,
            currentRuleIdentifier(),
            message));
  }

  private void warning(String message) {
    warning(currentLine != 0 ? currentLine : (lexer != null ? lexer.line() : 0), message);
  }

  private void warning(int line, String message) {
    messages.add(
        new CompilerMessage(
            CompilerMessage.Level.WARNING,
            null,
            fileNames.peek(),
            line,
            currentRuleIdentifier(),
            message));
  }

  /** fail_with_error: reports the error and aborts the current rule. */
  private ParseError fail(ErrorCode code, String extra) {
    reportError(code, extra, errorLine());
    if (code == ErrorCode.INSUFFICIENT_MEMORY) {
      throw new FatalError();
    }
    throw new ParseError();
  }

  private ParseError syntaxError() {
    if (shadow.recovering()) {
      // Bison doesn't report syntax errors until 3 tokens are shifted after an error.
      throw new ParseError();
    }
    String m = shadow.syntaxErrorMessage(tok);
    if (m == null) {
      m = "syntax error, unexpected " + tok.describe();
    }
    reportSyntax(m, errorLine());
    throw new ParseError();
  }

  private ParseError syntaxError(String expecting) {
    if (shadow.recovering()) {
      throw new ParseError();
    }
    String m = shadow.syntaxErrorMessage(tok);
    if (m == null) {
      m = "syntax error, unexpected " + tok.describe() + ", expecting " + expecting;
    }
    reportSyntax(m, errorLine());
    throw new ParseError();
  }

  /**
   * The line reported for an error in the action of a Bison rule: the line of the last consumed
   * token if Bison reduces the rule without reading the next token, otherwise the line where
   * the lexer is.
   */
  private int actionLine(int rule) {
    if (currentLine != 0) {
      return currentLine;
    }
    if (shadow != null && shadow.reducedWithoutLookahead(rule)) {
      return lastConsumedLine;
    }
    return errorLine();
  }

  // Bison rules (see BisonTables.yyrline) whose actions report errors and that can be reduced
  // without reading a lookahead token.
  private static final int R_IMPORT = 10;
  private static final int R_RULE_PHASE_1 = 11;
  private static final int R_TAG_LIST = 26;
  private static final int R_IDENTIFIER = 66;
  private static final int R_IDENTIFIER_FIELD = 67;
  private static final int R_IDENTIFIER_INDEX = 68;
  private static final int R_IDENTIFIER_CALL = 69;
  private static final int R_REGEXP = 74;
  private static final int R_MATCHES = 78;
  private static final int R_PERCENT_OF_STRING_SET = 95;
  private static final int R_PERCENT_OF_RULE_SET = 96;
  private static final int R_FOR_VARIABLE = 115;
  private static final int R_FOR_VARIABLES = 116;
  private static final int R_RANGE = 121;
  private static final int R_STRING_SET_THEM = 127;
  private static final int R_STRING_ENUMERATION_ITEM = 130;
  private static final int R_STRING_ENUMERATION_ITEM_WILDCARD = 131;
  private static final int R_RULE_ENUMERATION_ITEM = 136;
  private static final int R_RULE_ENUMERATION_ITEM_WILDCARD = 137;

  /** fail_with_error in the action of the given Bison rule. */
  private ParseError fail(int rule, ErrorCode code, String extra) {
    reportError(code, extra, actionLine(rule));
    if (code == ErrorCode.INSUFFICIENT_MEMORY) {
      throw new FatalError();
    }
    throw new ParseError();
  }

  /** Error message for an error code (yr_compiler_get_error_message). */
  public String errorMessage(ErrorCode code, String extra) {
    switch (code) {
      case INSUFFICIENT_MEMORY:
        return "not enough memory";
      case DUPLICATED_IDENTIFIER:
        return "duplicated identifier \"" + extra + "\"";
      case DUPLICATED_STRING_IDENTIFIER:
        return "duplicated string identifier \"" + extra + "\"";
      case DUPLICATED_TAG_IDENTIFIER:
        return "duplicated tag identifier \"" + extra + "\"";
      case DUPLICATED_META_IDENTIFIER:
        return "duplicated metadata identifier \"" + extra + "\"";
      case DUPLICATED_LOOP_IDENTIFIER:
        return "duplicated loop identifier \"" + extra + "\"";
      case UNDEFINED_STRING:
        return "undefined string \"" + extra + "\"";
      case UNDEFINED_IDENTIFIER:
        return "undefined identifier \"" + extra + "\"";
      case UNREFERENCED_STRING:
        return "unreferenced string \"" + extra + "\"";
      case EMPTY_STRING:
        return "empty string \"" + extra + "\"";
      case NOT_A_STRUCTURE:
        return "\"" + extra + "\" is not a structure";
      case NOT_INDEXABLE:
        return "\"" + extra + "\" is not an array or dictionary";
      case NOT_A_FUNCTION:
        return "\"" + extra + "\" is not a function";
      case INVALID_FIELD_NAME:
        return "invalid field name \"" + extra + "\"";
      case MISPLACED_ANONYMOUS_STRING:
        return "wrong use of anonymous string";
      case INCLUDES_CIRCULAR_REFERENCE:
        return "include circular reference";
      case INCLUDE_DEPTH_EXCEEDED:
        return "too many levels of included rules";
      case LOOP_NESTING_LIMIT_EXCEEDED:
        return "loop nesting limit exceeded";
      case NESTED_FOR_OF_LOOP:
        return "'for <quantifier> of <string set>' loops can't be nested";
      case UNKNOWN_MODULE:
        return "unknown module \"" + extra + "\"";
      case INVALID_MODULE_NAME:
        return "invalid module name \"" + extra + "\"";
      case DUPLICATED_STRUCTURE_MEMBER:
        return "duplicated structure member";
      case WRONG_ARGUMENTS:
        return "wrong arguments for function \"" + extra + "\"";
      case WRONG_RETURN_TYPE:
        return "wrong return type for overloaded function";
      case INVALID_HEX_STRING:
      case INVALID_REGULAR_EXPRESSION:
      case SYNTAX_ERROR:
      case WRONG_TYPE:
      case INVALID_MODIFIER:
      case INVALID_PERCENTAGE:
        return extra;
      case INTERNAL_FATAL_ERROR:
        return "internal fatal error";
      case DIVISION_BY_ZERO:
        return "division by zero";
      case REGULAR_EXPRESSION_TOO_LARGE:
        return "regular expression is too large";
      case REGULAR_EXPRESSION_TOO_COMPLEX:
        return "regular expression is too complex";
      case TOO_MANY_STRINGS:
        return "too many strings in rule \"" + extra + "\" (limit: " + maxStringsPerRule + ")";
      case INTEGER_OVERFLOW:
        return "integer overflow in \"" + extra + "\"";
      case COULD_NOT_READ_FILE:
        return "could not read file";
      case DUPLICATED_MODIFIER:
        return "duplicated modifier";
      case IDENTIFIER_MATCHES_WILDCARD:
        return "rule identifier \"" + extra + "\" matches previously used wildcard rule set";
      case INVALID_VALUE:
        return "invalid value in condition: \"" + extra + "\"";
      default:
        return "";
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Lexer host

  @Override
  public void lexerError(ErrorCode code, String extraInfo, int line) {
    reportError(code, extraInfo, currentLine != 0 ? currentLine : line);
  }

  @Override
  public void lexerSyntaxError(String message, int line) {
    reportSyntax(message, currentLine != 0 ? currentLine : line);
  }

  private static final boolean WINDOWS =
      System.getProperty("os.name", "").startsWith("Windows");

  private static byte[] defaultInclude(String includeName, String callingFile, String ns)
      throws IOException {
    Path p;
    try {
      p = Paths.get(includeName);
    } catch (java.nio.file.InvalidPathException e) {
      return null; // Like fopen() failing.
    }
    if (!Files.isRegularFile(p)) {
      return null;
    }
    return Files.readAllBytes(p);
  }

  private static boolean isAbsolutePath(String path) {
    if (WINDOWS) {
      return path.length() > 2
          && path.charAt(1) == ':'
          && (path.charAt(2) == '/' || path.charAt(2) == '\\');
    }
    return path.length() > 0 && path.charAt(0) == '/';
  }

  @Override
  public byte[] include(String path, int line) {
    if (includeResolver == null) {
      reportSyntax("includes are disabled", line);
      return null;
    }
    String currentFileName = fileNames.peek();
    String includePath;
    if (currentFileName == null || !usingDefaultIncludeResolver || isAbsolutePath(path)) {
      includePath = path;
    } else {
      int s = currentFileName.lastIndexOf('/');
      int b = currentFileName.lastIndexOf('\\');
      int sep = Math.max(s, java.io.File.separatorChar == '\\' ? b : -1);
      if (sep >= 0) {
        includePath = currentFileName.substring(0, sep + 1) + path;
      } else {
        includePath = path;
      }
    }
    byte[] content;
    if (includeReplay != null) {
      content = includeReplay.poll();
    } else {
      try {
        content = includeResolver.resolve(includePath, currentFileName, currentNs.name);
      } catch (IOException e) {
        content = null;
      }
    }
    if (includeLog != null && content != null) {
      includeLog.add(content);
    }
    if (content == null) {
      String fmt =
          usingDefaultIncludeResolver
              ? "can't open include file: "
              : "callback failed to provide include resource: ";
      reportSyntax(fmt + path, line);
      return null;
    }
    ErrorCode ec = pushFileName(includePath);
    if (ec != ErrorCode.SUCCESS) {
      if (ec == ErrorCode.INCLUDES_CIRCULAR_REFERENCE) {
        reportSyntax("includes circular reference", line);
      } else if (ec == ErrorCode.INCLUDE_DEPTH_EXCEEDED) {
        reportSyntax("includes depth exceeded", line);
      }
      lexer.terminate();
      return null;
    }
    return content;
  }

  private ErrorCode pushFileName(String fileName) {
    for (String f : fileNames) {
      if (f.equals(fileName)) {
        return ErrorCode.INCLUDES_CIRCULAR_REFERENCE;
      }
    }
    if (fileNames.size() == MAX_INCLUDE_DEPTH) {
      return ErrorCode.INCLUDE_DEPTH_EXCEEDED;
    }
    fileNames.push(fileName);
    return ErrorCode.SUCCESS;
  }

  private void popFileName() {
    if (!fileNames.isEmpty()) {
      fileNames.pop();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Entry points

  private void setNamespace(String name) {
    for (Namespace ns : namespaces) {
      if (ns.name.equals(name)) {
        currentNs = ns;
        return;
      }
    }
    Namespace ns = new Namespace(name, namespaces.size());
    namespaces.add(ns);
    currentNs = ns;
  }

  /**
   * Compiles rules from source (yr_compiler_add_string / add_file).
   *
   * @return number of errors.
   */
  public int addSource(byte[] source, String namespace, String fileName) {
    if (result != null) {
      throw new IllegalStateException("rules were already compiled");
    }
    if (errors != 0) {
      throw new IllegalStateException("a previous compilation failed");
    }
    setNamespace(namespace == null ? "default" : namespace);
    if (fileName != null) {
      ErrorCode ec = pushFileName(fileName);
      if (ec != ErrorCode.SUCCESS) {
        lastError = ec;
        return ++errors;
      }
    }
    int depth = fileNames.size();
    lexer = new Lexer(source, this);
    pending = null;
    tok = null;
    shadow = new ShadowParser();
    lastConsumedLine = 0;
    try {
      next();
      parseRules();
    } catch (FatalError e) {
      // parsing aborted
    } catch (StackOverflowError e) {
      // A last resort: expressions and groups in regular expressions and hex strings have
      // explicit limits, which a thread with a small stack may still not reach. It isn't
      // entirely safe, since a class whose initialization the overflow interrupted stays
      // unusable. Reporting the error makes the compiler unusable, so the rule left half
      // compiled can't be returned by getRules.
      reportSyntax("rules nested too deeply", errorLine());
    } finally {
      while (fileNames.size() > depth) {
        fileNames.pop();
      }
      if (fileName != null) {
        popFileName();
      }
      lexer = null;
      currentRule = null;
      currentLine = 0;
    }
    return errors;
  }

  /** Builds the compiled rule set (yr_compiler_get_rules). */
  public RuleSet getRules() {
    if (errors != 0) {
      throw new IllegalStateException("can't get rules after compilation errors");
    }
    if (result == null) {
      AhoCorasick.Tables ac = automaton.compile();
      result =
          new RuleSet(
              new ArrayList<>(rules),
              new ArrayList<>(strings),
              new ArrayList<>(namespaces),
              new ArrayList<>(externals),
              new ArrayList<>(imports),
              new ArrayList<>(rootObjects),
              reCode.toByteArray(),
              ac);
    }
    return result;
  }

  // ---------------------------------------------------------------------------------------------
  // Token handling

  private void next() {
    if (tok != null) {
      shadow.consume(tok);
      lastConsumedLine = tok.line;
    }
    if (pending != null) {
      tok = pending;
      pending = null;
    } else {
      tok = lexer.next();
    }
  }

  private boolean is(Token.Type t) {
    return tok.type == t;
  }

  private boolean isChar(char c) {
    return tok.type == Token.Type.CHAR && tok.ch == c;
  }

  private Token expect(Token.Type t) {
    if (tok.type != t) {
      throw syntaxError(t.display);
    }
    Token r = tok;
    next();
    return r;
  }

  private void expectChar(char c) {
    if (!isChar(c)) {
      throw syntaxError("'" + c + "'");
    }
    next();
  }

  // ---------------------------------------------------------------------------------------------
  // rules : (rule | import | END_OF_INCLUDED_FILE)*

  private boolean isRecoveryToken() {
    return is(Token.Type.RULE)
        || is(Token.Type.PRIVATE)
        || is(Token.Type.GLOBAL)
        || is(Token.Type.IMPORT)
        || is(Token.Type.END_OF_INCLUDED_FILE)
        || is(Token.Type.EOF);
  }

  private void parseRules() {
    while (true) {
      try {
        switch (tok.type) {
          case EOF:
            return;
          case END_OF_INCLUDED_FILE:
            popFileName();
            next();
            break;
          case IMPORT:
            parseImport();
            break;
          case RULE:
          case PRIVATE:
          case GLOBAL:
            parseRule();
            break;
          default:
            throw syntaxError();
        }
      } catch (ParseError e) {
        // Error recovery: skip tokens until something that can start a rule or an import.
        shadow.error();
        resetRuleState();
        while (!isRecoveryToken()) {
          next();
        }
        if (is(Token.Type.EOF)) {
          return;
        }
      }
    }
  }

  private void resetRuleState() {
    for (int i = 0; i <= loopIndex && i < loops.length; i++) {
      loops[i].varsCount = 0;
    }
    loopIndex = -1;
    loopForOfVarIndex = -1;
    currentRule = null;
    currentLine = 0;
  }

  // import : IMPORT TEXT_STRING
  private void parseImport() {
    next();
    Token name = expect(Token.Type.TEXT_STRING);
    byte[] b = name.bytes;
    boolean valid = b.length > 0;
    for (byte x : b) {
      if (x == 0) {
        valid = false;
      }
    }
    String moduleName = new String(cstring(b), StandardCharsets.ISO_8859_1);
    if (!valid) {
      throw fail(R_IMPORT, ErrorCode.INVALID_MODULE_NAME, moduleName);
    }
    Map<String, YObject> objs = nsObjects.computeIfAbsent(currentNs.name, k -> new HashMap<>());
    if (objs.containsKey(moduleName)) {
      return;
    }
    YaraModule module = registry.get(moduleName);
    YStructure structure = new YStructure(moduleName);
    objs.put(moduleName, structure);
    if (module == null) {
      throw fail(R_IMPORT, ErrorCode.UNKNOWN_MODULE, moduleName);
    }
    try {
      module.declare(new ModuleDeclarations(structure));
    } catch (IllegalStateException e) {
      throw fail(R_IMPORT, ErrorCode.DUPLICATED_STRUCTURE_MEMBER, moduleName);
    }
    if (!imports.contains(moduleName)) {
      imports.add(moduleName);
    }
    rootIndex(moduleName);
  }

  // ---------------------------------------------------------------------------------------------
  // rule

  private void parseRule() {
    int flags = 0;
    while (is(Token.Type.PRIVATE) || is(Token.Type.GLOBAL)) {
      flags |= is(Token.Type.PRIVATE) ? CompiledRule.FLAGS_PRIVATE : CompiledRule.FLAGS_GLOBAL;
      next();
    }
    expect(Token.Type.RULE);
    Token id = expect(Token.Type.IDENTIFIER);
    ruleDeclarationPhase1(flags, id.text);

    // tags
    if (isChar(':')) {
      next();
      if (!is(Token.Type.IDENTIFIER)) {
        throw syntaxError("identifier");
      }
      while (is(Token.Type.IDENTIFIER)) {
        String tag = tok.text;
        next();
        if (currentRule.tags.contains(tag)) {
          throw fail(R_TAG_LIST, ErrorCode.DUPLICATED_TAG_IDENTIFIER, tag);
        }
        currentRule.tags.add(tag);
      }
    }
    expectChar('{');

    // meta
    if (is(Token.Type.META)) {
      next();
      expectChar(':');
      if (!is(Token.Type.IDENTIFIER)) {
        throw syntaxError("identifier");
      }
      while (is(Token.Type.IDENTIFIER)) {
        parseMetaDeclaration();
      }
    }

    // strings
    if (is(Token.Type.STRINGS)) {
      next();
      expectChar(':');
      if (!is(Token.Type.STRING_IDENTIFIER)) {
        throw syntaxError("string identifier");
      }
      while (is(Token.Type.STRING_IDENTIFIER)) {
        parseStringDeclaration();
      }
    }

    expect(Token.Type.CONDITION);
    expectChar(':');
    Expr condition = booleanExpression(parseExpression(0));
    // Bison reduces the rule when it reads '}', without a lookahead token, so errors detected at
    // the end of the rule are reported at the line of the '}'.
    int endLine = tok.line;
    expectChar('}');
    currentRule.requiredStrings = condition.requiredStrings;
    currentRule.condition = condition.node;
    int savedLine = currentLine;
    currentLine = endLine;
    try {
      ruleDeclarationPhase2();
    } finally {
      currentLine = savedLine;
    }
  }

  private void ruleDeclarationPhase1(int flags, String identifier) {
    Map<String, Integer> nsRules =
        rulesTable.computeIfAbsent(currentNs.name, k -> new HashMap<>());
    if (nsRules.containsKey(identifier) || globalObjects.containsKey(identifier)) {
      throw fail(R_RULE_PHASE_1, ErrorCode.DUPLICATED_IDENTIFIER, identifier);
    }
    Set<String> wildcards = wildcardIdentifiers.get(currentNs.name);
    if (wildcards != null) {
      for (String prefix : wildcards) {
        if (identifier.startsWith(prefix)) {
          throw fail(R_RULE_PHASE_1, ErrorCode.IDENTIFIER_MATCHES_WILDCARD, identifier);
        }
      }
    }
    CompiledRule rule = new CompiledRule(identifier, rules.size(), currentNs, flags);
    rules.add(rule);
    currentRule = rule;
    stringsTable.clear();
    nsRules.put(identifier, rule.idx);
  }

  private void ruleDeclarationPhase2() {
    CompiledRule rule = currentRule;
    if (rule.numAtoms > ATOMS_PER_RULE_WARNING_THRESHOLD) {
      warning("rule is slowing down scanning");
    }
    int stringsInRule = 0;
    for (CompiledString s : rule.strings) {
      if (!s.is(StringFlags.REFERENCED)
          && s.chainedTo == null
          && (s.is(StringFlags.ANONYMOUS)
              || (!s.is(StringFlags.ANONYMOUS)
                  && !(s.identifier.length() > 1 && s.identifier.charAt(1) == '_')))) {
        throw fail(ErrorCode.UNREFERENCED_STRING, s.identifier);
      }
      if (!s.is(StringFlags.REFERENCED)
          && s.chainedTo == null
          && s.is(StringFlags.FIXED_OFFSET)) {
        s.flags &= ~StringFlags.FIXED_OFFSET;
      }
      stringsInRule++;
      if (stringsInRule > maxStringsPerRule) {
        throw fail(ErrorCode.TOO_MANY_STRINGS, rule.identifier);
      }
    }
    currentRule = null;
  }

  // meta_declaration
  private void parseMetaDeclaration() {
    String id = tok.text;
    next();
    expectChar('=');
    if (is(Token.Type.TEXT_STRING)) {
      byte[] s = cstring(tok.bytes);
      next();
      currentRule.metas.add(new CompiledMeta(CompiledMeta.TYPE_STRING, id, s, 0));
    } else if (is(Token.Type.NUMBER)) {
      long v = tok.integer;
      next();
      currentRule.metas.add(new CompiledMeta(CompiledMeta.TYPE_INTEGER, id, null, v));
    } else if (isChar('-')) {
      next();
      if (!is(Token.Type.NUMBER)) {
        throw syntaxError("integer number");
      }
      long v = -tok.integer;
      next();
      currentRule.metas.add(new CompiledMeta(CompiledMeta.TYPE_INTEGER, id, null, v));
    } else if (is(Token.Type.TRUE)) {
      next();
      currentRule.metas.add(new CompiledMeta(CompiledMeta.TYPE_BOOLEAN, id, null, 1));
    } else if (is(Token.Type.FALSE)) {
      next();
      currentRule.metas.add(new CompiledMeta(CompiledMeta.TYPE_BOOLEAN, id, null, 0));
    } else {
      throw syntaxError();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // String declarations

  private static final class Modifier {
    int flags;
    int xorMin;
    int xorMax;
    byte[] alphabet;
  }

  private void parseStringDeclaration() {
    String identifier = tok.text;
    next();
    if (!isChar('=')) {
      throw syntaxError("'='");
    }
    next();
    // compiler->current_line is set in a mid-rule action after '=', which Bison reduces after
    // reading the next token to choose between the three kinds of strings.
    currentLine = lexer.line();
    Modifier modifier;
    byte[] str;
    if (is(Token.Type.TEXT_STRING)) {
      str = tok.bytes;
      next();
      modifier = parseStringModifiers();
    } else if (is(Token.Type.REGEXP)) {
      Token re = tok;
      next();
      modifier = parseSimpleModifiers(true);
      modifier.flags |= StringFlags.REGEXP;
      str = re.bytes;
      if (re.regexpNoCase) {
        modifier.flags |= StringFlags.NO_CASE;
      }
      if (re.regexpDotAll) {
        modifier.flags |= StringFlags.DOT_ALL;
      }
    } else if (is(Token.Type.HEX_STRING)) {
      str = tok.bytes;
      next();
      modifier = parseSimpleModifiers(false);
      modifier.flags |= StringFlags.HEXADECIMAL;
    } else {
      throw syntaxError();
    }
    reduceStringDeclaration(modifier, identifier, str);
    currentLine = 0;
  }

  private Modifier parseStringModifiers() {
    Modifier m = new Modifier();
    while (true) {
      Modifier mod = new Modifier();
      switch (tok.type) {
        case WIDE:
          mod.flags = StringFlags.WIDE;
          next();
          break;
        case ASCII:
          mod.flags = StringFlags.ASCII;
          next();
          break;
        case NOCASE:
          mod.flags = StringFlags.NO_CASE;
          next();
          break;
        case FULLWORD:
          mod.flags = StringFlags.FULL_WORD;
          next();
          break;
        case PRIVATE:
          mod.flags = StringFlags.PRIVATE;
          next();
          break;
        case XOR:
          next();
          mod.flags = StringFlags.XOR;
          mod.xorMin = 0;
          mod.xorMax = 255;
          if (isChar('(')) {
            next();
            Token a = expect(Token.Type.NUMBER);
            if (isChar(')')) {
              next();
              if (a.integer < 0 || a.integer > 255) {
                throw fail(ErrorCode.INVALID_MODIFIER, "invalid xor range");
              }
              mod.xorMin = (int) a.integer;
              mod.xorMax = (int) a.integer;
            } else {
              expectChar('-');
              Token b = expect(Token.Type.NUMBER);
              expectChar(')');
              String err = null;
              if (a.integer < 0) {
                err = "lower bound for xor range exceeded (min: 0)";
              }
              if (b.integer > 255) {
                err = "upper bound for xor range exceeded (max: 255)";
              }
              if (a.integer > b.integer) {
                err = "xor lower bound exceeds upper bound";
              }
              if (err != null) {
                throw fail(ErrorCode.INVALID_MODIFIER, err);
              }
              mod.xorMin = (int) a.integer;
              mod.xorMax = (int) b.integer;
            }
          }
          break;
        case BASE64:
        case BASE64_WIDE:
          mod.flags = is(Token.Type.BASE64) ? StringFlags.BASE64 : StringFlags.BASE64_WIDE;
          next();
          mod.alphabet = Base64.DEFAULT_ALPHABET;
          if (isChar('(')) {
            next();
            Token a = expect(Token.Type.TEXT_STRING);
            expectChar(')');
            if (a.bytes.length != 64) {
              throw fail(ErrorCode.INVALID_MODIFIER, "length of base64 alphabet must be 64");
            }
            mod.alphabet = a.bytes;
          }
          break;
        default:
          return m;
      }
      if ((mod.flags & StringFlags.XOR) != 0) {
        m.xorMin = mod.xorMin;
        m.xorMax = mod.xorMax;
      }
      if ((mod.flags & (StringFlags.BASE64 | StringFlags.BASE64_WIDE)) != 0) {
        if (m.alphabet != null) {
          if (Nodes.compare(m.alphabet, mod.alphabet) != 0) {
            throw fail(ErrorCode.INVALID_MODIFIER, "can not specify multiple alphabets");
          }
        } else {
          m.alphabet = mod.alphabet;
        }
      }
      if ((m.flags & mod.flags) != 0) {
        throw fail(ErrorCode.DUPLICATED_MODIFIER, lastErrorExtraInfo);
      }
      m.flags |= mod.flags;
    }
  }

  private Modifier parseSimpleModifiers(boolean regexp) {
    Modifier m = new Modifier();
    while (true) {
      int f;
      if (is(Token.Type.PRIVATE)) {
        f = StringFlags.PRIVATE;
      } else if (regexp && is(Token.Type.WIDE)) {
        f = StringFlags.WIDE;
      } else if (regexp && is(Token.Type.ASCII)) {
        f = StringFlags.ASCII;
      } else if (regexp && is(Token.Type.NOCASE)) {
        f = StringFlags.NO_CASE;
      } else if (regexp && is(Token.Type.FULLWORD)) {
        f = StringFlags.FULL_WORD;
      } else {
        return m;
      }
      next();
      if ((m.flags & f) != 0) {
        throw fail(ErrorCode.DUPLICATED_MODIFIER, lastErrorExtraInfo);
      }
      m.flags |= f;
    }
  }

  private void checkStringModifiers(int flags) {
    if ((flags & StringFlags.XOR) != 0 && (flags & StringFlags.NO_CASE) != 0) {
      throw fail(ErrorCode.INVALID_MODIFIER, "invalid modifier combination: xor nocase");
    }
    boolean b64 = (flags & StringFlags.BASE64) != 0;
    boolean anyB64 = (flags & (StringFlags.BASE64 | StringFlags.BASE64_WIDE)) != 0;
    if ((flags & StringFlags.NO_CASE) != 0 && anyB64) {
      throw fail(
          ErrorCode.INVALID_MODIFIER,
          b64
              ? "invalid modifier combination: base64 nocase"
              : "invalid modifier combination: base64wide nocase");
    }
    if ((flags & StringFlags.FULL_WORD) != 0 && anyB64) {
      throw fail(
          ErrorCode.INVALID_MODIFIER,
          b64
              ? "invalid modifier combination: base64 fullword"
              : "invalid modifier combination: base64wide fullword");
    }
    if ((flags & StringFlags.XOR) != 0 && anyB64) {
      throw fail(
          ErrorCode.INVALID_MODIFIER,
          b64
              ? "invalid modifier combination: base64 xor"
              : "invalid modifier combination: base64wide xor");
    }
  }

  private static String asCString(byte[] b) {
    return new String(cstring(b), StandardCharsets.ISO_8859_1);
  }

  /** Port of yr_parser_reduce_string_declaration. */
  private void reduceStringDeclaration(Modifier modifier, String identifier, byte[] str) {
    int minAtomQuality = Atoms.MAX_ATOM_QUALITY;
    if (stringsTable.containsKey(identifier)) {
      throw fail(ErrorCode.DUPLICATED_STRING_IDENTIFIER, identifier);
    }
    if (str.length == 0) {
      throw fail(ErrorCode.EMPTY_STRING, identifier);
    }
    if ((modifier.flags & StringFlags.HEXADECIMAL) != 0) {
      modifier.flags |= StringFlags.DOT_ALL;
    }
    if ((modifier.flags & StringFlags.WIDE) == 0
        && (modifier.flags & (StringFlags.BASE64 | StringFlags.BASE64_WIDE)) == 0) {
      modifier.flags |= StringFlags.ASCII;
    }
    modifier.flags |= StringFlags.SINGLE_MATCH;
    modifier.flags |= StringFlags.FIXED_OFFSET;
    if (identifier.equals("$")) {
      modifier.flags |= StringFlags.ANONYMOUS;
    } else {
      stringsTable.put(identifier, strings.size());
    }
    checkStringModifiers(modifier.flags);

    if ((modifier.flags
            & (StringFlags.HEXADECIMAL
                | StringFlags.REGEXP
                | StringFlags.BASE64
                | StringFlags.BASE64_WIDE))
        != 0) {
      RegexParser.Result r;
      if ((modifier.flags & StringFlags.HEXADECIMAL) != 0) {
        r = HexParser.parse(str);
      } else if ((modifier.flags & StringFlags.REGEXP) != 0) {
        r = RegexParser.parse(str, strictEscape);
      } else {
        r = Base64.astFromString(str, modifier.flags, modifier.alphabet);
      }
      if (r.error != ErrorCode.SUCCESS) {
        if (r.error == ErrorCode.UNKNOWN_ESCAPE_SEQUENCE) {
          warning("unknown escape sequence");
        } else {
          String message =
              "invalid "
                  + ((modifier.flags & StringFlags.HEXADECIMAL) != 0
                      ? "hex string"
                      : "regular expression")
                  + " \""
                  + identifier
                  + "\": "
                  + r.message;
          throw fail(r.error, message);
        }
      }
      ReAst reAst = r.ast;
      if ((reAst.flags & Re.FLAGS_FAST_REGEXP) != 0) {
        modifier.flags |= StringFlags.FAST_REGEXP;
      }
      if ((reAst.flags & Re.FLAGS_GREEDY) != 0) {
        modifier.flags |= StringFlags.GREEDY_REGEXP;
      }
      if ((reAst.flags & Re.FLAGS_GREEDY) != 0 && (reAst.flags & Re.FLAGS_UNGREEDY) != 0) {
        throw fail(
            ErrorCode.INVALID_REGULAR_EXPRESSION,
            "greedy and ungreedy quantifiers can't be mixed in a regular expression");
      }
      if (ReEmitter.hasUnboundedQuantifierForDot(reAst)) {
        warning(
            identifier
                + " contains .*, .+ or .{x,} consider using .{,N}, .{1,N} or {x,N} with a"
                + " reasonable value for N");
      }
      CompiledString first = null;
      int minGap = 0;
      int maxGap = 0;
      while (reAst != null) {
        int prevMinGap = minGap;
        int prevMaxGap = maxGap;
        ReEmitter.Split split = ReEmitter.splitAtChainingPoint(reAst);
        minGap = split.minGap;
        maxGap = split.maxGap;
        CompiledString prevString = strings.isEmpty() ? null : strings.get(strings.size() - 1);
        int[] quality = new int[1];
        CompiledString s = writeString(identifier, modifier, null, reAst, quality);
        minAtomQuality = Math.min(minAtomQuality, quality[0]);
        if (first == null) {
          first = s;
        } else {
          s.chainedTo = prevString;
          s.chainGapMin = prevMinGap;
          s.chainGapMax = prevMaxGap;
          s.flags &= ~StringFlags.FIXED_OFFSET;
          prevString.flags |= StringFlags.CHAIN_PART;
          if (split.remainder == null) {
            s.flags |= StringFlags.CHAIN_PART | StringFlags.CHAIN_TAIL;
          }
        }
        reAst = split.remainder;
      }
    } else {
      int[] quality = new int[1];
      writeString(identifier, modifier, str, null, quality);
      minAtomQuality = quality[0];
    }
    if (minAtomQuality < atomQualityWarningThreshold) {
      warning("string \"" + identifier + "\" may slow down scanning");
    }
  }

  /** Port of _yr_parser_write_string. */
  private CompiledString writeString(
      String identifier, Modifier modifier, byte[] str, ReAst reAst, int[] minAtomQuality) {
    CompiledString string = new CompiledString(identifier, strings.size(), currentRule.idx);
    strings.add(string);
    currentRule.strings.add(string);
    int flags = modifier.flags;
    byte[] literal;
    if ((flags
            & (StringFlags.HEXADECIMAL
                | StringFlags.REGEXP
                | StringFlags.BASE64
                | StringFlags.BASE64_WIDE))
        != 0) {
      literal = ReEmitter.extractLiteral(reAst);
    } else {
      literal = str;
    }
    Atoms.Extraction atoms;
    try {
      if (literal != null) {
        flags |= StringFlags.LITERAL;
        string.string = literal;
        int maxStringLen = (flags & StringFlags.WIDE) != 0 ? literal.length * 2 : literal.length;
        if (maxStringLen <= Atoms.MAX_ATOM_LENGTH) {
          flags |= StringFlags.FITS_IN_ATOM;
        }
        atoms =
            Atoms.extractFromString(atomQuality, literal, flags, modifier.xorMin, modifier.xorMax);
      } else {
        flags &= ~StringFlags.FIXED_OFFSET;
        int forwardCodeStart = reCode.offset();
        ReEmitter.emit(reAst, reCode, false);
        ReEmitter.emit(reAst, reCode, true);
        atoms = Atoms.extractFromRe(atomQuality, reAst, flags);
        if (atoms.atoms == null) {
          Atoms.AtomListItem item = new Atoms.AtomListItem();
          item.atom.length = 0;
          item.backtrack = 0;
          item.backwardCodeRef = -1;
          item.forwardCodeRef = forwardCodeStart;
          atoms.atoms = item;
        }
      }
    } catch (YaraError e) {
      throw fail(e.code(), lastErrorExtraInfo);
    }
    string.flags = flags;
    automaton.addString(string, atoms.atoms);
    int c = 0;
    for (Atoms.AtomListItem a = atoms.atoms; a != null; a = a.next) {
      c++;
    }
    currentRule.numAtoms += c;
    minAtomQuality[0] = atoms.minQuality;
    return string;
  }

  // ---------------------------------------------------------------------------------------------
  // String references in conditions

  private CompiledString lookupString(String identifier) {
    for (CompiledString s : currentRule.strings) {
      if (s.chainedTo == null && s.identifier.equals(identifier)) {
        return s;
      }
    }
    throw fail(ErrorCode.UNDEFINED_STRING, identifier);
  }

  private static final int I_FOUND = 0;
  private static final int I_FOUND_AT = 1;
  private static final int I_OTHER = 2;

  private void updateStringFlagsForReference(CompiledString s, int instruction, long atOffset) {
    if (instruction != I_FOUND) {
      s.flags &= ~StringFlags.SINGLE_MATCH;
    }
    if (instruction == I_FOUND_AT) {
      if (s.fixedOffset == UNDEFINED) {
        s.fixedOffset = atOffset;
      }
      if (s.fixedOffset == UNDEFINED || s.fixedOffset != atOffset) {
        s.flags &= ~StringFlags.FIXED_OFFSET;
      }
    } else {
      s.flags &= ~StringFlags.FIXED_OFFSET;
    }
  }

  /** Port of yr_parser_reduce_string_identifier, returns the string reference. */
  private Nodes.StringRef reduceStringIdentifier(String identifier, int instruction, long atOffset) {
    if (identifier.equals("$")) {
      if (loopForOfVarIndex >= 0) {
        for (CompiledString s : currentRule.strings) {
          if (instruction != I_FOUND) {
            s.flags &= ~StringFlags.SINGLE_MATCH;
          }
          if (instruction == I_FOUND_AT) {
            if (s.fixedOffset == UNDEFINED) {
              s.fixedOffset = atOffset;
            }
            if (s.fixedOffset != atOffset) {
              s.flags &= ~StringFlags.FIXED_OFFSET;
            }
          } else {
            s.flags &= ~StringFlags.FIXED_OFFSET;
          }
        }
        return new Nodes.LoopString(loopForOfVarIndex);
      }
      throw fail(ErrorCode.MISPLACED_ANONYMOUS_STRING, lastErrorExtraInfo);
    }
    CompiledString s = lookupString(identifier);
    updateStringFlagsForReference(s, instruction, atOffset);
    s.flags |= StringFlags.REFERENCED;
    return new Nodes.FixedString(s);
  }

  /** Port of yr_parser_emit_pushes_for_strings. */
  private List<CompiledString> stringsForIdentifier(String identifier, int rule) {
    List<CompiledString> result = new ArrayList<>();
    for (CompiledString s : currentRule.strings) {
      if (s.chainedTo != null) {
        continue;
      }
      String si = s.identifier;
      int i = 0;
      while (i < identifier.length() && i < si.length() && identifier.charAt(i) == si.charAt(i)) {
        i++;
      }
      if ((i == identifier.length() && i == si.length())
          || (i < identifier.length() && identifier.charAt(i) == '*')) {
        s.flags |= StringFlags.REFERENCED;
        s.flags &= ~StringFlags.FIXED_OFFSET;
        result.add(s);
      }
    }
    if (result.isEmpty()) {
      throw fail(rule, ErrorCode.UNDEFINED_STRING, identifier);
    }
    return result;
  }

  // string_set : '(' string_enumeration ')' | THEM
  private List<CompiledString> parseStringSet() {
    if (is(Token.Type.THEM)) {
      next();
      return stringsForIdentifier("$*", R_STRING_SET_THEM);
    }
    if (!isChar('(')) {
      throw syntaxError();
    }
    next();
    List<CompiledString> result = new ArrayList<>();
    while (true) {
      if (is(Token.Type.STRING_IDENTIFIER) || is(Token.Type.STRING_IDENTIFIER_WITH_WILDCARD)) {
        String id = tok.text;
        next();
        result.addAll(
            stringsForIdentifier(
                id,
                id.endsWith("*") ? R_STRING_ENUMERATION_ITEM_WILDCARD : R_STRING_ENUMERATION_ITEM));
      } else {
        throw syntaxError();
      }
      if (isChar(',')) {
        next();
        continue;
      }
      expectChar(')');
      return result;
    }
  }

  // rule_set : '(' rule_enumeration ')'
  private List<Integer> parseRuleSet() {
    expectChar('(');
    List<Integer> result = new ArrayList<>();
    while (true) {
      if (!is(Token.Type.IDENTIFIER)) {
        throw syntaxError();
      }
      String id = tok.text;
      next();
      if (isChar('*')) {
        next();
        wildcardIdentifiers.computeIfAbsent(currentNs.name, k -> new LinkedHashSet<>()).add(id);
        Map<String, Integer> nsRules = rulesTable.get(currentNs.name);
        int matching = 0;
        for (int i = 0; i <= currentRule.idx; i++) {
          CompiledRule r = rules.get(i);
          if (r.identifier.startsWith(id)) {
            Integer idx = nsRules.get(r.identifier);
            if (idx != null) {
              result.add(idx);
              matching++;
            }
          }
        }
        if (matching == 0) {
          throw fail(R_RULE_ENUMERATION_ITEM_WILDCARD, ErrorCode.UNDEFINED_IDENTIFIER, id);
        }
      } else {
        Integer idx = rulesTable.get(currentNs.name).get(id);
        if (idx == null) {
          throw fail(R_RULE_ENUMERATION_ITEM, ErrorCode.UNDEFINED_IDENTIFIER, id);
        }
        result.add(idx);
      }
      if (isChar(',')) {
        next();
        continue;
      }
      expectChar(')');
      return result;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Expressions

  private Expr bool(Node node) {
    Expr e = new Expr(T_BOOLEAN, node);
    e.requiredStrings = 0;
    return e;
  }

  private Expr primary(int type, Node node) {
    Expr e = new Expr(type, node);
    e.primary = true;
    return e;
  }

  /** boolean_expression : expression */
  private Expr booleanExpression(Expr e) {
    Node node = e.node;
    if (e.type == T_STRING) {
      if (e.literal != null) {
        warning(
            "using literal string \"" + asCString(e.literal) + "\" in a boolean operation.");
      }
      node = new Nodes.StrToBool(node);
    }
    Expr r = new Expr(T_BOOLEAN, node);
    r.requiredStrings = e.type != T_BOOLEAN ? 0 : e.requiredStrings;
    return r;
  }

  private static String typeName(int type) {
    switch (type) {
      case T_INTEGER:
        return "integer";
      case T_FLOAT:
        return "float";
      case T_STRING:
        return "string";
      case T_BOOLEAN:
        return "boolean";
      default:
        return null;
    }
  }

  /** check_type macro. */
  private void checkType(Expr e, int expected, String op) {
    checkType(e, expected, op, 0);
  }

  /** check_type in the action of the given Bison rule (0 if it needs a lookahead). */
  private void checkType(Expr e, int expected, String op, int rule) {
    if ((e.type & expected) == 0) {
      String t = typeName(e.type);
      String extra = t != null ? "wrong type \"" + t + "\" for " + op + " operator" : lastErrorExtraInfo;
      throw fail(rule, ErrorCode.WRONG_TYPE, extra);
    }
  }

  private void requirePrimary(Expr e) {
    if (!e.primary) {
      throw syntaxError();
    }
  }

  /** True if the current token can start a primary_expression. */
  private boolean startsPrimary() {
    switch (tok.type) {
      case FILESIZE:
      case ENTRYPOINT:
      case INTEGER_FUNCTION:
      case NUMBER:
      case DOUBLE:
      case TEXT_STRING:
      case STRING_COUNT:
      case STRING_OFFSET:
      case STRING_LENGTH:
      case IDENTIFIER:
      case REGEXP:
        return true;
      case CHAR:
        return tok.ch == '(' || tok.ch == '-' || tok.ch == '~';
      default:
        return false;
    }
  }

  /** Parses a primary_expression. */
  private Expr parsePrimaryExpression() {
    if (!startsPrimary()) {
      throw syntaxError();
    }
    Expr e = parseExpression(PREC_BITOR);
    requirePrimary(e);
    return e;
  }

  // Precedence levels, from lowest to highest.
  private static final int PREC_OR = 1;
  private static final int PREC_AND = 2;
  private static final int PREC_NOT = 3;
  private static final int PREC_EQ = 4;
  private static final int PREC_REL = 5;
  private static final int PREC_OF = 6;
  private static final int PREC_BITOR = 7;
  private static final int PREC_BITXOR = 8;
  private static final int PREC_BITAND = 9;
  private static final int PREC_SHIFT = 10;
  private static final int PREC_ADD = 11;
  private static final int PREC_MUL = 12;
  private static final int PREC_UNARY = 13;

  private int binaryPrecedence() {
    switch (tok.type) {
      case OR:
        return PREC_OR;
      case AND:
        return PREC_AND;
      case EQ:
      case NEQ:
      case CONTAINS:
      case ICONTAINS:
      case STARTSWITH:
      case ENDSWITH:
      case ISTARTSWITH:
      case IENDSWITH:
      case IEQUALS:
      case MATCHES:
        return PREC_EQ;
      case LT:
      case LE:
      case GT:
      case GE:
        return PREC_REL;
      case OF:
        return PREC_OF;
      case SHIFT_LEFT:
      case SHIFT_RIGHT:
        return PREC_SHIFT;
      case CHAR:
        switch (tok.ch) {
          case '|':
            return PREC_BITOR;
          case '^':
            return PREC_BITXOR;
          case '&':
            return PREC_BITAND;
          case '+':
          case '-':
            return PREC_ADD;
          case '*':
          case '\\':
          case '%':
            return PREC_MUL;
          default:
            return -1;
        }
      default:
        return -1;
    }
  }

  /**
   * Maximum nesting of expressions. libyara's Bison parser fails with "memory exhausted" at a
   * deeper nesting, but this recursive descent parser and the evaluation of conditions would
   * need a large thread stack.
   */
  static final int MAX_EXPRESSION_DEPTH = 1000;

  private int expressionDepth;

  /** Precedence climbing parser for expressions. */
  private Expr parseExpression(int minPrec) {
    if (expressionDepth == MAX_EXPRESSION_DEPTH) {
      reportSyntax("expression nested too deeply", errorLine());
      throw new ParseError();
    }
    expressionDepth++;
    try {
      return parseExpressionUnlimited(minPrec);
    } finally {
      expressionDepth--;
    }
  }

  private Expr parseExpressionUnlimited(int minPrec) {
    Expr left = parseUnary();
    while (true) {
      int prec = binaryPrecedence();
      if (prec < 0 || prec < minPrec) {
        return left;
      }
      Token op = tok;
      switch (op.type) {
        case OR:
        case AND:
          {
            next();
            Expr l = booleanExpression(left);
            Expr r = booleanExpression(parseExpression(prec + 1));
            if (op.type == Token.Type.AND) {
              left = bool(Nodes.Chain.of(false, l.node, r.node));
              left.requiredStrings = r.requiredStrings + l.requiredStrings;
            } else {
              left = bool(Nodes.Chain.of(true, l.node, r.node));
              left.requiredStrings = Math.min(l.requiredStrings, r.requiredStrings);
            }
            break;
          }
        case OF:
          {
            requirePrimary(left);
            left = parseOf(forExpression(left));
            break;
          }
        case MATCHES:
          {
            requirePrimary(left);
            next();
            if (!is(Token.Type.REGEXP)) {
              throw syntaxError("regular expression");
            }
            Expr re = parseRegexp();
            checkType(left, T_STRING, "matches", R_MATCHES);
            checkType(re, T_REGEXP, "matches", R_MATCHES);
            left = bool(new Nodes.Matches(left.node, (Nodes.RegexpConst) re.node));
            break;
          }
        case CONTAINS:
        case ICONTAINS:
        case STARTSWITH:
        case ENDSWITH:
        case ISTARTSWITH:
        case IENDSWITH:
        case IEQUALS:
          {
            requirePrimary(left);
            next();
            if (!startsPrimary()) {
              throw syntaxError();
            }
            Expr right = parseExpression(prec + 1);
            requirePrimary(right);
            String name = op.text;
            checkType(left, T_STRING, name);
            checkType(right, T_STRING, name);
            int sop;
            switch (op.type) {
              case CONTAINS:
                sop = Nodes.SOP_CONTAINS;
                break;
              case ICONTAINS:
                sop = Nodes.SOP_ICONTAINS;
                break;
              case STARTSWITH:
                sop = Nodes.SOP_STARTSWITH;
                break;
              case ENDSWITH:
                sop = Nodes.SOP_ENDSWITH;
                break;
              case ISTARTSWITH:
                sop = Nodes.SOP_ISTARTSWITH;
                break;
              case IENDSWITH:
                sop = Nodes.SOP_IENDSWITH;
                break;
              default:
                sop = Nodes.SOP_IEQUALS;
                break;
            }
            left = bool(new Nodes.StrOp(sop, left.node, right.node));
            break;
          }
        case EQ:
        case NEQ:
        case LT:
        case LE:
        case GT:
        case GE:
          {
            requirePrimary(left);
            next();
            if (!startsPrimary()) {
              throw syntaxError();
            }
            Expr right = parseExpression(prec + 1);
            requirePrimary(right);
            String opText;
            int nop;
            switch (op.type) {
              case EQ:
                opText = "==";
                nop = Nodes.OP_EQ;
                break;
              case NEQ:
                opText = "!=";
                nop = Nodes.OP_NEQ;
                break;
              case LT:
                opText = "<";
                nop = Nodes.OP_LT;
                break;
              case LE:
                opText = "<=";
                nop = Nodes.OP_LE;
                break;
              case GT:
                opText = ">";
                nop = Nodes.OP_GT;
                break;
              default:
                opText = ">=";
                nop = Nodes.OP_GE;
                break;
            }
            Node n = reduceOperation(opText, nop, left, right);
            left = bool(n);
            break;
          }
        default:
          left = parseArithmetic(op, prec, left);
          break;
      }
    }
  }

  /** Arithmetic and bitwise binary operators (all produce primary expressions). */
  private Expr parseArithmetic(Token op, int prec, Expr left) {
    requirePrimary(left);
    next();
    char c = op.type == Token.Type.CHAR ? op.ch : 0;
    if (c == '%' && is(Token.Type.OF)) {
      return parsePercentOf(left);
    }
    if (!startsPrimary()) {
      throw syntaxError();
    }
    Expr right = parseExpression(prec + 1);
    requirePrimary(right);
    if (op.type == Token.Type.SHIFT_LEFT || op.type == Token.Type.SHIFT_RIGHT) {
      boolean shl = op.type == Token.Type.SHIFT_LEFT;
      checkType(left, T_INTEGER, shl ? "<<" : ">>");
      checkType(right, T_INTEGER, shl ? "<<" : ">>");
      Expr r =
          primary(
              T_INTEGER,
              new Nodes.IntBinary(shl ? Nodes.OP_SHL : Nodes.OP_SHR, left.node, right.node));
      long v2 = right.intValue;
      boolean invalid = false;
      if (v2 != UNDEFINED && v2 < 0) {
        invalid = true;
      } else if (v2 != UNDEFINED && v2 >= 64) {
        r.intValue = 0;
      } else {
        // libyara uses << for computing the compile time value of both operators.
        r.intValue = operation(left.intValue, v2, (a, b) -> a << b);
      }
      if (invalid) {
        throw fail(ErrorCode.INVALID_OPERAND, lastErrorExtraInfo);
      }
      return r;
    }
    switch (c) {
      case '+':
      case '-':
      case '*':
      case '\\':
        {
          String opText = String.valueOf(c);
          int nop =
              c == '+' ? Nodes.OP_ADD : c == '-' ? Nodes.OP_SUB : c == '*' ? Nodes.OP_MUL : Nodes.OP_DIV;
          ErrorCode result = ErrorCode.SUCCESS;
          String extra = null;
          Node n = null;
          try {
            n = reduceOperationNoFail(opText, nop, left, right);
          } catch (ReduceError e) {
            result = ErrorCode.WRONG_TYPE;
            extra = e.extra;
          }
          Expr r;
          if (left.type == T_INTEGER && right.type == T_INTEGER) {
            long i1 = left.intValue;
            long i2 = right.intValue;
            boolean defined = i1 != UNDEFINED && i2 != UNDEFINED;
            r = primary(T_INTEGER, n);
            switch (c) {
              case '+':
                if (defined
                    && ((i2 > 0 && i1 > Long.MAX_VALUE - i2)
                        || (i2 < 0 && i1 < Long.MIN_VALUE - i2))) {
                  result = ErrorCode.INTEGER_OVERFLOW;
                  extra = i1 + " + " + i2;
                } else {
                  r.intValue = operation(i1, i2, (a, b) -> a + b);
                }
                break;
              case '-':
                if (defined
                    && ((i2 < 0 && i1 > Long.MAX_VALUE + i2)
                        || (i2 > 0 && i1 < Long.MIN_VALUE + i2))) {
                  result = ErrorCode.INTEGER_OVERFLOW;
                  extra = i1 + " - " + i2;
                } else {
                  r.intValue = operation(i1, i2, (a, b) -> a - b);
                }
                break;
              case '*':
                {
                  long m1 = i1 < 0 ? -i1 : i1;
                  long m2 = i2 < 0 ? -i2 : i2;
                  if (defined
                      && i2 != 0
                      && Long.compareUnsigned(m1, Long.divideUnsigned(Long.MAX_VALUE, m2)) > 0) {
                    result = ErrorCode.INTEGER_OVERFLOW;
                    extra = i1 + " * " + i2;
                  } else {
                    r.intValue = operation(i1, i2, (a, b) -> a * b);
                  }
                  break;
                }
              default:
                if (i2 == 0) {
                  result = ErrorCode.DIVISION_BY_ZERO;
                } else if (i1 == Long.MIN_VALUE && i2 == -1) {
                  result = ErrorCode.INTEGER_OVERFLOW;
                  extra = i1 + " \\ " + i2;
                } else {
                  r.intValue = operation(i1, i2, (a, b) -> a / b);
                }
                break;
            }
          } else {
            r = primary(T_FLOAT, n);
          }
          if (result != ErrorCode.SUCCESS) {
            throw fail(result, extra != null ? extra : lastErrorExtraInfo);
          }
          return r;
        }
      case '%':
        {
          checkType(left, T_INTEGER, "%");
          checkType(right, T_INTEGER, "%");
          Expr r = primary(T_INTEGER, new Nodes.IntBinary(Nodes.OP_MOD, left.node, right.node));
          if (right.intValue != 0) {
            r.intValue =
                operation(left.intValue, right.intValue, (a, b) -> b == -1 ? 0 : a % b);
          } else {
            throw fail(ErrorCode.DIVISION_BY_ZERO, lastErrorExtraInfo);
          }
          return r;
        }
      case '^':
      case '&':
      case '|':
        {
          String name = c == '|' ? "|" : "^";
          checkType(left, T_INTEGER, name);
          checkType(right, T_INTEGER, name);
          int nop = c == '^' ? Nodes.OP_XOR : c == '&' ? Nodes.OP_AND : Nodes.OP_OR;
          Expr r = primary(T_INTEGER, new Nodes.IntBinary(nop, left.node, right.node));
          r.intValue =
              operation(
                  left.intValue,
                  right.intValue,
                  c == '^' ? (a, b) -> a ^ b : c == '&' ? (a, b) -> a & b : (a, b) -> a | b);
          return r;
        }
      default:
        throw syntaxError();
    }
  }

  private interface LongOp {
    long apply(long a, long b);
  }

  /** OPERATION macro: undefined if any operand is undefined. */
  private static long operation(long a, long b, LongOp op) {
    if (a == UNDEFINED || b == UNDEFINED) {
      return UNDEFINED;
    }
    return op.apply(a, b);
  }

  private static final class ReduceError extends Exception {
    private static final long serialVersionUID = 1L;
    final String extra;

    ReduceError(String extra) {
      super(extra, null, false, false);
      this.extra = extra;
    }
  }

  private Node reduceOperation(String opText, int op, Expr left, Expr right) {
    try {
      return reduceOperationNoFail(opText, op, left, right);
    } catch (ReduceError e) {
      throw fail(ErrorCode.WRONG_TYPE, e.extra);
    }
  }

  /** Port of yr_parser_reduce_operation. */
  private Node reduceOperationNoFail(String opText, int op, Expr left, Expr right)
      throws ReduceError {
    boolean lnum = left.type == T_INTEGER || left.type == T_FLOAT;
    boolean rnum = right.type == T_INTEGER || right.type == T_FLOAT;
    if (lnum && rnum) {
      if (left.type == T_INTEGER && right.type == T_INTEGER) {
        return new Nodes.IntBinary(op, left.node, right.node);
      }
      Node l = left.type == T_INTEGER ? new Nodes.IntToDbl(left.node) : left.node;
      Node r = right.type == T_INTEGER ? new Nodes.IntToDbl(right.node) : right.node;
      return new Nodes.DblBinary(op, l, r);
    } else if (left.type == T_STRING && right.type == T_STRING) {
      if (op >= Nodes.OP_EQ && op <= Nodes.OP_GE) {
        return new Nodes.StrCompare(op, left.node, right.node);
      }
      throw new ReduceError("strings don't support \"" + opText + "\" operation");
    } else {
      throw new ReduceError("type mismatch");
    }
  }

  /** Converts a for_expression primary into the quantifier expression. */
  private Expr forExpression(Expr e) {
    if (e.type == T_INTEGER && e.intValue != UNDEFINED) {
      if (e.intValue == 0) {
        warning("consider using \"none\" keyword, it is less ambiguous.");
      }
      if (e.intValue < 0) {
        throw fail(ErrorCode.INVALID_VALUE, Long.toString(e.intValue));
      }
    }
    if (e.type == T_FLOAT) {
      // libyara never stores float values in expressions, the "%a" format prints the unset field,
      // which is 0 for literals and arithmetic.
      throw fail(ErrorCode.INVALID_VALUE, hexDouble(0.0));
    }
    if (e.type == T_STRING) {
      if (e.literal != null) {
        throw fail(ErrorCode.INVALID_VALUE, asCString(e.literal));
      }
      throw fail(ErrorCode.INVALID_VALUE, "string in for_expression is invalid");
    }
    if (e.type == T_REGEXP) {
      throw fail(ErrorCode.INVALID_VALUE, "regexp in for_expression is invalid");
    }
    return e;
  }

  /** Formats a double like printf's %a. */
  /** printf("%a") as implemented by glibc. */
  private static String hexDouble(double d) {
    if (Double.isNaN(d)) {
      return "nan";
    }
    if (Double.isInfinite(d)) {
      return d > 0 ? "inf" : "-inf";
    }
    // Java prints "0x1.0p0" where glibc prints "0x1p+0".
    String s = Double.toHexString(d).replace(".0p", "p");
    int p = s.indexOf('p');
    if (p >= 0 && p + 1 < s.length() && s.charAt(p + 1) != '-') {
      s = s.substring(0, p + 1) + "+" + s.substring(p + 1);
    }
    return s;
  }

  private Expr quantifier() {
    Expr e;
    switch (tok.type) {
      case ALL:
        e = new Expr(T_QUANTIFIER, new Nodes.IntConst(UNDEFINED));
        e.intValue = FOR_ALL;
        break;
      case ANY:
        e = new Expr(T_QUANTIFIER, new Nodes.IntConst(1));
        e.intValue = FOR_ANY;
        break;
      default:
        e = new Expr(T_QUANTIFIER, new Nodes.IntConst(0));
        e.intValue = FOR_NONE;
        break;
    }
    next();
    return e;
  }

  private static boolean requiresStrings(Expr quant) {
    return (quant.type == T_INTEGER && quant.intValue > 0)
        || (quant.type == T_QUANTIFIER
            && (quant.intValue == FOR_ALL || quant.intValue == FOR_ANY));
  }

  /** for_expression OF (string_set [IN range | AT primary] | rule_set) */
  private Expr parseOf(Expr quant) {
    expect(Token.Type.OF);
    boolean ruleSet = isChar('(') && peekIsIdentifierAfterParen();
    if (ruleSet) {
      List<Integer> rs = parseRuleSet();
      if (quant.type == T_INTEGER && quant.intValue != UNDEFINED && quant.intValue > rs.size()) {
        warning(
            "expression always false - requesting " + quant.intValue + " of " + rs.size() + ".");
      }
      return bool(new Nodes.OfRules(quant.node, rs, false));
    }
    List<CompiledString> set = parseStringSet();
    long count = set.size();
    if (quant.type == T_INTEGER && quant.intValue != UNDEFINED && quant.intValue > count) {
      warning("expression always false - requesting " + quant.intValue + " of " + count + ".");
    }
    Expr r;
    if (is(Token.Type.IN)) {
      next();
      Node[] range = parseRange();
      r = bool(new Nodes.OfFoundIn(quant.node, set, range[0], range[1]));
      for (CompiledString s : set) {
        s.flags &= ~StringFlags.SINGLE_MATCH;
      }
    } else if (is(Token.Type.AT)) {
      next();
      Expr at = parsePrimaryExpression();
      if (at.type != T_INTEGER) {
        throw fail(ErrorCode.INVALID_VALUE, "at expression must be an integer");
      }
      if ((quant.type == T_INTEGER && quant.intValue != UNDEFINED && quant.intValue > 1)
          || (quant.type == T_QUANTIFIER && quant.intValue == FOR_ALL && count > 1)) {
        warning("multiple strings at an offset is usually false.");
      }
      r = bool(new Nodes.OfFoundAt(quant.node, set, at.node));
      for (CompiledString s : set) {
        s.flags &= ~StringFlags.SINGLE_MATCH;
      }
    } else {
      r = bool(new Nodes.OfStrings(quant.node, set, false));
    }
    r.requiredStrings = requiresStrings(quant) ? 1 : 0;
    return r;
  }

  /**
   * Distinguishes rule sets from string sets: the current token is '(' and we need to know if
   * the next token is an identifier. The lexer doesn't support lookahead so we use the fact that
   * string sets start with '$'.
   */
  private boolean peekIsIdentifierAfterParen() {
    Token paren = tok;
    Token after = lexer.next();
    pending = after;
    tok = paren;
    return after.type == Token.Type.IDENTIFIER;
  }

  private Token pending;

  /** primary '%' OF (string_set | rule_set) */
  private Expr parsePercentOf(Expr left) {
    next(); // OF
    boolean ruleSet = isChar('(') && peekIsIdentifierAfterParen();
    // The checks are in the action at the end of the rule, after the set has been parsed.
    List<Integer> rs = ruleSet ? parseRuleSet() : null;
    List<CompiledString> set = ruleSet ? null : parseStringSet();
    int rule = ruleSet ? R_PERCENT_OF_RULE_SET : R_PERCENT_OF_STRING_SET;
    checkType(left, T_INTEGER, "%", rule);
    if (left.intValue != UNDEFINED && (left.intValue < 1 || left.intValue > 100)) {
      throw fail(
          rule, ErrorCode.INVALID_PERCENTAGE, "percentage must be between 1 and 100 (inclusive)");
    }
    Expr r;
    if (ruleSet) {
      r = new Expr(left.type, new Nodes.OfRules(left.node, rs, true));
    } else {
      r = new Expr(left.type, new Nodes.OfStrings(left.node, set, true));
      r.requiredStrings = left.intValue != UNDEFINED ? 1 : 0;
    }
    // libyara doesn't set the type for these expressions, they keep the type of the
    // percentage (integer).
    r.intValue = left.intValue;
    r.primary = false;
    return r;
  }

  /** range : '(' primary_expression DOT_DOT primary_expression ')' */
  private Node[] parseRange() {
    expectChar('(');
    Expr lo = parsePrimaryExpression();
    expect(Token.Type.DOT_DOT);
    Expr hi = parsePrimaryExpression();
    expectChar(')');
    return checkRange(lo, hi);
  }

  private Node[] checkRange(Expr lo, Expr hi) {
    ErrorCode result = ErrorCode.SUCCESS;
    String extra = null;
    if (lo.type != T_INTEGER) {
      extra = "wrong type for range's lower bound";
      result = ErrorCode.WRONG_TYPE;
    }
    if (hi.type != T_INTEGER) {
      extra = "wrong type for range's upper bound";
      result = ErrorCode.WRONG_TYPE;
    }
    if (lo.intValue != UNDEFINED && hi.intValue != UNDEFINED) {
      if (lo.intValue > hi.intValue) {
        extra = "range lower bound must be less than upper bound";
        result = ErrorCode.INVALID_VALUE;
      } else if (lo.intValue < 0) {
        extra = "range lower bound can not be negative";
        result = ErrorCode.INVALID_VALUE;
      }
    }
    if (result != ErrorCode.SUCCESS) {
      throw fail(R_RANGE, result, extra);
    }
    return new Node[] {lo.node, hi.node};
  }

  private Expr parseRegexp() {
    Token t = tok;
    next();
    int reFlags = 0;
    if (t.regexpNoCase) {
      reFlags |= Re.FLAGS_NO_CASE;
    }
    if (t.regexpDotAll) {
      reFlags |= Re.FLAGS_DOT_ALL;
    }
    RegexParser.Result r = RegexParser.parse(t.bytes, strictEscape);
    if (r.error != ErrorCode.SUCCESS && r.error != ErrorCode.UNKNOWN_ESCAPE_SEQUENCE) {
      throw fail(R_REGEXP, r.error, r.message);
    }
    int offset;
    try {
      offset = ReEmitter.emit(r.ast, reCode, false);
    } catch (YaraError e) {
      throw fail(R_REGEXP, e.code(), lastErrorExtraInfo);
    }
    if (r.error == ErrorCode.UNKNOWN_ESCAPE_SEQUENCE) {
      warning(actionLine(R_REGEXP), "unknown escape sequence");
    }
    return primary(T_REGEXP, new Nodes.RegexpConst(offset, reFlags));
  }

  /** Converts a long-valued node for contexts where libyara would accept any value. */
  private static Node asLongNode(Expr e) {
    if (e.type == T_STRING || e.type == T_REGEXP || e.type == T_OBJECT) {
      final Node n = e.node;
      return new Node() {
        @Override
        public long evalLong(com.paveldan.yara4j.internal.exec.ExecContext ctx) {
          Object o = n.evalObj(ctx);
          // libyara pushes a pointer, which never equals small integers.
          return o == null ? UNDEFINED : 0x7FFF000000000000L;
        }
      };
    }
    return e.node;
  }

  private Expr parseUnary() {
    switch (tok.type) {
      case NOT:
        {
          next();
          Expr e = booleanExpression(parseExpression(PREC_NOT));
          return bool(new Nodes.Not(e.node));
        }
      case DEFINED:
        {
          next();
          Expr e = booleanExpression(parseExpression(PREC_NOT));
          return bool(new Nodes.Defined(e.node));
        }
      case TRUE:
        next();
        return bool(new Nodes.IntConst(1));
      case FALSE:
        next();
        return bool(new Nodes.IntConst(0));
      case STRING_IDENTIFIER:
        {
          String id = tok.text;
          next();
          if (is(Token.Type.AT)) {
            next();
            Expr at = parsePrimaryExpression();
            checkType(at, T_INTEGER, "at");
            Nodes.StringRef s = reduceStringIdentifier(id, I_FOUND_AT, at.intValue);
            Expr r = bool(new Nodes.FoundAt(s, at.node));
            r.requiredStrings = 1;
            return r;
          }
          if (is(Token.Type.IN)) {
            next();
            Node[] range = parseRange();
            Nodes.StringRef s = reduceStringIdentifier(id, I_OTHER, UNDEFINED);
            Expr r = bool(new Nodes.FoundIn(s, range[0], range[1]));
            r.requiredStrings = 1;
            return r;
          }
          Nodes.StringRef s = reduceStringIdentifier(id, I_FOUND, UNDEFINED);
          Expr r = bool(new Nodes.Found(s));
          r.requiredStrings = 1;
          return r;
        }
      case FOR:
        return parseFor();
      case ALL:
      case ANY:
      case NONE:
        {
          Expr q = quantifier();
          if (!is(Token.Type.OF)) {
            throw syntaxError("<of>");
          }
          return parseOf(q);
        }
      case CHAR:
        switch (tok.ch) {
          case '(':
            {
              next();
              Expr e = parseExpression(0);
              expectChar(')');
              return e;
            }
          case '-':
            {
              next();
              if (!startsPrimary()) {
                throw syntaxError();
              }
              Expr e = parseExpression(PREC_UNARY);
              requirePrimary(e);
              checkType(e, T_INTEGER | T_FLOAT, "-");
              if (e.type == T_INTEGER) {
                Expr r = primary(T_INTEGER, new Nodes.IntMinus(e.node));
                r.intValue = e.intValue == UNDEFINED ? UNDEFINED : -e.intValue;
                return r;
              }
              Expr r = primary(T_FLOAT, new Nodes.DblMinus(e.node));
              r.dblValue = -e.dblValue;
              return r;
            }
          case '~':
            {
              next();
              if (!startsPrimary()) {
                throw syntaxError();
              }
              Expr e = parseExpression(PREC_UNARY);
              requirePrimary(e);
              checkType(e, T_INTEGER, "~");
              Expr r = primary(T_INTEGER, new Nodes.BitNot(e.node));
              r.intValue = e.intValue == UNDEFINED ? UNDEFINED : ~e.intValue;
              return r;
            }
          default:
            throw syntaxError();
        }
      default:
        return parsePrimaryAtom();
    }
  }

  /** Primary expressions that are not built from operators. */
  private Expr parsePrimaryAtom() {
    switch (tok.type) {
      case FILESIZE:
        next();
        return primary(T_INTEGER, new Nodes.Filesize());
      case ENTRYPOINT:
        next();
        warning(
            "using deprecated \"entrypoint\" keyword. Use the \"entry_point\" function from PE"
                + " module instead.");
        return primary(T_INTEGER, new Nodes.Entrypoint());
      case INTEGER_FUNCTION:
        {
          int type = (int) tok.integer;
          next();
          expectChar('(');
          Expr e = parsePrimaryExpression();
          expectChar(')');
          checkType(e, T_INTEGER, "intXXXX or uintXXXX");
          return primary(T_INTEGER, new Nodes.ReadInt(type, e.node));
        }
      case NUMBER:
        {
          long v = tok.integer;
          next();
          Expr e = primary(T_INTEGER, new Nodes.IntConst(v));
          e.intValue = v;
          return e;
        }
      case DOUBLE:
        {
          double d = tok.dbl;
          next();
          Expr e = primary(T_FLOAT, new Nodes.FloatConst(d));
          e.dblValue = d;
          return e;
        }
      case TEXT_STRING:
        {
          byte[] s = tok.bytes;
          next();
          Expr e = primary(T_STRING, new Nodes.StringConst(s));
          e.literal = s;
          return e;
        }
      case STRING_COUNT:
        {
          String id = tok.text;
          next();
          if (is(Token.Type.IN)) {
            next();
            Node[] range = parseRange();
            Nodes.StringRef s = reduceStringIdentifier(id, I_OTHER, UNDEFINED);
            return primary(T_INTEGER, new Nodes.CountIn(s, range[0], range[1]));
          }
          Nodes.StringRef s = reduceStringIdentifier(id, I_OTHER, UNDEFINED);
          return primary(T_INTEGER, new Nodes.Count(s));
        }
      case STRING_OFFSET:
      case STRING_LENGTH:
        {
          boolean length = is(Token.Type.STRING_LENGTH);
          String id = tok.text;
          next();
          Node index;
          if (isChar('[')) {
            next();
            Expr e = parsePrimaryExpression();
            expectChar(']');
            index = asLongNode(e);
          } else {
            index = new Nodes.IntConst(1);
          }
          Nodes.StringRef s = reduceStringIdentifier(id, I_OTHER, UNDEFINED);
          return primary(T_INTEGER, new Nodes.OffsetOrLength(s, index, length));
        }
      case IDENTIFIER:
        return primaryFromIdentifier(parseIdentifier());
      case REGEXP:
        return parseRegexp();
      default:
        throw syntaxError();
    }
  }

  /** primary_expression : identifier */
  private Expr primaryFromIdentifier(Expr id) {
    if (id.type != T_OBJECT) {
      Expr r = new Expr(id.type, id.node);
      r.intValue = id.intValue;
      r.literal = id.literal;
      r.identifier = id.identifier;
      r.requiredStrings = id.requiredStrings;
      r.primary = true;
      return r;
    }
    YObject o = id.object;
    switch (o.type()) {
      case INTEGER:
        {
          Expr r = primary(T_INTEGER, new Nodes.ObjIntValue(id.node));
          r.intValue = ((YInteger) o).value();
          if (id.node instanceof CallMarker) {
            r.node = ((CallMarker) id.node).call;
          }
          return r;
        }
      case FLOAT:
        {
          Expr r = primary(T_FLOAT, new Nodes.ObjFloatValue(id.node));
          if (id.node instanceof CallMarker) {
            r.node = ((CallMarker) id.node).call;
          }
          return r;
        }
      case STRING:
        {
          Expr r = primary(T_STRING, new Nodes.ObjStringValue(id.node));
          if (id.node instanceof CallMarker) {
            r.node = ((CallMarker) id.node).call;
          }
          return r;
        }
      default:
        throw fail(
            ErrorCode.WRONG_TYPE, "wrong usage of identifier \"" + id.identifier + "\"");
    }
  }

  /**
   * Placeholder node for function calls: the Call node produces the value directly instead of
   * an object, so it replaces the OBJ_VALUE node when the call is used as primary expression.
   */
  private static final class CallMarker extends Node {
    final Nodes.Call call;

    CallMarker(Nodes.Call call) {
      this.call = call;
    }
  }

  private int lookupLoopVariable(String identifier, Expr[] expr) {
    int varOffset = 0;
    for (int i = 0; i <= loopIndex; i++) {
      varOffset += loops[i].varsInternalCount;
      for (int j = 0; j < loops[i].varsCount; j++) {
        if (loops[i].varNames[j] != null && identifier.equals(loops[i].varNames[j])) {
          if (expr != null) {
            expr[0] = loops[i].vars[j];
          }
          return varOffset + j;
        }
      }
      varOffset += loops[i].varsCount;
    }
    return -1;
  }

  private int varFrame() {
    int result = 0;
    for (int i = 0; i < loopIndex; i++) {
      result += loops[i].varsCount + loops[i].varsInternalCount;
    }
    return result;
  }

  /** identifier : IDENTIFIER | identifier '.' IDENTIFIER | identifier '[' ... ']' | call */
  private Expr parseIdentifier() {
    String name = tok.text;
    next();
    Expr result;
    Expr[] loopVar = new Expr[1];
    int varIndex = lookupLoopVariable(name, loopVar);
    if (varIndex >= 0) {
      Expr v = loopVar[0];
      int type = v == null ? T_UNKNOWN : v.type;
      Node node =
          type == T_INTEGER ? new Nodes.LoopVarLong(varIndex) : new Nodes.LoopVarObj(varIndex);
      result = new Expr(type, node);
      if (v != null) {
        result.object = v.object;
        result.intValue = v.intValue;
      }
      result.identifier = name;
    } else {
      YObject object = globalObjects.get(name);
      if (object == null) {
        Map<String, YObject> objs = nsObjects.get(currentNs.name);
        if (objs != null) {
          object = objs.get(name);
        }
      }
      if (object != null) {
        result = new Expr(T_OBJECT, new Nodes.ObjLoad(rootIndex(name)));
        result.object = object;
        result.identifier = name;
      } else {
        Map<String, Integer> nsRules = rulesTable.get(currentNs.name);
        Integer ruleIdx = nsRules == null ? null : nsRules.get(name);
        if (ruleIdx != null) {
          result = new Expr(T_BOOLEAN, new Nodes.RuleRef(ruleIdx));
          result.intValue = UNDEFINED;
          result.identifier = rules.get(ruleIdx).identifier;
          result.requiredStrings = 0;
        } else {
          throw fail(R_IDENTIFIER, ErrorCode.UNDEFINED_IDENTIFIER, name);
        }
      }
    }
    while (true) {
      if (isChar('.')) {
        next();
        if (!is(Token.Type.IDENTIFIER)) {
          throw syntaxError("identifier");
        }
        String field = tok.text;
        next();
        if (result.type == T_OBJECT && result.object instanceof YStructure) {
          YObject f = ((YStructure) result.object).field(field);
          if (f == null) {
            throw fail(R_IDENTIFIER_FIELD, ErrorCode.INVALID_FIELD_NAME, field);
          }
          Expr r = new Expr(T_OBJECT, new Nodes.ObjField(result.node, field));
          r.object = f;
          r.identifier = field;
          result = r;
        } else {
          throw fail(R_IDENTIFIER_FIELD, ErrorCode.NOT_A_STRUCTURE, result.identifier);
        }
      } else if (isChar('[')) {
        next();
        Expr index = parsePrimaryExpression();
        expectChar(']');
        if (result.type == T_OBJECT && result.object instanceof YArray) {
          if (index.type != T_INTEGER) {
            throw fail(R_IDENTIFIER_INDEX, ErrorCode.WRONG_TYPE, "array indexes must be of integer type");
          }
          YArray a = (YArray) result.object;
          Expr r = new Expr(T_OBJECT, new Nodes.IndexArray(result.node, index.node));
          r.object = a.prototype();
          r.identifier = a.identifier();
          result = r;
        } else if (result.type == T_OBJECT && result.object instanceof YDictionary) {
          if (index.type != T_STRING) {
            throw fail(R_IDENTIFIER_INDEX, ErrorCode.WRONG_TYPE, "dictionary keys must be of string type");
          }
          YDictionary d = (YDictionary) result.object;
          Expr r = new Expr(T_OBJECT, new Nodes.LookupDict(result.node, index.node));
          r.object = d.prototype();
          r.identifier = d.identifier();
          result = r;
        } else {
          throw fail(R_IDENTIFIER_INDEX, ErrorCode.NOT_INDEXABLE, result.identifier);
        }
      } else if (isChar('(')) {
        next();
        List<Expr> args = new ArrayList<>();
        StringBuilder fmt = new StringBuilder();
        if (!isChar(')')) {
          while (true) {
            Expr a = parseExpression(0);
            if (fmt.length() == MAX_FUNCTION_ARGS) {
              throw fail(ErrorCode.TOO_MANY_ARGUMENTS, lastErrorExtraInfo);
            }
            switch (a.type) {
              case T_INTEGER:
                fmt.append('i');
                break;
              case T_FLOAT:
                fmt.append('f');
                break;
              case T_BOOLEAN:
                fmt.append('b');
                break;
              case T_STRING:
                fmt.append('s');
                break;
              case T_REGEXP:
                fmt.append('r');
                break;
              default:
                throw fail(
                    ErrorCode.WRONG_TYPE,
                    "unknown type for argument " + (fmt.length() + 1) + " in function call");
            }
            args.add(a);
            if (isChar(',')) {
              next();
              continue;
            }
            break;
          }
        }
        expectChar(')');
        if (result.type == T_OBJECT && result.object instanceof YFunction) {
          YFunction f = (YFunction) result.object;
          String argsFmt = fmt.toString();
          if (f.findOverload(argsFmt) == null) {
            throw fail(R_IDENTIFIER_CALL, ErrorCode.WRONG_ARGUMENTS, f.identifier());
          }
          List<Node> argNodes = new ArrayList<>();
          for (Expr a : args) {
            argNodes.add(a.node);
          }
          char ret;
          switch (f.returnObject().type()) {
            case INTEGER:
              ret = 'i';
              break;
            case FLOAT:
              ret = 'f';
              break;
            default:
              ret = 's';
              break;
          }
          Nodes.Call call = new Nodes.Call(result.node, argNodes, argsFmt, ret);
          Expr r = new Expr(T_OBJECT, new CallMarker(call));
          r.object = f.returnObject();
          r.identifier = argsFmt;
          result = r;
        } else {
          throw fail(R_IDENTIFIER_CALL, ErrorCode.NOT_A_FUNCTION, result.identifier);
        }
      } else {
        return result;
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // for loops

  private Expr parseFor() {
    next(); // FOR
    Expr quant;
    if (is(Token.Type.ALL) || is(Token.Type.ANY) || is(Token.Type.NONE)) {
      quant = quantifier();
    } else {
      quant = forExpression(parsePrimaryExpression());
    }
    if (loopIndex + 1 == ExecLimits.MAX_LOOP_NESTING) {
      throw fail(ErrorCode.LOOP_NESTING_LIMIT_EXCEEDED, lastErrorExtraInfo);
    }
    loopIndex++;
    LoopContext loop = loops[loopIndex];
    loop.varsInternalCount = ExecLimits.INTERNAL_LOOP_VARS;
    loop.varsCount = 0;
    int varFrame = varFrame();
    boolean stringSet = false;
    java.util.function.Supplier<Nodes.LoopIterator> iterator;

    if (is(Token.Type.OF)) {
      next();
      if (loopForOfVarIndex != -1) {
        throw fail(ErrorCode.NESTED_FOR_OF_LOOP, lastErrorExtraInfo);
      }
      loop.varsCount = 1;
      loopForOfVarIndex = varFrame + loop.varsInternalCount;
      final int slot = loopForOfVarIndex;
      final List<CompiledString> set = parseStringSet();
      iterator = () -> new Nodes.StringSetIterator(set, slot);
      stringSet = true;
    } else {
      // for_variables
      if (!is(Token.Type.IDENTIFIER)) {
        throw syntaxError("identifier");
      }
      while (true) {
        String var = tok.text;
        next();
        int varRule = loop.varsCount == 0 ? R_FOR_VARIABLE : R_FOR_VARIABLES;
        if (loop.varsCount == ExecLimits.MAX_LOOP_VARS) {
          throw fail(varRule, ErrorCode.SYNTAX_ERROR, "too many loop variables");
        }
        if (lookupLoopVariable(var, null) >= 0) {
          throw fail(varRule, ErrorCode.DUPLICATED_LOOP_IDENTIFIER, var);
        }
        loop.varNames[loop.varsCount] = var;
        loop.vars[loop.varsCount] = null;
        loop.varsCount++;
        if (isChar(',')) {
          next();
          if (!is(Token.Type.IDENTIFIER)) {
            throw syntaxError("identifier");
          }
          continue;
        }
        break;
      }
      expect(Token.Type.IN);
      iterator = parseIterator(loop, varFrame);
    }
    expectChar(':');
    expectChar('(');
    Expr body = booleanExpression(parseExpression(0));
    expectChar(')');
    if (stringSet) {
      loopForOfVarIndex = -1;
    }
    loop.varsCount = 0;
    for (int i = 0; i < ExecLimits.MAX_LOOP_VARS; i++) {
      loop.varNames[i] = null;
      loop.vars[i] = null;
    }
    loopIndex--;
    return bool(new Nodes.For(quant.node, iterator, body.node));
  }

  private java.util.function.Supplier<Nodes.LoopIterator> parseIterator(
      LoopContext loop, int varFrame) {
    final int slot0 = varFrame + ExecLimits.INTERNAL_LOOP_VARS;
    final int slot1 = slot0 + 1;
    if (isChar('(')) {
      // set : '(' enumeration ')' | range
      next();
      Expr first = parsePrimaryExpression();
      if (is(Token.Type.DOT_DOT)) {
        next();
        Expr hi = parsePrimaryExpression();
        expectChar(')');
        final Node[] range = checkRange(first, hi);
        setSingleVar(loop, T_INTEGER);
        return () -> new Nodes.RangeIterator(range[0], range[1], slot0);
      }
      if (first.type != T_INTEGER && first.type != T_STRING) {
        throw fail(ErrorCode.WRONG_TYPE, "wrong type for enumeration item");
      }
      int type = first.type;
      final List<Node> items = new ArrayList<>();
      items.add(first.node);
      while (isChar(',')) {
        next();
        Expr item = parsePrimaryExpression();
        if (item.type != type) {
          throw fail(ErrorCode.WRONG_TYPE, "enumerations must be all the same type");
        }
        items.add(item.node);
      }
      expectChar(')');
      setSingleVar(loop, type);
      if (type == T_INTEGER) {
        return () -> new Nodes.IntEnumIterator(items, slot0);
      }
      return () -> new Nodes.TextStringIterator(items, slot0);
    }
    if (!is(Token.Type.IDENTIFIER)) {
      throw syntaxError();
    }
    Expr id = parseIdentifier();
    if (id.type == T_OBJECT) {
      if (id.object instanceof YArray) {
        if (loop.varsCount == 1) {
          Expr v = new Expr(T_OBJECT, null);
          v.object = ((YArray) id.object).prototype();
          loop.vars[0] = v;
          final Node array = id.node;
          return () -> new Nodes.ArrayIterator(array, slot0);
        }
        throw fail(
            ErrorCode.SYNTAX_ERROR,
            "iterator for \""
                + id.identifier
                + "\" yields a single item on each iteration, but the loop expects "
                + loop.varsCount);
      }
      if (id.object instanceof YDictionary) {
        if (loop.varsCount == 2) {
          Expr k = new Expr(T_STRING, null);
          Expr v = new Expr(T_OBJECT, null);
          v.object = ((YDictionary) id.object).prototype();
          loop.vars[0] = k;
          loop.vars[1] = v;
          final Node dict = id.node;
          return () -> new Nodes.DictIterator(dict, slot0, slot1);
        }
        throw fail(
            ErrorCode.SYNTAX_ERROR,
            "iterator for \"" + id.identifier + "\" yields a key,value pair item on each iteration");
      }
    }
    throw fail(ErrorCode.WRONG_TYPE, "identifier \"" + id.identifier + "\" is not iterable");
  }

  private void setSingleVar(LoopContext loop, int type) {
    if (loop.varsCount == 1) {
      Expr v = new Expr(type, null);
      v.intValue = UNDEFINED;
      loop.vars[0] = v;
    } else {
      throw fail(
          ErrorCode.SYNTAX_ERROR,
          "iterator yields one value on each iteration , but the loop expects " + loop.varsCount);
    }
  }
}
