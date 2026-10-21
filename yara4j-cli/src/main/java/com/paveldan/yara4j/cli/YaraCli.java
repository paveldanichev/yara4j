package com.paveldan.yara4j.cli;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.Callable;
import com.paveldan.yara4j.CallbackResult;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.Meta;
import com.paveldan.yara4j.Rule;
import com.paveldan.yara4j.RuleMatch;
import com.paveldan.yara4j.Rules;
import com.paveldan.yara4j.ScanCallback;
import com.paveldan.yara4j.Scanner;
import com.paveldan.yara4j.StringMatch;
import com.paveldan.yara4j.YaraCompiler;
import com.paveldan.yara4j.YaraException;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YStructure;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/** The yara command, a port of cli/yara.c. */
@Command(
    name = "yara",
    usageHelpWidth = 100,
    sortOptions = false,
    headerHeading = "YARA " + Common.VERSION + " (yara4j), the pattern matching swiss army knife.%n",
    header = "",
    customSynopsis = "Usage: yara [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR",
    footer = "%nyara4j can't scan process memory, the target must be a file or a directory.")
public final class YaraCli implements Callable<Integer> {

  private static final int MAX_THREADS = 32;
  private static final int MAX_QUEUED_FILES = 64;

  @Option(names = "--atom-quality-table", paramLabel = "FILE",
      description = "path to a file with the atom quality table")
  String atomQualityTable;

  @Option(names = {"-C", "--compiled-rules"}, description = "load compiled rules")
  boolean rulesAreCompiled;

  @Option(names = {"-c", "--count"}, description = "print only number of matches")
  boolean printCountOnly;

  @Option(names = {"-E", "--strict-escape"}, description = "warn on unknown escape sequences")
  boolean strictEscape;

  @Option(names = {"-d", "--define"}, paramLabel = "VAR=VALUE",
      description = "define external variable")
  List<String> extVars = new ArrayList<>();

  @Option(names = {"-q", "--disable-console-logs"},
      description = "disable printing console log messages")
  boolean disableConsoleLogs;

  @Option(names = "--fail-on-warnings", description = "fail on warnings")
  boolean failOnWarnings;

  @Option(names = {"-f", "--fast-scan"}, description = "fast matching mode")
  boolean fastScan;

  @Option(names = {"-h", "--help"}, usageHelp = true, description = "show this help and exit")
  boolean showHelp;

  @Option(names = {"-i", "--identifier"}, paramLabel = "IDENTIFIER",
      description = "print only rules named IDENTIFIER")
  List<String> identifiers = new ArrayList<>();

  @Option(names = "--max-process-memory-chunk", paramLabel = "NUMBER", hidden = true,
      description = "ignored, process scanning is not supported")
  long maxProcessMemoryChunk;

  @Option(names = {"-l", "--max-rules"}, paramLabel = "NUMBER",
      description = "abort scanning after matching a NUMBER of rules")
  long limit;

  @Option(names = "--max-strings-per-rule", paramLabel = "NUMBER",
      description = "set maximum number of strings per rule (default=10000)")
  int maxStringsPerRule = 10000;

  @Option(names = {"-x", "--module-data"}, paramLabel = "MODULE=FILE",
      description = "pass FILE's content as extra data to MODULE")
  List<String> modulesData = new ArrayList<>();

  @Option(names = {"-n", "--negate"}, description = "print only not satisfied rules (negate)")
  boolean negate;

  @Option(names = {"-N", "--no-follow-symlinks"},
      description = "do not follow symlinks when scanning")
  boolean noFollowSymlinks;

  @Option(names = {"-w", "--no-warnings"}, description = "disable warnings")
  boolean ignoreWarnings;

  @Option(names = {"-m", "--print-meta"}, description = "print metadata")
  boolean showMeta;

  @Option(names = {"-D", "--print-module-data"}, description = "print module data")
  boolean showModuleData;

  @Option(names = {"-M", "--module-names"}, description = "show module names")
  boolean showModuleNames;

  @Option(names = {"-e", "--print-namespace"}, description = "print rules' namespace")
  boolean showNamespace;

  @Option(names = {"-S", "--print-stats"}, description = "print rules' statistics (not supported)")
  boolean showStats;

  @Option(names = {"-s", "--print-strings"}, description = "print matching strings")
  boolean showStrings;

  @Option(names = {"-L", "--print-string-length"},
      description = "print length of matched strings")
  boolean showStringLength;

  @Option(names = {"-X", "--print-xor-key"},
      description = "print xor key and plaintext of matched strings")
  boolean showXorKey;

  @Option(names = {"-g", "--print-tags"}, description = "print tags")
  boolean showTags;

  @Option(names = {"-r", "--recursive"}, description = "recursively search directories")
  boolean recursiveSearch;

  @Option(names = "--scan-list", description = "scan files listed in FILE, one per line")
  boolean scanListSearch;

  @Option(names = {"-z", "--skip-larger"}, paramLabel = "NUMBER",
      description = "skip files larger than the given size when scanning a directory")
  long skipLarger;

  @Option(names = {"-k", "--stack-size"}, paramLabel = "SLOTS",
      description = "set maximum stack size (accepted for compatibility, ignored)")
  long stackSize;

  @Option(names = {"-t", "--tag"}, paramLabel = "TAG", description = "print only rules tagged as TAG")
  List<String> tags = new ArrayList<>();

  @Option(names = {"-p", "--threads"}, paramLabel = "NUMBER",
      description = "use the specified NUMBER of threads to scan a directory")
  int threads = MAX_THREADS;

  @Option(names = {"-a", "--timeout"}, paramLabel = "SECONDS",
      description = "abort scanning after the given number of SECONDS")
  long timeout = 1000000;

  @Option(names = {"-v", "--version"}, versionHelp = true, description = "show version information")
  boolean showVersion;

  @Parameters(paramLabel = "ARGS", description = "rules files followed by the target")
  List<String> args = new ArrayList<>();

  private final PrintStream out;
  private final Object outputLock = new Object();
  private final AtomicLong totalCount = new AtomicLong();
  private final Map<String, byte[]> moduleData = new LinkedHashMap<>();

  YaraCli(PrintStream out) {
    this.out = out;
  }

  public static void main(String[] argv) {
    PrintStream out = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out),
        false, StandardCharsets.ISO_8859_1);
    CommandLine cl = new CommandLine(new YaraCli(out));
    cl.getCommandSpec().version(Common.VERSION);
    int rc = cl.execute(argv);
    out.flush();
    System.exit(rc);
  }

  /** Exception used to exit with a failure after printing a message. */
  private static final class Exit extends Exception {
    private static final long serialVersionUID = 1L;
  }

  @Override
  public Integer call() {
    try {
      return run();
    } catch (Exit e) {
      return 1;
    } finally {
      out.flush();
    }
  }

  private int run() throws Exit {
    if (threads > MAX_THREADS) {
      System.err.println("maximum number of threads is " + MAX_THREADS);
      return 1;
    }
    if (showModuleNames) {
      for (YaraModule m : ServiceLoader.load(YaraModule.class, YaraCli.class.getClassLoader())) {
        out.print(m.name() + "\n");
      }
      return 0;
    }
    if (args.size() < 2) {
      System.err.println("yara: wrong number of arguments");
      System.err.println("Usage: yara [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR | PID");
      System.err.println();
      System.err.println("Try `--help` for more options");
      return 1;
    }
    loadModulesData();
    Rules rules = loadRules();
    if (showStats) {
      System.err.println("warning: --print-stats is not supported by yara4j");
    }
    long deadline = System.currentTimeMillis() + Math.min(timeout, Long.MAX_VALUE / 2000) * 1000;
    String target = args.get(args.size() - 1);
    boolean argIsDir = Common.isDirectory(target);
    if (scanListSearch && argIsDir) {
      System.err.println("error: cannot use a directory as scan list.");
      return 1;
    }
    if (scanListSearch || argIsDir) {
      return scanMany(rules, target, argIsDir, deadline);
    }
    Scanner scanner = newScanner(rules);
    int[] count = {0};
    scanner.setCallback(callback(target, count));
    scanner.setTimeout(Duration.ofSeconds(Math.max(1, timeout)));
    ErrorCode result = scanFile(scanner, target);
    if (result != ErrorCode.SUCCESS) {
      out.flush();
      System.err.print("error scanning " + target + ": ");
      if (result == ErrorCode.COULD_NOT_OPEN_FILE && isPid(target)) {
        System.err.println("process memory scanning is not supported by yara4j");
      } else {
        Common.printError(System.err, result);
      }
      return 1;
    }
    if (printCountOnly) {
      out.print(count[0] + "\n");
    }
    return 0;
  }

  private static boolean isPid(String s) {
    return !s.isEmpty() && s.chars().allMatch(c -> c >= '0' && c <= '9') && !s.matches("0+");
  }

  private void loadModulesData() throws Exit {
    for (String md : modulesData) {
      int eq = md.indexOf('=');
      if (eq < 0) {
        System.err.println("error: wrong syntax for `-x` option.");
        throw new Exit();
      }
      String file = md.substring(eq + 1);
      try {
        moduleData.put(md.substring(0, eq), Files.readAllBytes(Paths.get(file)));
      } catch (IOException | RuntimeException e) {
        System.err.println("error: could not open file \"" + file + "\".");
        throw new Exit();
      }
    }
  }

  private Rules loadRules() throws Exit {
    if (rulesAreCompiled) {
      if (args.size() != 2) {
        System.err.println(
            "error: can't accept multiple rules files if one of them is in compiled form.");
        throw new Exit();
      }
      try {
        Rules rules = Rules.load(Paths.get(args.get(0)));
        // The variables are checked here; they are defined again in every scanner.
        Common.defineExternals(extVars, Common.definer(rules.newScanner()));
        return rules;
      } catch (YaraException e) {
        Common.printError(System.err, e.getErrorCode());
        throw new Exit();
      } catch (IOException | InvalidPathException e) {
        Common.printError(System.err, ErrorCode.COULD_NOT_OPEN_FILE);
        throw new Exit();
      }
    }
    YaraCompiler compiler = new YaraCompiler();
    try {
      Common.defineExternals(extVars, Common.definer(compiler));
    } catch (YaraException e) {
      Common.printError(System.err, e.getErrorCode());
      throw new Exit();
    }
    if (atomQualityTable != null && !Common.loadAtomQualityTable(compiler, atomQualityTable)) {
      System.err.print("error loading atom quality table: ");
      Common.printError(System.err, ErrorCode.COULD_NOT_OPEN_FILE);
      throw new Exit();
    }
    compiler.setMaxStringsPerRule(maxStringsPerRule);
    compiler.setStrictEscape(strictEscape);
    Common.CompilerResults cr = new Common.CompilerResults();
    if (!Common.compileFiles(compiler, args, ignoreWarnings, cr)) {
      throw new Exit();
    }
    if (cr.errors > 0 || (failOnWarnings && cr.warnings > 0)) {
      throw new Exit();
    }
    try {
      return compiler.getRules();
    } catch (YaraException e) {
      Common.printError(System.err, e.getErrorCode());
      throw new Exit();
    }
  }

  private Scanner newScanner(Rules rules) throws Exit {
    Scanner scanner = rules.newScanner();
    scanner.setFastMode(fastScan);
    scanner.setReportRules(true, true);
    try {
      if (rulesAreCompiled) {
        Common.defineExternals(extVars, Common.definer(scanner));
      }
    } catch (YaraException e) {
      Common.printError(System.err, e.getErrorCode());
      throw new Exit();
    }
    return scanner;
  }

  private ErrorCode scanFile(Scanner scanner, String file) {
    try {
      Path p = Paths.get(file);
      if (!Files.isReadable(p) || Files.isDirectory(p)) {
        return ErrorCode.COULD_NOT_OPEN_FILE;
      }
      scanner.scan(p);
      return ErrorCode.SUCCESS;
    } catch (YaraException e) {
      return e.getErrorCode();
    } catch (IOException | RuntimeException e) {
      return ErrorCode.COULD_NOT_OPEN_FILE;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Directory and scan list scanning with a pool of threads.

  private static final String END = new String("\0end");

  private int scanMany(Rules rules, String target, boolean isDir, long deadline) throws Exit {
    BlockingQueue<String> queue = new ArrayBlockingQueue<>(MAX_QUEUED_FILES);
    List<Thread> workers = new ArrayList<>();
    int n = Math.max(1, threads);
    for (int i = 0; i < n; i++) {
      Scanner scanner = newScanner(rules);
      Thread t = new Thread(() -> worker(scanner, queue, deadline), "yara-scan-" + i);
      t.setDaemon(true);
      workers.add(t);
      t.start();
    }
    boolean ok = true;
    try {
      if (isDir) {
        scanDir(Paths.get(target), queue, deadline);
      } else {
        ok = populateScanList(target, queue, deadline);
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    for (int i = 0; i < n; i++) {
      try {
        queue.put(END);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    for (Thread t : workers) {
      try {
        long wait = Math.max(1, deadline - System.currentTimeMillis());
        t.join(wait);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    return ok ? 0 : 1;
  }

  private void worker(Scanner scanner, BlockingQueue<String> queue, long deadline) {
    while (true) {
      String path;
      try {
        long wait = deadline - System.currentTimeMillis();
        path = wait <= 0 ? null : queue.poll(wait, TimeUnit.MILLISECONDS);
      } catch (InterruptedException e) {
        return;
      }
      if (path == null || path == END) {
        return;
      }
      long remaining = (deadline - System.currentTimeMillis()) / 1000;
      if (remaining <= 0) {
        return;
      }
      int[] count = {0};
      scanner.setCallback(callback(path, count));
      scanner.setTimeout(Duration.ofSeconds(remaining));
      ErrorCode result = scanFile(scanner, path);
      synchronized (outputLock) {
        if (printCountOnly) {
          out.println(nativePath(path) + ": " + count[0]);
        }
        if (result != ErrorCode.SUCCESS) {
          out.flush();
          System.err.print("error scanning " + path + ": ");
          Common.printError(System.err, result);
        }
      }
    }
  }

  private void put(BlockingQueue<String> queue, String path, long deadline)
      throws InterruptedException {
    long wait = deadline - System.currentTimeMillis();
    if (wait <= 0 || !queue.offer(path, wait, TimeUnit.MILLISECONDS)) {
      throw new InterruptedException("timeout");
    }
  }

  private void scanDir(Path dir, BlockingQueue<String> queue, long deadline)
      throws InterruptedException {
    List<Path> entries = new ArrayList<>();
    try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
      for (Path p : ds) {
        entries.add(p);
      }
    } catch (IOException | RuntimeException e) {
      return;
    }
    for (Path p : entries) {
      BasicFileAttributes attrs;
      try {
        attrs = Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (attrs.isSymbolicLink()) {
          if (noFollowSymlinks) {
            continue;
          }
          Path link = Files.readSymbolicLink(p);
          if (link.toString().equals(".") || link.toString().equals("..")) {
            continue;
          }
        }
        attrs = Files.readAttributes(p, BasicFileAttributes.class);
      } catch (IOException | RuntimeException e) {
        continue;
      }
      // yara.exe joins with a backslash, yara with a slash.
      String full = dir.toString() + (Common.WINDOWS ? "\\" : "/") + p.getFileName();
      if (attrs.isRegularFile()) {
        if (skipLarger > attrs.size() || skipLarger <= 0) {
          put(queue, full, deadline);
        } else if (!ignoreWarnings) {
          System.err.printf(
              "skipping %s (%d bytes) because it's larger than %d bytes.%n",
              full, attrs.size(), skipLarger);
        }
      } else if (recursiveSearch && attrs.isDirectory()) {
        scanDir(Paths.get(full), queue, deadline);
      }
    }
  }

  private boolean populateScanList(String file, BlockingQueue<String> queue, long deadline)
      throws InterruptedException {
    byte[] content;
    try {
      content = Files.readAllBytes(Paths.get(file));
    } catch (IOException | RuntimeException e) {
      System.err.println("error: could not open file \"" + file + "\".");
      return false;
    }
    String text = new String(content, StandardCharsets.ISO_8859_1);
    int start = 0;
    while (start < text.length()) {
      int nl = text.indexOf('\n', start);
      String path = nl < 0 ? text.substring(start) : text.substring(start, nl);
      start = nl < 0 ? text.length() : nl + 1;
      if (Common.WINDOWS) {
        // yara.exe splits with _tcstok_s, which skips empty lines, and removes a trailing \r.
        if (path.isEmpty()) {
          continue;
        }
        if (path.endsWith("\r")) {
          path = path.substring(0, path.length() - 1);
        }
      }
      if (Common.isDirectory(path)) {
        scanDir(Paths.get(path), queue, deadline);
      } else {
        put(queue, path, deadline);
      }
    }
    return true;
  }

  // ---------------------------------------------------------------------------------------------
  // Output

  private static final char[] CESCAPES = new char[32];

  static {
    CESCAPES[7] = 'a';
    CESCAPES[8] = 'b';
    CESCAPES[9] = 't';
    CESCAPES[10] = 'n';
    CESCAPES[11] = 'v';
    CESCAPES[12] = 'f';
    CESCAPES[13] = 'r';
  }

  private static void printString(StringBuilder sb, byte[] data, int length, int xorKey) {
    for (int i = 0; i < length && i < data.length; i++) {
      int c = (data[i] ^ xorKey) & 0xFF;
      if (c >= 32 && c <= 126) {
        sb.append((char) c);
      } else {
        sb.append(String.format("\\x%02X", c));
      }
    }
  }

  private static void printEscapedData(StringBuilder sb, byte[] data) {
    for (byte b : data) {
      int c = b & 0xFF;
      if (c == '"' || c == '\'' || c == '\\') {
        sb.append('\\').append((char) c);
      } else if (c >= 127) {
        sb.append(String.format("\\%03o", c));
      } else if (c >= 32) {
        sb.append((char) c);
      } else if (CESCAPES[c] != 0) {
        sb.append('\\').append(CESCAPES[c]);
      } else {
        sb.append(String.format("\\%03o", c));
      }
    }
  }

  private static void printHexString(StringBuilder sb, byte[] data, int length) {
    for (int i = 0; i < Math.min(64, length) && i < data.length; i++) {
      sb.append(i == 0 ? "" : " ").append(String.format("%02X", data[i] & 0xFF));
    }
    if (length > 64) {
      sb.append(" ...");
    }
  }

  /** The bytes of a path in the platform charset, as a Latin-1 string for the raw output. */
  private static String nativePath(String path) {
    return new String(
        path.getBytes(java.nio.charset.Charset.defaultCharset()), StandardCharsets.ISO_8859_1);
  }

  private static void printEscapedFilePath(StringBuilder sb, String path) {
    path = nativePath(path);
    for (int i = 0; i < path.length(); i++) {
      char c = path.charAt(i);
      if (c == '\n') {
        sb.append("\\n");
      } else if (c == '\r') {
        sb.append("\\r");
      } else {
        sb.append(c);
      }
    }
    sb.append('\n');
  }

  private CallbackResult handleMessage(Rule rule, RuleMatch match, String filePath, int[] count) {
    boolean show = true;
    if (!tags.isEmpty()) {
      show = false;
      for (String t : tags) {
        if (rule.getTags().contains(t)) {
          show = true;
          break;
        }
      }
    }
    if (!identifiers.isEmpty()) {
      show = identifiers.contains(rule.getIdentifier());
    }
    boolean isMatching = match != null;
    show = show && ((!negate && isMatching) || (negate && !isMatching));
    if (show && !printCountOnly) {
      StringBuilder sb = new StringBuilder();
      if (showNamespace) {
        sb.append(rule.getNamespace()).append(':');
      }
      sb.append(rule.getIdentifier()).append(' ');
      if (showTags) {
        sb.append('[').append(String.join(",", rule.getTags())).append("] ");
      }
      if (showMeta) {
        sb.append('[');
        boolean first = true;
        for (Meta meta : rule.getMetas()) {
          if (!first) {
            sb.append(',');
          }
          first = false;
          switch (meta.getType()) {
            case INTEGER:
              sb.append(meta.getIdentifier()).append(" =").append(meta.getInteger());
              break;
            case BOOLEAN:
              sb.append(meta.getIdentifier()).append('=').append(meta.getBoolean());
              break;
            default:
              sb.append(meta.getIdentifier()).append("=\"");
              printEscapedData(sb, com.paveldan.yara4j.util.CStrings.cstr(meta.getStringBytes()));
              sb.append('"');
              break;
          }
        }
        sb.append("] ");
      }
      printEscapedFilePath(sb, filePath);
      if ((showStrings || showStringLength || showXorKey) && match != null) {
        for (StringMatch m : match.getPublicStringMatches()) {
          if (showStringLength) {
            sb.append(String.format("0x%x:%d:%s", m.getOffset(), m.getLength(),
                m.getIdentifier()));
          } else {
            sb.append(String.format("0x%x:%s", m.getOffset(), m.getIdentifier()));
          }
          if (showXorKey) {
            sb.append(String.format(":xor(0x%02x,", m.getXorKey()));
            printString(sb, m.getData(), m.getData().length, m.getXorKey());
            sb.append(')');
          }
          if (showStrings) {
            sb.append(": ");
            if (m.isHex()) {
              printHexString(sb, m.getData(), m.getData().length);
            } else {
              printString(sb, m.getData(), m.getData().length, 0);
            }
          }
          sb.append('\n');
        }
      }
      synchronized (outputLock) {
        out.print(sb);
      }
    }
    if (isMatching) {
      count[0]++;
      totalCount.incrementAndGet();
    }
    if (limit != 0 && totalCount.get() >= limit) {
      return CallbackResult.ABORT;
    }
    return CallbackResult.CONTINUE;
  }

  private ScanCallback callback(String filePath, int[] count) {
    return new ScanCallback() {
      @Override
      public CallbackResult ruleMatching(RuleMatch match) {
        return handleMessage(match, match, filePath, count);
      }

      @Override
      public CallbackResult ruleNotMatching(Rule rule) {
        return handleMessage(rule, null, filePath, count);
      }

      @Override
      public byte[] importModule(String moduleName) {
        return moduleData.get(moduleName);
      }

      @Override
      public void moduleImported(String moduleName, YStructure module) {
        if (showModuleData) {
          StringBuilder sb = new StringBuilder();
          module.printData(sb, 0, true);
          synchronized (outputLock) {
            out.print(sb);
            out.print('\n');
          }
        }
      }

      @Override
      public boolean tooManyMatches(Rule rule, String stringIdentifier) {
        if (ignoreWarnings) {
          return true;
        }
        synchronized (outputLock) {
          out.flush();
          System.err.printf(
              "warning: rule \"%s\": too many matches for %s, results for this rule may be "
                  + "incorrect%n",
              rule.getIdentifier(), stringIdentifier);
        }
        return !failOnWarnings;
      }

      @Override
      public boolean tooSlowScanning(Rule rule, String stringIdentifier) {
        if (ignoreWarnings) {
          return true;
        }
        synchronized (outputLock) {
          out.flush();
          System.err.printf(
              "warning: rule \"%s\": scanning with string %s is taking a very long time, it is "
                  + "either too general or very common.%n",
              rule.getIdentifier(), stringIdentifier);
        }
        return !failOnWarnings;
      }

      @Override
      public void consoleLog(String message) {
        if (!disableConsoleLogs) {
          synchronized (outputLock) {
            out.print(message);
            out.print('\n');
          }
        }
      }
    };
  }
}
