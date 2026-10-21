package com.paveldan.yara4j.cli;

import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.Rules;
import com.paveldan.yara4j.YaraCompiler;
import com.paveldan.yara4j.YaraException;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * The yarac command, a port of cli/yarac.c. The output uses yara4j's compiled rules format,
 * which can be loaded with {@code yara -C} or {@link Rules#load}, but not by libyara.
 */
@Command(
    name = "yarac",
    usageHelpWidth = 100,
    sortOptions = false,
    customSynopsis = "Usage: yarac [OPTION]... [NAMESPACE:]SOURCE_FILE... OUTPUT_FILE")
public final class YaracCli implements Callable<Integer> {

  @Option(names = "--atom-quality-table", paramLabel = "FILE",
      description = "path to a file with the atom quality table")
  String atomQualityTable;

  @Option(names = {"-d", "--define"}, paramLabel = "VAR=VALUE",
      description = "define external variable")
  List<String> extVars = new ArrayList<>();

  @Option(names = "--fail-on-warnings", description = "fail on warnings")
  boolean failOnWarnings;

  @Option(names = {"-h", "--help"}, usageHelp = true, description = "show this help and exit")
  boolean showHelp;

  @Option(names = {"-E", "--strict-escape"}, description = "warn on unknown escape sequences")
  boolean strictEscape;

  @Option(names = "--max-strings-per-rule", paramLabel = "NUMBER",
      description = "set maximum number of strings per rule (default=10000)")
  int maxStringsPerRule = 10000;

  @Option(names = {"-w", "--no-warnings"}, description = "disable warnings")
  boolean ignoreWarnings;

  @Option(names = {"-v", "--version"}, versionHelp = true, description = "show version information")
  boolean showVersion;

  @Parameters(paramLabel = "ARGS", description = "rules files followed by the output file")
  List<String> args = new ArrayList<>();

  public static void main(String[] argv) {
    CommandLine cl = new CommandLine(new YaracCli());
    cl.getCommandSpec().version(Common.VERSION);
    System.exit(cl.execute(argv));
  }

  @Override
  public Integer call() {
    if (args.size() < 2) {
      System.err.println("yarac: wrong number of arguments");
      System.err.println("Usage: yarac [OPTION]... [NAMESPACE:]SOURCE_FILE... OUTPUT_FILE");
      System.err.println();
      System.err.println("Try `--help` for more options");
      return 1;
    }
    YaraCompiler compiler = new YaraCompiler();
    try {
      Common.defineExternals(extVars, Common.definer(compiler));
    } catch (YaraException e) {
      return 1;
    }
    if (atomQualityTable != null && !Common.loadAtomQualityTable(compiler, atomQualityTable)) {
      System.err.println("error loading atom quality table");
      return 1;
    }
    compiler.setMaxStringsPerRule(maxStringsPerRule);
    compiler.setStrictEscape(strictEscape);
    Common.CompilerResults cr = new Common.CompilerResults();
    if (!Common.compileFiles(compiler, args, ignoreWarnings, cr)) {
      return 1;
    }
    if (cr.errors > 0 || (failOnWarnings && cr.warnings > 0)) {
      return 1;
    }
    try {
      Rules rules = compiler.getRules();
      rules.save(Paths.get(args.get(args.size() - 1)));
    } catch (YaraException e) {
      System.err.println("error: " + e.getErrorCode().code());
      return 1;
    } catch (IOException | InvalidPathException e) {
      System.err.println("error: " + ErrorCode.COULD_NOT_OPEN_FILE.code());
      return 1;
    }
    return 0;
  }
}
