package com.paveldan.yara4j.cli;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import com.paveldan.yara4j.CompilerMessage;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.Scanner;
import com.paveldan.yara4j.YaraCompiler;
import com.paveldan.yara4j.YaraException;
import com.paveldan.yara4j.util.CStrings;

/** Code shared by the yara and yarac commands (port of cli/common.c). */
final class Common {
  private Common() {}

  static final String VERSION = "4.5.8";

  /** True on Windows, where yara.exe behaves differently in a few places. */
  static final boolean WINDOWS = System.getProperty("os.name", "").startsWith("Windows");

  /**
   * Converts a command line argument to a path, or returns null if it isn't a valid path on this
   * system (on Windows, names can't contain characters like ':', '*' or '?').
   */
  static Path path(String s) {
    try {
      return Paths.get(s);
    } catch (InvalidPathException e) {
      return null;
    }
  }

  /** Like access(name, 0) in C: false for invalid paths instead of throwing. */
  static boolean exists(String s) {
    Path p = path(s);
    return p != null && Files.exists(p);
  }

  /** Like the CLI's is_directory(): false for invalid paths instead of throwing. */
  static boolean isDirectory(String s) {
    Path p = path(s);
    return p != null && Files.isDirectory(p);
  }

  /** Counters updated while printing compiler messages (COMPILER_RESULTS). */
  static final class CompilerResults {
    int errors;
    int warnings;
  }

  static boolean isInteger(String s) {
    int i = 0;
    if (i < s.length() && s.charAt(i) == '-') {
      i++;
    }
    if (i == s.length()) {
      return false;
    }
    for (; i < s.length(); i++) {
      if (!Character.isDigit(s.charAt(i)) || s.charAt(i) > '9') {
        return false;
      }
    }
    return true;
  }

  static boolean isFloat(String s) {
    boolean hasDot = false;
    int i = 0;
    if (i < s.length() && s.charAt(i) == '-') {
      i++;
    }
    if (i < s.length() && s.charAt(i) == '.') {
      return false;
    }
    for (; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '.') {
        if (hasDot) {
          return false;
        }
        hasDot = true;
      } else if (c < '0' || c > '9') {
        return false;
      }
    }
    return hasDot;
  }

  /** atoi(): strtol truncated to int. */
  static int atoi(String s) {
    return (int) CStrings.strtoll(s.getBytes(StandardCharsets.ISO_8859_1), 10).value;
  }

  /** A variable defined with -d: the definition is applied to a compiler or a scanner. */
  interface Definer {
    void integer(String id, long v) throws YaraException;

    void bool(String id, boolean v) throws YaraException;

    void dbl(String id, double v) throws YaraException;

    void string(String id, String v) throws YaraException;
  }

  /**
   * define_external_variables(). Returns false after printing a message if the syntax is
   * wrong (libyara prints the message but continues, returning ERROR_SUCCESS).
   */
  static void defineExternals(List<String> vars, Definer d) throws YaraException {
    for (String var : vars) {
      int eq = var.indexOf('=');
      if (eq < 0) {
        System.err.println("error: wrong syntax for `-d` option.");
        return;
      }
      String id = var.substring(0, eq);
      String value = var.substring(eq + 1);
      if (isFloat(value)) {
        d.dbl(id, Double.parseDouble(value.endsWith(".") ? value + "0" : value));
      } else if (isInteger(value)) {
        d.integer(id, atoi(value));
      } else if (value.equals("true") || value.equals("false")) {
        d.bool(id, value.equals("true"));
      } else {
        d.string(id, value);
      }
    }
  }

  static Definer definer(YaraCompiler c) {
    return new Definer() {
      @Override
      public void integer(String id, long v) throws YaraException {
        c.defineInteger(id, v);
      }

      @Override
      public void bool(String id, boolean v) throws YaraException {
        c.defineBoolean(id, v);
      }

      @Override
      public void dbl(String id, double v) throws YaraException {
        c.defineFloat(id, v);
      }

      @Override
      public void string(String id, String v) throws YaraException {
        c.defineString(id, v);
      }
    };
  }

  static Definer definer(Scanner s) {
    return new Definer() {
      @Override
      public void integer(String id, long v) throws YaraException {
        s.defineInteger(id, v);
      }

      @Override
      public void bool(String id, boolean v) throws YaraException {
        s.defineBoolean(id, v);
      }

      @Override
      public void dbl(String id, double v) throws YaraException {
        s.defineFloat(id, v);
      }

      @Override
      public void string(String id, String v) throws YaraException {
        s.defineString(id, v);
      }
    };
  }

  /** Prints a compiler message like print_compiler_error / report_error. */
  static void printCompilerMessage(
      CompilerMessage m, boolean ignoreWarnings, CompilerResults results) {
    String type;
    if (m.getLevel() == CompilerMessage.Level.ERROR) {
      type = "error";
      results.errors++;
    } else if (!ignoreWarnings) {
      results.warnings++;
      type = "warning";
    } else {
      return;
    }
    String file = m.getFileName() == null ? "(null)" : m.getFileName();
    if (m.getRuleIdentifier() != null) {
      System.err.printf(
          "%s: rule \"%s\" in %s(%d): %s%n",
          type, m.getRuleIdentifier(), file, m.getLine(), m.getMessage());
    } else {
      System.err.printf("%s(%d): %s: %s%n", file, m.getLine(), type, m.getMessage());
    }
  }

  /** compile_files(): all the arguments except the last one are rules files. */
  static boolean compileFiles(
      YaraCompiler compiler,
      List<String> args,
      boolean ignoreWarnings,
      CompilerResults results) {
    int printed = 0;
    for (int i = 0; i < args.size() - 1; i++) {
      String arg = args.get(i);
      String ns = null;
      String fileName = arg;
      if (!exists(arg)) {
        int colon = arg.indexOf(':');
        if (colon >= 0 && (colon + 1 >= arg.length() || arg.charAt(colon + 1) != '\\')) {
          ns = arg.substring(0, colon);
          fileName = arg.substring(colon + 1);
        }
      }
      byte[] content;
      try {
        content =
            fileName.equals("-") ? System.in.readAllBytes() : Files.readAllBytes(Path.of(fileName));
      } catch (IOException | RuntimeException e) {
        System.err.println("error: could not open file: " + fileName);
        return false;
      }
      int errors = compiler.addSource(content, ns, fileName);
      List<CompilerMessage> messages = compiler.getMessages();
      for (; printed < messages.size(); printed++) {
        printCompilerMessage(messages.get(printed), ignoreWarnings, results);
      }
      if (errors > 0) {
        return false;
      }
    }
    return true;
  }

  /** Loads an atom quality table file (yr_compiler_load_atom_quality_table). */
  static boolean loadAtomQualityTable(YaraCompiler compiler, String file) {
    try {
      byte[] table = Files.readAllBytes(Path.of(file));
      int entries = table.length / 5;
      compiler.setAtomQualityTable(java.util.Arrays.copyOf(table, entries * 5), 0);
      return true;
    } catch (IOException | RuntimeException e) {
      return false;
    }
  }

  /** print_error(). */
  static void printError(PrintStream err, ErrorCode error) {
    switch (error) {
      case SUCCESS:
        break;
      case COULD_NOT_ATTACH_TO_PROCESS:
        err.println("can not attach to process (try running as root)");
        break;
      case INSUFFICIENT_MEMORY:
        err.println("not enough memory");
        break;
      case SCAN_TIMEOUT:
        err.println("scanning timed out");
        break;
      case COULD_NOT_OPEN_FILE:
        err.println("could not open file");
        break;
      case UNSUPPORTED_FILE_VERSION:
        err.println("rules were compiled with a different version of YARA");
        break;
      case INVALID_FILE:
        err.println("invalid compiled rules file.");
        break;
      case CORRUPT_FILE:
        err.println("corrupt compiled rules file.");
        break;
      case EXEC_STACK_OVERFLOW:
        err.println(
            "stack overflow while evaluating condition (see --stack-size argument) ");
        break;
      case INVALID_EXTERNAL_VARIABLE_TYPE:
        err.println("invalid type for external variable");
        break;
      case TOO_MANY_MATCHES:
        err.println("too many matches");
        break;
      default:
        err.println("error: " + error.code());
        break;
    }
  }
}
