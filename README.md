# yara4j

yara4j is a pure Java port of [YARA](https://github.com/VirusTotal/yara) 4.5.8. It compiles
and runs YARA rules inside any JVM (Java 17 or later), on any platform, without JNI or native
libraries.

> [!WARNING]
> **yara4j is an AI-generated port.** The code was written with an AI coding assistant by
> translating [VirusTotal's YARA](https://github.com/VirusTotal/yara). It is not affiliated with
> or endorsed by VirusTotal or the YARA authors. It is tested extensively against native libyara
> (see below), but AI-generated code can still contain subtle bugs. **Use it at your own risk**,
> especially when scanning untrusted files. You are encouraged to review the code, test it on
> your own rules and files, and report issues or submit fixes.

The port follows libyara closely: the rule language, the regular expression engine, atom
selection, Aho-Corasick scanning, string matching limits and the module outputs behave like
libyara 4.5.8, quirks included. YARA's own C test suite (test-rules, test-pe, test-elf,
test-macho, test-dex, test-dotnet, test-math, test-string, test-atoms, test-re-split and the
relevant parts of test-api) is ported to JUnit and passes. The complete output of the pe, elf,
macho, dotnet and dex modules for all the samples in YARA's `tests/data` is also checked against
the output of a native libyara build (see [tools/module-output](tools/module-output)).
Authenticode results (`pe.signatures`) are compared with libyara built with OpenSSL
3.0.13 on 47 generated samples covering unusual signature structures (see
[tools/authenticode-samples](tools/authenticode-samples)) and on Secure Boot signed binaries.

The test suite also includes about 1,500 cases taken from
[yara-x](https://github.com/VirusTotal/yara-x) (conditions, patterns, and compiler errors and
warnings), with the results of native libyara as expectations, down to the text and line of
every compiler message. The module outputs were also compared with libyara on yara-x's 150 module
samples. See [tools/yara-x-tests](tools/yara-x-tests).

## Modules

| Artifact | Contents |
|---|---|
| `yara4j-core` | The library and all the modules: `pe` (including Authenticode signatures), `elf` (including `telfhash`), `macho`, `dex`, `dotnet`, `math`, `hash`, `string`, `time`, `console`, `cuckoo`, `magic` and `tests`. Its only runtime dependency is Bouncy Castle (`bcprov`), used to verify Authenticode signatures. |
| `yara4j-magic-tika` | A provider for the `magic` module based on Apache Tika (`tika-core`). |
| `yara4j-cli` | The `yara` and `yarac` command line tools, as a runnable jar. |

All dependencies use licenses that allow use in commercial closed source software (MIT,
Apache 2.0, BSD). See [NOTICE](NOTICE).

## Building

```bash
mvn verify
```

The runnable command line jar is `yara4j-cli/target/yara4j-cli-4.5.8-SNAPSHOT.jar`.

## Releases

Released jars are on the [Releases](../../releases) page: the runnable command line tool
(`yara4j-cli-<version>.jar`), the libraries (`yara4j-core`, `yara4j-magic-tika`), their
sources, and SHA-256 checksums. yara4j isn't published to Maven Central yet: to use the
libraries with Maven, install them in your local repository with `mvn install`, or with
`mvn install:install-file` from the downloaded jars.

Versions look like `4.5.8-1`: the first part is the YARA version that yara4j follows, the
number after the dash counts the yara4j releases for that YARA version (fixes, dependency
updates). The version in the POMs stays `4.5.8-SNAPSHOT` between releases.

To publish a release, push a tag named after the version:

```bash
git tag v4.5.8-1
git push origin v4.5.8-1
```

The [release workflow](.github/workflows/release.yml) checks that the tag matches the
project's YARA version, sets the version, builds and runs all the tests with Java 17, and
creates the GitHub Release with the jars and generated release notes. The
[build workflow](.github/workflows/build.yml) runs the tests on Linux, macOS and Windows for
every push and pull request.

## Using the library

```xml
<dependency>
  <groupId>com.paveldan.yara4j</groupId>
  <artifactId>yara4j-core</artifactId>
  <version>4.5.8-SNAPSHOT</version>
</dependency>
```

```java
YaraCompiler compiler = new YaraCompiler();
compiler.defineString("filename", "");                 // declares the external variable "filename"
compiler.addFileOrThrow(Path.of("rules.yar"), null);   // null = "default" namespace
Rules rules = compiler.getRules();

// Rules are immutable and thread-safe. Scanners are not: use one per thread.
Scanner scanner = rules.newScanner()
    .setTimeout(Duration.ofSeconds(30))
    .defineString("filename", "sample.exe");           // value of "filename" for this scanner
for (RuleMatch match : scanner.scan(Path.of("sample.exe"))) {
  System.out.println(match.getNamespace() + ":" + match.getIdentifier());
  for (StringMatch s : match.getPublicStringMatches()) {
    System.out.printf("  0x%x %s%n", s.getOffset(), s.getIdentifier());
  }
}
```

The two `defineString` calls are explained in [External variables](#external-variables).

`Scanner.scan` accepts a `byte[]`, a `ByteBuffer`, a `Path` (memory mapped, split in blocks
like libyara's multi-block scanning when larger than 2 GiB), an `InputStream`, or an explicit
list of memory blocks (`scanBlocks`).

Windows doesn't allow deleting, renaming or writing a file while it is memory mapped, and Java
normally releases mappings only when they are garbage collected. So on Windows,
`Scanner.scan(Path)` releases the mapping as soon as the scan ends, like libyara does, and the
file can be modified or deleted right after. Other systems don't have this restriction and
leave the mapping to the garbage collector, which keeps their scans exactly as fast as before.
The system property `-Dyara4j.unmap=true` (or `false`) overrides the default.

Compilation errors are reported in `YaraCompilationException.getMessages()` (or
`YaraCompiler.getMessages()`), with file, line, rule and libyara's error code. Scan errors
throw `YaraException`, whose `getErrorCode()` is the libyara error code (for example
`SCAN_TIMEOUT` or `TOO_MANY_MATCHES`).

### Rules from strings

Rules don't have to come from a file. For a single source, `YaraCompiler.compile` returns the
compiled rules, or throws `YaraCompilationException` if they contain errors:

```java
Rules rules = YaraCompiler.compile("rule evil { strings: $a = \"evil\" condition: $a }");
List<RuleMatch> matches = rules.scan(data);   // shortcut for rules.newScanner().scan(data)
```

To combine several sources, put rules in namespaces or declare external variables, create a
`YaraCompiler` and add the sources one by one (Java 17 text blocks are convenient for rules
written in the code):

```java
YaraCompiler compiler = new YaraCompiler();
compiler.addSourceOrThrow("""
    rule mz_header {
      condition: uint16(0) == 0x5A4D
    }
    """);                                                          // "default" namespace
compiler.addSourceOrThrow(rulesFromDatabase, "malware");           // "malware" namespace
compiler.addFileOrThrow(Path.of("more.yar"), "malware");           // strings and files mix
Rules rules = compiler.getRules();
```

| Method | Input | On errors |
|---|---|---|
| `YaraCompiler.compile(String)` | one source, "default" namespace | throws `YaraCompilationException` |
| `addSourceOrThrow(String)` / `addSourceOrThrow(String, namespace)` | a source | throws `YaraCompilationException` |
| `addSource(String)` / `addSource(String, namespace)` | a source | returns the number of errors |
| `addSource(byte[], namespace)` / `addSource(byte[], namespace, fileName)` | raw bytes, not decoded | returns the number of errors |
| `addFile(Path, namespace)` / `addFileOrThrow(Path, namespace)` | a file | returns the number of errors / throws |

The namespace may be null for "default". Strings are encoded in UTF-8; use the `byte[]`
variants for rules in another encoding. `fileName` is used in error messages and to resolve
relative `include` directives. To load included files from elsewhere (the classpath, a
database...), set an `IncludeResolver` with `setIncludeResolver`, or forbid includes with
`disableIncludes()`.

Like in libyara, after a source with errors the compiler can't be used any more: create a new
`YaraCompiler`. To handle errors without exceptions, use the methods that return the number of
errors:

```java
YaraCompiler compiler = new YaraCompiler();
if (compiler.addSource(source) > 0) {
  for (CompilerMessage m : compiler.getErrors()) {
    System.err.println("line " + m.getLine() + ": " + m.getMessage());   // line 1: undefined identifier "foo"
  }
}
```

`getWarnings()` returns the warnings (slow strings, unreferenced strings, ...), also present
when compilation succeeds.

### External variables

External variables are identifiers that rules use in conditions but whose values come from
your application, like `filename` in this rule:

```
rule suspicious_exe {
  strings: $a = "This program cannot be run in DOS mode"
  condition: $a and filename matches /\.(jpg|pdf|txt)$/i
}
```

YARA doesn't know `filename`: the application declares it, gives it a value, and the
condition compares that value. They are libyara's external variables (`yara -d` on the command
line), commonly used for file names, paths, size limits, thresholds or flags that differ per
scan without recompiling the rules.

There are four types, each with a method on `YaraCompiler` and on `Scanner`:

| Method | Type in conditions | Example condition |
|---|---|---|
| `defineString(name, String)` | string | `filename matches /\.exe$/i`, `filepath contains "\\Temp\\"`, `owner == "root"` |
| `defineInteger(name, long)` | integer | `filesize < max_size`, `pid != 4` |
| `defineBoolean(name, boolean)` | boolean | `not trusted and $a` |
| `defineFloat(name, double)` | float | `math.entropy(0, filesize) > threshold` |

**On the compiler**, the method *declares* the variable: its name, its type, and the value used
when a scanner doesn't set another one. A variable must be declared before adding the rules
that use it, otherwise compilation fails with `undefined identifier "filename"`. Declaring the
same name twice throws `YaraException` (`DUPLICATED_EXTERNAL_VARIABLE`). This is why the first
example declares `filename` with an empty string: the value is only a placeholder, the real one
is given for each file when scanning. The declared values are also stored by `Rules.save`.

**On the scanner**, the method changes the value of an already declared variable for the scans
done by that scanner. The value stays until it is changed again, and other scanners of the
same `Rules` are not affected (each new scanner starts with the compiler's values). Setting a
variable that wasn't declared throws `YaraException` (`INVALID_ARGUMENT`), and setting it with
another type throws `INVALID_EXTERNAL_VARIABLE_TYPE`, except that booleans and integers are
interchangeable, as in libyara.

```java
YaraCompiler compiler = new YaraCompiler();
compiler.defineString("filename", "");
compiler.defineInteger("max_size", 10 * 1024 * 1024);   // 10 MiB unless the scanner says otherwise
compiler.defineBoolean("trusted", false);
compiler.addFileOrThrow(Path.of("rules.yar"), null);
Rules rules = compiler.getRules();

Scanner scanner = rules.newScanner();
for (Path file : files) {
  scanner.defineString("filename", file.getFileName().toString());
  scanner.defineBoolean("trusted", file.startsWith("/usr/bin"));
  List<RuleMatch> matches = scanner.scan(file);
  ...
}
```

String values are converted to UTF-8, and conditions compare the bytes (`icontains`,
`iequals` and `/.../i` ignore the case of ASCII letters only). String values end at the
first `\0` character, like in libyara's C API.

On the command line, `-d name=value` does the same: the value is a float if it is a number
with a decimal point (`0.75`), an integer if it is a number without one, a boolean if it is
`true` or `false`, and a string otherwise.

### Callbacks

A `ScanCallback` receives the same events as a libyara callback:

```java
scanner.setReportRules(true, true).setCallback(new ScanCallback() {
  @Override public CallbackResult ruleMatching(RuleMatch m) { ...; return CallbackResult.CONTINUE; }
  @Override public CallbackResult ruleNotMatching(Rule r) { ...; return CallbackResult.CONTINUE; }
  @Override public byte[] importModule(String module) { return null; }   // module data
  @Override public void moduleImported(String module, YStructure data) { }
  @Override public void consoleLog(String message) { }
  @Override public boolean tooManyMatches(Rule rule, String string) { return true; }
});
```

### Compiled rules

```java
rules.save(Path.of("rules.y4j"));
Rules loaded = Rules.load(Path.of("rules.y4j"));
```

libyara's `.yarc` files are dumps of its internal memory and can't be read by yara4j. yara4j
uses its own versioned format, which records the compilation inputs (options, external
variables, sources and the content of included files) and replays the compilation when loading.
Loading is deterministic, doesn't need the original include files, and doesn't use Java
serialization. If the compiler had custom modules registered, pass them to `Rules.load`.

### Custom modules

Modules implement `com.paveldan.yara4j.module.YaraModule` and are discovered with
`ServiceLoader` (`META-INF/services/com.paveldan.yara4j.module.YaraModule`) or registered with
`YaraCompiler.registerModule`. `ModuleDeclarations` mirrors libyara's `begin_declarations`
macros, and `YObject` provides the `yr_set_*`/`yr_get_*` path based accessors:

```java
public final class MyModule implements YaraModule {
  public String name() { return "my"; }
  public void declare(ModuleDeclarations d) {
    d.declareInteger("size");
    d.declareFunction("twice", "i", "i", call -> call.integerArgument(1) * 2);
  }
  public void load(ScanContext ctx, YStructure module, byte[] moduleData) {
    module.setInteger(ctx.fileSize(), "size");
  }
  public void unload(YStructure module) {}
}
```

The data of `ctx.blocks()` is valid only during the scan: a module must not keep the buffers
(or views of them) after `unload`, because the file mapping may be released when the scan ends,
and reading an unmapped buffer crashes the JVM. Copy the bytes that must be kept. The values set
in the module structure are copies and can be used after the scan.

### The magic module

libmagic isn't available in pure Java, so `magic.type()` and `magic.mime_type()` delegate to a
`com.paveldan.yara4j.modules.magic.MagicProvider`. Add `yara4j-magic-tika` to the classpath to
use Apache Tika, or set your own provider with `MagicModule.setProvider`. Without a provider
both functions are undefined. MIME types are usually the same as libmagic's for common formats,
but the descriptions returned by `magic.type()` come from Tika and differ from libmagic's (for
example "Portable Document Format" instead of "PDF document, version 1.4").

## Command line tools

```bash
java -jar yara4j-cli.jar [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR
java -cp yara4j-cli.jar com.paveldan.yara4j.cli.YaracCli [OPTION]... [NAMESPACE:]SOURCE_FILE... OUTPUT_FILE
```

The options and the output format are the same as the native `yara` and `yarac` 4.5.8 tools
(`-s`, `-m`, `-g`, `-e`, `-n`, `-c`, `-l`, `-r`, `-p`, `-a`, `-d`, `-x`, `-D`, `-C`, `-f`,
`-w`, `--scan-list`, ...). The jar includes the Tika provider for the `magic` module.

On Windows the CLI behaves like `yara.exe`: `C:\...` isn't mistaken for a namespace prefix,
paths found in directories are joined with `\`, and scan lists may have `\r\n` line endings
(empty lines are skipped). Standard output always uses `\n` line endings.

## Differences from libyara

* Process memory scanning isn't supported (it is platform specific). The CLI reports an error
  when given a PID.
* Compiled rules use yara4j's own format, see above.
* `magic.type()` descriptions come from Apache Tika, see above.
* The CLI accepts but ignores `--stack-size` and `--max-process-memory-chunk` (the condition
  evaluator doesn't use a fixed size stack), and doesn't implement `--print-stats`.
* `pe.signatures` is always available. Like libyara built with OpenSSL, certificate chains are
  built from the certificates in the signature without trust anchors, which depends on the
  current time when several candidate issuers exist; names, serials and algorithm names follow
  OpenSSL 3's formatting.
* Rule evaluation uses a tree interpreter instead of libyara's bytecode VM. Conditions nested
  deeply enough to exhaust the Java thread stack fail with `EXEC_STACK_OVERFLOW`, but the limit
  isn't the same as libyara's stack size.

## License

yara4j is distributed under the BSD 3-Clause license, like YARA. See [LICENSE](LICENSE) and
[NOTICE](NOTICE) for third party components.
