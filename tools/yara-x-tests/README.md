# Tests derived from yara-x

[yara-x](https://github.com/VirusTotal/yara-x) is VirusTotal's Rust rewrite of YARA. Its test
suite is a good source of test cases, but yara-x is not 100% compatible with libyara, so
yara4j doesn't use yara-x's expectations: every case is run with **native libyara 4.5.8** and
its result becomes the expected result.

`YaraXTest` (in `yara4j-core`) checks, from the resources in `src/test/resources/yarax`:

* the 1250 condition, rule and pattern tests of `lib/src/tests/mod.rs` (matching rules and
  matched data, or the exact compiler errors for constructs libyara doesn't support);
* the 218 compiler error and warning test files of `lib/src/compiler/tests/testdata` (text,
  line and rule of every message).

Test names mention yara-x's expectation where libyara differs: Unicode case folding in
`icontains` and friends, regexp anchors such as `\A`, `\z` and `\b{start}`, leftmost-longest
regexp matches, `xor` combined with `fullword`, and `base64` edge cases.

`module_diff.py` compares the output of the pe, elf, macho, dotnet and dex modules (`yara -D`)
with native libyara on the 150 module samples of yara-x. The samples aren't copied into yara4j.

## Regenerating

```bash
# libyara objects built from YARA 4.5.8 with the same defines as libyara (HAVE_LIBCRYPTO, ...)
gcc $DEFS -o harness harness.c libyara/*.o -lcrypto -lm -lpthread
python3 make_resources.py path/to/yara-x ./harness ../../yara4j-core/src/test/resources/yarax
python3 module_diff.py path/to/yara-x path/to/native/yara ../../yara4j-cli/target/yara4j-cli-*.jar
```
