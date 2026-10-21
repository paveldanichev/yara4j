# Module output of native libyara

`ModuleOutputTest` (in `yara4j-core`) compares the complete output of the pe, elf, macho,
dotnet and dex modules, as printed by `yara -D`, with native libyara 4.5.8 for every sample of
YARA's `tests/data` (`yara4j-core/src/test/resources/data`). The ported YARA tests only check
some fields; this test checks all of them.

The expected output is in `yara4j-core/src/test/resources/module-output/<module>.txt.gz`: for
each sample, a `### <file name>` line followed by the output of native `yara -D`.

## Regenerating

Needed after adding a sample to `tests/data` (the test fails until then) or when moving to a
new YARA version. `yara` must be built with OpenSSL (`HAVE_LIBCRYPTO`) so that `pe.signatures`
is available; the current files were produced with OpenSSL 3.0.13.

```bash
python3 make_expected.py path/to/native/yara ../../yara4j-core/src/test/resources/data \
    ../../yara4j-core/src/test/resources/module-output
```

The output is reproducible, so an unchanged native build gives identical files. Use
`zcat` or `zdiff` to review changes.
