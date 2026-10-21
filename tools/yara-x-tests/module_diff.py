"""Compares "yara -D" of native libyara with yara4j on the module samples of yara-x.

usage: module_diff.py YARA_X_DIR NATIVE_YARA YARA4J_CLI_JAR [MODULE...]

The samples are stored by yara-x as zipped Intel HEX files (some are malware); they are
decoded in a temporary directory and only parsed, never executed.
"""
import glob
import os
import subprocess
import sys
import tempfile
import zipfile

yx, native, jar = sys.argv[1:4]
modules = sys.argv[4:] or ['pe', 'elf', 'macho', 'dotnet', 'dex']
tmp = tempfile.mkdtemp()
samples = []
for z in sorted(glob.glob(os.path.join(yx, 'lib/src/modules/*/tests/testdata/*.in.zip'))):
    name = os.path.basename(z)[:-len('.in.zip')]
    with zipfile.ZipFile(z) as zf:
        ihex = zf.read(os.path.basename(z)[:-4]).decode('ascii')
    data, base = bytearray(), 0
    for line in ihex.splitlines():
        if not line.startswith(':'):
            continue
        b = bytes.fromhex(line[1:])
        count, addr, rtype = b[0], (b[1] << 8) | b[2], b[3]
        if rtype == 0:
            off = base + addr
            if len(data) < off:
                data.extend(b'\0' * (off - len(data)))
            data[off:off + count] = b[4:4 + count]
        elif rtype == 2:
            base = ((b[4] << 8) | b[5]) << 4
        elif rtype == 4:
            base = ((b[4] << 8) | b[5]) << 16
    path = os.path.join(tmp, name)
    open(path, 'wb').write(data)
    samples.append(path)

failures = 0
for m in modules:
    rule = os.path.join(tmp, m + '.yar')
    open(rule, 'w').write('import "%s" rule r { condition: false }' % m)
    for s in samples:
        a = subprocess.run([native, '-D', rule, s], capture_output=True).stdout
        b = subprocess.run(['java', '-jar', jar, '-D', rule, s], capture_output=True).stdout
        if a != b:
            failures += 1
            print('DIFF', m, os.path.basename(s))
print(len(samples), 'samples,', len(modules), 'modules,', failures, 'differences')
sys.exit(1 if failures else 0)
