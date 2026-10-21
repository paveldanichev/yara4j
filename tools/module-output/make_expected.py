"""Records the output of native "yara -D" for the samples in YARA's tests/data.

usage: make_expected.py NATIVE_YARA DATA_DIR OUTPUT_DIR [MODULE...]

Writes OUTPUT_DIR/<module>.txt.gz for each module: for each regular file of DATA_DIR, sorted
by name, a "### <file name>" line followed by the exact output of
"yara -D <rule importing the module> <file>".
"""
import gzip
import os
import subprocess
import sys
import tempfile

native, data_dir, out_dir = sys.argv[1:4]
modules = sys.argv[4:] or ['pe', 'elf', 'macho', 'dotnet', 'dex']
samples = sorted(f for f in os.listdir(data_dir) if os.path.isfile(os.path.join(data_dir, f)))
tmp = tempfile.mkdtemp()
for m in modules:
    rule = os.path.join(tmp, m + '.yar')
    with open(rule, 'w') as f:
        f.write('import "%s" rule r { condition: false }' % m)
    out = bytearray()
    for s in samples:
        r = subprocess.run([native, '-D', rule, os.path.join(data_dir, s)], capture_output=True)
        if r.returncode != 0 or r.stderr:
            sys.exit('%s %s: %s' % (m, s, r.stderr.decode(errors='replace')))
        out += b'### ' + s.encode() + b'\n' + r.stdout
    # mtime=0 makes the output reproducible.
    with open(os.path.join(out_dir, m + '.txt.gz'), 'wb') as f:
        with gzip.GzipFile(fileobj=f, mode='wb', mtime=0, filename='') as gz:
            gz.write(out)
    print(m, len(samples), 'samples,', len(out), 'bytes')
