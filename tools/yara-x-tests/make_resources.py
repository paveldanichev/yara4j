"""Builds yara4j-core/src/test/resources/yarax from a yara-x checkout and a native libyara.

usage: make_resources.py YARA_X_DIR HARNESS OUT_DIR

HARNESS is harness.c compiled against libyara 4.5.8 (see README.md). Every case is run with
libyara and its result becomes the expected result of YaraXTest.
"""
import glob
import json
import os
import subprocess
import sys
import tempfile

yx, harness, out = sys.argv[1], sys.argv[2], sys.argv[3]
here = os.path.dirname(os.path.abspath(__file__))
tests = os.path.join(yx, 'lib/src/tests')
tmp = tempfile.mkdtemp()
os.makedirs(os.path.join(out, 'compiler/errors'), exist_ok=True)
os.makedirs(os.path.join(out, 'compiler/warnings'), exist_ok=True)

jumps = open(os.path.join(tests, 'testdata/jumps.bin'), 'rb').read()
open(os.path.join(out, 'jumps.bin'), 'wb').write(jumps)
cases_json = os.path.join(tmp, 'cases.json')
subprocess.run([sys.executable, '-I', os.path.join(here, 'extract.py'), os.path.join(tests, 'mod.rs'),
                os.path.join(tests, 'testdata/jumps.bin'), cases_json], check=True)


def native(rule_path, data_path, warnings=False):
    env = dict(os.environ)
    if warnings:
        env['WARNINGS'] = '1'
    return subprocess.run([harness, rule_path, data_path], capture_output=True, env=env,
                          timeout=60).stdout


def esc(s):
    return s.replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n')


rf, df = os.path.join(tmp, 'r.yar'), os.path.join(tmp, 'd.bin')
with open(os.path.join(out, 'conditions.tsv'), 'w', encoding='utf-8') as f:
    f.write('# Cases extracted from yara-x lib/src/tests/mod.rs (https://github.com/VirusTotal/yara-x, BSD-3-Clause).\n')
    f.write('# Columns: yara-x line, test function, kind, yara-x expectation, libyara 4.5.8 result, rule (hex), data (hex or @jumps).\n')
    f.write('# "libyara result" is the output of libyara built natively: "RESULT <matching rules> <first match hex>" or the compiler errors.\n')
    for c in json.load(open(cases_json)):
        open(rf, 'w', encoding='utf-8').write(c['rule'])
        open(df, 'wb').write(bytes.fromhex(c['data']))
        result = native(rf, df).decode('latin1').strip()
        data = '@jumps' if c['data'] and c['data'] == jumps.hex() else c['data']
        f.write('\t'.join([str(c['line']), c['fn'], c['kind'], str(c['expected']), esc(result),
                           c['rule'].encode('utf-8').hex(), data]) + '\n')

open(df, 'wb').close()
for kind in ['errors', 'warnings']:
    for p in glob.glob(os.path.join(yx, 'lib/src/compiler/tests/testdata', kind, '*.in')):
        name = os.path.basename(p)
        open(os.path.join(out, 'compiler', kind, name), 'wb').write(open(p, 'rb').read())
        open(os.path.join(out, 'compiler', kind, name[:-3] + '.expected'), 'wb').write(
            native(p, df, warnings=True))
