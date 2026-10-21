"""Extracts condition/rule/pattern test cases from yara-x's lib/src/tests/mod.rs.

Output: JSON list of {fn, kind, rule, data(hex), expected, line}.
kind: "bool" (expected = 0/1 matching rules) or "match" (expected = hex of match data).
"""
import json
import re
import sys

src = open(sys.argv[1], encoding='utf-8').read()
jumps = open(sys.argv[2], 'rb').read()

MACROS = ['condition_true', 'condition_false', 'rule_true', 'rule_false',
          'pattern_true', 'pattern_false', 'pattern_match']


class Unsupported(Exception):
    pass


def parse_string(s, i, byte=False):
    """Parses a "..." literal starting at s[i] == '"'. Returns (value, new_index)."""
    assert s[i] == '"'
    i += 1
    out = bytearray() if byte else []
    while True:
        c = s[i]
        if c == '"':
            i += 1
            break
        if c == '\\':
            n = s[i + 1]
            if n == '\n':
                i += 2
                while s[i] in ' \t\n\r':
                    i += 1
                continue
            i += 2
            if n == 'n':
                v = '\n'
            elif n == 't':
                v = '\t'
            elif n == 'r':
                v = '\r'
            elif n == '0':
                v = '\0'
            elif n in '\\"\'':
                v = n
            elif n == 'x':
                v = chr(int(s[i:i + 2], 16))
                i += 2
            elif n == 'u':
                m = re.match(r'\{([0-9a-fA-F]+)\}', s[i:])
                v = chr(int(m.group(1), 16))
                i += m.end()
            else:
                raise Unsupported('escape \\' + n)
            if byte:
                out.extend(v.encode('latin1'))
            else:
                out.append(v)
            continue
        if byte:
            out.extend(c.encode('utf-8'))
        else:
            out.append(c)
        i += 1
    return (bytes(out) if byte else ''.join(out)), i


def parse_raw(s, i):
    """Parses r"..." or r#"..."# with s[i] == 'r'."""
    i += 1
    hashes = 0
    while s[i] == '#':
        hashes += 1
        i += 1
    assert s[i] == '"'
    end = '"' + '#' * hashes
    j = s.index(end, i + 1)
    return s[i + 1:j], j + len(end)


def skip_ws(s, i):
    while True:
        while i < len(s) and s[i] in ' \t\r\n':
            i += 1
        if s.startswith('//', i):
            i = s.index('\n', i)
            continue
        return i


def parse_int(tok):
    tok = tok.replace('_', '')
    tok = re.sub(r'(u8|i32|u32|usize)$', '', tok)
    return int(tok, 0)


def parse_expr(s, i):
    """Returns (('str'|'bytes', value), new_index)."""
    i = skip_ws(s, i)
    if s.startswith('br', i):
        v, i = parse_raw(s, i + 1)
        val = ('bytes', v.encode('utf-8'))
    elif s.startswith('b"', i):
        v, i = parse_string(s, i + 1, byte=True)
        val = ('bytes', v)
    elif s.startswith('r"', i) or s.startswith('r#', i):
        v, i = parse_raw(s, i)
        val = ('str', v)
    elif s[i] == '"':
        v, i = parse_string(s, i)
        val = ('str', v)
    elif s.startswith('&[', i) or s.startswith('[', i):
        j = s.index('[', i)
        depth, k = 0, j
        while True:
            if s[k] == '[':
                depth += 1
            elif s[k] == ']':
                depth -= 1
                if depth == 0:
                    break
            k += 1
        body = s[j + 1:k]
        i = k + 1
        if ';' in body:
            a, b = body.split(';')
            data = bytes([parse_int(a.strip())]) * parse_int(b.strip())
        else:
            items = [x.strip() for x in body.split(',') if x.strip()]
            data = bytes(parse_int(x) for x in items)
        val = ('bytes', data)
    elif re.match(r'&?[a-z_][a-z0-9_]*\b', s[i:]) and not re.match(r'&?(format|vec)!', s[i:]):
        m = re.match(r'&?([a-z_][a-z0-9_]*)\b', s[i:])
        name = m.group(1)
        lets = [x for x in re.finditer(r'\blet\s+(?:mut\s+)?' + name + r'(?:\s*:\s*[^=]+)?\s*=\s*', s[:i])]
        if not lets:
            raise Unsupported('var ' + name)
        val, _ = parse_expr(s, lets[-1].end())
        i += m.end()
    elif s.startswith('JUMPS_DATA', i):
        i += len('JUMPS_DATA')
        val = ('bytes', jumps)
    else:
        raise Unsupported('expr: ' + s[i:i + 30].replace('\n', ' '))
    i = skip_ws(s, i)
    # method calls we understand
    while s.startswith('.', i):
        m = re.match(r'\.(as_bytes|as_slice|to_vec|as_ref)\(\)', s[i:])
        if not m:
            raise Unsupported('method: ' + s[i:i + 20])
        if val[0] == 'str':
            val = ('bytes', val[1].encode('utf-8'))
        i = skip_ws(s, i + m.end())
    return val, i


def fn_name_at(pos):
    m = None
    for m2 in re.finditer(r'\bfn\s+(\w+)\s*\(', src[:pos]):
        m = m2
    return m.group(1) if m else '?'


cases = []
skipped = {}
for m in re.finditer(r'\b(' + '|'.join(MACROS) + r')!\(', src):
    macro = m.group(1)
    if src[max(0, m.start() - 20):m.start()].rstrip().endswith('macro_rules!'):
        continue
    line = src.count('\n', 0, m.start()) + 1
    i = m.end()
    try:
        args = []
        while True:
            i = skip_ws(src, i)
            if src[i] == ')':
                break
            v, i = parse_expr(src, i)
            args.append(v)
            i = skip_ws(src, i)
            if src[i] == ',':
                i += 1
        def text(a):
            return a[1] if a[0] == 'str' else a[1].decode('latin1')
        def data(a):
            return a[1] if a[0] == 'bytes' else a[1].encode('utf-8')
        payload = text(args[0])
        d = data(args[1]) if len(args) > 1 else b''
        if macro.startswith('condition'):
            rule = 'rule t {condition: %s }' % payload
        elif macro.startswith('rule'):
            rule = payload
        else:
            rule = 'rule test { strings: $a = %s condition: $a}' % payload
        if macro == 'pattern_match':
            kind, expected = 'match', data(args[2]).hex()
        else:
            kind, expected = 'bool', 1 if macro.endswith('_true') else 0
        cases.append({'fn': fn_name_at(m.start()), 'macro': macro, 'kind': kind,
                      'rule': rule, 'data': d.hex(), 'expected': expected, 'line': line})
    except (Unsupported, IndexError, ValueError, AttributeError) as e:
        key = str(e)[:40]
        skipped[key] = skipped.get(key, 0) + 1

json.dump(cases, open(sys.argv[3], 'w'), indent=0)
print(len(cases), 'cases;', sum(skipped.values()), 'skipped', file=sys.stderr)
for k, v in sorted(skipped.items(), key=lambda x: -x[1])[:15]:
    print('  ', v, k, file=sys.stderr)
