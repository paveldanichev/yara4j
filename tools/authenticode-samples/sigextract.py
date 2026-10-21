import sys
# Keeps the signature related part of "yara -D" output for the pe module.
out=[]; skip=None
for line in sys.stdin.buffer.read().decode('latin1').split('\n'):
    ind=len(line)-len(line.lstrip('\t')); s=line.strip()
    if skip is not None:
        if ind>skip and s: out.append(line); continue
        skip=None
    if ind==1 and s=='signatures': out.append(line); skip=1; continue
    if ind==1 and (s.startswith('number_of_signatures ') or s.startswith('is_signed ')): out.append(line)
sys.stdout.buffer.write(('\n'.join(out)+'\n').encode('latin1'))
