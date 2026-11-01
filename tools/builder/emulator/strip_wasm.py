# Remove all custom sections (DWARF .debug_*, "name", llvm.* annotations) from a wasm file.
# They are ~28 MB of the 40.8 MB prebuilt binary and are not needed at run time.
#   python3 -I strip_wasm.py in.wasm out.wasm
import sys


def leb(f, p):
    r = 0
    s = 0
    while True:
        b = f[p]
        p += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return r, p


f = open(sys.argv[1], 'rb').read()
assert f[:8] == b'\0asm\x01\0\0\0'
out = bytearray(f[:8])
p = 8
dropped = 0
while p < len(f):
    start = p
    sid = f[p]
    p += 1
    size, p = leb(f, p)
    end = p + size
    if sid == 0:
        dropped += end - start
    else:
        out += f[start:end]
    p = end
open(sys.argv[2], 'wb').write(out)
print('in', len(f), 'out', len(out), 'dropped custom sections', dropped)
