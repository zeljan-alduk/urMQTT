# Binary-patch for a bug in the prebuilt qemu-wasm x86_64 binary (QEMU 8.2.0 + ktock's wasm32 TCG backend).
#
# Bug: tcg/wasm32/tcg-target.c.inc, tcg_out_op():
#     case INDEX_op_ctpop_i32: tcg_out_ctpop_i32(s, opc, args[1], args[2]);   // should be args[0], args[1]
#     case INDEX_op_ctpop_i64: tcg_out_ctpop_i64(s, opc, args[1], args[2]);   // should be args[0], args[1]
# so x86 POPCNT writes to the wrong register with a garbage source. The urMQTT kernel's config
# validator does `heap.is_power_of_two()` == `popcntq %rax,%rax; cmpl $1,%eax` and refuses to boot.
#
# The compiled code in tcg_gen_code (wasm function 16936) loads the two operands with
#     i32.load align=2 offset=112 ; local.set 3     (src  = args[2])
#     i32.load align=2 offset=104 ; local.set 1     (dest = args[1])
# The patch changes the two one-byte offsets: 112 -> 104 (args[1]) and 104 -> 96 (args[0]).
# Same-length edit: no section sizes change.
#
#   python3 -I patch_ctpop.py in.wasm out.wasm
import sys

src, dst = sys.argv[1], sys.argv[2]
b = bytearray(open(src, 'rb').read())

# (offset of the 3-byte "i32.load align=2 offset=N" instruction, expected N, new N)
PATCHES = [
    (9576764, 112, 104),  # ctpop_i32: src  <- args[1]
    (9576771, 104, 96),   # ctpop_i32: dest <- args[0]
    (9576824, 112, 104),  # ctpop_i64: src  <- args[1]
    (9576831, 104, 96),   # ctpop_i64: dest <- args[0]
]
for off, old, new in PATCHES:
    assert b[off] == 0x28 and b[off + 1] == 0x02 and b[off + 2] == old, (off, bytes(b[off:off + 3]))
    b[off + 2] = new
open(dst, 'wb').write(b)
print('patched', len(PATCHES), 'sites ->', dst)
