"""Regenerates p256-x86_64-asm.S and p256-table.bin from an unpacked ring 0.17.14
(the crates.io source). Usage, from the repository root:

    python3 -I vendor/nistz256/derive.py /path/to/ring-0.17.14

and compare with `git diff vendor/nistz256` (see vendor/README.md).
"""
import sys, re, hashlib, struct
R = sys.argv[1]
text = open(R + "/pregenerated/p256-x86_64-asm-elf.S").read()
a = text.index(".globl\tecp_nistz256_select_w5_avx2")
endmark = ".size\tecp_nistz256_select_w7_avx2,.-ecp_nistz256_select_w7_avx2\n"
b = text.index(endmark) + len(endmark)
text = text[:a] + text[b:]
text = text.replace("#include <ring-core/asm_base.h>\n", "")
text = re.sub(r"^#if .*\n", "", text, flags=re.M)
text = re.sub(r"^#endif\n?", "", text, flags=re.M)
text = text.replace("_CET_ENDBR\n", "")
text = text.replace("ecp_nistz256_", "urmqtt_nistz256_")
text = re.sub(r"^// This file is generated.*\n// source tree.*\n", "", text, flags=re.M)
hdr = """# P-256 field and point arithmetic for x86_64 (Montgomery, 4x64, MULX/ADX
# and plain-MUL variants).
#
# Derived from the pregenerated GNU-assembler output shipped in ring 0.17.14
# (pregenerated/p256-x86_64-asm-elf.S), which is generated from BoringSSL's
# p256-x86_64-asm.pl, itself from OpenSSL's ecp_nistz256-x86_64.pl.
# Copyright 2014-2016 The OpenSSL Project Authors. Copyright (c) 2014, Intel
# Corporation. Copyright (c) 2015 CloudFlare, Inc.  Licensed under the Apache
# License, Version 2.0 (see LICENSE-APACHE in this directory).
# Originally written by Shay Gueron and Vlad Krasnov.
#
# Changes for urMQTT (vendor/README.md): the C preprocessor lines and the
# _CET_ENDBR markers are removed, the AVX2 select functions are removed (the
# kernel keeps no AVX state), and the symbols are renamed from
# ecp_nistz256_* to urmqtt_nistz256_*.
"""
# the original begins with "// This file is generated" lines; convert // comments to #
text = "\n".join(("#" + l[2:]) if l.startswith("//") else l for l in text.split("\n"))
open("vendor/nistz256/p256-x86_64-asm.S", "w").write(hdr + text)
h = open(R + "/crypto/fipsmodule/ec/p256-nistz-table.h").read()
nums = re.findall(r"TOBN\((0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)", h)
print(len(nums), len(nums) / 8)
bb = b"".join(struct.pack("<Q", (int(hi, 16) << 32) | int(lo, 16)) for hi, lo in nums)
open("vendor/nistz256/p256-table.bin", "wb").write(bb)
print(len(bb), hashlib.sha256(bb).hexdigest())
