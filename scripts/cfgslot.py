#!/usr/bin/env python3
"""Configuration slots in image files (C1, ADR-215, ADR-217).

  cfgslot.py as-disk SLOT OUT      OUT = SLOT with the installation image's
                                   "not yet configured" marker
  cfgslot.py patch IMAGE SLOT      replace the one unconfigured (DISK-marked)
                                   slot inside IMAGE by SLOT, in place

A slot is 256 KiB: a 16-byte marker, the urmqtt-cfg blob, zero padding. In an
image it sits at a multiple of 512 bytes (a FAT file or an ISO 9660 file
written to a fresh image is contiguous). A marker that is not followed by the
blob magic and zero padding to the end of the slot (for instance the constant
inside the kernel) is not a slot.
"""
import struct
import sys

SLOT_SIZE = 256 * 1024
SLOT_MARKER = b"URMQTT-CFG-SLOT\0"
DISK_MARKER = b"URMQTT-CFG-DISK\0"
MAGIC = b"URMQCFG\0"


def blob_len(slot):
    """Length of the blob inside a slot, or None if it does not look like one."""
    if slot[16:24] != MAGIC:
        return None
    plen = struct.unpack_from("<I", slot, 16 + 12)[0]
    end = 16 + 16 + plen + 32
    if end + 1 > SLOT_SIZE:
        return None
    kind = slot[end]
    if kind == 0:
        return end + 1 - 16
    if kind == 1:
        return end + 1 + 32 + 64 - 16
    return None


def find(image, marker):
    out = []
    off = 0
    while off + SLOT_SIZE <= len(image):
        if image[off : off + 16] == marker:
            slot = image[off : off + SLOT_SIZE]
            n = blob_len(slot)
            if n is not None and not any(slot[16 + n :]):
                out.append(off)
                off += SLOT_SIZE
                continue
        off += 512
    return out


def main(argv):
    if len(argv) == 4 and argv[1] == "as-disk":
        slot = open(argv[2], "rb").read()
        if len(slot) != SLOT_SIZE or slot[:16] != SLOT_MARKER:
            sys.exit(f"error: {argv[2]} is not a boot slot")
        open(argv[3], "wb").write(DISK_MARKER + slot[16:])
        return
    if len(argv) == 4 and argv[1] == "patch":
        image = bytearray(open(argv[2], "rb").read())
        slot = open(argv[3], "rb").read()
        if len(slot) != SLOT_SIZE or slot[:16] != SLOT_MARKER:
            sys.exit(f"error: {argv[3]} is not a boot slot")
        found = find(bytes(image), DISK_MARKER)
        if len(found) != 1:
            sys.exit(f"error: {argv[2]}: expected one unconfigured slot, found {len(found)}")
        image[found[0] : found[0] + SLOT_SIZE] = slot
        open(argv[2], "wb").write(image)
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
