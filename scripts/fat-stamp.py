#!/usr/bin/env python3
"""Makes a FAT12/16/32 image deterministic (M17): every timestamp becomes
SOURCE_DATE_EPOCH, and free clusters are zeroed.

    scripts/fat-stamp.py ESP.img EPOCH

mtools versions differ in which timestamps follow SOURCE_DATE_EPOCH (e.g.
directories made by `mmd`, and their `.`/`..` entries, take the current time
on Ubuntu 24.04's mtools 4.0.43). Rewriting every directory entry's times
afterwards makes the image independent of the mtools version and of the
clock. Ubuntu's mformat also leaves uninitialised memory (heap pointers,
different on every run) in an unused sector at the end of the image, so free
clusters and the slack after the last cluster are zeroed as well
(reproducible builds).
"""

import struct
import sys
import time


def dos_datetime(epoch: int) -> tuple[int, int]:
    t = time.gmtime(max(epoch, 315532800))  # FAT dates start in 1980
    date = ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    tod = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    return date, tod


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    path, epoch = sys.argv[1], int(sys.argv[2])
    img = bytearray(open(path, "rb").read())
    bps, spc, reserved, nfats, root_entries, total16, _, fat16 = struct.unpack_from("<HBHBHHBH", img, 11)
    total = total16 or struct.unpack_from("<I", img, 32)[0]
    fat_sectors = fat16 or struct.unpack_from("<I", img, 36)[0]
    root_sectors = (root_entries * 32 + bps - 1) // bps
    first_data = reserved + nfats * fat_sectors + root_sectors
    clusters = (total - first_data) // spc
    kind = 12 if clusters < 4085 else 16 if clusters < 65525 else 32
    fat_at = reserved * bps
    cluster_bytes = spc * bps

    def next_cluster(c: int) -> int:
        if kind == 12:
            v = struct.unpack_from("<H", img, fat_at + c * 3 // 2)[0]
            v = v >> 4 if c & 1 else v & 0xFFF
            return v if v < 0xFF8 else -1
        if kind == 16:
            v = struct.unpack_from("<H", img, fat_at + c * 2)[0]
            return v if v < 0xFFF8 else -1
        v = struct.unpack_from("<I", img, fat_at + c * 4)[0] & 0x0FFFFFFF
        return v if v < 0x0FFFFFF8 else -1

    def chain(c: int) -> list[tuple[int, int]]:
        out, seen = [], set()
        while c >= 2 and c not in seen and len(seen) <= clusters:
            seen.add(c)
            out.append(((first_data + (c - 2) * spc) * bps, cluster_bytes))
            c = next_cluster(c)
        return out

    date, tod = dos_datetime(epoch)
    stamped = 0

    def walk(regions: list[tuple[int, int]], depth: int) -> None:
        nonlocal stamped
        for start, length in regions:
            for at in range(start, start + length, 32):
                first = img[at]
                if first == 0:
                    return
                attr = img[at + 11]
                if first == 0xE5 or attr == 0x0F:
                    continue
                img[at + 13] = 0  # creation time, 10 ms units
                struct.pack_into("<HHH", img, at + 14, tod, date, date)  # created, accessed
                struct.pack_into("<HH", img, at + 22, tod, date)  # written
                stamped += 1
                name = bytes(img[at : at + 11])
                if attr & 0x10 and name[:1] != b"." and depth < 16:
                    hi = struct.unpack_from("<H", img, at + 20)[0] if kind == 32 else 0
                    lo = struct.unpack_from("<H", img, at + 26)[0]
                    walk(chain((hi << 16) | lo), depth + 1)

    if kind == 32:
        walk(chain(struct.unpack_from("<I", img, 44)[0]), 0)
    else:
        walk([((reserved + nfats * fat_sectors) * bps, root_sectors * bps)], 0)
    # Free clusters (FAT entry 0) and the slack after the last cluster hold
    # no data: zero them.
    zeroed = 0
    for c in range(2, clusters + 2):
        if kind == 12:
            v = struct.unpack_from("<H", img, fat_at + c * 3 // 2)[0]
            v = v >> 4 if c & 1 else v & 0xFFF
        elif kind == 16:
            v = struct.unpack_from("<H", img, fat_at + c * 2)[0]
        else:
            v = struct.unpack_from("<I", img, fat_at + c * 4)[0] & 0x0FFFFFFF
        if v == 0:
            at = (first_data + (c - 2) * spc) * bps
            img[at : at + cluster_bytes] = bytes(cluster_bytes)
            zeroed += 1
    tail = (first_data + clusters * spc) * bps
    img[tail : total * bps] = bytes(max(0, total * bps - tail))
    open(path, "wb").write(img)
    print(f"fat-stamp: {zeroed} free cluster(s) zeroed, {stamped} entr(y/ies) set to {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch))} UTC (FAT{kind})")


if __name__ == "__main__":
    main()
