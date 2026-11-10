#!/usr/bin/env python3
"""The Authenticode SHA-256 of a PE/COFF file (an EFI loader), as UEFI firmware computes it
to match a `db` or `dbx` hash entry (LATER-6, ADR-322).

    python3 -I scripts/authenticode.py FILE...     one line per file: <64 hex>  <FILE>

The digest covers the whole file except the optional header's CheckSum field, the Certificate
Table entry of the data directories, and the attribute certificate table (the signature itself),
so a loader has the same Authenticode hash before and after signing. This is the layout every
signer of this project writes (sbsign, osslsigncode: the certificate table is appended at the end
of the file). Files are the operator's own build output; anything malformed is refused with a
message, never hashed by guess. Checked against osslsigncode's "Calculated message digest" and by
the firmware itself (smoke `secureboot`: a loader whose hash is in dbx is refused).
"""
import hashlib
import struct
import sys


def authenticode_sha256(data: bytes) -> str:
    def u16(off):
        if off + 2 > len(data):
            raise ValueError("cut off")
        return struct.unpack_from("<H", data, off)[0]

    def u32(off):
        if off + 4 > len(data):
            raise ValueError("cut off")
        return struct.unpack_from("<I", data, off)[0]

    if data[:2] != b"MZ":
        raise ValueError("not a PE file (no MZ header)")
    pe = u32(0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file (no PE signature)")
    opt = pe + 24
    magic = u16(opt)
    if magic == 0x10B:
        dirs = opt + 96
    elif magic == 0x20B:
        dirs = opt + 112
    else:
        raise ValueError(f"unknown optional header magic {magic:#x}")
    if u32(dirs - 4) < 5:  # NumberOfRvaAndSizes: the Certificate Table is entry 4
        raise ValueError("no certificate table entry in the data directories")
    checksum = opt + 64
    secdir = dirs + 4 * 8
    cert_off, cert_len = u32(secdir), u32(secdir + 4)
    end = len(data)
    if cert_len:
        if cert_off + cert_len != len(data) or cert_off < secdir + 8:
            raise ValueError("the certificate table is not at the end of the file")
        end = cert_off
    h = hashlib.sha256()
    h.update(data[:checksum])
    h.update(data[checksum + 4:secdir])
    h.update(data[secdir + 8:end])
    return h.hexdigest()


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    status = 0
    for path in argv:
        try:
            with open(path, "rb") as f:
                print(f"{authenticode_sha256(f.read())}  {path}")
        except (OSError, ValueError) as e:
            print(f"authenticode: {path}: {e}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
