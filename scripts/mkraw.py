#!/usr/bin/env python3
"""Wraps the EFI system partition image from mkiso.sh in a GPT disk (M17).

    scripts/mkraw.py [--bios-boot] ESP.img OUT.img

The result is a raw disk image for hosts that boot disks rather than ISOs
(KVM/Proxmox, a cloud server's disk written from a rescue system). Layout:
protective MBR, GPT with one EFI system partition at 1 MiB, backup GPT at
the end. Every GUID is derived from the ESP's contents, so the same ESP
always gives the same image (reproducible builds).
"""

import hashlib
import struct
import sys
import uuid
import zlib

SECTOR = 512
ENTRIES = 128
ENTRY_SIZE = 128
ENTRY_SECTORS = ENTRIES * ENTRY_SIZE // SECTOR  # 32
FIRST = 2048  # 1 MiB alignment
ESP_TYPE = uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
# --bios-boot (the universal image, X10): a BIOS boot partition in the gap
# before the ESP, where `limine bios-install` puts Limine's second stage.
BIOS_TYPE = uuid.UUID("21686148-6449-6E6F-744E-656564454649")
BIOS_FIRST, BIOS_LAST = 64, FIRST - 1
GPT_FIRST_USABLE = 34


def guid(seed: bytes, label: str) -> bytes:
    """A deterministic random-format (v4) GUID, in GPT's mixed-endian form."""
    h = bytearray(hashlib.sha256(label.encode() + seed).digest()[:16])
    h[6] = (h[6] & 0x0F) | 0x40
    h[8] = (h[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(h)).bytes_le


def header(current: int, backup: int, first: int, last: int, disk: bytes, entries_lba: int, entries_crc: int) -> bytes:
    h = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART",
        0x00010000,
        92,
        0,
        0,
        current,
        backup,
        first,
        last,
        disk,
        entries_lba,
        ENTRIES,
        ENTRY_SIZE,
        entries_crc,
    )
    h = h[:16] + struct.pack("<I", zlib.crc32(h)) + h[20:]
    return h.ljust(SECTOR, b"\0")


def main() -> None:
    args = sys.argv[1:]
    bios = "--bios-boot" in args
    args = [a for a in args if a != "--bios-boot"]
    if len(args) != 2:
        sys.exit(__doc__)
    esp = open(args[0], "rb").read()
    if len(esp) % SECTOR:
        sys.exit("error: ESP size is not a multiple of 512")
    seed = hashlib.sha256(esp).digest()
    esp_sectors = len(esp) // SECTOR
    # Whole MiBs (hosts and O_DIRECT want aligned sizes), with at least
    # 1 MiB after the ESP for the backup GPT.
    total = -(-(FIRST + esp_sectors + 2048) // 2048) * 2048
    last_usable = total - 1 - ENTRY_SECTORS - 1
    disk_guid = guid(seed, "disk")

    entry = struct.pack(
        "<16s16sQQQ72s",
        ESP_TYPE.bytes_le,
        guid(seed, "esp"),
        FIRST,
        FIRST + esp_sectors - 1,
        0,
        "EFI system partition".encode("utf-16-le"),
    )
    first_usable = FIRST
    if bios:
        first_usable = GPT_FIRST_USABLE
        entry += struct.pack(
            "<16s16sQQQ72s",
            BIOS_TYPE.bytes_le,
            guid(seed, "bios"),
            BIOS_FIRST,
            BIOS_LAST,
            0,
            "BIOS boot partition".encode("utf-16-le"),
        )
    table = entry.ljust(ENTRIES * ENTRY_SIZE, b"\0")
    table_crc = zlib.crc32(table)

    # Protective MBR: one partition of type 0xEE covering the disk.
    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\0\x02\0", 0xEE, b"\xff\xff\xff", 1, min(total - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"

    img = bytearray(total * SECTOR)
    img[0:SECTOR] = mbr
    img[SECTOR : 2 * SECTOR] = header(1, total - 1, first_usable, last_usable, disk_guid, 2, table_crc)
    img[2 * SECTOR : (2 + ENTRY_SECTORS) * SECTOR] = table
    img[FIRST * SECTOR : (FIRST + esp_sectors) * SECTOR] = esp
    backup_entries = total - 1 - ENTRY_SECTORS
    img[backup_entries * SECTOR : (total - 1) * SECTOR] = table
    img[(total - 1) * SECTOR :] = header(total - 1, 1, first_usable, last_usable, disk_guid, backup_entries, table_crc)
    with open(args[1], "wb") as f:
        f.write(img)
    print(f"raw: {args[1]} ({len(img)} bytes, GPT, EFI system partition of {len(esp)} bytes)")


if __name__ == "__main__":
    main()
