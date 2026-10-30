#!/usr/bin/env bash
# Builds a UEFI-only (no BIOS, no hybrid MBR/GPT) bootable ISO for aarch64.
#
#   scripts/mkiso.sh --kernel ELF --out ISO [--cmdline "smoke test=brk"] [--esp-out IMG]
#                    [--arch aarch64|x86_64]
#   scripts/mkiso.sh --universal --kernel-aarch64 ELF --kernel-x86_64 ELF --out ISO
#                    [--cmdline STR] [--esp-out IMG] [--disk-out IMG]
#                    [--install-cmdline STR] [--install-default]
#
# --universal (X10, ADR-043) builds ONE hybrid ISO for aarch64 UEFI, x86_64
# UEFI and x86_64 BIOS: both kernels (urmqtt-<arch>.elf, ${ARCH} spelling of
# Limine: aarch64, x86-64), both UEFI loaders, one limine.conf whose entries
# each carry `if_arch`. See the universal section below.
#
# --arch x86_64 (X2) builds a hybrid ISO that boots on x86 BIOS (El Torito,
# Limine stage 1) and UEFI (BOOTX64.EFI in the ESP image): one entry, no
# menu, no install entry. See the x86_64 section below.
#                    [--install-cmdline "install"] [--install-default]
#
# Layout of the El Torito EFI image (FAT), which is also the EFI system
# partition of the raw image and of an installed disk:
#   /EFI/BOOT/BOOTAA64.EFI   Limine (vendor/limine, checksum-verified)
#   /EFI/BOOT/limine.conf    no menu, no editor, kernel path pinned by blake2b
#   /boot/urmqtt             the kernel
#
# The ISO9660 filesystem (what Limine reads on a CD boot) has the same
# loader and kernel, plus the ESP itself as /esp.img, and its own
# limine.conf with a menu (S1b, STORAGE-PLAN §2b):
#   1. urMQTT                                   cmdline "live" (O3, RAM-backed;
#                                               default, after 10 s)
#   2. Install urMQTT on this machine's disk    cmdline "install", module esp.img
# Both the kernel and the module are pinned by blake2b, the editor is off.
# --install-cmdline replaces the install entry's command line (dev tests add
# options after "install"); --install-default makes it the default entry
# with no timeout (unattended smoke tests).
#
# The menu's first entry boots with the word `live` on its command line (O3,
# ADR-054): the kernel then keeps its data in RAM and needs no disk, if the
# baked configuration allows it (storage.mode = "auto" or "ram"; otherwise it
# refuses loudly). --no-live leaves the word out (tests of the read-only-media
# refusal); the x86_64-only ISO has no menu and takes the word with --live.
# The no-menu configuration of the installed disk never carries it.
#
# Timestamps and the FAT volume serial are fixed (SOURCE_DATE_EPOCH, default:
# last commit time) so identical inputs produce an identical image.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ARCH=${URMQTT_ARCH:-aarch64}
KERNEL="" OUT="" CMDLINE="" ESP_OUT="" INSTALL_CMDLINE="install" INSTALL_DEFAULT=0
UNIVERSAL=0 KERNEL_A64="" KERNEL_X86="" DISK_OUT="" LIVE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --arch) ARCH=$2; shift 2 ;;
        --kernel) KERNEL=$2; shift 2 ;;
        --universal) UNIVERSAL=1; shift ;;
        --kernel-aarch64) KERNEL_A64=$2; shift 2 ;;
        --kernel-x86_64) KERNEL_X86=$2; shift 2 ;;
        --disk-out) DISK_OUT=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --cmdline) CMDLINE=$2; shift 2 ;;
        --esp-out) ESP_OUT=$2; shift 2 ;;
        --install-cmdline) INSTALL_CMDLINE=$2; shift 2 ;;
        --install-default) INSTALL_DEFAULT=1; shift ;;
        --live) LIVE=1; shift ;;
        --no-live) LIVE=0; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [[ $UNIVERSAL -eq 1 ]]; then
    [[ -n "$KERNEL_A64" && -n "$KERNEL_X86" && -n "$OUT" ]] \
        || { echo "usage: $0 --universal --kernel-aarch64 ELF --kernel-x86_64 ELF --out ISO [--cmdline STR]" >&2; exit 2; }
    for k in "$KERNEL_A64" "$KERNEL_X86"; do
        [[ -f "$k" ]] || { echo "error: kernel $k not found (make build ARCH=aarch64 and ARCH=x86_64)" >&2; exit 1; }
    done
else
    [[ -n "$KERNEL" && -n "$OUT" ]] || { echo "usage: $0 --kernel ELF --out ISO [--cmdline STR] [--esp-out IMG]" >&2; exit 2; }
    [[ -f "$KERNEL" ]] || { echo "error: kernel $KERNEL not found (run make build)" >&2; exit 1; }
fi
for tool in mformat mmd mcopy xorriso python3; do
    command -v "$tool" >/dev/null || { echo "error: $tool not found (brew install mtools xorriso / apt install mtools xorriso)" >&2; exit 1; }
done
if [[ "$CMDLINE$INSTALL_CMDLINE" == *$'\n'* ]]; then
    echo "error: command line must be a single line" >&2; exit 2
fi

# The live entry's command line: `live`, then whatever --cmdline adds.
LIVE_CMDLINE="live${CMDLINE:+ $CMDLINE}"
[[ ${LIVE:-1} == 0 ]] && LIVE_CMDLINE=$CMDLINE

# Verify the vendored bootloader before using it.
(cd "$ROOT/vendor/limine" && grep -v '^#' CHECKSUMS | shasum -a 256 -c --quiet -) \
    || { echo "error: vendor/limine checksum mismatch" >&2; exit 1; }

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}
STAMP=$(python3 -I -c 'import sys,time; print(time.strftime("%Y%m%d%H%M.%S", time.gmtime(int(sys.argv[1]))))' "$SOURCE_DATE_EPOCH")

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

blake2b() { python3 -I -c 'import hashlib,sys; print(hashlib.blake2b(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }

# The menu's look (ALDO TECH wallpaper, no Limine branding or key help),
# hash-pinned like the kernels. Only the menus carry it: the no-menu ESP
# config shows nothing. The wallpaper must be on the volume Limine boots from.
WALLPAPER="$ROOT/assets/boot/wallpaper.png"
menu_style() {
    echo "wallpaper: boot():/boot/wallpaper.png#$(blake2b "$WALLPAPER")"
    echo "wallpaper_style: centered"
    echo "backdrop: 2c2c44"
    echo "interface_branding: "
    echo "interface_help_hidden: yes"
}

if [[ $UNIVERSAL -eq 1 ]]; then
    # One ISO for aarch64 UEFI, x86_64 UEFI and x86_64 BIOS. Every artifact
    # exists once per architecture; Limine's `if_arch` shows each machine
    # only its own entries, and each entry pins its own kernel by blake2b.
    #
    #   ESP image (FAT; the installed disk's EFI system partition):
    #     /EFI/BOOT/BOOTAA64.EFI, BOOTX64.EFI   the loaders
    #     /EFI/BOOT/limine.conf, /boot/limine/limine.conf   no menu
    #     /boot/limine/limine-bios.sys           BIOS stage 2 (installed disk)
    #     /boot/urmqtt-aarch64.elf, /boot/urmqtt-x86-64.elf
    #   disk image (the install module): GPT with a BIOS boot partition and
    #   the ESP, `limine bios-install` applied, so the installed disk boots
    #   by UEFI and by BIOS.
    #   The ISO's ESP (El Torito UEFI image, GPT partition of the hybrid
    #   image) is that ESP plus /disk.img and the menu config; the ISO9660
    #   tree (what a BIOS boot from the CD reads) has the same files, with
    #   /esp.img. El Torito: BIOS (limine-bios-cd.bin) and UEFI (esp.img).
    LCC=${CC:-cc}
    command -v "$LCC" >/dev/null || { echo "error: no C compiler ($LCC) to build the limine tool" >&2; exit 1; }
    "$LCC" -O2 -std=c99 -D_FILE_OFFSET_BITS=64 -o "$TMP/limine" "$ROOT/vendor/limine/limine.c"
    HASH_A64=$(blake2b "$KERNEL_A64")
    HASH_X86=$(blake2b "$KERNEL_X86")
    # entry <title> <extra lines...>: one entry per architecture.
    entries() {
        local title=$1 cmd=$2 module=$3 arch hash
        for arch in aarch64 x86-64; do
            if [[ $arch == aarch64 ]]; then hash=$HASH_A64; else hash=$HASH_X86; fi
            echo
            echo "/$title"
            echo "    if_arch: $arch"
            echo "    protocol: limine"
            # shellcheck disable=SC2016 # ${ARCH} is Limine's macro
            echo "    path: boot():/boot/urmqtt-"'${ARCH}'".elf#$hash"
            if [[ -n "${URMQTT_RESOLUTION:-}" ]]; then printf '    resolution: %s\n' "$URMQTT_RESOLUTION"; fi
            if [[ -n "$cmd" ]]; then printf '    cmdline: %s\n' "$cmd"; fi
            if [[ -n "$module" ]]; then echo "    module_path: $module"; fi
        done
    }
    {
        echo "# Generated by scripts/mkiso.sh --universal. No menu and no editor."
        echo "timeout: 0"
        echo "quiet: yes"
        echo "editor_enabled: no"
        echo "hash_mismatch_panic: yes"
        entries urMQTT "$CMDLINE" ""
    } > "$TMP/limine.conf"
    for f in BOOTAA64.EFI BOOTX64.EFI limine-bios.sys limine-bios-cd.bin; do cp "$ROOT/vendor/limine/$f" "$TMP/$f"; done
    cp "$KERNEL_A64" "$TMP/urmqtt-aarch64.elf"
    cp "$KERNEL_X86" "$TMP/urmqtt-x86-64.elf"
    TZ=UTC touch -t "$STAMP" "$TMP"/*.EFI "$TMP"/*.elf "$TMP"/limine.conf "$TMP"/limine-bios.sys "$TMP"/limine-bios-cd.bin
    payload=0
    for f in BOOTAA64.EFI BOOTX64.EFI limine-bios.sys urmqtt-aarch64.elf urmqtt-x86-64.elf; do
        payload=$(( payload + $(wc -c < "$TMP/$f") ))
    done
    mib=$(( (payload * 2 / 1048576) + 1 ))
    (( mib < 8 )) && mib=8
    ESP="$TMP/esp.img"
    export MTOOLS_SKIP_CHECK=1
    mformat -i "$ESP" -C -T $(( mib * 2048 )) -h 64 -s 32 -N 55524d51 -v URMQTT ::
    mmd -i "$ESP" ::/EFI ::/EFI/BOOT ::/boot ::/boot/limine
    mcopy -m -i "$ESP" "$TMP/BOOTAA64.EFI" "$TMP/BOOTX64.EFI" ::/EFI/BOOT/
    mcopy -m -i "$ESP" "$TMP/limine.conf" ::/EFI/BOOT/limine.conf
    mcopy -m -i "$ESP" "$TMP/limine.conf" ::/boot/limine/limine.conf
    mcopy -m -i "$ESP" "$TMP/limine-bios.sys" ::/boot/limine/limine-bios.sys
    mcopy -m -i "$ESP" "$TMP/urmqtt-aarch64.elf" "$TMP/urmqtt-x86-64.elf" ::/boot/
    python3 -I "$ROOT/scripts/fat-stamp.py" "$ESP" "$SOURCE_DATE_EPOCH" >/dev/null
    # The installed disk: GPT, BIOS boot partition, ESP; Limine's BIOS stage 1
    # and stage 1.5 applied (the tool is deterministic: checked by `make repro`).
    python3 -I "$ROOT/scripts/mkraw.py" --bios-boot "$ESP" "$TMP/disk.img" >/dev/null
    "$TMP/limine" bios-install "$TMP/disk.img" >/dev/null 2>&1 || { echo "error: limine bios-install failed on the disk image" >&2; exit 1; }
    DISK_HASH=$(blake2b "$TMP/disk.img")
    # `default_entry` counts the entries visible to the running architecture
    # (verified against Limine 12.9.4): 1 is urMQTT, 2 the installer.
    if [[ $INSTALL_DEFAULT -eq 1 ]]; then
        MENU_TIMEOUT=0 DEFAULT_ENTRY=2
    else
        MENU_TIMEOUT=${URMQTT_MENU_TIMEOUT:-10} DEFAULT_ENTRY=1
    fi
    {
        echo "# Generated by scripts/mkiso.sh --universal: the menu (S1b, X10). No editor;"
        echo "# kernels and the installation image pinned by blake2b."
        echo "timeout: $MENU_TIMEOUT"
        echo "default_entry: $DEFAULT_ENTRY"
        echo "editor_enabled: no"
        echo "hash_mismatch_panic: yes"
        menu_style
        entries urMQTT "$LIVE_CMDLINE" ""
        entries "Install urMQTT on this machine's disk" "$INSTALL_CMDLINE" "boot():/disk.img#$DISK_HASH"
    } >"$TMP/iso-limine.conf"
    # The ISO's own EFI system partition (El Torito, and the GPT partition of
    # the hybrid image) is what UEFI firmware boots from, so it carries the
    # menu and the installation image too: the installed disk's ESP above
    # plus /disk.img and the menu in place of the no-menu config.
    OUTER="$TMP/esp-iso.img"
    outer_payload=$(( payload + $(wc -c < "$TMP/disk.img") ))
    outer_mib=$(( (outer_payload * 5 / 4 / 1048576) + 2 ))
    mformat -i "$OUTER" -C -T $(( outer_mib * 2048 )) -h 64 -s 32 -N 55524d51 -v URMQTT ::
    mmd -i "$OUTER" ::/EFI ::/EFI/BOOT ::/boot ::/boot/limine
    mcopy -m -i "$OUTER" "$TMP/BOOTAA64.EFI" "$TMP/BOOTX64.EFI" ::/EFI/BOOT/
    mcopy -m -i "$OUTER" "$TMP/iso-limine.conf" ::/EFI/BOOT/limine.conf
    mcopy -m -i "$OUTER" "$TMP/iso-limine.conf" ::/boot/limine/limine.conf
    mcopy -m -i "$OUTER" "$TMP/limine-bios.sys" ::/boot/limine/limine-bios.sys
    mcopy -m -i "$OUTER" "$TMP/urmqtt-aarch64.elf" "$TMP/urmqtt-x86-64.elf" ::/boot/
    mcopy -m -i "$OUTER" "$TMP/disk.img" ::/disk.img
    cp "$WALLPAPER" "$TMP/wallpaper.png"
    TZ=UTC touch -t "$STAMP" "$TMP/wallpaper.png"
    mcopy -m -i "$OUTER" "$TMP/wallpaper.png" ::/boot/wallpaper.png
    python3 -I "$ROOT/scripts/fat-stamp.py" "$OUTER" "$SOURCE_DATE_EPOCH" >/dev/null
    mkdir -p "$TMP/iso/EFI/BOOT" "$TMP/iso/boot/limine" "$(dirname "$OUT")"
    cp "$OUTER" "$TMP/iso/esp.img"
    cp "$TMP/disk.img" "$TMP/iso/disk.img"
    cp "$TMP/BOOTAA64.EFI" "$TMP/BOOTX64.EFI" "$TMP/iso/EFI/BOOT/"
    cp "$TMP/iso-limine.conf" "$TMP/iso/EFI/BOOT/limine.conf"
    cp "$TMP/iso-limine.conf" "$TMP/iso/boot/limine/limine.conf"
    cp "$TMP/limine-bios.sys" "$TMP/limine-bios-cd.bin" "$TMP/iso/boot/limine/"
    cp "$TMP/urmqtt-aarch64.elf" "$TMP/urmqtt-x86-64.elf" "$TMP/wallpaper.png" "$TMP/iso/boot/"
    find "$TMP/iso" -exec env TZ=UTC touch -t "$STAMP" {} +
    xorriso -as mkisofs -quiet -iso-level 3 -R -V URMQTT \
        --set_all_file_dates "=$SOURCE_DATE_EPOCH" \
        -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table \
        --efi-boot esp.img -efi-boot-part --efi-boot-image --protective-msdos-label \
        -o "$OUT" "$TMP/iso" 2>&1 | grep -vE '^(xorriso : NOTE|GNU xorriso|$)' >&2 || true
    [[ -s "$OUT" ]] || { echo "error: xorriso produced no image" >&2; exit 1; }
    "$TMP/limine" bios-install "$OUT" >/dev/null 2>&1 || { echo "error: limine bios-install failed" >&2; exit 1; }
    if [[ -n "$ESP_OUT" ]]; then cp "$ESP" "$ESP_OUT"; fi
    if [[ -n "$DISK_OUT" ]]; then cp "$TMP/disk.img" "$DISK_OUT"; fi
    echo "iso: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes, universal: aarch64 ${HASH_A64:0:16}…, x86-64 ${HASH_X86:0:16}…)"
    exit 0
fi

HASH=$(blake2b "$KERNEL")
if [[ $ARCH == x86_64 ]]; then
    # X2: the minimal x86 boot image. The self-installing menu (S1b) and the
    # raw GPT image are X10's. The ESP image carries the UEFI loader, the
    # config and the kernel; the ISO9660 tree carries the same config and
    # kernel (Limine reads the CD itself on a CD boot) plus the BIOS stage 2.
    # `limine bios-install` patches stage 1's pointer to stage 2 into the
    # finished image; the tool is built from the vendored source
    # (vendor/limine/limine.c) with the host C compiler.
    LCC=${CC:-cc}
    command -v "$LCC" >/dev/null || { echo "error: no C compiler ($LCC) to build the limine tool" >&2; exit 1; }
    "$LCC" -O2 -std=c99 -D_FILE_OFFSET_BITS=64 -o "$TMP/limine" "$ROOT/vendor/limine/limine.c"
    {
        echo "# Generated by scripts/mkiso.sh (x86_64). No menu and no editor."
        echo "timeout: 0"
        echo "quiet: yes"
        echo "editor_enabled: no"
        echo "hash_mismatch_panic: yes"
        echo
        echo "/urMQTT"
        echo "    protocol: limine"
        echo "    path: boot():/boot/urmqtt#$HASH"
        if [[ -n "${URMQTT_RESOLUTION:-}" ]]; then printf '    resolution: %s\n' "$URMQTT_RESOLUTION"; fi
        X86_CMDLINE=$CMDLINE
        [[ ${LIVE:-0} == 1 ]] && X86_CMDLINE=$LIVE_CMDLINE
        if [[ -n "$X86_CMDLINE" ]]; then printf '    cmdline: %s\n' "$X86_CMDLINE"; fi
    } > "$TMP/limine.conf"
    cp "$ROOT/vendor/limine/BOOTX64.EFI" "$TMP/BOOTX64.EFI"
    cp "$KERNEL" "$TMP/urmqtt"
    TZ=UTC touch -t "$STAMP" "$TMP/BOOTX64.EFI" "$TMP/urmqtt" "$TMP/limine.conf"
    payload=$(( $(wc -c < "$TMP/BOOTX64.EFI") + $(wc -c < "$TMP/urmqtt") ))
    mib=$(( (payload * 2 / 1048576) + 1 ))
    (( mib < 8 )) && mib=8
    ESP="$TMP/esp.img"
    export MTOOLS_SKIP_CHECK=1
    mformat -i "$ESP" -C -T $(( mib * 2048 )) -h 64 -s 32 -N 55524d51 -v URMQTT ::
    mmd -i "$ESP" ::/EFI ::/EFI/BOOT ::/boot
    mcopy -m -i "$ESP" "$TMP/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
    mcopy -m -i "$ESP" "$TMP/limine.conf" ::/EFI/BOOT/limine.conf
    mcopy -m -i "$ESP" "$TMP/urmqtt" ::/boot/urmqtt
    python3 -I "$ROOT/scripts/fat-stamp.py" "$ESP" "$SOURCE_DATE_EPOCH" >/dev/null
    mkdir -p "$TMP/iso/EFI/BOOT" "$TMP/iso/boot/limine" "$(dirname "$OUT")"
    cp "$ESP" "$TMP/iso/esp.img"
    cp "$TMP/limine.conf" "$TMP/iso/EFI/BOOT/limine.conf"
    cp "$TMP/limine.conf" "$TMP/iso/boot/limine/limine.conf"
    cp "$TMP/BOOTX64.EFI" "$TMP/iso/EFI/BOOT/BOOTX64.EFI"
    cp "$TMP/urmqtt" "$TMP/iso/boot/urmqtt"
    cp "$ROOT/vendor/limine/limine-bios.sys" "$ROOT/vendor/limine/limine-bios-cd.bin" "$TMP/iso/boot/limine/"
    find "$TMP/iso" -exec env TZ=UTC touch -t "$STAMP" {} +
    xorriso -as mkisofs -quiet -iso-level 3 -R -V URMQTT \
        --set_all_file_dates "=$SOURCE_DATE_EPOCH" \
        -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table \
        --efi-boot esp.img -efi-boot-part --efi-boot-image --protective-msdos-label \
        -o "$OUT" "$TMP/iso" 2>&1 | grep -vE '^(xorriso : NOTE|GNU xorriso|$)' >&2 || true
    [[ -s "$OUT" ]] || { echo "error: xorriso produced no image" >&2; exit 1; }
    "$TMP/limine" bios-install "$OUT" >/dev/null 2>&1 || { echo "error: limine bios-install failed" >&2; exit 1; }
    if [[ -n "$ESP_OUT" ]]; then cp "$ESP" "$ESP_OUT"; fi
    echo "iso: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes, x86_64, kernel blake2b ${HASH:0:16}…)"
    exit 0
fi
[[ $ARCH == aarch64 ]] || { echo "error: --arch aarch64|x86_64" >&2; exit 2; }

cat > "$TMP/limine.conf" <<EOF
# Generated by scripts/mkiso.sh. No menu and no editor: the image accepts no input.
timeout: 0
quiet: yes
editor_enabled: no
hash_mismatch_panic: yes

/urMQTT
    protocol: limine
    path: boot():/boot/urmqtt#$HASH
EOF
if [[ -n "${URMQTT_RESOLUTION:-}" ]]; then
    printf '    resolution: %s\n' "$URMQTT_RESOLUTION" >> "$TMP/limine.conf"
fi
if [[ -n "$CMDLINE" ]]; then
    printf '    cmdline: %s\n' "$CMDLINE" >> "$TMP/limine.conf"
fi

cp "$ROOT/vendor/limine/BOOTAA64.EFI" "$TMP/BOOTAA64.EFI"
cp "$KERNEL" "$TMP/urmqtt"
TZ=UTC touch -t "$STAMP" "$TMP/BOOTAA64.EFI" "$TMP/urmqtt" "$TMP/limine.conf"

# FAT image: twice the payload, at least 8 MiB.
payload=$(( $(wc -c < "$TMP/BOOTAA64.EFI") + $(wc -c < "$TMP/urmqtt") ))
mib=$(( (payload * 2 / 1048576) + 1 ))
(( mib < 8 )) && mib=8
ESP="$TMP/esp.img"
export MTOOLS_SKIP_CHECK=1
mformat -i "$ESP" -C -T $(( mib * 2048 )) -h 64 -s 32 -N 55524d51 -v URMQTT ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT ::/boot
mcopy -m -i "$ESP" "$TMP/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI
mcopy -m -i "$ESP" "$TMP/limine.conf" ::/EFI/BOOT/limine.conf
mcopy -m -i "$ESP" "$TMP/urmqtt" ::/boot/urmqtt
# mtools versions differ in which timestamps follow SOURCE_DATE_EPOCH
# (directories, `.` and `..`): set them all explicitly.
python3 -I "$ROOT/scripts/fat-stamp.py" "$ESP" "$SOURCE_DATE_EPOCH" >/dev/null

# Limine treats the ISO9660 volume as the boot volume on CD boots, so the
# kernel lives on the ISO filesystem too, with the menu config.
ESP_HASH=$(python3 -I -c 'import hashlib,sys; print(hashlib.blake2b(open(sys.argv[1],"rb").read()).hexdigest())' "$ESP")
if [[ $INSTALL_DEFAULT -eq 1 ]]; then
    MENU_TIMEOUT=0 DEFAULT_ENTRY=2
else
    MENU_TIMEOUT=${URMQTT_MENU_TIMEOUT:-10} DEFAULT_ENTRY=1
fi
{
    echo "# Generated by scripts/mkiso.sh: the ISO's menu (S1b). No editor; kernel and"
    echo "# installation image pinned by blake2b."
    echo "timeout: $MENU_TIMEOUT"
    echo "default_entry: $DEFAULT_ENTRY"
    echo "editor_enabled: no"
    echo "hash_mismatch_panic: yes"
    menu_style
    echo
    echo "/urMQTT"
    echo "    protocol: limine"
    echo "    path: boot():/boot/urmqtt#$HASH"
    if [[ -n "${URMQTT_RESOLUTION:-}" ]]; then
        printf '    resolution: %s\n' "$URMQTT_RESOLUTION"
    fi
    if [[ -n "$LIVE_CMDLINE" ]]; then
        printf '    cmdline: %s\n' "$LIVE_CMDLINE"
    fi
    echo
    echo "/Install urMQTT on this machine's disk"
    echo "    protocol: limine"
    echo "    path: boot():/boot/urmqtt#$HASH"
    printf '    cmdline: %s\n' "$INSTALL_CMDLINE"
    echo "    module_path: boot():/esp.img#$ESP_HASH"
} >"$TMP/iso-limine.conf"
TZ=UTC touch -t "$STAMP" "$TMP/iso-limine.conf"
mkdir -p "$TMP/iso/EFI/BOOT" "$TMP/iso/boot" "$(dirname "$OUT")"
cp "$ESP" "$TMP/iso/esp.img"
cp "$TMP/iso-limine.conf" "$TMP/iso/EFI/BOOT/limine.conf"
cp "$TMP/urmqtt" "$TMP/iso/boot/urmqtt"
cp "$WALLPAPER" "$TMP/iso/boot/wallpaper.png"
find "$TMP/iso" -exec env TZ=UTC touch -t "$STAMP" {} +
xorriso -as mkisofs -quiet -iso-level 3 -R -V URMQTT \
    --set_all_file_dates "=$SOURCE_DATE_EPOCH" \
    -e esp.img -no-emul-boot \
    -o "$OUT" "$TMP/iso" 2>&1 | grep -vE '^(xorriso : NOTE|GNU xorriso|$)' >&2 || true
[[ -s "$OUT" ]] || { echo "error: xorriso produced no image" >&2; exit 1; }
if [[ -n "$ESP_OUT" ]]; then
    cp "$ESP" "$ESP_OUT"
fi
echo "iso: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes, kernel blake2b ${HASH:0:16}…)"
