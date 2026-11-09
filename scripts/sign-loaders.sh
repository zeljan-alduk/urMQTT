#!/usr/bin/env bash
# UEFI Secure Boot for the urMQTT image (H8, ADR-251): keys, signing, verifying, and the
# OVMF/QEMU variable store with those keys enrolled.
#
#   scripts/sign-loaders.sh gen-keys [DIR]            throwaway PK, KEK and db under DIR (default build/secureboot)
#   scripts/sign-loaders.sh sign KEY CERT IN OUT      Authenticode-sign one EFI binary (a Limine loader)
#   scripts/sign-loaders.sh verify CERT FILE          is FILE signed by CERT
#   scripts/sign-loaders.sh ovmf-vars DIR IN OUT [--dbx-hash SHA256]...
#                                                     OVMF (x86_64) or AAVMF (aarch64) variable store IN with
#                                                     DIR's PK/KEK/db enrolled, Secure Boot on, and the given
#                                                     Authenticode hashes in dbx (needs virt-fw-vars,
#                                                     `pip install virt-firmware`)
#   scripts/sign-loaders.sh sign-iso KEY CERT IN.iso OUT.iso [--template TPL.iso] [--config FILE [--root DIR]]
#                                    [--disk-out IMG] [--esp-out IMG] [--allow-empty] [-- MKISO-ARGS...]
#                                                     the signed, sealed image of a configured ISO (from the
#                                                     builder page or `urmqtt-config pack --iso`) or of a
#                                                     template with --config: its own kernels, re-built
#                                                     around them with mkiso.sh (LATER-6, ADR-321).
#                                                     --template: the release template whose minisign
#                                                     signature you checked; IN's kernels must be its kernels
#                                                     byte for byte (without it, nothing ties IN's kernels to
#                                                     a release: you sign whatever kernels IN carries)
#   scripts/sign-loaders.sh authenticode FILE...      the Authenticode SHA-256 of EFI loaders (for db/dbx)
#
# What is signed. The firmware verifies only the PE/COFF loaders `BOOTX64.EFI` and
# `BOOTAA64.EFI`. Limine, once running, verifies everything else itself: it checks the
# enrolled hash of its `limine.conf` (ADR-250) and, when Secure Boot is active, REFUSES any
# file that has no hash in the configuration ("Secure Boot is active and URI ... has no
# associated hash"). The kernel and the configuration module are pinned by hash, so the chain
# is firmware -> signature -> loader -> enrolled config hash -> kernel and module hashes.
# `scripts/mkiso.sh --universal --sb-key KEY --sb-cert CERT` signs the loaders as the last step
# of making an image (after enrolling, because the signature covers the enrolled hash).
#
# Which tool signs. `sbsign` (sbsigntools; apt install sbsigntool) when present, else
# `osslsigncode` (brew install osslsigncode; apt install osslsigncode). Both write an
# Authenticode signature the firmware accepts. The signing time is SOURCE_DATE_EPOCH, so the
# same key and the same loader give the same signed bytes (RSA PKCS#1 v1.5 is deterministic).
#
# Keys. `gen-keys` makes development keys; they are for tests and must not protect anything.
# The project key of a release is generated and kept offline (ideally in an HSM); it is never
# in this repository (.gitignore: *.key, *.pem, build/). See docs/DEPLOY.md, "Secure Boot",
# and docs/secure-boot-keys.md for the custody procedures (the maintainer's decision, D-2).
#
# Installed disks (LATER-6, ADR-320). A signed image is also SEALED: the installed disk's own
# limine.conf pins the configuration module, so the disk the installer writes (and the raw image,
# and an ESP staged into an A/B slot) boots under Secure Boot. A sealed image belongs to one
# configuration; `sign-iso` makes one from the image the builder page or `urmqtt-config pack
# --iso` configured, without building a kernel: the kernels are taken from that image (and must
# be the ones its menu pins), so they stay the release's, byte for byte.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "sign-loaders: $*" >&2; exit 1; }

signer() {
    if command -v sbsign >/dev/null; then echo sbsign
    elif command -v osslsigncode >/dev/null; then echo osslsigncode
    else die "neither sbsign (sbsigntools) nor osslsigncode is installed (apt install sbsigntool | brew install osslsigncode)"; fi
}

cmd=${1:-}
[[ -n $cmd ]] && shift
case $cmd in
    gen-keys)
        dir=${1:-$ROOT/build/secureboot}
        mkdir -p "$dir"
        case "$(cd "$dir" && pwd)" in
            "$ROOT"/build/*|/tmp/*|/var/folders/*) ;;
            *) echo "sign-loaders: warning: $dir is outside build/; never commit these keys" >&2 ;;
        esac
        for k in PK KEK db; do
            [[ -e $dir/$k.key ]] && die "$dir/$k.key exists; remove it to generate a new set"
            openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
                -subj "/CN=urMQTT development Secure Boot $k (do not trust)/" \
                -keyout "$dir/$k.key" -out "$dir/$k.crt" 2>/dev/null
            chmod 600 "$dir/$k.key"
            openssl x509 -in "$dir/$k.crt" -outform DER -out "$dir/$k.der"
        done
        echo "sign-loaders: development PK, KEK and db in $dir (throwaway; not for any real machine)"
        ;;
    sign)
        [[ $# -eq 4 ]] || die "usage: sign KEY CERT IN OUT"
        key=$1 cert=$2 in=$3 out=$4
        [[ -f $key && -f $cert && -f $in ]] || die "key, certificate or input missing"
        epoch=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}
        case $(signer) in
            sbsign) sbsign --key "$key" --cert "$cert" --output "$out" "$in" >/dev/null ;;
            osslsigncode)
                osslsigncode sign -certs "$cert" -key "$key" -h sha256 -time "$epoch" \
                    -in "$in" -out "$out" >/dev/null 2>"$out.log" \
                    || { cat "$out.log" >&2; rm -f "$out" "$out.log"; die "osslsigncode failed on $in"; }
                rm -f "$out.log"
                ;;
        esac
        ;;
    verify)
        [[ $# -eq 2 ]] || die "usage: verify CERT FILE"
        cert=$1 file=$2
        case $(signer) in
            sbsign) command -v sbverify >/dev/null || die "sbverify missing"; sbverify --cert "$cert" "$file" >/dev/null ;;
            osslsigncode) osslsigncode verify -CAfile "$cert" -in "$file" >/dev/null 2>&1 ;;
        esac
        ;;
    ovmf-vars)
        [[ $# -ge 3 ]] || die "usage: ovmf-vars DIR IN OUT [--dbx-hash SHA256]..."
        dir=$1 in=$2 out=$3
        shift 3
        vfv=${URMQTT_VIRT_FW_VARS:-virt-fw-vars}
        command -v "$vfv" >/dev/null || die "virt-fw-vars not found (pip install virt-firmware, or set URMQTT_VIRT_FW_VARS)"
        for k in PK KEK db; do [[ -f $dir/$k.crt ]] || die "$dir/$k.crt missing (gen-keys)"; done
        guid=$(python3 -I -c 'import uuid; print(uuid.uuid4())')
        dbx=()
        while [[ $# -gt 0 ]]; do
            case $1 in
                --dbx-hash)
                    [[ ${2:-} =~ ^[0-9a-fA-F]{64}$ ]] || die "--dbx-hash takes 64 hex digits (scripts/sign-loaders.sh authenticode)"
                    dbx+=(--add-dbx-hash "$guid" "$2"); shift 2 ;;
                *) die "ovmf-vars: unknown argument $1" ;;
            esac
        done
        "$vfv" --input "$in" --output "$out" \
            --set-pk "$guid" "$dir/PK.crt" --add-kek "$guid" "$dir/KEK.crt" --add-db "$guid" "$dir/db.crt" \
            ${dbx[@]+"${dbx[@]}"} --secure-boot >/dev/null 2>"$out.log" \
            || { cat "$out.log" >&2; rm -f "$out" "$out.log"; die "virt-fw-vars failed"; }
        rm -f "$out.log"
        ;;
    authenticode)
        [[ $# -ge 1 ]] || die "usage: authenticode FILE..."
        python3 -I "$ROOT/scripts/authenticode.py" "$@"
        ;;
    sign-iso)
        [[ $# -ge 4 ]] || die "usage: sign-iso KEY CERT IN.iso OUT.iso [--template TPL.iso] [--config FILE [--root DIR]] [--disk-out IMG] [--esp-out IMG] [--allow-empty] [-- MKISO-ARGS...]"
        key=$1 cert=$2 in=$3 out=$4
        shift 4
        config="" root="" extra=() allow_empty=0 template=""
        while [[ $# -gt 0 ]]; do
            case $1 in
                --config) config=$2; shift 2 ;;
                --root) root=$2; shift 2 ;;
                --template) template=$2; shift 2 ;;
                --disk-out|--esp-out) extra+=("$1" "$2"); shift 2 ;;
                --allow-empty) allow_empty=1; shift ;;
                # The rest goes to mkiso.sh as it is (tests: the --cmdline the unsigned image was built with).
                --) shift; extra+=("$@"); break ;;
                *) die "sign-iso: unknown argument $1" ;;
            esac
        done
        [[ -f $key && -f $cert && -f $in ]] || die "sign-iso: key, certificate or image missing"
        [[ -z $config || -f $config ]] || die "sign-iso: $config not found"
        [[ -z $root || -n $config ]] || die "sign-iso: --root goes with --config"
        [[ -z $template || -f $template ]] || die "sign-iso: $template not found"
        command -v xorriso >/dev/null || die "xorriso not found (brew install xorriso / apt install xorriso)"
        signer >/dev/null
        tmp=$(mktemp -d)
        # shellcheck disable=SC2064 # expand now: tmp is local to this branch
        trap "rm -rf '$tmp'" EXIT
        for f in boot/urmqtt-aarch64.elf boot/urmqtt-x86-64.elf boot/urmqtt.cfg EFI/BOOT/limine.conf; do
            xorriso -osirrox on -indev "$in" -extract "/$f" "$tmp/${f##*/}" >/dev/null 2>&1 \
                || die "sign-iso: $in has no /$f: not a universal urMQTT ISO"
        done
        # The kernels must be the ones the image's own menu pins (the image is the release's template,
        # whose signature the operator checked, configured by the builder page or urmqtt-config).
        python3 -I - "$tmp" <<'PY' || die "sign-iso: the kernels of $in are not the ones its limine.conf pins"
import hashlib, sys
d = sys.argv[1]
conf = open(f"{d}/limine.conf", encoding="utf-8", errors="replace").read()
for k in ("urmqtt-aarch64.elf", "urmqtt-x86-64.elf"):
    h = hashlib.blake2b(open(f"{d}/{k}", "rb").read()).hexdigest()
    if f"#{h}" not in conf:
        sys.exit(1)
PY
        # The menu check above only says that IN is consistent with itself: whoever made IN chose both its
        # kernels and its menu. What ties them to a release is the template the operator verified
        # (minisign, DEPLOY.md section 3): its kernels must be IN's, byte for byte.
        if [[ -n $template ]]; then
            mkdir "$tmp/tpl"
            for f in boot/urmqtt-aarch64.elf boot/urmqtt-x86-64.elf; do
                xorriso -osirrox on -indev "$template" -extract "/$f" "$tmp/tpl/${f##*/}" >/dev/null 2>&1 \
                    || die "sign-iso: $template has no /$f: not a universal urMQTT ISO"
                cmp -s "$tmp/tpl/${f##*/}" "$tmp/${f##*/}" \
                    || die "sign-iso: ${f##*/} of $in is not the one of $template: refusing to sign kernels that are not the release's"
            done
        else
            echo "sign-iso: NOTE: no --template: the kernels of $in are checked only against its own menu; pass the release template whose minisign signature you verified (--template) to tie them to the release" >&2
        fi
        cfgtool() { (cd "$ROOT" && cargo run -q --locked -p urmqtt-config-tool --bin urmqtt-config -- "$@"); }
        if [[ -n $config ]]; then
            cfg=$(cd "$(dirname "$config")" && pwd)/$(basename "$config")
        else
            cfg=$tmp/urmqtt.cfg
        fi
        if [[ $allow_empty -eq 0 && $cfg != *.toml ]] && cfgtool verify --dev "$cfg" 2>&1 | grep -q "will not serve"; then
            die "sign-iso: the configuration of $in is empty (a template?): configure it first (builder page or urmqtt-config pack --iso), or give --config; --allow-empty signs it anyway"
        fi
        "$ROOT/scripts/mkiso.sh" --universal --kernel-aarch64 "$tmp/urmqtt-aarch64.elf" --kernel-x86_64 "$tmp/urmqtt-x86-64.elf" \
            --config "$cfg" ${root:+--config-root "$root"} --sb-key "$key" --sb-cert "$cert" --out "$out" \
            ${extra[@]+"${extra[@]}"} || die "sign-iso: mkiso.sh failed"
        for f in BOOTAA64.EFI BOOTX64.EFI; do
            if ! { xorriso -osirrox on -indev "$out" -extract "/EFI/BOOT/$f" "$tmp/$f" >/dev/null 2>&1 \
                && "$0" verify "$cert" "$tmp/$f"; }; then
                die "sign-iso: $f of $out is not signed by $cert"
            fi
        done
        echo "sign-iso: $out: signed by $(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject= *//'), sealed to its configuration"
        ;;
    *)
        sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
        exit 2
        ;;
esac
