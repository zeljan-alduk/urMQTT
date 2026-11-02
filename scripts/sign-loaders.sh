#!/usr/bin/env bash
# UEFI Secure Boot for the urMQTT image (H8, ADR-251): keys, signing, verifying, and the
# OVMF/QEMU variable store with those keys enrolled.
#
#   scripts/sign-loaders.sh gen-keys [DIR]            throwaway PK, KEK and db under DIR (default build/secureboot)
#   scripts/sign-loaders.sh sign KEY CERT IN OUT      Authenticode-sign one EFI binary (a Limine loader)
#   scripts/sign-loaders.sh verify CERT FILE          is FILE signed by CERT
#   scripts/sign-loaders.sh ovmf-vars DIR IN OUT      OVMF variable store IN with DIR's PK/KEK/db enrolled,
#                                                     Secure Boot on (needs virt-fw-vars, `pip install virt-firmware`)
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
# in this repository (.gitignore: *.key, *.pem, build/). See docs/DEPLOY.md, "Secure Boot".
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
        [[ $# -eq 3 ]] || die "usage: ovmf-vars DIR IN OUT"
        dir=$1 in=$2 out=$3
        vfv=${URMQTT_VIRT_FW_VARS:-virt-fw-vars}
        command -v "$vfv" >/dev/null || die "virt-fw-vars not found (pip install virt-firmware, or set URMQTT_VIRT_FW_VARS)"
        for k in PK KEK db; do [[ -f $dir/$k.crt ]] || die "$dir/$k.crt missing (gen-keys)"; done
        guid=$(python3 -I -c 'import uuid; print(uuid.uuid4())')
        "$vfv" --input "$in" --output "$out" \
            --set-pk "$guid" "$dir/PK.crt" --add-kek "$guid" "$dir/KEK.crt" --add-db "$guid" "$dir/db.crt" \
            --secure-boot >/dev/null 2>"$out.log" || { cat "$out.log" >&2; rm -f "$out" "$out.log"; die "virt-fw-vars failed"; }
        rm -f "$out.log"
        ;;
    *)
        sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
        exit 2
        ;;
esac
