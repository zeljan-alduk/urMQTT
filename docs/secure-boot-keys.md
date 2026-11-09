# Secure Boot keys: the owner's procedures (LATER-6, ADR-324)

These are the procedures for whoever controls the firmware an urMQTT image boots on with UEFI Secure Boot: your
own hypervisor, a Proxmox host, a physical PC. **Only you generate and hold the private keys.** This repository, its
CI and its release workflow hold no Secure Boot key, and release images are published unsigned (ADR-251). Who holds a
project key, if there ever is one, is the maintainer's decision (ROADMAP D-2); nothing here decides it.

`scripts/sign-loaders.sh gen-keys` makes **throwaway** keys under `build/` for the tests. Never use them for a machine
that matters, and never copy them out of `build/`.

What exists after these steps:

| Key | Signs | Where it lives | Enrolled as |
|---|---|---|---|
| PK (platform key) | changes of KEK | offline only (a USB stick in a safe, an HSM) | `PK` |
| KEK (key exchange key) | changes of `db` and `dbx` | offline only | `KEK` |
| db (signing key) | the EFI loaders of your images (`sign-iso`, `mkiso.sh --sb-key`) | where you sign images: an HSM, or an offline machine | `db` |

The firmware checks images against `db` and `dbx`; PK and KEK are needed only to change those lists. That is why
PK and KEK can stay offline for years, and why losing db (a leak) is recovered with KEK.

## 1. Generate the keys, offline

On a machine without network, from a checkout of the release tag you will sign:

```bash
umask 077
mkdir -p ~/sb-keys && cd ~/sb-keys
for k in PK KEK db; do
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 \
    -subj "/CN=<your organisation> Secure Boot $k/" -keyout $k.key -out $k.crt     # asks for a passphrase
  openssl x509 -in $k.crt -outform DER -out $k.der
done
```

RSA 2048 is what every UEFI implementation accepts; some refuse RSA 4096 and most refuse EC keys in `db`. Keep the
passphrase separate from the key files. Write down the SHA-256 fingerprint of each certificate
(`openssl x509 -in db.crt -noout -fingerprint -sha256`): it is how you will recognise them in a firmware menu.

With an HSM: generate the db key inside it (PKCS#11) and export only the certificate; sign with
`sbsign --engine pkcs11 --key 'pkcs11:...'` (sbsigntools) instead of a key file. `scripts/sign-loaders.sh sign`
passes a key file; for an HSM run `sbsign` yourself on the two loaders, or build with `mkiso.sh` and replace the
signing step (ADR-251 says where it is).

Keep **two** copies of PK and KEK, both encrypted at rest and both offline. db is needed every time you configure an
image; keep it where you build images and nowhere else (not in a repository, a cloud folder in the clear, a chat or a
ticket).

## 2. Enroll them

`*.der` (certificates only, never a key) go to the firmware. DEPLOY.md section 5d has the procedure for QEMU/OVMF
(`scripts/sign-loaders.sh ovmf-vars`, tested), AAVMF on aarch64 (the same command on `AAVMF_VARS.fd`, tested),
Proxmox and a physical PC (not tested). Enroll `db.der` at least; PK and KEK when you replace the vendor's (custom
mode). A firmware that keeps only Microsoft's keys cannot boot these images under Secure Boot: shim and MOK are not
supported (ADR-324).

Check: an unsigned urMQTT ISO must now fail with `Access Denied` (or `Security Violation`), and your signed one boot.

## 3. Sign an image

Configure first (builder page or `urmqtt-config pack --iso`), then sign the configured ISO; the kernels stay the
release's (ADR-321). `--template` names the release template whose minisign signature you verified (DEPLOY.md
section 3): the configured ISO's kernels must be its kernels, byte for byte. Without it nothing ties them to the
release (the configured ISO's own menu vouches only for itself), and you would sign whatever kernels it carries:

```bash
scripts/sign-loaders.sh sign-iso ~/sb-keys/db.key ~/sb-keys/db.crt urmqtt-configured.iso urmqtt-signed.iso \
    --template urmqtt-template-<version>-universal.iso --disk-out urmqtt-signed.img --esp-out urmqtt-signed.esp
```

The result is **sealed** to that configuration (ADR-320): the installed disk boots under Secure Boot, and every tool
refuses to put another configuration into it. A new configuration is a new signed image, put on the installed disk as
an A/B update (`urmqtt-disk slots stage DISK --esp urmqtt-signed.esp --unsigned --replace-config --write`: the
new configuration is the ESP's own; DEPLOY.md section 8b). A sealed disk refuses an unsealed ESP, such as the
release's own `.img` (`--allow-unsealed` on a machine without Secure Boot).

Check: `scripts/sign-loaders.sh verify ~/sb-keys/db.crt` on `/EFI/BOOT/BOOTX64.EFI` and `BOOTAA64.EFI` of the ISO
(`xorriso -osirrox on -indev urmqtt-signed.iso -extract /EFI/BOOT/BOOTX64.EFI x.efi`); `urmqtt-disk info` on an
installed disk prints `secure boot: sealed to its configuration`.

## 4. Revoke one image (an old release, a leaked configuration)

Every signed loader is a different binary (its enrolled configuration hash differs), so the firmware's `dbx` revokes
one image exactly (ADR-322). Each image has four loaders to revoke: the ISO's and the installed disk's, for each
architecture.

```bash
xorriso -osirrox on -indev old-signed.iso -extract /EFI/BOOT/BOOTX64.EFI iso-x64.efi -extract /EFI/BOOT/BOOTAA64.EFI iso-aa64.efi
mcopy -i old-signed.esp ::/EFI/BOOT/BOOTX64.EFI disk-x64.efi; mcopy -i old-signed.esp ::/EFI/BOOT/BOOTAA64.EFI disk-aa64.efi
scripts/sign-loaders.sh authenticode iso-x64.efi iso-aa64.efi disk-x64.efi disk-aa64.efi
```

- QEMU/OVMF/AAVMF: `scripts/sign-loaders.sh ovmf-vars ~/sb-keys VARS.fd NEW-VARS.fd --dbx-hash HASH ...` (tested).
- Real firmware: an authenticated `dbx` append signed with KEK, e.g. with efitools:
  `hash-to-efi-sig-list iso-x64.efi iso-aa64.efi disk-x64.efi disk-aa64.efi revoke.esl` (it computes the same
  Authenticode SHA-256 from the loaders; compare its output with the hashes above), then
  `sign-efi-sig-list -a -k KEK.key -c KEK.crt dbx revoke.esl revoke.auth`, and `efi-updatevar -a -f revoke.auth dbx`
  from a Linux on that machine, or the firmware menu. Not tested here.

Revocation is not a version counter: an image you did not revoke still boots (ADR-322). Keep a list of the images you
signed (date, release, configuration fingerprint, the four hashes) next to the keys.

## 5. Rotate db, or recover from a leaked db key

1. Generate a new db key and certificate (step 1).
2. Enroll the new `db.der` **in addition to** the old one (KEK-signed append, or the firmware menu).
3. Sign new images with the new key and put them on every machine (A/B update).
4. Only then put the **old db certificate into `dbx`** (`virt-fw-vars --add-dbx-cert` for OVMF; `efisiglist -t x509`
   and `sign-efi-sig-list ... dbx` for real firmware). Every image signed with the old key stops booting; that is the
   point after a leak, and the reason step 3 comes first in a planned rotation.

A leaked KEK or PK means replacing the firmware's key hierarchy from setup mode on each machine: physical or
hypervisor access is needed. Plan for it by keeping PK and KEK offline.

## 6. What this does not protect

The BIOS path (no signatures exist, AUDIT H8-W3); someone who can enter the firmware setup and change the keys
(physical access, or the hypervisor's owner on a VPS); an older image you did not revoke; the configuration's secrets
(the TLS key and the disk key are in the image: LATER-7). See docs/SECURITY.md, "Secure Boot".
