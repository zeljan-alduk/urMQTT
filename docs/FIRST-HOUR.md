# The first hour

From nothing to a first MQTT message over mutual TLS, in about an hour. For a reader who knows what MQTT is and has a
Linux or macOS laptop. Nothing here needs our help: if a step fails, section 6 lists the usual causes with the log
line each one prints, and section 7 says where to report the rest.

urMQTT is **pre-alpha**. Releases from v0.4.2 on are signed with the release key in `minisign.pub` and ship the
release kernel and images with an empty configuration; v0.1.0 to v0.4.1 were signed with the former test key
`9229E05252D01F8E` (pinned, docs/RELEASE.md section 9) and shipped dev builds. Read
[KNOWN-ISSUES.md](KNOWN-ISSUES.md) before you put it anywhere that matters.

| Step | What | Time |
|---|---|---|
| [0](#0-tools-5-minutes) | Tools and a checkout | 5 min |
| [1](#1-a-test-pki-5-minutes) | A test PKI | 5 min |
| [2](#2-an-image-with-your-settings-10-minutes) | An image with your settings (builder page or command line) | 10 min |
| [3](#3-boot-it-in-qemu-on-the-laptop-10-minutes) | Boot it in QEMU on the laptop | 10 min |
| [4](#4-or-boot-it-on-a-kvm-vps-20-minutes) | Or on a KVM VPS | 20 min |
| [5](#5-the-first-connection-5-minutes) | The first connection | 5 min |
| [6](#6-when-it-does-not-work) | When it does not work | as needed |
| [7](#7-where-to-report) | Where to report | |

What was run for this guide is listed at the end, in [Tested](#tested).

## 0. Tools (5 minutes)

macOS (Homebrew):

```bash
brew install qemu mosquitto openssl@3 minisign
```

Debian or Ubuntu:

```bash
sudo apt install git openssl mosquitto-clients minisign qemu-system-arm qemu-efi-aarch64 qemu-system-x86 ovmf
```

Then the repository, for the test certificates and the scripts:

```bash
git clone https://github.com/zeljan-alduk/urMQTT.git
cd urMQTT
```

Every command below runs from the top of this checkout. Rust is needed only for the command-line route of step 2
(`urmqtt-config`); the builder page needs nothing but a browser.

## 1. A test PKI (5 minutes)

```bash
make certs              # the same as scripts/gen-dev-certs.sh; needs OpenSSL 3 (not macOS's LibreSSL)
```

It writes `deploy/dev/` (git-ignored) and verifies what it made:

| File | What it is |
|---|---|
| `ca.pem`, `ca.key` | the test CA that signs the devices (and the server) |
| `server.pem`, `server.key` | the broker's certificate for `localhost`, `urmqtt.local` and `127.0.0.1` |
| `devices/device-001.pem`, `.key` (and 002, 003, 005) | device certificates; the identity is the CN (`device-001`) |
| `services/backend.pem`, `.key` | the service identity `backend`, which may read every device's topics |
| `services/operator.pem`, `.key` | the operator identity, which reads `$SYS` |
| `control.pub`, `control.key` | the Ed25519 key of the signed control channel |
| `negative/` | certificates the broker must refuse (unknown CA, expired, revoked) |

These keys are throwaway, for a laptop or a lab. A production CA is run offline and is described in
`docs/PKI.md` (in preparation); until it exists, [PROVISIONING.md](PROVISIONING.md) describes the roles.

**For a VPS** the server certificate must name the address the clients connect to. Issue one from the same test CA
(replace the address with yours):

```bash
export PATH="$(brew --prefix openssl@3)/bin:$PATH"     # macOS only: OpenSSL 3 instead of LibreSSL
IP=203.0.113.10
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -keyout deploy/dev/server-vps.key \
  -subj "/O=urMQTT test/CN=$IP" -out deploy/dev/server-vps.csr
openssl x509 -req -in deploy/dev/server-vps.csr -CA deploy/dev/ca.pem -CAkey deploy/dev/ca.key -days 365 -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n' "$IP") \
  -out deploy/dev/server-vps.pem
```

## 2. An image with your settings (10 minutes)

An image is the whole deployment: kernel and configuration, with your server key inside, so **treat the ISO as a
secret**. Every release carries a *template* ISO (the kernels for aarch64 and x86_64 with an empty configuration);
your settings are written into a copy of it.

### With the builder page

Open <https://aldo.tech/en/products/urmqtt-builder/>. Everything happens in the browser: your files never leave it.

1. **Release.** The page picks the newest release that has a template and checks its signature and checksums
   against the key built into the page (a green "Verified" chip). This guide was written against **v0.4.1**.
2. **Where will it run?** "A VM or a lab machine" (DHCP; it also adds the Diagnostic boot entry) for QEMU on the
   laptop. "A server with a fixed address" for a VPS whose provider gives you an address and a gateway; "DHCP first,
   then a fixed address" if you are not sure the provider runs DHCP for a custom ISO.
3. **Your certificates.** Drop `deploy/dev/server.pem`, `deploy/dev/server.key` and `deploy/dev/ca.pem` together
   (for a VPS, `server-vps.pem` and `server-vps.key` instead of the first two). The page sorts them into the server
   certificate, its key and the CA. The CA is the one that signed your **devices**: the broker accepts any device
   certificate it signed. The device certificate itself (`device-001.pem`) does not go into the image; it stays
   with the client.
4. **Name** the image and press **Build ISO**, then **Download ISO**.

The settings that matter for a first boot, all reachable in the simple view or under **Advanced**:

| Setting | Key | For a first boot |
|---|---|---|
| Network | `network.mode` | `dhcp` under QEMU; `static` (address with prefix length, gateway) or `auto` on a VPS |
| TLS certificate and key | `tls.cert`, `tls.key` | required: without them the broker boots and refuses to serve |
| Device CA | `trust.operational` | required, at least one |
| Storage | `storage.mode` | `auto` (the default): the ISO's live entry runs from RAM, an installed disk keeps the data. `disk` forbids the live entry |
| Console display | `console.virtio_gpu` | `on` (or `auto`) on a VPS whose web console goes dark after the boot menu (netcup ARM, see step 4) |
| Control key | `control.public_key` | optional; `deploy/dev/control.pub` lets you revoke devices at run time later |

The page shows the configuration **fingerprint**. The broker prints the same fingerprint at every boot
(`config: fingerprint ...`); if they differ, the machine is not running this configuration.

### Or with the command line (offline, same bytes)

The page and `urmqtt-config pack --iso` produce identical images for the same input (README, "Configure and
download your ISO"). The template and its signed checksums:

```bash
mkdir -p build/first-hour && cd build/first-hour
V=v0.4.1
for f in urmqtt-template-$V-universal.iso SHA256SUMS SHA256SUMS.minisig; do
  curl -fLO "https://github.com/zeljan-alduk/urMQTT/releases/download/$V/$f"
done
minisign -Vm SHA256SUMS -P RWSOH9BSUuApkkBWq/AZJ03Rn63oOYq+yXzC/vgI1PZ/i5yaE+SVzOWS   # the former test key (v0.1.0 to v0.4.1); from v0.4.2 on: -p minisign.pub at the tag
shasum -a 256 -c SHA256SUMS --ignore-missing      # Linux: sha256sum -c SHA256SUMS --ignore-missing
cd ../..
```

`urmqtt-config` is built from the checkout (the releases do not ship the binary yet). The first build installs the
pinned toolchain from `rust-toolchain.toml` and downloads the crates; after that it takes under a minute:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh      # once, if you have no rustup
cargo build --release --locked -p urmqtt-config-tool
```

A configuration for QEMU on the laptop: DHCP, the test certificates, everything else at its default (file names
are read relative to `--root`):

```bash
cat > build/first-hour/config.toml <<'EOF'
[tls]
cert = "server.pem"
key = "server.key"

[trust]
operational = ["ca.pem"]

[control]
public_key = "control.pub"
EOF
target/release/urmqtt-config pack build/first-hour/config.toml --root deploy/dev \
  --iso build/first-hour/urmqtt-template-v0.4.1-universal.iso --out build/first-hour/urmqtt-first.iso
target/release/urmqtt-config show build/first-hour/urmqtt-first.iso      # fingerprint and every non-default value
```

`pack` ends with `ok: fingerprint <64 hex>, unsigned, complete: a kernel will serve with it`. For a VPS add the
network and, for netcup ARM, the console, and use the VPS certificate of step 1:

```toml
[network]
mode = "static"                 # or "auto": DHCP first, then these values
address = "203.0.113.10/24"     # from the provider's panel
gateway = "203.0.113.1"

[tls]
cert = "server-vps.pem"
key = "server-vps.key"

[console]
virtio_gpu = "on"               # netcup ARM: keeps the console visible (step 4)
```

## 3. Boot it in QEMU on the laptop (10 minutes)

The ISO goes in as a CD and an empty disk next to it, so that the installer has a target. The serial console is
on your terminal (quit QEMU with `Ctrl-A X`); TCP 8883 of the guest is forwarded to `127.0.0.1:8883`.

```bash
truncate -s 8G build/first-hour/disk.img
scripts/run-qemu.sh --iso build/first-hour/urmqtt-first.iso --data build/first-hour/disk.img               # aarch64
scripts/run-qemu.sh --arch x86_64 --iso build/first-hour/urmqtt-first.iso --data build/first-hour/disk.img # x86_64
```

The script picks the accelerator (HVF on an Apple Silicon Mac, KVM on Linux when `/dev/kvm` is writable, otherwise
TCG) and finds the UEFI firmware. An x86_64 guest on a Mac or an Arm Linux machine runs under TCG: it works, it
takes a minute or two to boot instead of seconds. If the script says `no ... UEFI firmware found`, point it at
your firmware with `URMQTT_FIRMWARE=...` (and `URMQTT_FIRMWARE_VARS=...` for x86_64; Ubuntu 24.04's are
`/usr/share/OVMF/OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd`). If port 8883 is taken on your laptop, add
`--fwd 18883:8883` and connect to 18883.

The plain QEMU command lines the script runs (macOS paths; the Linux firmware paths are in the comments):

```bash
FW="$(brew --prefix qemu)/share/qemu/edk2-aarch64-code.fd"       # Debian/Ubuntu: /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
qemu-system-aarch64 -machine virt,gic-version=3,acpi=on -accel hvf -cpu host -smp 4 -m 512M \
  -bios "$FW" -device ramfb -display none -no-reboot \
  -device virtio-rng-pci,romfile= \
  -device virtio-scsi-pci,id=scsi0,romfile= \
  -drive if=none,id=cd0,file=build/first-hour/urmqtt-first.iso,format=raw,readonly=on,media=cdrom \
  -device scsi-cd,drive=cd0,bus=scsi0.0,bootindex=0 \
  -drive if=none,id=data0,file=build/first-hour/disk.img,format=raw,cache=none \
  -device virtio-blk-pci,drive=data0,romfile= \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8883-:8883 \
  -device virtio-net-pci,netdev=n0,romfile= \
  -serial mon:stdio
```

```bash
FW="$(brew --prefix qemu)/share/qemu/edk2-x86_64-code.fd"        # Ubuntu 24.04: /usr/share/OVMF/OVMF_CODE_4M.fd
VARS="$(brew --prefix qemu)/share/qemu/edk2-i386-vars.fd"        # Ubuntu 24.04: /usr/share/OVMF/OVMF_VARS_4M.fd
qemu-system-x86_64 -machine q35 -accel tcg -cpu max -smp 4 -m 512M -display none -no-reboot \
  -drive if=pflash,format=raw,unit=0,readonly=on,file="$FW" \
  -drive if=pflash,format=raw,unit=1,snapshot=on,file="$VARS" \
  -device virtio-rng-pci,romfile= \
  -drive if=none,id=cd0,file=build/first-hour/urmqtt-first.iso,format=raw,readonly=on,media=cdrom \
  -device ide-cd,drive=cd0,bootindex=0 \
  -drive if=none,id=data0,file=build/first-hour/disk.img,format=raw,cache=none \
  -device virtio-blk-pci,drive=data0,romfile= \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8883-:8883 \
  -device virtio-net-pci,netdev=n0,romfile= \
  -serial mon:stdio
```

On an aarch64 Linux host replace `-accel hvf` with `-accel kvm`; on an x86_64 Linux host replace
`-accel tcg -cpu max` with `-accel kvm -cpu host`. Where neither guest matches the host, use `-accel tcg -cpu max`.
The x86_64 guest needs a CPU of at least x86-64-v2: `max` and `host` are.

**The boot menu** has three entries: **urMQTT** (the live entry, the default after 10 seconds), **Install urMQTT on
this machine's disk** and **Diagnostic**. The menu is drawn on the display only, not on the serial port, but the
serial port takes the keys: with the commands above the terminal shows no menu for those 10 seconds; press **Down**
and then **Enter** to choose the installer, or wait for the live entry.

**Live** keeps everything in RAM and says so in a framed `EPHEMERAL: data is lost on reboot` banner. That is enough
for the first message. **Install** names the disk, counts down 30 seconds (quit QEMU to cancel), writes and
verifies the image and powers off with `install: done: ... remove the installation medium`. Then boot the disk on
its own; the first boot creates the data partition:

```bash
scripts/run-qemu.sh --disk build/first-hour/disk.img                    # aarch64
scripts/run-qemu.sh --arch x86_64 --disk build/first-hour/disk.img      # x86_64
```

**A good boot log** (aarch64 under HVF; the order and the numbers vary). The lines to look for:

```text
URMQTT BOOT v0.4.1 cpu=4 mem=503
INFO  config: fingerprint 1435dd81...a6b1 (1773 bytes, unsigned), env=prod
INFO  crypto: aes-gcm=armv8-aes ghash=armv8-pmull chacha=neon sha256=armv8-sha2 crc32c=armv8-crc toeplitz=bitwise
INFO  crypto: known-answer tests passed (AES-128-GCM, ChaCha20-Poly1305, SHA-256, HMAC-SHA-256, CRC-32C)
INFO  boot: from optical media (CD/ISO)                       (installed disk: boot: from a GPT disk, disk GUID ...)
INFO  net: mac 52:54:00:12:34:56, link up
INFO  entropy: 64 bytes from virtio-rng
INFO  entropy: ChaCha20 CSPRNG seeded
INFO  crypto: ecc=nistz256-armv8 x25519=armv8 (P-256 and X25519 field arithmetic)
INFO  storage: data disk formatted (was blank) (8173 MiB, ...)   (first boot of the installed disk)
INFO  db: restored 0 retained message(s), 0 persistent session(s) with 0 queued message(s), ...
INFO  mqtt: TLS 1.3 listener on port 8883 (mutual TLS, identity = certificate Cn, 0 revoked serial(s), 1 operational and 0 bootstrap CA file(s))
URMQTT READY
INFO  net: dhcp lease 10.0.2.15/24 router 10.0.2.2 dns [10.0.2.3]
```

- `config: fingerprint` must be the one the page or `pack` showed.
- `crypto:` names the implementations chosen for this CPU (x86_64 under TCG: `aes-gcm=aesni ...`,
  `ecc=nistz256-adx x25519=adx`); the known-answer tests must pass, or the boot stops.
- `entropy:` names where the random generator's seed came from. Without virtio-rng and without `RNDR`/`RDRAND`
  you see a `WARN entropy: no hardware source ... CPU jitter fallback ...` line instead (section 6 of
  [KNOWN-ISSUES.md](KNOWN-ISSUES.md)).
- `net:` shows the link, then the DHCP lease (or `net: static address ...`). `URMQTT READY` is printed when the
  listener is up, which can be before the lease arrives.

## 4. Or boot it on a KVM VPS (20 minutes)

What was done on a netcup "VPS 500 ARM G12.5" (aarch64 KVM, UEFI, virtio-net and virtio-blk, 64 GiB disk), recorded
in [PROGRESS.md](PROGRESS.md) ("netcup ARM64 VPS"). One server, one run of each step.

1. **Snapshot the VPS first** if anything on its disk matters: the installer erases the disk. (On netcup an online
   snapshot is not possible with UEFI; it was taken offline.)
2. **Upload the ISO** with the provider's custom-ISO feature, attach it as the virtual CD and power-cycle the VPS.
   (The recorded run did upload, attach and power cycles through netcup's REST API.)
3. **The boot menu** appears on the provider's VNC or web console, drawn by the firmware. Let it boot **live** first
   (the default after 10 seconds, with `storage.mode = "auto"`) and do step 5 from your laptop against the VPS
   address: that proves the network settings, the firewall and the certificates before anything is written.
4. **Install.** Power-cycle, choose **Install urMQTT on this machine's disk**, watch the 30-second countdown (power
   the VPS off to cancel). The recorded run took about 40 seconds and powered the machine off.
5. **Detach the ISO** and boot from the disk. The recorded run reached a TLS 1.3 handshake from the Internet about
   35 seconds after power-on; a retained message survived a hard power cycle.

**"Display output is not active".** On netcup's ARM VPS the only display is a virtio-gpu. The firmware draws the
boot menu through it, then resets it when the kernel starts, and the console shows "Display output is not active"
from then on: urMQTT is running, you just cannot see it. With `console.virtio_gpu = "on"` in the configuration
(builder: **Console display**; needs a v0.4.0 or newer template) the kernel drives the device itself and the screen
shows its output: on netcup this was seen with `"on"` (ADR-256). `"auto"` chooses the device in the same situation
(no usable boot framebuffer, or one in RAM); that was tested under QEMU, not on netcup. Without it, the views of a running broker are the network: `$SYS/console/out`
(step 5) and, for the Diagnostic entry, the boot word `diag-serve` (docs/DEPLOY.md, "Live mode").

**On x86_64 VPSes** (the Contabo run of PERFORMANCE.md section 3) the console shows the log from the first line.
[DEPLOY.md](DEPLOY.md) section 5b lists what the console should show, and section 4 the virtual hardware an image
needs (virtio-net, one virtio-blk or virtio-scsi disk, UEFI or BIOS).

Allow **TCP 8883 inbound** in the provider's firewall. Nothing else is needed (UDP out only if you configured syslog,
statsd or SNTP).

## 5. The first connection (5 minutes)

Under QEMU the host is `localhost` (the server certificate names it); on a VPS use its address. In one terminal, the
`backend` service identity watches every device's topics:

```bash
D=deploy/dev
mosquitto_sub -h localhost -p 8883 --cafile $D/ca.pem \
  --cert $D/services/backend.pem --key $D/services/backend.key -i backend -v -t 'devices/#'
```

In another, a device publishes; the first terminal prints `devices/device-001/telemetry/temp 21.5`:

```bash
D=deploy/dev
mosquitto_pub -h localhost -p 8883 --cafile $D/ca.pem \
  --cert $D/devices/device-001.pem --key $D/devices/device-001.key -i device-001 -q 1 \
  -t devices/device-001/telemetry/temp -m 21.5
```

The client id (`-i`) must equal the identity in the certificate. A device may publish under `devices/<its id>/#`
and subscribe to `devices/<its id>/cmd/#`; README "Usage examples" has more (retained messages, a Last Will,
persistent sessions, the rejections).

**The operator view.** The `operator` identity reads the `$SYS` topics, which nothing else can:

```bash
D=deploy/dev
mosquitto_sub -h localhost -p 8883 --cafile $D/ca.pem \
  --cert $D/services/operator.pem --key $D/services/operator.key -i operator -v -t '$SYS/broker/#'
mosquitto_sub -h localhost -p 8883 --cafile $D/ca.pem \
  --cert $D/services/operator.pem --key $D/services/operator.key -i operator -t '$SYS/console/out'
```

The first prints the statistics (`$SYS/broker/version`, `uptime`, `clients/connected`, `handshakes/...`), retained
and refreshed every 10 seconds. The second is the kernel log over MQTT, starting with its last 64 lines: on a VPS
with a dark console, this is how you read the boot log. The console's commands (`status`, `help`, `log level`,
`reboot`) and the full list of topics are in [OPERATE.md](OPERATE.md). One session per identity: a second
connection as `operator` takes the first one over.

If you installed to a disk: publish with `-r` (retained), restart the VM, and subscribe again; the boot log says
`db: restored 1 retained message(s) ...` and the message is delivered.

## 6. When it does not work

The five most likely causes, with the line the boot log or the client prints. The table "Messages for what is
missing" in [DEPLOY.md](DEPLOY.md) section 5b has more (an old CPU, a legacy-only virtio device, a NIC without a
driver, no entropy source).

**1. No data partition.**

```text
ERROR fatal: storage: no data partition: booted from read-only media (CD/ISO): write the image to the machine's disk (docs/DEPLOY.md); refusing to serve
ERROR fatal: storage: no data partition: the boot disk is not among the disks this kernel drives; refusing to serve
ERROR fatal: live mode (RAM, ephemeral) was requested by the boot menu, but this image's storage.mode is "disk": rebuild with storage.mode = "auto" or "ram" in deploy/<env>/config.toml, or choose the Install entry
```

The first: there is no disk to keep the data on; use the live entry or install. The second: the disk is one this
kernel has no driver for (an NVMe or other non-virtio disk: [EDITIONS.md](EDITIONS.md)); give the VM a virtio-blk
or virtio-scsi disk. The third: the image forbids the live entry; set `storage.mode = "auto"` or install.

**2. Refusing to serve without certificates.**

```text
WARN  config: the configuration slot is empty (all defaults): no certificates, the broker will not serve
ERROR fatal: refusing to serve: no server certificate and key (tls.cert, tls.key). This image carries the empty (default) configuration; create one with `urmqtt-config pack` (or the builder page) and put it in the image's configuration slot, see docs/DEPLOY.md
```

You booted the template itself, or an image built without the server certificate, its key or a CA. Build the image
again with them (step 2). The installer and the Diagnostic entry work without a configuration; serving does not.

**3. No DHCP lease.** There is no `net: dhcp lease ...` line, and nothing answers. Many VPS providers run no DHCP for
a custom ISO: use `network.mode = "static"` with the values from the provider's panel, or `"auto"`, which waits
`network.dhcp_timeout_s` (15 s) and then says `WARN  net: no dhcp lease in time, falling back to the static settings`.
A NIC that sees no traffic at all shows `WARN  net: no ARP reply within 500 ms (RX path not confirmed)`. Check that
the VM's NIC is virtio-net: otherwise `net: network controller <vendor>:<device> (...) has no driver; urMQTT needs
virtio-net`.

**4. TLS handshake refused: the wrong CA.** The broker log names which side does not trust the other:

```text
WARN  tls: connection refused: Handshake("invalid peer certificate: UnknownIssuer")
WARN  tls: connection refused: Handshake("received fatal alert: UnknownCA")
```

`UnknownIssuer`: the device's certificate is not signed by a CA in the image (`trust.operational`); the client
says `Error: The connection was lost` (mosquitto 2.1). `UnknownCA`: the client does not trust the server's
certificate, because its `--cafile` is not the CA that signed `server.pem`; mosquitto 2.1 says
`Error: Protocol error`. Also common: a client id that is not the certificate's identity
(`Connection Refused: identifier rejected`), and, on a VPS, a server certificate that does not name the address
you connect to (step 1).

**5. A firewall.** The client waits, or fails to connect, and the broker log shows no new handshake (the
`handshakes: core N: ... started` counters every few seconds stay where they were). Allow TCP 8883 inbound at the
provider; under QEMU check the port forward (`--fwd`) and that no other program holds the port on your laptop.

## 7. Where to report

- **A vulnerability:** privately, never as a public issue: [SECURITY.md](../SECURITY.md).
- **A bug, or a boot that fails:** a GitHub issue with the "Bug report" or "Boot failure" form. They ask for the
  release, the platform, how you booted, the serial log (or a photo of the console), `urmqtt-config show` of the
  image (it prints no key) and the hypervisor's device list. Never attach your ISO or a private key.
- **A question:** the "Question" form.
- First check [KNOWN-ISSUES.md](KNOWN-ISSUES.md): the limit you hit may be listed there, with its workaround.

## Tested

Run for this guide on 2026-11-06, on a MacBook (Apple M4 Pro, macOS 26), QEMU 11.1.2, mosquitto 2.1.2, OpenSSL
3.6.3, with the published v0.4.1 template (its `SHA256SUMS` minisign-verified against the former test key, then the release key of v0.4.1, and the
template's SHA-256 checked) configured by `urmqtt-config pack` from this repository:

- `make certs`; the VPS server certificate of step 1 (`openssl verify` OK; packed and booted with
  `console.virtio_gpu = "auto"` under QEMU with `--gpu virtio`, which moved the log to the virtio-gpu); the
  configuration of step 2 packed, `show` and `verify` clean.
- aarch64 under **HVF**: the live entry, the publish/subscribe round trip, `$SYS/broker/#` and `$SYS/console/out`;
  the install entry chosen with Down and Enter on the serial port, the installed disk booted, a retained message
  read back after `kill -9` of QEMU and a new boot.
- x86_64 under **TCG** (q35, OVMF): the live entry and the round trip; the install entry, the installed disk, a
  retained message read back after a restart.
- The failure lines of section 6, causes 2, 3 (no network: `--dgram` to nothing) and 4: from these boots. The lines
  of cause 1 are quoted from the kernel source, not from a run.

Not run for this guide: the builder page itself (its output is the same as `pack`'s, a test in `make check`), the
`curl` downloads (the files were already on the machine), the Debian/Ubuntu commands, KVM on Linux, and any VPS. The
VPS steps are those of the netcup run recorded in PROGRESS.md.
