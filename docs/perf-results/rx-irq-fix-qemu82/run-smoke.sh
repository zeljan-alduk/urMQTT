#!/usr/bin/env bash
# run-smoke.sh OUTDIR SMOKE_ENV... -- smoke.sh args : the worktree's smoke suite inside the QEMU 8.2.2 container
set -e
mkdir -p /work && rsync -a --exclude target --exclude 'build/rx' --exclude 'build/smoke*' /src/ /work/
mkdir -p /work/target/aarch64-unknown-none/release /work/target/x86_64-urmqtt-none/release
cp /src/target/aarch64-unknown-none/release/urmqtt /work/target/aarch64-unknown-none/release/urmqtt
cp /src/target/x86_64-urmqtt-none/release/urmqtt /work/target/x86_64-urmqtt-none/release/urmqtt 2>/dev/null || true
cd /work && export CARGO_TARGET_DIR=/cache/target CARGO_HOME=/cache/cargo-home
mkdir -p /cache/cargo-home && cp -rn /root/.cargo/. /cache/cargo-home/ 2>/dev/null || true
cargo build --release -q -p urmqtt-attack -p urmqtt-config-tool -p urmqtt-loadgen
cargo build -q -p urmqtt-config-tool && mkdir -p /work/target/debug && cp /cache/target/debug/urmqtt-config /work/target/debug/
mkdir -p /work/target/release && cp /cache/target/release/urmqtt-attack /cache/target/release/urmqtt-config /cache/target/release/urmqtt-loadgen /work/target/release/
export URMQTT_FIRMWARE=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd
"$@"
