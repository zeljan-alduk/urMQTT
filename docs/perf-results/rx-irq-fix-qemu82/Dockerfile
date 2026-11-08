FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-system-arm qemu-efi-aarch64 xorriso mtools python3 mosquitto-clients procps iproute2 socat bc >/dev/null && rm -rf /var/lib/apt/lists/*
