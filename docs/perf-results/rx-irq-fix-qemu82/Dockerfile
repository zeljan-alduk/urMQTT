FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-system-arm qemu-efi-aarch64 xorriso mtools python3 mosquitto-clients procps iproute2 socat bc >/dev/null && rm -rf /var/lib/apt/lists/*
