# The multiqueue rig (NEXT-6, ADR-314): QEMU for both architectures on Linux,
# where a multi-queue tap exists. Built on the image of the rx-irq repro
# (../rx-irq-fix-qemu82/Dockerfile: Ubuntu 24.04 pinned by digest, QEMU 8.2.2
# for aarch64, the UEFI firmware, mosquitto clients), plus QEMU for x86_64,
# OVMF and SeaBIOS from the same release.
FROM now13b-c-qemu82
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-system-x86 ovmf python3-paho-mqtt >/dev/null && rm -rf /var/lib/apt/lists/*
