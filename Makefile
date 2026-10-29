# urMQTT build entry point. Run `make help` for the target list.
#
# Targets that belong to a later milestone exit non-zero with a clear message
# instead of pretending to work (PROMPT.md §0.5).

SHELL       := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

ENV       ?= dev
N         ?= 8
T         ?= config_parse
FUZZ_TIME ?= 600
DATA_SIZE ?= 1G

TARGET      := aarch64-unknown-none
CARGO       := cargo
CARGO_FLAGS := --locked
# core/alloc rebuilt with the kernel's branch protection (ADR-002).
KERNEL_FLAGS := -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
BUILD_DIR   := build
KERNEL_ELF  := target/$(TARGET)/release/urmqtt
ISO         := $(BUILD_DIR)/urmqtt-$(ENV)-$(VERSION).iso
DISK_IMG    := $(BUILD_DIR)/disk-$(ENV).img

# Reproducible images (M17): paths of the toolchain, the crate cache and the
# checkout are remapped, so neither the home directory nor the checkout
# location ends up in the kernel. Cargo merges this with the rustflags of
# .cargo/config.toml (branch protection).
SYSROOT     := $(shell rustc --print sysroot 2>/dev/null)
CARGO_DIR   := $(or $(CARGO_HOME),$(HOME)/.cargo)
export CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUSTFLAGS := \
	--remap-path-prefix=$(SYSROOT)=/rustc --remap-path-prefix=$(CARGO_DIR)=/cargo \
	--remap-path-prefix=$(CURDIR)=/urmqtt
# Dev images carry the in-guest benchmark and its TLS client; others do not.
KERNEL_FEATURES := $(if $(filter dev,$(ENV)),--features selftest)
export URMQTT_ENV := $(ENV)
export URMQTT_VERSION := $(VERSION)
# The commit time: reproducible (M17) and the kernel's lower bound for the
# wall clock (H7). The ISO tools use the same value.
export SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
ACCEL ?=
QEMU_ARGS ?=

define not_yet
	@echo "make $@: not implemented yet — arrives in $(1) (see docs/PROGRESS.md)" >&2
	@exit 1
endef

.PHONY: help
help: ## Show this help
	@awk 'BEGIN{FS=":.*## "; printf "urMQTT %s — make <target> [ENV=dev|prod] [N=8] [T=fuzz-target]\n\n", "$(VERSION)"} \
	  /^[a-zA-Z_-]+:.*## /{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: certs
certs: ## Generate development certificates into deploy/dev/ (idempotent)
	@scripts/gen-dev-certs.sh

.PHONY: build
build: $(if $(filter dev,$(ENV)),certs) ## Build the kernel ELF (release, LTO, panic=abort)
	$(CARGO) build $(CARGO_FLAGS) $(KERNEL_FLAGS) $(KERNEL_FEATURES) --release -p urmqtt-kernel --target $(TARGET)
	@printf 'kernel: %s (%s bytes)\n' "$(KERNEL_ELF)" "$$(wc -c < $(KERNEL_ELF) | tr -d ' ')"

.PHONY: iso
iso: build ## Build the bootable UEFI ISO for deploy/<ENV>/
	scripts/mkiso.sh --kernel $(KERNEL_ELF) --out $(ISO)
	@ln -sf $(notdir $(ISO)) $(BUILD_DIR)/urmqtt-$(ENV).iso

.PHONY: run
run: disk ## Boot the dev disk in QEMU (HVF on macOS), 4 vCPU, 512 MB, serial on stdio
	scripts/run-qemu.sh --disk $(DISK_IMG) $(if $(ACCEL),--accel $(ACCEL)) -- $(QEMU_ARGS)

.PHONY: run-tcg
run-tcg: disk ## Same as run, with TCG instead of HVF
	scripts/run-qemu.sh --disk $(DISK_IMG) --accel tcg -- $(QEMU_ARGS)

.PHONY: run-smp
run-smp: disk ## Boot with N vCPUs (make run-smp N=8)
	scripts/run-qemu.sh --disk $(DISK_IMG) --smp $(N) $(if $(ACCEL),--accel $(ACCEL)) -- $(QEMU_ARGS)

.PHONY: debug
debug: disk ## Boot QEMU halted with a gdb stub (-s -S)
	scripts/run-qemu.sh --disk $(DISK_IMG) --gdb $(if $(ACCEL),--accel $(ACCEL)) -- $(QEMU_ARGS)

.PHONY: disk
disk: raw ## The VM's only disk (single-disk model, S1): created from the raw image, or its ESP updated in place (data kept)
	@if [[ -e $(DISK_IMG) ]]; then \
	 scripts/mkiso.sh --kernel $(KERNEL_ELF) --out $(BUILD_DIR)/.disk-tmp.iso --esp-out $(BUILD_DIR)/.disk-esp.img >/dev/null && \
	 dd if=$(BUILD_DIR)/.disk-esp.img of=$(DISK_IMG) bs=1048576 seek=1 conv=notrunc status=none && \
	 rm -f $(BUILD_DIR)/.disk-tmp.iso $(BUILD_DIR)/.disk-esp.img && \
	 echo "$(DISK_IMG): kernel updated, data partition kept"; \
	 else cp $(RAW) $(DISK_IMG) && truncate -s $(DATA_SIZE) $(DISK_IMG) && \
	 echo "created $(DATA_SIZE) $(DISK_IMG) (the first boot creates the data partition)"; fi

.PHONY: fmt
fmt: ## Format all Rust code
	$(CARGO) fmt --all
	cd fuzz && $(CARGO) fmt

.PHONY: check
check: certs ## fmt --check, typos, clippy -D warnings (host + bare metal), host tests
	$(CARGO) fmt --all --check
	@if command -v typos >/dev/null; then typos; else echo "check: typos not installed, skipped (CI runs it)"; fi
	cd fuzz && $(CARGO) fmt --check
	scripts/check-arch-leaks.sh
	$(CARGO) clippy $(CARGO_FLAGS) --workspace --all-targets -- -D warnings
	$(CARGO) clippy $(CARGO_FLAGS) $(KERNEL_FLAGS) -p urmqtt-kernel --target $(TARGET) -- -D warnings
	$(CARGO) clippy $(CARGO_FLAGS) $(KERNEL_FLAGS) --features selftest -p urmqtt-kernel --target $(TARGET) -- -D warnings
	$(CARGO) test $(CARGO_FLAGS) --workspace

.PHONY: fuzz
fuzz: ## Run fuzz target T for FUZZ_TIME seconds (default 600)
	@command -v cargo-fuzz >/dev/null || { echo "install cargo-fuzz: cargo install cargo-fuzz --locked" >&2; exit 1; }
	@mkdir -p fuzz/corpus/$(T)
	$(CARGO) fuzz run $(T) fuzz/corpus/$(T) $(wildcard fuzz/seeds/$(T)) -- -max_total_time=$(FUZZ_TIME)

.PHONY: smoke
smoke: ## Boot headless (HVF+TCG on macOS, TCG elsewhere) and check the serial log
	@$(MAKE) --no-print-directory build ENV=dev
	scripts/smoke.sh $(if $(ACCELS),--accels "$(ACCELS)")

.PHONY: loadtest
loadtest: certs ## Host-side load generator, e.g. ARGS="handshake --port 18883 --threads 32 --duration 10"
	$(CARGO) run $(CARGO_FLAGS) --release -p urmqtt-loadgen -- $(ARGS)

.PHONY: bench
bench: build certs ## Multicore benchmarks (in-guest dp-bench + network handshakes), table to stdout
	scripts/bench.sh

RAW := $(BUILD_DIR)/urmqtt-$(ENV)-$(VERSION).img

.PHONY: raw
raw: build ## Build a raw GPT disk image (EFI system partition) for KVM/Proxmox/cloud disks
	@mkdir -p $(BUILD_DIR)
	scripts/mkiso.sh --kernel $(KERNEL_ELF) --out $(BUILD_DIR)/.raw-tmp.iso --esp-out $(BUILD_DIR)/.esp.img >/dev/null
	scripts/mkraw.py $(BUILD_DIR)/.esp.img $(RAW)
	@rm -f $(BUILD_DIR)/.raw-tmp.iso $(BUILD_DIR)/.esp.img

.PHONY: dist
dist: iso raw ## Release artifacts (ELF, ISO, raw image) and SHA256SUMS in build/dist/
	@rm -rf $(BUILD_DIR)/dist && mkdir -p $(BUILD_DIR)/dist
	cp $(KERNEL_ELF) $(BUILD_DIR)/dist/urmqtt-$(ENV)-$(VERSION).elf
	cp $(ISO) $(RAW) $(BUILD_DIR)/dist/
	cd $(BUILD_DIR)/dist && shasum -a 256 * > SHA256SUMS && cat SHA256SUMS

.PHONY: sign
sign: ## Sign build/dist/SHA256SUMS with minisign (MINISIGN_KEY=path to the secret key)
	@test -s $(BUILD_DIR)/dist/SHA256SUMS || { echo "make sign: run make dist first" >&2; exit 1; }
	@command -v minisign >/dev/null || { echo "make sign: install minisign" >&2; exit 1; }
	minisign -S -s "$(or $(MINISIGN_KEY),$(HOME)/.minisign/minisign.key)" -m $(BUILD_DIR)/dist/SHA256SUMS \
		-t "urMQTT $$(cd $(BUILD_DIR)/dist && ls *.elf | sed 's/^urmqtt-//; s/\.elf$$//') $$(git rev-parse HEAD)"
	@echo "verify: minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS"

.PHONY: repro
repro: ## Build HEAD twice in separate worktrees and compare ELF and ISO (ENV=prod by default)
	scripts/repro.sh $(if $(filter command line,$(origin ENV)),$(ENV),prod)

.PHONY: audit
audit: ## Regenerate the TCB and unsafe inventory (docs/audit/, referenced by docs/AUDIT.md)
	scripts/audit-inventory.py

.PHONY: clean
clean: ## Remove build outputs (keeps certificates and data.img)
	$(CARGO) clean
	rm -rf $(BUILD_DIR)/dist $(BUILD_DIR)/smoke $(BUILD_DIR)/*.iso fuzz/target
