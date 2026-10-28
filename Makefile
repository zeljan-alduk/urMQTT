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
DATA_IMG    := $(BUILD_DIR)/data.img

export URMQTT_ENV := $(ENV)
export URMQTT_VERSION := $(VERSION)
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
	$(CARGO) build $(CARGO_FLAGS) $(KERNEL_FLAGS) --release -p urmqtt-kernel --target $(TARGET)
	@printf 'kernel: %s (%s bytes)\n' "$(KERNEL_ELF)" "$$(wc -c < $(KERNEL_ELF) | tr -d ' ')"

.PHONY: iso
iso: build ## Build the bootable UEFI ISO for deploy/<ENV>/
	scripts/mkiso.sh --kernel $(KERNEL_ELF) --out $(ISO)
	@ln -sf $(notdir $(ISO)) $(BUILD_DIR)/urmqtt-$(ENV).iso

.PHONY: run
run: iso data-img ## Boot the ISO in QEMU (HVF on macOS), 4 vCPU, 512 MB, serial on stdio
	scripts/run-qemu.sh --iso $(ISO) --data $(DATA_IMG) $(if $(ACCEL),--accel $(ACCEL)) -- $(QEMU_ARGS)

.PHONY: run-tcg
run-tcg: iso data-img ## Same as run, with TCG instead of HVF
	scripts/run-qemu.sh --iso $(ISO) --data $(DATA_IMG) --accel tcg -- $(QEMU_ARGS)

.PHONY: run-smp
run-smp: iso data-img ## Boot with N vCPUs (make run-smp N=8)
	scripts/run-qemu.sh --iso $(ISO) --data $(DATA_IMG) --smp $(N) $(if $(ACCEL),--accel $(ACCEL)) -- $(QEMU_ARGS)

.PHONY: debug
debug: iso data-img ## Boot QEMU halted with a gdb stub (-s -S)
	scripts/run-qemu.sh --iso $(ISO) --data $(DATA_IMG) --gdb $(if $(ACCEL),--accel $(ACCEL)) -- $(QEMU_ARGS)

.PHONY: data-img
data-img: ## Create a blank sparse data disk image (layout init arrives in M11)
	@mkdir -p $(BUILD_DIR)
	@if [[ -e $(DATA_IMG) ]]; then echo "$(DATA_IMG) exists, leaving it alone"; \
	 else truncate -s $(DATA_SIZE) $(DATA_IMG) && echo "created blank $(DATA_SIZE) $(DATA_IMG)"; fi

.PHONY: fmt
fmt: ## Format all Rust code
	$(CARGO) fmt --all
	cd fuzz && $(CARGO) fmt

.PHONY: check
check: certs ## fmt --check, clippy -D warnings (host + bare metal), host tests
	$(CARGO) fmt --all --check
	cd fuzz && $(CARGO) fmt --check
	$(CARGO) clippy $(CARGO_FLAGS) --workspace --all-targets -- -D warnings
	$(CARGO) clippy $(CARGO_FLAGS) $(KERNEL_FLAGS) -p urmqtt-kernel --target $(TARGET) -- -D warnings
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
loadtest: ## Run the host-side load generator
	$(call not_yet,M10/M13)

.PHONY: dist
dist: iso ## Collect release artifacts and SHA256SUMS into build/dist/
	@rm -rf $(BUILD_DIR)/dist && mkdir -p $(BUILD_DIR)/dist
	cp $(KERNEL_ELF) $(BUILD_DIR)/dist/urmqtt-$(ENV)-$(VERSION).elf
	cp $(ISO) $(BUILD_DIR)/dist/
	cd $(BUILD_DIR)/dist && shasum -a 256 * > SHA256SUMS && cat SHA256SUMS

.PHONY: clean
clean: ## Remove build outputs (keeps certificates and data.img)
	$(CARGO) clean
	rm -rf $(BUILD_DIR)/dist $(BUILD_DIR)/smoke $(BUILD_DIR)/*.iso fuzz/target
