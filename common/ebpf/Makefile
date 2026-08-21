BPF_CLANG ?= $(if $(strip $(ANDROID_NDK_HOME)),$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang,clang)
BPF_SYSTEM_INCLUDE ?= /usr/include
BPF_HOST_CC ?= cc
BPF_MULTIARCH ?= $(shell $(BPF_HOST_CC) -print-multiarch 2>/dev/null)
BPF_MULTIARCH_INCLUDE ?= $(BPF_SYSTEM_INCLUDE)/$(BPF_MULTIARCH)
BPF_CFLAGS ?= -target bpfel -mcpu=v1 -O2 -g -ffreestanding
BPF_READELF ?= readelf
BPF_INCLUDE_FLAGS := -Inative -I$(BPF_SYSTEM_INCLUDE)
ifneq (,$(wildcard $(BPF_MULTIARCH_INCLUDE)))
BPF_INCLUDE_FLAGS += -I$(BPF_MULTIARCH_INCLUDE)
endif

# Luan fuller eBPF stack (shared_network + splice + v3). Upstream cgroup not mixed.
SOURCES := native/shared_network.bpf.c native/shared_network_v2.bpf.c native/splice.bpf.c v3/kern/tc.bpf.c
OBJECTS := $(SOURCES:.c=.o)
V2_PROVENANCE_INPUTS := Makefile native/shared_network_v2.bpf.c native/shared_network.h \
	native/dataplane_v2.h native/dataplane_v2_parser.h native/btf_map.h
V2_SOURCE_HASH := $(shell cat $(V2_PROVENANCE_INPUTS) | sha256sum | cut -d' ' -f1)
V3_PROVENANCE_INPUTS := Makefile v3/kern/tc.bpf.c v3/kern/abi.h v3/kern/parser.h v3/kern/policy_maps.h native/btf_map.h
V3_SOURCE_HASH := $(shell cat $(V3_PROVENANCE_INPUTS) | sha256sum | cut -d' ' -f1)
BPF_INCLUDE_FLAGS += -Iv3/kern

.PHONY: generate check check-v2-source clean

generate:
	@set -eu; \
	for src in $(SOURCES); do \
		obj="$${src%.c}.o"; \
		temporary="$$(mktemp "$${obj}.XXXXXX")"; \
		trap 'rm -f "$$temporary"' EXIT; \
		extra_flags=""; \
		if [ "$$src" = native/shared_network_v2.bpf.c ]; then \
			extra_flags='-DSB_SOURCE_HASH="$(V2_SOURCE_HASH)"'; \
		fi; \
		if [ "$$src" = v3/kern/tc.bpf.c ]; then \
			extra_flags='-DSB_V3_SOURCE_HASH="$(V3_SOURCE_HASH)"'; \
		fi; \
		$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) $$extra_flags -c "$$src" -o "$$temporary"; \
		mv "$$temporary" "$$obj"; \
		trap - EXIT; \
	done

check:
	@set -eu; \
	for src in $(SOURCES); do \
		obj="$${src%.c}.o"; \
		if [ ! -f "$$obj" ]; then echo "$$obj missing" >&2; exit 1; fi; \
		temporary="$$(mktemp "$${obj}.XXXXXX")"; \
		trap 'rm -f "$$temporary"' EXIT; \
		extra_flags=""; \
		if [ "$$src" = native/shared_network_v2.bpf.c ]; then \
			extra_flags='-DSB_SOURCE_HASH="$(V2_SOURCE_HASH)"'; \
		fi; \
		if [ "$$src" = v3/kern/tc.bpf.c ]; then \
			extra_flags='-DSB_V3_SOURCE_HASH="$(V3_SOURCE_HASH)"'; \
		fi; \
		$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) $$extra_flags -c "$$src" -o "$$temporary"; \
		if ! cmp -s "$$obj" "$$temporary"; then echo "$$obj stale" >&2; exit 1; fi; \
		rm -f "$$temporary"; \
		trap - EXIT; \
	done

check-v2-source:
	@set -eu; \
	actual="$$($(BPF_READELF) -p .sb.source native/shared_network_v2.bpf.o 2>/dev/null \
		| sed -n 's/.*\]  \([0-9a-f]\{64\}\).*/\1/p')"; \
	if [ "$$actual" != "$(V2_SOURCE_HASH)" ]; then \
		echo "native/shared_network_v2.bpf.o source provenance stale" >&2; \
		echo "embedded=$$actual expected=$(V2_SOURCE_HASH)" >&2; \
		exit 1; \
	fi

clean:
	rm -f $(OBJECTS)
