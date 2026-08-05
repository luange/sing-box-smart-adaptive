BPF_CLANG ?= $(if $(strip $(ANDROID_NDK_HOME)),$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang,clang)
BPF_SYSTEM_INCLUDE ?= /usr/include
BPF_HOST_CC ?= cc
BPF_MULTIARCH ?= $(shell $(BPF_HOST_CC) -print-multiarch 2>/dev/null)
BPF_MULTIARCH_INCLUDE ?= $(BPF_SYSTEM_INCLUDE)/$(BPF_MULTIARCH)
BPF_CFLAGS ?= -target bpfel -O2 -g0
BPF_INCLUDE_FLAGS := -Inative -I$(BPF_SYSTEM_INCLUDE)
ifneq (,$(wildcard $(BPF_MULTIARCH_INCLUDE)))
BPF_INCLUDE_FLAGS += -I$(BPF_MULTIARCH_INCLUDE)
endif

# Multi-object list (master framework §5.2). Add new clang BPF sources here.
SOURCES := native/shared_network.bpf.c native/splice.bpf.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: generate check clean

generate:
	@set -eu; \
	for src in $(SOURCES); do \
		obj="$${src%.c}.o"; \
		temporary="$$(mktemp "$${obj}.XXXXXX")"; \
		trap 'rm -f "$$temporary"' EXIT; \
		$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) -c "$$src" -o "$$temporary"; \
		mv "$$temporary" "$$obj"; \
		trap - EXIT; \
	done

check:
	@set -eu; \
	for src in $(SOURCES); do \
		obj="$${src%.c}.o"; \
		if [ ! -f "$$obj" ]; then \
			echo "$$obj missing; run 'make generate' in this directory" >&2; \
			exit 1; \
		fi; \
		temporary="$$(mktemp "$${obj}.XXXXXX")"; \
		trap 'rm -f "$$temporary"' EXIT; \
		$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) -c "$$src" -o "$$temporary"; \
		if ! cmp -s "$$obj" "$$temporary"; then \
			echo "$$obj is stale; run 'make generate' in this directory" >&2; \
			exit 1; \
		fi; \
		rm -f "$$temporary"; \
		trap - EXIT; \
	done

clean:
	rm -f $(OBJECTS)
