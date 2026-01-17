# Makefile for liburing BPF filter tests
# 
# This Makefile compiles BPF programs in test/bpf_filters/ to bytecode
# and integrates with the existing liburing test infrastructure

# Compiler settings
CLANG ?= clang
LLC ?= llc
STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
BPF_FILTER_DIR := .
BPF_OBJ_DIR := $(BPF_FILTER_DIR)

# BPF source files
BPF_SOURCES := $(wildcard $(BPF_FILTER_DIR)/*.bpf.c)
BPF_OBJECTS := $(patsubst $(BPF_FILTER_DIR)/%.bpf.c,$(BPF_OBJ_DIR)/%.bpf.o,$(BPF_SOURCES))

# BPF compilation flags
BPF_CFLAGS := -O2 -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -Wall -Werror
BPF_CFLAGS += -I$(BPF_FILTER_DIR)
BPF_CFLAGS += -I/usr/include
BPF_CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu

# Targets
.PHONY: all bpf_filters bpf_clean help

# Default target includes BPF filters
all: bpf_filters

# Compile individual BPF programs
$(BPF_OBJ_DIR)/%.bpf.o: $(BPF_FILTER_DIR)/%.bpf.c | $(BPF_OBJ_DIR)
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@$(STRIP) $@

# Build all BPF filters
bpf_filters: $(BPF_OBJECTS)

# Clean BPF objects
bpf_clean:
	@rm -rf $(BPF_OBJECTS)

clean: bpf_clean

# Dependency tracking for BPF files
-include $(BPF_OBJ_DIR)/.*.d

# Generate dependencies
$(BPF_OBJ_DIR)/%.bpf.o: $(BPF_FILTER_DIR)/%.bpf.c | $(BPF_OBJ_DIR)
	@$(CLANG) $(BPF_CFLAGS) -MD -MF $(BPF_OBJ_DIR)/.$*.d -c $< -o $@
	@$(STRIP) -g $@
