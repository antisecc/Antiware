# AntiRansom Makefile

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -D_GNU_SOURCE
LDFLAGS = -lpthread -lrt

# Build type (debug or release)
BUILD_TYPE ?= debug

ifeq ($(BUILD_TYPE), debug)
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# Directories
SRC_DIR = .
INCLUDE_DIR = ./include
COMMON_DIR = ./common
LINUX_DIR = ./linux
WINDOWS_DIR = ./windows  # For future use
BUILD_DIR = ./build
BIN_DIR = ./bin

# Output binary
LINUX_TARGET = $(BIN_DIR)/antiransom-linux
WINDOWS_TARGET = $(BIN_DIR)/antiransom-win.exe  # For future use

# Linux source files
LINUX_SOURCES = \
    $(LINUX_DIR)/main.c \
    $(LINUX_DIR)/detection.c \
    $(LINUX_DIR)/syscall_monitor.c \
    $(LINUX_DIR)/memory_monitor.c \
    $(LINUX_DIR)/process_monitor.c \
    $(LINUX_DIR)/user_filter.c

# Common source files
COMMON_SOURCES = \
    $(COMMON_DIR)/logger.c \
    $(COMMON_DIR)/config.c \
    $(COMMON_DIR)/scoring.c

# Windows source files (for future use)
WINDOWS_SOURCES = \
    $(WINDOWS_DIR)/main.c \
    $(WINDOWS_DIR)/detection.c \
    $(WINDOWS_DIR)/api_monitor.c \
    $(WINDOWS_DIR)/memory_monitor.c \
    $(WINDOWS_DIR)/process_monitor.c \
    $(WINDOWS_DIR)/user_filter.c

# All Linux objects
LINUX_OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(LINUX_SOURCES) $(COMMON_SOURCES))

# All Windows objects (for future use)
WINDOWS_OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(WINDOWS_SOURCES) $(COMMON_SOURCES))

# Default target
all: linux

# Linux target
linux: dirs $(LINUX_TARGET)

# Windows target (commented out for now)
# windows: dirs $(WINDOWS_TARGET)

# Create necessary directories
dirs:
    @mkdir -p $(BUILD_DIR)/$(LINUX_DIR)
    @mkdir -p $(BUILD_DIR)/$(COMMON_DIR)
    @mkdir -p $(BIN_DIR)
    # @mkdir -p $(BUILD_DIR)/$(WINDOWS_DIR)

# Linux build
$(LINUX_TARGET): $(LINUX_OBJECTS)
    $(CC) -o $@ $^ $(LDFLAGS)

# Windows build (commented out for now)
# $(WINDOWS_TARGET): $(WINDOWS_OBJECTS)
# 	$(CC) -o $@ $^ $(WINDOWS_LDFLAGS)

# Generic rule for object files
$(BUILD_DIR)/%.o: %.c
    @mkdir -p $(dir $@)
    $(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Install the Linux binary
install: linux
    @mkdir -p /usr/local/bin
    cp $(LINUX_TARGET) /usr/local/bin/antiransom
    @echo "Installed to /usr/local/bin/antiransom"

# Clean build artifacts
clean:
    rm -rf $(BUILD_DIR) $(BIN_DIR)

# Show available targets
help:
    @echo "Available targets:"
    @echo "  all (default) - Build Linux version"
    @echo "  linux         - Build Linux version"
    @echo "  install       - Install Linux binary to /usr/local/bin"
    @echo "  clean         - Remove build artifacts"
    @echo "  help          - Show this help message"
    @echo ""
    @echo "Options:"
    @echo "  BUILD_TYPE=debug|release (default: debug)"

.PHONY: all linux windows dirs install clean help