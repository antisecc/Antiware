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

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    PLATFORM = linux
    PLATFORM_CFLAGS = 
    PLATFORM_LDFLAGS = -lpthread -lrt
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM = macos
    PLATFORM_CFLAGS = 
    PLATFORM_LDFLAGS = 
endif
ifneq (,$(findstring MINGW,$(UNAME_S)))
    PLATFORM = windows
    PLATFORM_CFLAGS = -D_WIN32_WINNT=0x0600
    PLATFORM_LDFLAGS = -lpsapi -lws2_32
endif

# Directories
SRC_DIR = .
INCLUDE_DIR = ./include
COMMON_DIR = ./common
LINUX_DIR = ./linux
WINDOWS_DIR = ./windows
BUILD_DIR = ./build
BIN_DIR = ./bin

# Output binary
TARGET = $(BIN_DIR)/antiransom
ifeq ($(PLATFORM),windows)
    TARGET = $(BIN_DIR)/antiransom.exe
endif

# Common source files
COMMON_SOURCES = \
    $(SRC_DIR)/main.c \
    $(COMMON_DIR)/logger.c \
    $(COMMON_DIR)/config.c \
    $(COMMON_DIR)/scoring.c

# Platform-specific source files
LINUX_SOURCES = \
    $(LINUX_DIR)/main.c \
    $(LINUX_DIR)/detection.c \
    $(LINUX_DIR)/syscall_monitor.c \
    $(LINUX_DIR)/memory_monitor.c \
    $(LINUX_DIR)/process_monitor.c \
    $(LINUX_DIR)/user_filter.c

WINDOWS_SOURCES = \
    $(WINDOWS_DIR)/main.c \
    $(WINDOWS_DIR)/detection.c \
    $(WINDOWS_DIR)/api_monitor.c \
    $(WINDOWS_DIR)/memory_monitor.c \
    $(WINDOWS_DIR)/process_monitor.c \
    $(WINDOWS_DIR)/user_filter.c

# Select sources based on platform
ifeq ($(PLATFORM),linux)
    PLATFORM_SOURCES = $(LINUX_SOURCES)
else ifeq ($(PLATFORM),windows)
    PLATFORM_SOURCES = $(WINDOWS_SOURCES)
else
    # Default to Linux if we can't detect platform
    PLATFORM_SOURCES = $(LINUX_SOURCES)
endif

# All objects
COMMON_OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(COMMON_SOURCES))
PLATFORM_OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(PLATFORM_SOURCES))
ALL_OBJECTS = $(COMMON_OBJECTS) $(PLATFORM_OBJECTS)

# Default target
all: dirs $(TARGET)

# Create necessary directories
dirs:
    @mkdir -p $(BUILD_DIR)/$(COMMON_DIR)
    @mkdir -p $(BUILD_DIR)/$(LINUX_DIR)
    @mkdir -p $(BUILD_DIR)/$(WINDOWS_DIR)
    @mkdir -p $(BIN_DIR)

# Build the target
$(TARGET): $(ALL_OBJECTS)
    $(CC) -o $@ $^ $(LDFLAGS) $(PLATFORM_LDFLAGS)

# Generic rule for object files
$(BUILD_DIR)/%.o: %.c
    @mkdir -p $(dir $@)
    $(CC) $(CFLAGS) $(PLATFORM_CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Platform-specific targets
linux:
    $(MAKE) PLATFORM=linux

windows:
    $(MAKE) PLATFORM=windows

# Install the binary
install: $(TARGET)
    @mkdir -p /usr/local/bin
    cp $(TARGET) /usr/local/bin/antiransom
    @echo "Installed to /usr/local/bin/antiransom"

# Clean build artifacts
clean:
    rm -rf $(BUILD_DIR) $(BIN_DIR)

# Show available targets
help:
    @echo "AntiRansom Makefile"
    @echo ""
    @echo "Available targets:"
    @echo "  all       - Build for detected platform ($(PLATFORM))"
    @echo "  linux     - Build for Linux platform"
    @echo "  windows   - Build for Windows platform"
    @echo "  install   - Install binary to /usr/local/bin (Linux only)"
    @echo "  clean     - Remove build artifacts"
    @echo "  help      - Show this help message"
    @echo ""
    @echo "Options:"
    @echo "  BUILD_TYPE=debug|release (default: debug)"

.PHONY: all linux windows dirs install clean help