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

# Allow overriding platform for cross-compilation
PLATFORM ?= linux

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
    LDFLAGS += $(PLATFORM_LDFLAGS)
else ifeq ($(PLATFORM),windows)
    PLATFORM_SOURCES = $(WINDOWS_SOURCES)
    LDFLAGS += $(PLATFORM_LDFLAGS)
else ifeq ($(PLATFORM),macos)
    $(error macOS platform not supported yet)
else
    # Default to Linux if we can't detect platform
    PLATFORM_SOURCES = $(LINUX_SOURCES)
    LDFLAGS += -lpthread -lrt
endif

# All objects
COMMON_OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(COMMON_SOURCES))
PLATFORM_OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(PLATFORM_SOURCES))
ALL_OBJECTS = $(COMMON_OBJECTS) $(PLATFORM_OBJECTS)

# All source files
ALL_SOURCES = $(COMMON_SOURCES) $(LINUX_SOURCES) $(WINDOWS_SOURCES)

# Header files - used for dependency tracking
HEADERS = $(wildcard $(INCLUDE_DIR)/*.h) $(wildcard $(COMMON_DIR)/*.h)

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
    $(CC) -o $@ $(ALL_OBJECTS) $(LDFLAGS) -lm

# Generic rule for object files
$(BUILD_DIR)/%.o: %.c $(HEADERS)
    @mkdir -p $(dir $@)
    $(CC) $(CFLAGS) $(PLATFORM_CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Generate dependencies
DEPFILES = $(ALL_OBJECTS:.o=.d)
-include $(DEPFILES)

# Rule to generate dependency files
$(BUILD_DIR)/%.d: %.c
    @mkdir -p $(dir $@)
    @$(CC) $(CFLAGS) $(PLATFORM_CFLAGS) -I$(INCLUDE_DIR) -MM -MT '$(BUILD_DIR)/$*.o' $< > $@

# Platform-specific targets
linux:
    $(MAKE) PLATFORM=linux

windows:
    $(MAKE) PLATFORM=windows

# Code analysis using cppcheck
analyze:
    cppcheck --enable=all --std=c11 --inconclusive --check-config \
        --suppress=missingIncludeSystem \
        -I$(INCLUDE_DIR) $(ALL_SOURCES)

# Install the binary (Linux only)
install: $(TARGET)
    @if [ "$(PLATFORM)" = "linux" ]; then \
        mkdir -p /usr/local/bin; \
        cp $(TARGET) /usr/local/bin/antiransom; \
        echo "Installed to /usr/local/bin/antiransom"; \
    else \
        echo "Install only supported on Linux"; \
    fi

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
    @echo "  analyze   - Run static code analysis (requires cppcheck)"
    @echo "  install   - Install binary to /usr/local/bin (Linux only)"
    @echo "  clean     - Remove build artifacts"
    @echo "  help      - Show this help message"
    @echo ""
    @echo "Options:"
    @echo "  BUILD_TYPE=debug|release (default: debug)"

.PHONY: all linux windows dirs install clean help analyze