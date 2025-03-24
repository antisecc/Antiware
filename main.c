/**
 * AntiRansom - Cross-platform ransomware detection and prevention tool
 * 
 * Main entry point - Detects operating system and delegates to platform-specific implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>  // Add this for getopt_long

#include "include/antiransom.h"
#include "common/logger.h"
#include "common/config.h"

// Version information
#define ANTIRANSOM_VERSION "1.0.0"

// Platform detection macros
#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS 1
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
#elif defined(__APPLE__) && defined(__MACH__)
    #define PLATFORM_MACOS 1
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    #define PLATFORM_BSD 1
#else
    #define PLATFORM_UNKNOWN 1
#endif

// Global configuration structure to pass to platform-specific code
typedef struct {
    int daemon_mode;
    int verbose_mode;
    char config_path[512];
    char watch_directory[512];
} GlobalArgs;

// Forward declarations for platform-specific entry points with updated signatures
#ifdef PLATFORM_LINUX
    extern int linux_main(int argc, char* argv[], const GlobalArgs* global_args);
#endif

#ifdef PLATFORM_WINDOWS
    extern int windows_main(int argc, char* argv[], const GlobalArgs* global_args);
#endif

// Display platform-independent help information
static void print_usage(const char* program_name) {
    printf("AntiRansom v%s - Ransomware Detection and Prevention Tool\n\n", ANTIRANSOM_VERSION);
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Common Options:\n");
    printf("  -h, --help               Display this help message\n");
    printf("  -v, --version            Display version information\n");
    printf("  -d, --daemon             Run as a background service\n");
    printf("  -V, --verbose            Enable verbose logging\n");
    printf("  -c, --config=FILE        Use specified config file\n");
    printf("  -w, --watch-dir=PATH     Watch a specific directory for suspicious activity\n");
    printf("\n");
    printf("For platform-specific options, use %s --help on the target platform\n", program_name);
}

// Display version information
static void print_version(void) {
    printf("AntiRansom v%s\n", ANTIRANSOM_VERSION);
    printf("Copyright (c) 2025 AntiRansom Team\n");
    
    // Display platform information
#ifdef PLATFORM_WINDOWS
    printf("Platform: Windows\n");
#elif defined(PLATFORM_LINUX)
    printf("Platform: Linux\n");
#elif defined(PLATFORM_MACOS)
    printf("Platform: macOS\n");
#elif defined(PLATFORM_BSD)
    printf("Platform: BSD\n");
#else
    printf("Platform: Unknown\n");
#endif
}

// Initialize common components before delegating to platform-specific code
static int initialize_common(void) {
    // Initialize basic logging (will be reconfigured by platform-specific code)
    logger_init(LOG_TO_STDOUT, LOG_LEVEL_INFO);
    
    LOG_INFO("AntiRansom v%s initializing", ANTIRANSOM_VERSION);
    
    return 0;
}

// Parse command-line arguments
static void parse_args(int argc, char* argv[], GlobalArgs* args) {
    if (!args) {
        return;
    }
    
    // Initialize defaults
    args->daemon_mode = 0;
    args->verbose_mode = 0;
    args->config_path[0] = '\0';
    args->watch_directory[0] = '\0';
    
    // Define long options
    static struct option long_options[] = {
        {"help",      no_argument,       0, 'h'},
        {"version",   no_argument,       0, 'v'},
        {"daemon",    no_argument,       0, 'd'},
        {"verbose",   no_argument,       0, 'V'},
        {"config",    required_argument, 0, 'c'},
        {"watch-dir", required_argument, 0, 'w'},
        {0,           0,                 0,  0 }
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "hvdVc:w:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h': // Handle in main directly
            case 'v': // Handle in main directly
                break;
                
            case 'd':
                args->daemon_mode = 1;
                break;
                
            case 'V':
                args->verbose_mode = 1;
                break;
                
            case 'c':
                if (optarg) {
                    strncpy(args->config_path, optarg, sizeof(args->config_path) - 1);
                    args->config_path[sizeof(args->config_path) - 1] = '\0';
                }
                break;
                
            case 'w':
                if (optarg) {
                    strncpy(args->watch_directory, optarg, sizeof(args->watch_directory) - 1);
                    args->watch_directory[sizeof(args->watch_directory) - 1] = '\0';
                    LOG_INFO("Directory monitoring enabled for: %s", args->watch_directory);
                }
                break;
                
            default:
                break;
        }
    }
}

// Main entry point
int main(int argc, char* argv[]) {
    // Check for basic help/version arguments that don't need initialization
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            print_version();
            return EXIT_SUCCESS;
        }
    }
    
    // Initialize common components
    if (initialize_common() != 0) {
        fprintf(stderr, "Failed to initialize common components\n");
        return EXIT_FAILURE;
    }
    
    // Parse command-line arguments
    GlobalArgs global_args;
    parse_args(argc, argv, &global_args);
    
    // Set logger verbosity based on arguments
    logger_set_verbose(global_args.verbose_mode);
    
    // Dispatch to platform-specific implementation with global arguments
#ifdef PLATFORM_LINUX
    LOG_INFO("Detected Linux platform%s", "");
    return linux_main(argc, argv, &global_args);
#elif defined(PLATFORM_WINDOWS)
    LOG_INFO("Detected Windows platform");
    return windows_main(argc, argv, &global_args);
#elif defined(PLATFORM_MACOS)
    LOG_WARNING("macOS platform is not yet supported");
    fprintf(stderr, "AntiRansom does not yet support macOS. Support is planned for a future release.\n");
    return EXIT_FAILURE;
#elif defined(PLATFORM_BSD)
    LOG_WARNING("BSD platform is not yet supported");
    fprintf(stderr, "AntiRansom does not yet support BSD systems. Support is planned for a future release.\n");
    return EXIT_FAILURE;
#else
    LOG_ERROR("Unsupported platform detected");
    fprintf(stderr, "AntiRansom does not support this platform. Supported platforms are: Windows, Linux\n");
    return EXIT_FAILURE;
#endif
}