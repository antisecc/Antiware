/**
 * AntiRansom - Logger Implementation
 * Provides logging functionality for the anti-ransomware system
 */

#include "logger.h"
#include "config.h"  // Add this include for Configuration type
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <syslog.h>
#endif

// Logger state
static struct {
    LogDestination destination;
    LogLevel current_level;
    FILE* log_file;
    char log_filename[256];
    int initialized;
    int verbose_mode;  // Store verbose mode directly in logger state
} logger_state = {
    .destination = LOG_TO_STDOUT,
    .current_level = LOG_LEVEL_INFO,
    .log_file = NULL,
    .log_filename = "",
    .initialized = 0,
    .verbose_mode = 0
};

// Convert LogLevel to string representation
static const char* level_to_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:   return "DEBUG";
        case LOG_LEVEL_INFO:    return "INFO";
        case LOG_LEVEL_WARNING: return "WARNING";
        case LOG_LEVEL_ERROR:   return "ERROR";
        case LOG_LEVEL_FATAL:   return "FATAL";
        default:                return "UNKNOWN";
    }
}

// Map our log levels to syslog priorities (Linux only)
#ifdef __linux__
static int level_to_syslog(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:   return LOG_DEBUG;
        case LOG_LEVEL_INFO:    return LOG_INFO;
        case LOG_LEVEL_WARNING: return LOG_WARNING;
        case LOG_LEVEL_ERROR:   return LOG_ERR;
        case LOG_LEVEL_FATAL:   return LOG_CRIT;
        default:                return LOG_NOTICE;
    }
}
#endif

// Filter function to reduce noise in logs - simplified version
static int should_filter_log(LogLevel level, const char *message) {
    // Never filter warnings, errors, or fatal messages
    if (level > LOG_LEVEL_INFO) {
        return 0;  // Don't filter
    }
    
    // Don't filter when verbose logging is enabled
    if (logger_state.verbose_mode) {
        return 0;
    }
    
    // Common patterns that flood the logs
    const char *noise_patterns[] = {
        "Added process to monitoring:", 
        "Process whitelisted, minimal monitoring",
        "Syscall detected:", 
        "Analyzing memory region at",
        "Skipping process",
        "Process command line:",
        "Unlikely to be ransomware",
        "No suspicious activity detected",
        "Using default configuration settings",
        NULL
    };
    
    // System processes that generate excessive logs
    const char *noisy_processes[] = {
        "kworker", "systemd", "snapd", "cron", "dbus", "NetworkManager",
        "avahi", "cups", "polkit", "udisks", "pulseaudio", "rsyslog",
        NULL
    };
    
    // Check for noise patterns
    for (int i = 0; noise_patterns[i] != NULL; i++) {
        if (strstr(message, noise_patterns[i])) {
            return 1;  // Filter this message
        }
    }
    
    // Check for noisy processes
    for (int i = 0; noisy_processes[i] != NULL; i++) {
        if (strstr(message, noisy_processes[i])) {
            return 1;  // Filter this message
        }
    }
    
    return 0;  // Don't filter
}

// Initialize the logger
int logger_init(LogDestination destination, LogLevel level) {
    // Close any open resources if already initialized
    if (logger_state.initialized) {
        logger_cleanup();
    }
    
    // Set the state
    logger_state.destination = destination;
    logger_state.current_level = level;
    logger_state.verbose_mode = 0;  // Default to non-verbose
    
    // Handle destination-specific initialization
    switch (destination) {
        case LOG_TO_FILE:
            if (logger_state.log_filename[0] == '\0') {
                // Default log file name if none is set
                strcpy(logger_state.log_filename, "antiransom.log");
            }
            
            logger_state.log_file = fopen(logger_state.log_filename, "a");
            if (!logger_state.log_file) {
                fprintf(stderr, "Error: Could not open log file %s\n", logger_state.log_filename);
                return -1;
            }
            break;
            
        case LOG_TO_SYSLOG:
#ifdef __linux__
            openlog("antiransom", LOG_PID, LOG_DAEMON);
#else
            // Fall back to stdout on non-Linux platforms
            fprintf(stderr, "Warning: Syslog not supported on this platform, using stdout\n");
            logger_state.destination = LOG_TO_STDOUT;
#endif
            break;
            
        case LOG_TO_STDOUT:
            // Nothing special needed for stdout
            break;
    }
    
    logger_state.initialized = 1;
    
    // Log initial message
    log_info(__FILE__, __LINE__, "Logging initialized with level %s", level_to_string(level));
    return 0;
}

// Close the logger and free resources
void logger_cleanup(void) {
    if (!logger_state.initialized) {
        return;
    }
    
    if (logger_state.destination == LOG_TO_FILE && logger_state.log_file) {
        fclose(logger_state.log_file);
        logger_state.log_file = NULL;
    } 
    else if (logger_state.destination == LOG_TO_SYSLOG) {
#ifdef __linux__
        closelog();
#endif
    }
    
    logger_state.initialized = 0;
}

// Modify the write_log_message function to use the filter
void write_log_message(LogLevel level, const char* source_file, int line_number, const char* format, ...) {
    // Skip logging if level is below current threshold
    if (level < logger_state.current_level || !logger_state.initialized) {
        return;
    }
    
    // Format the message first so we can filter based on content
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // Apply filtering
    if (should_filter_log(level, message)) {
        return;
    }
    
    // Rest of original function stays the same
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Format the log message
    char formatted_message[1200];
    
    if (source_file && line_number > 0) {
        char source_info[128];
        char filename[64] = {0};
        
        // Extract just the filename from the path
        const char* last_slash = strrchr(source_file, '/');
        if (!last_slash) {
            last_slash = strrchr(source_file, '\\');
        }
        
        if (last_slash) {
            strncpy(filename, last_slash + 1, sizeof(filename) - 1);
        } else {
            strncpy(filename, source_file, sizeof(filename) - 1);
        }
        
        snprintf(source_info, sizeof(source_info), "%s:%d", filename, line_number);
        snprintf(formatted_message, sizeof(formatted_message), "[%s] [%s] %-15s | %s", 
                timestamp, level_to_string(level), source_info, message);
    } else {
        snprintf(formatted_message, sizeof(formatted_message), "[%s] [%s] | %s", 
                timestamp, level_to_string(level), message);
    }
    
    // Output based on destination
    switch (logger_state.destination) {
        case LOG_TO_FILE:
            if (logger_state.log_file) {
                fprintf(logger_state.log_file, "%s\n", formatted_message);
                fflush(logger_state.log_file);
            }
            break;
            
        case LOG_TO_SYSLOG:
#ifdef __linux__
            syslog(level_to_syslog(level), "%s", message);
#else
            fprintf(stdout, "%s\n", formatted_message);
#endif
            break;
            
        case LOG_TO_STDOUT:
        default:
            fprintf(stdout, "%s\n", formatted_message);
            fflush(stdout);
            break;
    }
}

// Log functions for each level
void log_debug(const char* file, int line, const char* format, ...) {
    if (logger_state.current_level > LOG_LEVEL_DEBUG) {
        return;
    }
    
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    write_log_message(LOG_LEVEL_DEBUG, file, line, message);
}

void log_info(const char* file, int line, const char* format, ...) {
    if (logger_state.current_level > LOG_LEVEL_INFO) {
        return;
    }
    
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    write_log_message(LOG_LEVEL_INFO, file, line, message);
}

void log_warning(const char* file, int line, const char* format, ...) {
    if (logger_state.current_level > LOG_LEVEL_WARNING) {
        return;
    }
    
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    write_log_message(LOG_LEVEL_WARNING, file, line, message);
}

void log_error(const char* file, int line, const char* format, ...) {
    if (logger_state.current_level > LOG_LEVEL_ERROR) {
        return;
    }
    
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    write_log_message(LOG_LEVEL_ERROR, file, line, message);
}

void log_fatal(const char* file, int line, const char* format, ...) {
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    write_log_message(LOG_LEVEL_FATAL, file, line, message);
}

/**
 * Logs detection events with specialized formatting
 * Used for recording actual security detections
 */
void logger_detection(const char* format, ...) {
    // Format the original message
    char message[900]; // Reduced size to allow for prefix
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // Create the formatted detection message - already includes space for prefix
    char detection_message[1024];
    snprintf(detection_message, sizeof(detection_message), "[DETECTION] %s", message);
    
    // Use a dedicated detection log level with appropriate formatting
    write_log_message(LOG_LEVEL_WARNING, NULL, 0, detection_message);
    
    // For critical detections, we might also want to log to syslog
    #ifdef __linux__
    if (logger_state.destination == LOG_TO_SYSLOG || 
        logger_state.current_level >= LOG_LEVEL_ERROR) {
        syslog(LOG_WARNING, "[DETECTION] %s", message);
    }
    #endif
}

/**
 * Logs response actions taken by the anti-ransomware system
 * Used for recording interventions and mitigations
 */
void logger_action(const char* format, ...) {
    // Format the original message
    char message[900]; // Reduced size to allow for prefix
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // Create the formatted action message - already includes space for prefix
    char action_message[1024];
    snprintf(action_message, sizeof(action_message), "[ACTION] %s", message);
    
    // Actions are generally informational but important to track
    write_log_message(LOG_LEVEL_INFO, NULL, 0, action_message);
    
    // For significant actions, also log to syslog
    #ifdef __linux__
    if (logger_state.destination == LOG_TO_SYSLOG) {
        syslog(LOG_NOTICE, "[ACTION] %s", message);
    }
    #endif
}

// Add this function to set verbose mode from configuration
void logger_set_verbose(int verbose) {
    logger_state.verbose_mode = verbose;
    if (verbose) {
        log_info(__FILE__, __LINE__, "Verbose logging enabled");
    }
}