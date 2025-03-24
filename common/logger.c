/**
 * AntiRansom - Logger Implementation
 * Provides logging functionality for the anti-ransomware system
 */

#include "logger.h"
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
} logger_state = {
    .destination = LOG_TO_STDOUT,
    .current_level = LOG_LEVEL_INFO,
    .log_file = NULL,
    .log_filename = "",
    .initialized = 0
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

// Initialize the logger
int logger_init(LogDestination destination, LogLevel level) {
    // Close any open resources if already initialized
    if (logger_state.initialized) {
        logger_cleanup();
    }
    
    // Set the state
    logger_state.destination = destination;
    logger_state.current_level = level;
    
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

// Internal function to write a log message
static void write_log_message(LogLevel level, const char* file, int line, const char* message) {
    if (!logger_state.initialized || level < logger_state.current_level) {
        return;
    }
    
    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Create formatted message with timestamp, level, and source location
    char full_message[1024];
    snprintf(full_message, sizeof(full_message), "[%s] [%s] %s:%d - %s", 
             timestamp, level_to_string(level), file, line, message);
    
    // Output based on destination
    switch (logger_state.destination) {
        case LOG_TO_STDOUT:
            printf("%s\n", full_message);
            fflush(stdout);
            break;
            
        case LOG_TO_FILE:
            if (logger_state.log_file) {
                fprintf(logger_state.log_file, "%s\n", full_message);
                fflush(logger_state.log_file);
            }
            break;
            
        case LOG_TO_SYSLOG:
#ifdef __linux__
            syslog(level_to_syslog(level), "%s:%d - %s", file, line, message);
#endif
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
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // Use a dedicated detection log level with appropriate formatting
    write_log_message(LOG_LEVEL_WARNING, NULL, 0, "[DETECTION] %s", message);
    
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
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // Actions are generally informational but important to track
    write_log_message(LOG_LEVEL_INFO, NULL, 0, "[ACTION] %s", message);
    
    // For significant actions, also log to syslog
    #ifdef __linux__
    if (logger_state.destination == LOG_TO_SYSLOG) {
        syslog(LOG_NOTICE, "[ACTION] %s", message);
    }
    #endif
}