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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <syslog.h>
#include <pthread.h>

// Default configuration
static LogDestination log_destination = LOG_TO_STDOUT;
static LogLevel log_level = LOG_LEVEL_INFO;
static int verbose_mode = 0;
static float min_risk_score = 10.0f;  // Minimum risk score for logging
static FILE* json_file = NULL;
static char json_file_path[256] = {0};
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Logger statistics
static LoggerStats stats = {0};

// Level names for output
static const char* level_names[] = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "FATAL"
};

// Level names for JSON output (lowercase)
static const char* json_level_names[] = {
    "debug",
    "info",
    "warning",
    "error",
    "critical"
};

// Initialize logger
int logger_init(LogDestination destination, LogLevel level) {
    log_destination = destination;
    log_level = level;
    
    // Initialize statistics
    memset(&stats, 0, sizeof(stats));
    stats.lowest_risk_logged = 999.9f;
    
    // Open syslog if needed
    if (destination == LOG_TO_SYSLOG) {
        openlog("antiransom", LOG_PID | LOG_CONS, LOG_DAEMON);
    }
    
    // Open JSON file if specified
    if (destination == LOG_TO_JSON && json_file_path[0] != '\0') {
        pthread_mutex_lock(&log_mutex);
        json_file = fopen(json_file_path, "a");
        if (!json_file) {
            fprintf(stderr, "Failed to open JSON log file %s: %s\n",
                   json_file_path, strerror(errno));
            pthread_mutex_unlock(&log_mutex);
            return -1;
        }
        
        // Write header if it's a new file
        struct stat st;
        if (stat(json_file_path, &st) == 0 && st.st_size == 0) {
            fprintf(json_file, 
                   "# AntiRansom JSON Log File\n"
                   "# Format: {timestamp, severity, pid, risk_score, action}\n"
                   "# Created: %s\n", 
                   ctime(&(time_t){time(NULL)}));
        }
        pthread_mutex_unlock(&log_mutex);
    }
    
    return 0;
}

// Clean up logger resources
void logger_cleanup(void) {
    if (log_destination == LOG_TO_SYSLOG) {
        closelog();
    }
    
    pthread_mutex_lock(&log_mutex);
    if (json_file != NULL && json_file != stdout) {
        fclose(json_file);
        json_file = NULL;
    }
    pthread_mutex_unlock(&log_mutex);
}

// Set verbose mode
void logger_set_verbose(int verbose) {
    verbose_mode = verbose;
    if (verbose) {
        log_level = LOG_LEVEL_DEBUG;
    }
}

// Set JSON output file
void logger_set_json_file(const char* path) {
    if (!path) return;
    
    pthread_mutex_lock(&log_mutex);
    
    // Close existing file if open
    if (json_file != NULL && json_file != stdout) {
        fclose(json_file);
        json_file = NULL;
    }
    
    // Store path for later use
    strncpy(json_file_path, path, sizeof(json_file_path) - 1);
    json_file_path[sizeof(json_file_path) - 1] = '\0';
    
    // Open new file
    json_file = fopen(path, "a");
    if (!json_file) {
        fprintf(stderr, "Failed to open JSON log file %s: %s\n",
               path, strerror(errno));
    } else if (ftell(json_file) == 0) {
        // Write header if it's a new file
        fprintf(json_file, 
               "# AntiRansom JSON Log File\n"
               "# Format: {timestamp, severity, pid, risk_score, action}\n"
               "# Created: %s\n", 
               ctime(&(time_t){time(NULL)}));
    }
    
    pthread_mutex_unlock(&log_mutex);
}

// Configure minimum risk score for event logging
void logger_set_min_risk_score(float min_score) {
    min_risk_score = min_score;
}

// Get current minimum risk score
float logger_get_min_risk_score(void) {
    return min_risk_score;
}

// Get logger statistics
LoggerStats logger_get_stats(void) {
    LoggerStats current_stats;
    
    pthread_mutex_lock(&log_mutex);
    memcpy(&current_stats, &stats, sizeof(LoggerStats));
    pthread_mutex_unlock(&log_mutex);
    
    return current_stats;
}

// Internal common logging function
static void log_message(LogLevel level, const char* file, int line, const char* format, va_list args) {
    if (level < log_level) return;
    
    char timestamp[32];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    char message[4096];
    vsnprintf(message, sizeof(message), format, args);
    
    switch (log_destination) {
        case LOG_TO_STDOUT:
            if (verbose_mode) {
                fprintf(stdout, "[%s] [%s] %s:%d - %s\n", 
                       timestamp, level_names[level], file, line, message);
            } else {
                fprintf(stdout, "[%s] [%s] %s\n", 
                       timestamp, level_names[level], message);
            }
            break;
            
        case LOG_TO_FILE: {
            FILE* f = fopen("antiransom.log", "a");
            if (f) {
                if (verbose_mode) {
                    fprintf(f, "[%s] [%s] %s:%d - %s\n", 
                           timestamp, level_names[level], file, line, message);
                } else {
                    fprintf(f, "[%s] [%s] %s\n", 
                           timestamp, level_names[level], message);
                }
                fclose(f);
            }
            break;
        }
        
        case LOG_TO_SYSLOG: {
            int syslog_priority;
            switch (level) {
                case LOG_LEVEL_DEBUG:    syslog_priority = LOG_DEBUG; break;
                case LOG_LEVEL_INFO:     syslog_priority = LOG_INFO; break;
                case LOG_LEVEL_WARNING:  syslog_priority = LOG_WARNING; break;
                case LOG_LEVEL_ERROR:    syslog_priority = LOG_ERR; break;
                case LOG_LEVEL_FATAL:    syslog_priority = LOG_CRIT; break;
                default:                 syslog_priority = LOG_NOTICE; break;
            }
            
            if (verbose_mode) {
                syslog(syslog_priority, "[%s] %s:%d - %s", 
                      level_names[level], file, line, message);
            } else {
                syslog(syslog_priority, "[%s] %s", level_names[level], message);
            }
            break;
        }
        
        case LOG_TO_JSON:
            // JSON logging is handled separately for structured events
            break;
    }
}

// Implement existing log functions
void log_debug(const char* file, int line, const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_DEBUG, file, line, format, args);
    va_end(args);
}

void log_info(const char* file, int line, const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_INFO, file, line, format, args);
    va_end(args);
}

void log_warning(const char* file, int line, const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_WARNING, file, line, format, args);
    va_end(args);
}

void log_error(const char* file, int line, const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_ERROR, file, line, format, args);
    va_end(args);
}

void log_fatal(const char* file, int line, const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_FATAL, file, line, format, args);
    va_end(args);
}

// Specialized logging for detections
void logger_detection(const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    char message[4096];
    vsnprintf(message, sizeof(message), format, args);
    
    log_message(LOG_LEVEL_WARNING, "detection", 0, message, args);
    
    va_end(args);
}

// Specialized logging for actions
void logger_action(const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    char message[4096];
    vsnprintf(message, sizeof(message), format, args);
    
    log_message(LOG_LEVEL_INFO, "action", 0, message, args);
    
    va_end(args);
}

/**
 * Sanitize a string for JSON output by escaping quotes and backslashes
 */
static char* sanitize_for_json(const char* input) {
    if (!input) return NULL;
    
    size_t input_len = strlen(input);
    char* output = (char*)malloc(input_len * 2 + 1); // Worst case: every char needs escaping
    
    if (!output) return NULL;
    
    char* dst = output;
    const char* src = input;
    
    while (*src) {
        if (*src == '"' || *src == '\\' || *src == '\n' || *src == '\r' || *src == '\t') {
            *dst++ = '\\';
            if (*src == '\n') {
                *dst++ = 'n';
            } else if (*src == '\r') {
                *dst++ = 'r';
            } else if (*src == '\t') {
                *dst++ = 't';
            } else {
                *dst++ = *src;
            }
        } else {
            *dst++ = *src;
        }
        src++;
    }
    
    *dst = '\0';
    return output;
}

/**
 * Log an event in JSON format
 */
void log_event(LogLevel severity, pid_t pid, float risk_score, const char* action) {
    if (!action) return;
    
    // Update statistics
    pthread_mutex_lock(&log_mutex);
    stats.total_events++;
    stats.events_by_level[severity < 5 ? severity : 4]++;
    
    if (risk_score > stats.highest_risk_logged) {
        stats.highest_risk_logged = risk_score;
    }
    
    if (risk_score < stats.lowest_risk_logged) {
        stats.lowest_risk_logged = risk_score;
    }
    
    // Check JSON file availability
    FILE* output = json_file;
    if (!output) {
        if (log_destination == LOG_TO_JSON) {
            // Try to reopen JSON file if configured
            if (json_file_path[0] != '\0') {
                output = fopen(json_file_path, "a");
                if (output) {
                    json_file = output;
                }
            } else {
                output = stdout; // Fallback
            }
        } else {
            output = stdout; // Default
        }
    }
    
    // Get timestamp with millisecond precision
    char timestamp[32];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm* tm_info = localtime(&tv.tv_sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Sanitize action for JSON
    char* sanitized_action = sanitize_for_json(action);
    if (!sanitized_action) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    
    // Write JSON formatted output
    fprintf(output, 
           "{\"timestamp\":\"%s.%03ld\",\"severity\":\"%s\",\"pid\":%d,\"risk_score\":%.2f,\"action\":\"%s\"}\n",
           timestamp, tv.tv_usec / 1000,
           json_level_names[severity < 5 ? severity : 4],
           pid, 
           risk_score,
           sanitized_action);
    
    // Flush to ensure immediate write
    fflush(output);
    stats.json_writes++;
    
    // Free sanitized string
    free(sanitized_action);
    pthread_mutex_unlock(&log_mutex);
}

/**
 * Wrapper for log_event with threshold check
 */
void log_process_event(LogLevel severity, pid_t pid, float risk_score, const char* action) {
    // Skip if below minimum risk score threshold
    if (risk_score <= min_risk_score) {
        pthread_mutex_lock(&log_mutex);
        stats.filtered_events++;
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    
    // Skip if below log level
    if (severity < log_level) {
        pthread_mutex_lock(&log_mutex);
        stats.filtered_events++;
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    
    // Log the event
    log_event(severity, pid, risk_score, action);
}