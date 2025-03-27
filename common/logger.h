#ifndef ANTIRANSOM_LOGGER_H
#define ANTIRANSOM_LOGGER_H

#include <sys/types.h>  // For pid_t

// Log destinations
typedef enum {
    LOG_TO_STDOUT = 0,
    LOG_TO_FILE = 1,
    LOG_TO_SYSLOG = 2,
    LOG_TO_JSON = 3      // New destination for JSON-formatted logs
} LogDestination;

// Log levels
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_FATAL = 4,
    LOG_LEVEL_CRITICAL = 4  // Alias for FATAL to maintain compatibility
} LogLevel;

// Logger API
int logger_init(LogDestination destination, LogLevel level);
void logger_cleanup(void);
void logger_set_verbose(int verbose);
void logger_set_json_file(const char* json_file_path);  // Set JSON output file

// Basic log functions (existing API)
void log_debug(const char* file, int line, const char* format, ...);
void log_info(const char* file, int line, const char* format, ...);
void log_warning(const char* file, int line, const char* format, ...);
void log_error(const char* file, int line, const char* format, ...);
void log_fatal(const char* file, int line, const char* format, ...);

// Helper macros for logging (existing)
#define LOG_DEBUG(format, ...) log_debug(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) log_info(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) log_warning(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) log_error(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) log_fatal(__FILE__, __LINE__, format, ##__VA_ARGS__)

// Specialized logging (existing)
void logger_detection(const char* format, ...);
void logger_action(const char* format, ...);

// New JSON-formatted event logging for process events
void log_event(LogLevel severity, pid_t pid, float risk_score, const char* action);

// Only log events where risk score > threshold (default 10.0)
#define LOG_PROCESS_EVENT(severity, pid, risk_score, action) \
    log_process_event(severity, pid, risk_score, action)

// Internal function with threshold check
void log_process_event(LogLevel severity, pid_t pid, float risk_score, const char* action);

// Configure minimum risk score for event logging
void logger_set_min_risk_score(float min_score);

// Get current minimum risk score
float logger_get_min_risk_score(void);

// Structure for enhanced logging statistics
typedef struct {
    unsigned long total_events;          // Total event count
    unsigned long filtered_events;       // Events filtered by risk score
    unsigned long events_by_level[5];    // Events by severity level
    float highest_risk_logged;           // Highest risk score logged
    float lowest_risk_logged;            // Lowest risk score logged
    unsigned long json_writes;           // Number of JSON records written
} LoggerStats;

// Get logger statistics
LoggerStats logger_get_stats(void);

#endif // ANTIRANSOM_LOGGER_H