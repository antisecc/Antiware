#ifndef ANTIRANSOM_LOGGER_H
#define ANTIRANSOM_LOGGER_H

// Log destinations
typedef enum {
    LOG_TO_STDOUT = 0,
    LOG_TO_FILE = 1,
    LOG_TO_SYSLOG = 2
} LogDestination;

// Log levels
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_FATAL = 4
} LogLevel;

// Logger API
int logger_init(LogDestination destination, LogLevel level);
void logger_cleanup(void);
void logger_set_verbose(int verbose);  // Add this function declaration

// Log functions
void log_debug(const char* file, int line, const char* format, ...);
void log_info(const char* file, int line, const char* format, ...);
void log_warning(const char* file, int line, const char* format, ...);
void log_error(const char* file, int line, const char* format, ...);
void log_fatal(const char* file, int line, const char* format, ...);

// Helper macros for logging
#define LOG_DEBUG(format, ...) log_debug(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) log_info(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) log_warning(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) log_error(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) log_fatal(__FILE__, __LINE__, format, ##__VA_ARGS__)

// Specialized logging
void logger_detection(const char* format, ...);
void logger_action(const char* format, ...);

#endif // ANTIRANSOM_LOGGER_H