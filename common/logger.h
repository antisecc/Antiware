#ifndef LOGGER_H
#define LOGGER_H

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_FATAL = 4,
    LOG_LEVEL_DETECTION = 5,  // Add this line
    LOG_LEVEL_ACTION = 6      // Add this line
} LogLevel;

typedef enum {
    LOG_TO_STDOUT = 0,
    LOG_TO_FILE,
    LOG_TO_SYSLOG
} LogDestination;

// Initialize the logger
int logger_init(LogDestination destination, LogLevel level);

// Close the logger
void logger_cleanup(void);

// Log functions
void log_debug(const char* file, int line, const char* format, ...);
void log_info(const char* file, int line, const char* format, ...);
void log_warning(const char* file, int line, const char* format, ...);
void log_error(const char* file, int line, const char* format, ...);
void log_fatal(const char* file, int line, const char* format, ...);
void logger_detection(const char* message, ...);
void logger_action(const char* message, ...);

// Convenient macros
#define LOG_DEBUG(format, ...) log_debug(__FILE__, __LINE__, format "%s", ##__VA_ARGS__, "")
#define LOG_INFO(format, ...) log_info(__FILE__, __LINE__, format "%s", ##__VA_ARGS__, "")
#define LOG_WARNING(format, ...) log_warning(__FILE__, __LINE__, format "%s", ##__VA_ARGS__, "")
#define LOG_ERROR(format, ...) log_error(__FILE__, __LINE__, format "%s", ##__VA_ARGS__, "")
#define LOG_FATAL(format, ...) log_fatal(__FILE__, __LINE__, format "%s", ##__VA_ARGS__, "")

#endif // LOGGER_H