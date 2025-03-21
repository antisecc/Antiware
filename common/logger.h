#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>
#include "../include/antiransom.h"

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
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

// Convenient macros
#define LOG_DEBUG(format, ...) log_debug(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) log_info(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) log_warning(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) log_error(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) log_fatal(__FILE__, __LINE__, format, ##__VA_ARGS__)

#endif // LOGGER_H