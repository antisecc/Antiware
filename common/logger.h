#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>
#include "../include/antiransom.h"

/* Log levels */
typedef enum {
    LOG_FATAL,   // Critical errors that cause program termination
    LOG_ERROR,   // Error conditions
    LOG_WARNING, // Warning conditions
    LOG_INFO,    // Informational messages
    LOG_DEBUG,   // Debug-level messages
    LOG_TRACE    // Detailed tracing information
} LogLevel;

/* Initialize the logger */
void logger_init(bool console_output, const char* log_file);

/* Close the logger and free resources */
void logger_close(void);

/* Set the minimum log level to display */
void logger_set_level(LogLevel level);

/* Log a message with the specified level */
void logger_log(LogLevel level, const char* file, int line, const char* fmt, ...);

/* Log detection events */
void logger_detection(const DetectionContext* context, const char* reason);

/* Log action taken */
void logger_action(ResponseAction action, uint32_t process_id, const char* process_name);

/* Helper macros */
#define LOG_FATAL(...)   logger_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...)   logger_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARNING(...) logger_log(LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)    logger_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...)   logger_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_TRACE(...)   logger_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)

#endif /* LOGGER_H */