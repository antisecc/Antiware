#ifndef CONFIG_H
#define CONFIG_H

#include "../include/antiransom.h"
#include <stdbool.h>

typedef struct {
    OperationMode mode;
    bool verbose_logging;
    uint32_t scan_interval_ms;
    float threshold_low;
    float threshold_medium;
    float threshold_high;
    float threshold_critical;
    bool auto_respond;
    char whitelist_path[512];
    char watch_directory[512];  // Directory to monitor for suspicious activity
    
    // Other existing fields...
    DetectionThresholds thresholds;
    MonitorSettings monitor_settings;
    ResponseSettings response_settings;
    LogSettings log_settings;
} Configuration;

/* Initialize configuration with default values */
void config_init(Configuration* config);

/* Load configuration from file */
bool config_load(Configuration* config, const char* filepath);

/* Save current configuration to file */
bool config_save(const Configuration* config, const char* filepath);

/* Process whitelist handling */
bool config_is_process_whitelisted(const char* process_path);
bool config_is_path_whitelisted(const char* file_path);

/* Add item to whitelist */
bool config_add_to_whitelist(const char* item);

/* Configure detection thresholds */
void config_set_thresholds(Configuration* config, 
                          float low, 
                          float medium, 
                          float high, 
                          float critical);

/* Toggle response behavior */
void config_set_auto_respond(Configuration* config, bool enabled);

/* Update scan interval */
void config_set_scan_interval(Configuration* config, uint32_t interval_ms);

#endif /* CONFIG_H */