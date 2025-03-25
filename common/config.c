/**
 * AntiRansom - Configuration Implementation
 * Implements the configuration interface defined in config.h
 */

#include "config.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

// Static whitelist for trusted processes and paths
static struct {
    char* process_whitelist[100];
    char* path_whitelist[100];
    int process_count;
    int path_count;
} whitelist = {
    .process_count = 0,
    .path_count = 0
};

// Set sensible default values for configuration
static void set_default_values(Configuration* config) {
    if (!config) {
        return;
    }
    
    config->mode = MODE_STANDALONE;
    config->verbose_logging = false;
    config->scan_interval_ms = 1000;  // 1 second default
    config->threshold_low = 30.0f;
    config->threshold_medium = 50.0f;
    config->threshold_high = 70.0f;
    config->threshold_critical = 90.0f;
    config->auto_respond = false;
    
    // Initialize thresholds struct from individual values
    config->thresholds.low = config->threshold_low;
    config->thresholds.medium = config->threshold_medium;
    config->thresholds.high = config->threshold_high;
    config->thresholds.critical = config->threshold_critical;
    
    // Set empty watch directory
    config->watch_directory[0] = '\0';
    
    // Other default settings...
    LOG_DEBUG("Set default configuration values%s", "");
}

/* Initialize configuration with default values */
void config_init(Configuration* config) {
    if (config == NULL) {
        return;
    }
    
    // Zero out the configuration
    memset(config, 0, sizeof(Configuration));
    
    // Set default values
    set_default_values(config);
    
    LOG_INFO("Configuration initialized with default values%s", "");
}

// Helper to trim whitespace from strings
static void trim(char* str) {
    if (!str) return;
    
    // Trim leading space
    char* start = str;
    while (isspace((unsigned char)*start)) {
        start++;
    }
    
    // All spaces?
    if (*start == 0) {
        *str = 0;
        return;
    }
    
    // Trim trailing space
    char* end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    
    // Write new null terminator
    *(end + 1) = 0;
    
    // Move if needed
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

/* Load configuration from file */
bool config_load(Configuration* config, const char* filepath) {
    if (config == NULL) {
        return false;
    }
    
    // Set default values first
    set_default_values(config);
    
    if (filepath == NULL) {
        LOG_INFO("No configuration file specified, using defaults%s", "");
        return true;
    }
    
    FILE* file = fopen(filepath, "r");
    if (file == NULL) {
        LOG_INFO("Could not open configuration file %s: %s", filepath, strerror(errno));
        LOG_INFO("Using default configuration settings%s", "");
        return true;  // Not a failure, just using defaults
    }
    
    char line[512];
    char key[256];
    char value[256];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        
        // Parse "key = value" format
        if (sscanf(line, "%255[^=]=%255[^\n]", key, value) == 2) {
            trim(key);
            trim(value);
            
            // Process standard settings (for backward compatibility)
            if (strcmp(key, "mode") == 0) {
                if (strcasecmp(value, "daemon") == 0) {
                    config->mode = MODE_DAEMON;
                } else {
                    config->mode = MODE_STANDALONE;
                }
            }
            else if (strcmp(key, "verbose_logging") == 0) {
                config->verbose_logging = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "scan_interval") == 0) {
                config->scan_interval_ms = (uint32_t)atol(value);
            }
            else if (strcmp(key, "threshold_low") == 0) {
                config->threshold_low = (float)atof(value);
                config->thresholds.low = config->threshold_low; // Update both for consistency
            }
            else if (strcmp(key, "threshold_medium") == 0) {
                config->threshold_medium = (float)atof(value);
                config->thresholds.medium = config->threshold_medium;
            }
            else if (strcmp(key, "threshold_high") == 0) {
                config->threshold_high = (float)atof(value);
                config->thresholds.high = config->threshold_high;
            }
            else if (strcmp(key, "threshold_critical") == 0) {
                config->threshold_critical = (float)atof(value);
                config->thresholds.critical = config->threshold_critical;
            }
            else if (strcmp(key, "auto_respond") == 0) {
                config->auto_respond = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "whitelist_path") == 0) {
                strncpy(config->whitelist_path, value, sizeof(config->whitelist_path) - 1);
            }
            
            // Process structured threshold settings
            else if (strcmp(key, "threshold.low") == 0) {
                config->thresholds.low = (float)atof(value);
                config->threshold_low = config->thresholds.low; // Update both for consistency
            }
            else if (strcmp(key, "threshold.medium") == 0) {
                config->thresholds.medium = (float)atof(value);
                config->threshold_medium = config->thresholds.medium;
            }
            else if (strcmp(key, "threshold.high") == 0) {
                config->thresholds.high = (float)atof(value);
                config->threshold_high = config->thresholds.high;
            }
            else if (strcmp(key, "threshold.critical") == 0) {
                config->thresholds.critical = (float)atof(value);
                config->threshold_critical = config->thresholds.critical;
            }
            
            // Process monitoring settings
            else if (strcmp(key, "monitor.file_ops") == 0) {
                config->monitor_settings.monitor_file_ops = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "monitor.process") == 0) {
                config->monitor_settings.monitor_process_creation = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "monitor.network") == 0) {
                config->monitor_settings.monitor_network = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "monitor.registry") == 0) {
                config->monitor_settings.monitor_registry = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "monitor.memory") == 0) {
                config->monitor_settings.monitor_memory = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            
            // Process response settings
            else if (strcmp(key, "response.notify") == 0) {
                config->response_settings.notify_user = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "response.block") == 0) {
                config->response_settings.block_suspicious = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "response.backup") == 0) {
                config->response_settings.create_backups = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            
            // Process logging settings
            else if (strcmp(key, "log.level") == 0) {
                config->log_settings.log_level = atoi(value);
            }
            else if (strcmp(key, "log.file") == 0) {
                strncpy(config->log_settings.log_file, value, sizeof(config->log_settings.log_file) - 1);
            }
            else if (strcmp(key, "log.console") == 0) {
                config->log_settings.log_to_console = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "log.use_file") == 0) {
                config->log_settings.log_to_file = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            
            // Process whitelist entries
            else if (strcmp(key, "whitelist.process") == 0) {
                if (whitelist.process_count < 100) {
                    whitelist.process_whitelist[whitelist.process_count] = strdup(value);
                    whitelist.process_count++;
                }
            }
            else if (strcmp(key, "whitelist.path") == 0) {
                if (whitelist.path_count < 100) {
                    whitelist.path_whitelist[whitelist.path_count] = strdup(value);
                    whitelist.path_count++;
                }
            }
            else {
                LOG_WARNING("Unknown configuration key at line %d: %s", line_num, key);
            }
        } else {
            LOG_WARNING("Invalid configuration format at line %d", line_num);
        }
    }
    
    fclose(file);
    LOG_INFO("Configuration loaded from %s", filepath);
    return true;
}

/* Save current configuration to file */
bool config_save(const Configuration* config, const char* filepath) {
    if (config == NULL || filepath == NULL) {
        return false;
    }
    
    FILE* file = fopen(filepath, "w");
    if (file == NULL) {
        LOG_ERROR("Could not open configuration file for writing: %s", filepath);
        return false;
    }
    
    // Write header
    fprintf(file, "# AntiRansom Configuration File\n");
    fprintf(file, "# Generated automatically\n\n");
    
    // Write basic settings
    fprintf(file, "# Basic settings\n");
    fprintf(file, "mode = %s\n", config->mode == MODE_DAEMON ? "daemon" : "standalone");
    fprintf(file, "verbose_logging = %s\n", config->verbose_logging ? "true" : "false");
    fprintf(file, "scan_interval = %u\n", config->scan_interval_ms);
    fprintf(file, "auto_respond = %s\n", config->auto_respond ? "true" : "false");
    if (config->whitelist_path[0] != '\0') {
        fprintf(file, "whitelist_path = %s\n", config->whitelist_path);
    }
    fprintf(file, "\n");
    
    // Write threshold settings
    fprintf(file, "# Detection thresholds\n");
    fprintf(file, "threshold_low = %.1f\n", config->threshold_low);
    fprintf(file, "threshold_medium = %.1f\n", config->threshold_medium);
    fprintf(file, "threshold_high = %.1f\n", config->threshold_high);
    fprintf(file, "threshold_critical = %.1f\n\n", config->threshold_critical);
    
    // Write structured settings
    fprintf(file, "# Monitoring settings\n");
    fprintf(file, "monitor.file_ops = %s\n", config->monitor_settings.monitor_file_ops ? "true" : "false");
    fprintf(file, "monitor.process = %s\n", config->monitor_settings.monitor_process_creation ? "true" : "false");
    fprintf(file, "monitor.network = %s\n", config->monitor_settings.monitor_network ? "true" : "false");
    fprintf(file, "monitor.registry = %s\n", config->monitor_settings.monitor_registry ? "true" : "false");
    fprintf(file, "monitor.memory = %s\n\n", config->monitor_settings.monitor_memory ? "true" : "false");
    
    // Write response settings
    fprintf(file, "# Response settings\n");
    fprintf(file, "response.notify = %s\n", config->response_settings.notify_user ? "true" : "false");
    fprintf(file, "response.block = %s\n", config->response_settings.block_suspicious ? "true" : "false");
    fprintf(file, "response.backup = %s\n\n", config->response_settings.create_backups ? "true" : "false");
    
    // Write logging settings
    fprintf(file, "# Logging settings\n");
    fprintf(file, "log.level = %d\n", config->log_settings.log_level);
    fprintf(file, "log.file = %s\n", config->log_settings.log_file);
    fprintf(file, "log.console = %s\n", config->log_settings.log_to_console ? "true" : "false");
    fprintf(file, "log.use_file = %s\n\n", config->log_settings.log_to_file ? "true" : "false");
    
    // Write whitelist entries
    fprintf(file, "# Process whitelist\n");
    for (int i = 0; i < whitelist.process_count; i++) {
        fprintf(file, "whitelist.process = %s\n", whitelist.process_whitelist[i]);
    }
    
    fprintf(file, "\n# Path whitelist\n");
    for (int i = 0; i < whitelist.path_count; i++) {
        fprintf(file, "whitelist.path = %s\n", whitelist.path_whitelist[i]);
    }
    
    fclose(file);
    LOG_INFO("Configuration saved to %s", filepath);
    return true;
}

/* Process whitelist handling */
bool config_is_process_whitelisted(const char* process_path) {
    if (process_path == NULL) {
        return false;
    }
    
    for (int i = 0; i < whitelist.process_count; i++) {
        // Check for exact match
        if (strcmp(whitelist.process_whitelist[i], process_path) == 0) {
            return true;
        }
        
        // Check for pattern match with wildcard (*)
        if (strchr(whitelist.process_whitelist[i], '*') != NULL) {
            // Simple pattern matching
            // TODO: Implement proper wildcard pattern matching
            const char* pattern = whitelist.process_whitelist[i];
            const char* wildcard = strchr(pattern, '*');
            
            // Check prefix match before the wildcard
            size_t prefix_len = wildcard - pattern;
            if (strncmp(pattern, process_path, prefix_len) == 0) {
                return true;
            }
        }
    }
    
    return false;
}

bool config_is_path_whitelisted(const char* file_path) {
    if (file_path == NULL) {
        return false;
    }
    
    for (int i = 0; i < whitelist.path_count; i++) {
        // Check for exact match
        if (strcmp(whitelist.path_whitelist[i], file_path) == 0) {
            return true;
        }
        
        // Check for directory prefix match (path is in whitelisted directory)
        size_t whitelist_len = strlen(whitelist.path_whitelist[i]);
        if (strncmp(whitelist.path_whitelist[i], file_path, whitelist_len) == 0) {
            // Ensure it's a directory match (next char is path separator)
            if (file_path[whitelist_len] == '/' || file_path[whitelist_len] == '\\' || 
                whitelist.path_whitelist[i][whitelist_len-1] == '/' || 
                whitelist.path_whitelist[i][whitelist_len-1] == '\\') {
                return true;
            }
        }
        
        // Check for pattern match with wildcard (*)
        if (strchr(whitelist.path_whitelist[i], '*') != NULL) {
            // Simple pattern matching
            // TODO: Implement proper wildcard pattern matching
            const char* pattern = whitelist.path_whitelist[i];
            const char* wildcard = strchr(pattern, '*');
            
            // Check prefix match before the wildcard
            size_t prefix_len = wildcard - pattern;
            if (strncmp(pattern, file_path, prefix_len) == 0) {
                return true;
            }
        }
    }
    
    return false;
}

/* Add item to whitelist */
bool config_add_to_whitelist(const char* item) {
    if (item == NULL) {
        return false;
    }
    
    // Determine if this is a process or path whitelist entry
    bool is_process = false;
    
    // Check if it looks like an executable
    const char* ext = strrchr(item, '.');
    if (ext && (strcasecmp(ext, ".exe") == 0 || 
                strcasecmp(ext, ".com") == 0 || 
                strcasecmp(ext, ".bat") == 0 || 
                strcasecmp(ext, ".cmd") == 0 ||
                strcasecmp(ext, ".sh") == 0)) {
        is_process = true;
    }
    
    // Add to appropriate whitelist
    if (is_process) {
        if (whitelist.process_count < 100) {
            whitelist.process_whitelist[whitelist.process_count] = strdup(item);
            whitelist.process_count++;
            LOG_INFO("Added process to whitelist: %s", item);
            return true;
        } else {
            LOG_WARNING("Process whitelist is full, cannot add: %s", item);
            return false;
        }
    } else {
        if (whitelist.path_count < 100) {
            whitelist.path_whitelist[whitelist.path_count] = strdup(item);
            whitelist.path_count++;
            LOG_INFO("Added path to whitelist: %s", item);
            return true;
        } else {
            LOG_WARNING("Path whitelist is full, cannot add: %s", item);
            return false;
        }
    }
}

/* Configure detection thresholds */
void config_set_thresholds(Configuration* config, 
                          float low, 
                          float medium, 
                          float high, 
                          float critical) {
    if (config == NULL) {
        return;
    }
    
    // Validate and set thresholds in ascending order
    config->threshold_low = low;
    config->threshold_medium = (medium > low) ? medium : low + 5.0f;
    config->threshold_high = (high > config->threshold_medium) ? high : config->threshold_medium + 5.0f;
    config->threshold_critical = (critical > config->threshold_high) ? critical : config->threshold_high + 5.0f;
    
    // Update structured thresholds as well for consistency
    config->thresholds.low = config->threshold_low;
    config->thresholds.medium = config->threshold_medium;
    config->thresholds.high = config->threshold_high;
    config->thresholds.critical = config->threshold_critical;
    
    LOG_INFO("Detection thresholds updated: Low=%.1f, Medium=%.1f, High=%.1f, Critical=%.1f",
             config->threshold_low, config->threshold_medium, 
             config->threshold_high, config->threshold_critical);
}

/* Toggle response behavior */
void config_set_auto_respond(Configuration* config, bool enabled) {
    if (config == NULL) {
        return;
    }
    
    config->auto_respond = enabled;
    LOG_INFO("Automatic response %s", enabled ? "enabled" : "disabled");
}

/* Update scan interval */
void config_set_scan_interval(Configuration* config, uint32_t interval_ms) {
    if (config == NULL) {
        return;
    }
    
    // Validate minimum interval to prevent excessive CPU usage
    if (interval_ms < 100) {
        interval_ms = 100;
        LOG_WARNING("Specified scan interval too small, setting to minimum (100ms)%s", "");
    }
    
    config->scan_interval_ms = interval_ms;
    LOG_INFO("Scan interval updated to %u ms", interval_ms);
}

/**
 * Retrieves the current active configuration
 * Thread-safe access to the global configuration
 * 
 * @return Pointer to the current configuration or NULL on failure
 */
Configuration* config_get_current(void) {
    // Use a static global configuration
    static Configuration global_config;
    static int initialized = 0;
    
    // Initialize on first call
    if (!initialized) {
        // Set default values
        config_init(&global_config);
        initialized = 1;
    }
    
    return &global_config;
}