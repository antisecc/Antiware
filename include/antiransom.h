#ifndef ANTIRANSOM_H
#define ANTIRANSOM_H

#include <stdint.h>
#include <stdbool.h>

/* Operating modes */
typedef enum {
    MODE_STANDALONE,  // Interactive mode with real-time feedback
    MODE_DAEMON       // Background monitoring service
} OperationMode;

/* Threat severity levels */
typedef enum {
    SEVERITY_NONE,    // No threat detected
    SEVERITY_LOW,     // Suspicious but likely benign
    SEVERITY_MEDIUM,  // Concerning behavior detected
    SEVERITY_HIGH,    // Likely ransomware activity
    SEVERITY_CRITICAL // Confirmed ransomware behavior
} ThreatSeverity;

/* Response actions */
typedef enum {
    ACTION_NONE,      // No action needed
    ACTION_MONITOR,   // Continue monitoring with heightened scrutiny
    ACTION_ALERT,     // Alert the user/admin
    ACTION_ISOLATE,   // Isolate the process network access
    ACTION_SUSPEND,   // Suspend the process
    ACTION_TERMINATE  // Terminate the suspicious process
} ResponseAction;

/* Core detection context */
typedef struct {
    uint32_t process_id;
    char process_name[256];
    uint64_t start_time;
    float total_score;
    
    // Component scores
    float syscall_score;
    float memory_score;
    float process_score;
    
    ThreatSeverity severity;
    ResponseAction action;
    
    // Flags for specific behaviors
    bool mass_file_operations;
    bool encryption_detected;
    bool network_activity;
    bool shadow_copy_access;
    bool registry_modification; // Windows-specific
    
    // Statistics
    uint32_t files_modified;
    uint32_t files_deleted;
    uint32_t entropy_increases;
    
    void* platform_specific; // OS-specific data
} DetectionContext;

/**
 * Detection thresholds
 */
typedef struct {
    float low;        // Low suspicion threshold (matches threshold_low)
    float medium;     // Medium suspicion threshold (matches threshold_medium)
    float high;       // High suspicion threshold (matches threshold_high)
    float critical;   // Critical suspicion threshold (matches threshold_critical)
} DetectionThresholds;

/**
 * Monitoring settings
 */
typedef struct {
    bool monitor_file_ops;          // Monitor file operations
    bool monitor_process_creation;  // Monitor process creation
    bool monitor_network;           // Monitor network connections
    bool monitor_registry;          // Monitor registry changes (Windows)
    bool monitor_memory;            // Monitor memory for suspicious patterns
} MonitorSettings;

/**
 * Response settings
 */
typedef struct {
    bool notify_user;               // Show notifications to user
    bool block_suspicious;          // Block suspicious activities
    bool create_backups;            // Create backups before response actions
} ResponseSettings;

/**
 * Logging settings
 */
typedef struct {
    int log_level;                  // Minimum log level to record
    char log_file[256];             // Path to log file
    bool log_to_console;            // Log to console
    bool log_to_file;               // Log to file
} LogSettings;

/* Configuration options */
typedef struct {
    // Original fields (for backward compatibility)
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
    
    // Enhanced configuration structure
    DetectionThresholds thresholds;  // Structured thresholds
    MonitorSettings monitor_settings;
    ResponseSettings response_settings;
    LogSettings log_settings;
} Configuration;

// Add this structure definition:
typedef struct {
    unsigned long total_memory_kb;
    int rwx_region_count;
    int memory_region_count;
    int has_new_rwx_region;
    int has_modified_executable_region;
    int has_large_memory_increase;
    int has_suspicious_allocation_pattern;
} MemoryStats;

typedef struct {
    float file_access_rate;
    int spawn_rate;
    int is_from_suspicious_location;
    int has_suspicious_name;
    int has_suspicious_cmdline;
    int has_elevated_privileges;
    int has_rapid_file_access;
    int has_rapid_process_spawning;
    float suspicion_score;
} ProcessStats;

// Add this structure definition:
typedef struct {
    int rapid_file_access;
    int high_file_io;
    int multiple_file_extension_changes;
    int multiple_file_renames;
    int memory_pattern;
    int system_changes;
} BehaviorFlags;

#endif /* ANTIRANSOM_H */