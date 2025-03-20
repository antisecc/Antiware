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

/* Configuration options */
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
} Configuration;

#endif /* ANTIRANSOM_H */