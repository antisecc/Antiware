#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#include "../include/antiransom.h"
#include "../include/events.h"
#include "../common/logger.h"
#include "../common/scoring.h"
#include "../common/config.h"

// Maximum monitored processes
#define MAX_MONITORED_PROCESSES 1024

// Maximum events to keep in history per process
#define MAX_EVENT_HISTORY 100

// Time window for sequential operations (seconds)
#define TIME_WINDOW 10

// Structure to track events for a specific process
typedef struct {
    pid_t pid;
    char process_name[256];
    time_t first_event;
    Event event_history[MAX_EVENT_HISTORY];
    size_t event_count;
    size_t history_index;
    DetectionContext context;
    DetectionPatterns patterns;
} ProcessMonitor;

// Array of monitored processes
static ProcessMonitor *monitored_processes = NULL;
static size_t process_count = 0;

// Forward declarations
static ProcessMonitor *find_or_create_process_monitor(pid_t pid, const char *process_name);
static void analyze_event_sequence(ProcessMonitor *monitor, const Event *new_event);
static void check_file_operation_patterns(ProcessMonitor *monitor);
static void check_process_behavior(ProcessMonitor *monitor);
static int is_sensitive_file_type(const char *path);
static void update_detection_score(ProcessMonitor *monitor);

// Forward declarations for logger functions
extern void logger_detection(const DetectionContext *context, const char *message);
extern void logger_action(ResponseAction action, pid_t pid, const char *process_name);

// Initialize the detection system
int detection_init(void) {
    monitored_processes = malloc(MAX_MONITORED_PROCESSES * sizeof(ProcessMonitor));
    if (!monitored_processes) {
        LOG_ERROR("Failed to allocate memory for process monitors%s", "");
        return -1;
    }
    
    memset(monitored_processes, 0, MAX_MONITORED_PROCESSES * sizeof(ProcessMonitor));
    process_count = 0;
    
    LOG_INFO("Detection system initialized%s", "");
    return 0;
}

// Clean up resources used by the detection system
void detection_cleanup(void) {
    if (monitored_processes) {
        free(monitored_processes);
        monitored_processes = NULL;
    }
    process_count = 0;
    
    LOG_INFO("Detection system cleaned up%s", "");
}

// Process a new event and update detection state
void detection_process_event(const Event *event, const Configuration *config) {
    if (!event || !config) {
        return;
    }
    
    // Get process information
    char process_name[256] = {0};
    char proc_comm_path[64];
    snprintf(proc_comm_path, sizeof(proc_comm_path), "/proc/%d/comm", event->process_id);
    FILE *f = fopen(proc_comm_path, "r");
    if (f) {
        if (fgets(process_name, sizeof(process_name), f)) {
            // Remove trailing newline
            size_t len = strlen(process_name);
            if (len > 0 && process_name[len - 1] == '\n') {
                process_name[len - 1] = '\0';
            }
        }
        fclose(f);
    }
    
    // Skip whitelisted processes
    if (config_is_process_whitelisted(process_name)) {
        return;
    }
    
    // Find or create monitor for this process
    ProcessMonitor *monitor = find_or_create_process_monitor(event->process_id, process_name);
    if (!monitor) {
        LOG_ERROR("Failed to create process monitor for pid %d", event->process_id);
        return;
    }
    
    // Add event to history
    monitor->event_history[monitor->history_index] = *event;
    monitor->history_index = (monitor->history_index + 1) % MAX_EVENT_HISTORY;
    if (monitor->event_count < MAX_EVENT_HISTORY) {
        monitor->event_count++;
    }
    
    // Update the first event time if this is the first event
    if (monitor->event_count == 1) {
        monitor->first_event = event->timestamp;
    }
    
    // Process the event for scoring
    scoring_process_event(&monitor->context, event, &monitor->patterns);
    
    // Analyze event sequences
    analyze_event_sequence(monitor, event);
    
    // Check file operation patterns
    check_file_operation_patterns(monitor);
    
    // Check process behavior patterns
    check_process_behavior(monitor);
    
    // Update detection scores
    update_detection_score(monitor);
    
    // Check if threat level requires action
    if (monitor->context.severity >= SEVERITY_MEDIUM) {
        LOG_WARNING("Suspicious activity detected in process %s (PID %d), score: %.2f", 
                   monitor->process_name, monitor->pid, monitor->context.total_score);
        
        // Log detailed information about the detection
        logger_detection(&monitor->context, "Suspicious file operation patterns detected");
        
        // Take action based on severity and configuration
        ResponseAction action = scoring_determine_action(monitor->context.severity, config);
        monitor->context.action = action;
        
        // Log the action taken
        logger_action(action, monitor->pid, monitor->process_name);
    }
}

// Find a process monitor or create one if it doesn't exist
static ProcessMonitor *find_or_create_process_monitor(pid_t pid, const char *process_name) {
    // First, try to find an existing monitor
    for (size_t i = 0; i < process_count; i++) {
        if (monitored_processes[i].pid == pid) {
            return &monitored_processes[i];
        }
    }
    
    // If we've reached the maximum, find the oldest one to replace
    if (process_count >= MAX_MONITORED_PROCESSES) {
        time_t oldest_time = time(NULL);
        size_t oldest_index = 0;
        
        for (size_t i = 0; i < process_count; i++) {
            if (monitored_processes[i].first_event < oldest_time) {
                oldest_time = monitored_processes[i].first_event;
                oldest_index = i;
            }
        }
        
        // Clear the oldest entry
        memset(&monitored_processes[oldest_index], 0, sizeof(ProcessMonitor));
        
        // Initialize the reused entry
        monitored_processes[oldest_index].pid = pid;
        strncpy(monitored_processes[oldest_index].process_name, process_name, sizeof(monitored_processes[oldest_index].process_name) - 1);
        monitored_processes[oldest_index].first_event = time(NULL);
        
        // Initialize detection context
        scoring_init_context(&monitored_processes[oldest_index].context, pid, process_name);
        memset(&monitored_processes[oldest_index].patterns, 0, sizeof(DetectionPatterns));
        
        return &monitored_processes[oldest_index];
    }
    
    // Create a new monitor
    monitored_processes[process_count].pid = pid;
    strncpy(monitored_processes[process_count].process_name, process_name, sizeof(monitored_processes[process_count].process_name) - 1);
    monitored_processes[process_count].first_event = time(NULL);
    monitored_processes[process_count].event_count = 0;
    monitored_processes[process_count].history_index = 0;
    
    // Initialize detection context
    scoring_init_context(&monitored_processes[process_count].context, pid, process_name);
    memset(&monitored_processes[process_count].patterns, 0, sizeof(DetectionPatterns));
    
    return &monitored_processes[process_count++];
}

// Analyze sequence of events to detect suspicious patterns
static void analyze_event_sequence(ProcessMonitor *monitor, const Event *new_event) {
    // Skip if we don't have enough events for analysis
    if (monitor->event_count < 3) {
        return;
    }
    
    // Check for read-encrypt-write pattern
    if (new_event->type == EVENT_FILE_MODIFY) {
        // Look for a read on the same file in recent history
        const char *write_path = new_event->data.file_event.path;
        time_t write_time = new_event->timestamp;
        bool found_read = false;
        
        // Scan back through history
        for (size_t i = 0; i < monitor->event_count; i++) {
            size_t idx = (monitor->history_index + MAX_EVENT_HISTORY - 1 - i) % MAX_EVENT_HISTORY;
            const Event *prev_event = &monitor->event_history[idx];
            
            // If we're looking too far back in time, stop searching
            if (write_time - prev_event->timestamp > TIME_WINDOW) {
                break;
            }
            
            if (prev_event->type == EVENT_FILE_ACCESS && 
                strcmp(prev_event->data.file_event.path, write_path) == 0) {
                found_read = true;
                break;
            }
        }
        
        // If we found a read followed by write with entropy increase, flag as suspicious
        if (found_read && 
            new_event->data.file_event.entropy_after > new_event->data.file_event.entropy_before + 20) {
            LOG_DEBUG("Detected possible encryption pattern in process %s (PID %d): %s",
                     monitor->process_name, monitor->pid, write_path);
            
            // Update pattern detection
            monitor->patterns.detected_encryption_pattern = true;
            monitor->patterns.entropy_increases++;
            monitor->patterns.avg_entropy_delta += 
                (new_event->data.file_event.entropy_after - new_event->data.file_event.entropy_before);
            
            // Mark sensitive files
            if (is_sensitive_file_type(write_path)) {
                monitor->patterns.sensitive_files_accessed++;
            }
        }
    }
    
    // Check for extension changes (potential ransomware renaming)
    if (new_event->type == EVENT_FILE_RENAME) {
        const char *old_path = new_event->data.file_event.path;
        const char *new_path = new_event->data.file_event.path; // In a real implementation, this would be the new path
        
        char *old_ext = strrchr(old_path, '.');
        char *new_ext = strrchr(new_path, '.');
        
        if (old_ext && new_ext && strcmp(old_ext, new_ext) != 0) {
            LOG_DEBUG("Detected file extension change in process %s (PID %d): %s to %s",
                     monitor->process_name, monitor->pid, old_ext, new_ext);
            
            monitor->patterns.file_extension_changes++;
            
            // Check if new extension matches known ransomware extensions
            const char *ransomware_extensions[] = {
                ".encrypted", ".locked", ".crypt", ".crypted", ".enc", ".ransom", 
                ".pays", ".wallet", ".cryptolocker", ".locky", NULL
            };
            
            for (int i = 0; ransomware_extensions[i] != NULL; i++) {
                if (strcmp(new_ext, ransomware_extensions[i]) == 0) {
                    // Higher score for known ransomware extensions
                    monitor->context.total_score += 15.0;
                    LOG_WARNING("Detected known ransomware extension: %s", new_ext);
                    break;
                }
            }
        }
    }
    
    // Check for mass file operations in short time
    time_t current_time = new_event->timestamp;
    int operations_in_window = 0;
    
    for (size_t i = 0; i < monitor->event_count; i++) {
        size_t idx = (monitor->history_index + MAX_EVENT_HISTORY - 1 - i) % MAX_EVENT_HISTORY;
        if (current_time - monitor->event_history[idx].timestamp <= TIME_WINDOW) {
            operations_in_window++;
        } else {
            break;
        }
    }
    
    // Update consecutive operations counter
    if (operations_in_window > 10) {
        monitor->patterns.consecutive_file_ops = operations_in_window;
        
        if (operations_in_window > 50) {
            LOG_WARNING("Process %s (PID %d) performing mass file operations: %d in %d seconds",
                       monitor->process_name, monitor->pid, operations_in_window, TIME_WINDOW);
        } else {
            LOG_DEBUG("Process %s (PID %d) performing multiple file operations: %d in %d seconds",
                     monitor->process_name, monitor->pid, operations_in_window, TIME_WINDOW);
        }
    }
}

// Check for suspicious file operation patterns
static void check_file_operation_patterns(ProcessMonitor *monitor) {
    // Update average entropy delta if we have entropy increases
    if (monitor->patterns.entropy_increases > 0) {
        monitor->patterns.avg_entropy_delta /= monitor->patterns.entropy_increases;
    }
    
    // Check for ransom note creation (text files with suspicious content)
    for (size_t i = 0; i < monitor->event_count; i++) {
        const Event *event = &monitor->event_history[i];
        
        if (event->type == EVENT_FILE_CREATE) {
            const char *path = event->data.file_event.path;
            char *ext = strrchr(path, '.');
            
            // Check for text files that might be ransom notes
            if (ext && (strcmp(ext, ".txt") == 0 || strcmp(ext, ".html") == 0)) {
                // In a real implementation, we would analyze file content
                // For now, just check if the filename contains suspicious keywords
                if (strstr(path, "README") || 
                    strstr(path, "HOW_TO") || 
                    strstr(path, "DECRYPT") || 
                    strstr(path, "RANSOM") || 
                    strstr(path, "HELP_") || 
                    strstr(path, "RECOVERY")) {
                    
                    LOG_WARNING("Possible ransom note creation detected: %s", path);
                    monitor->patterns.detected_ransom_note_creation = true;
                    monitor->context.total_score += 20.0;
                }
            }
        }
    }
}

// Check for suspicious process behavior
static void check_process_behavior(ProcessMonitor *monitor) {
    // In a real implementation, this would involve checking process relationships,
    // command-line arguments, and other behavior indicators
    
    // For now, we'll use a simple heuristic based on the patterns we've detected
    if (monitor->patterns.consecutive_file_ops > 20 && 
        monitor->patterns.entropy_increases > 5 && 
        monitor->patterns.file_extension_changes > 0) {
        
        LOG_WARNING("Process %s (PID %d) shows strong indicators of ransomware behavior",
                   monitor->process_name, monitor->pid);
                   
        // Apply a score multiplier for combined indicators
        monitor->context.total_score *= 1.5;
        if (monitor->context.total_score > 100.0) {
            monitor->context.total_score = 100.0;
        }
    }
}

// Check if a file is a sensitive document type
static int is_sensitive_file_type(const char *path) {
    if (!path) return 0;
    
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;
    
    // Common sensitive file types
    const char *sensitive_extensions[] = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", 
        ".jpg", ".jpeg", ".png", ".gif", ".psd", ".ai", 
        ".zip", ".rar", ".7z", ".tar", ".gz", 
        ".c", ".cpp", ".h", ".java", ".py", ".php", ".js", ".html", ".css",
        ".txt", ".md", ".csv", ".json", ".xml", 
        ".db", ".sql", ".mdb", ".accdb", ".sqlite",
        NULL
    };
    
    for (int i = 0; sensitive_extensions[i] != NULL; i++) {
        if (strcasecmp(ext, sensitive_extensions[i]) == 0) {
            return 1;
        }
    }
    
    return 0;
}

// Update the detection score based on all analysis
static void update_detection_score(ProcessMonitor *monitor) {
    // Reset component scores
    monitor->context.syscall_score = 0;
    monitor->context.memory_score = 0;
    monitor->context.process_score = 0;
    
    // Calculate syscall score
    if (monitor->patterns.consecutive_file_ops > 50) {
        monitor->context.syscall_score = 30.0;
    } else if (monitor->patterns.consecutive_file_ops > 20) {
        monitor->context.syscall_score = 15.0;
    } else if (monitor->patterns.consecutive_file_ops > 10) {
        monitor->context.syscall_score = 5.0;
    }
    
    // Add for entropy changes
    if (monitor->patterns.entropy_increases > 0) {
        float entropy_score = monitor->patterns.entropy_increases * 2.0;
        if (monitor->patterns.avg_entropy_delta > 30) {
            entropy_score *= 1.5;
        }
        monitor->context.syscall_score += entropy_score;
    }
    
    // Add for extension changes
    monitor->context.syscall_score += monitor->patterns.file_extension_changes * 5.0;
    
    // Add for sensitive files accessed
    monitor->context.syscall_score += monitor->patterns.sensitive_files_accessed * 1.0;
    
    // Calculate process score based on behavior
    if (monitor->patterns.detected_encryption_pattern) {
        monitor->context.process_score += 25.0;
    }
    
    if (monitor->patterns.detected_ransom_note_creation) {
        monitor->context.process_score += 35.0;
    }
    
    if (monitor->patterns.detected_shadow_copy_deletion) {
        monitor->context.process_score += 40.0;
    }
    
    // Update total score and determine severity
    scoring_update_total(&monitor->context);
    monitor->context.severity = scoring_assess_severity(
        monitor->context.total_score, NULL); // NULL for now, should be config
}

// Get the current detection status for a specific process
DetectionContext *detection_get_status(pid_t pid) {
    for (size_t i = 0; i < process_count; i++) {
        if (monitored_processes[i].pid == pid) {
            return &monitored_processes[i].context;
        }
    }
    return NULL;
}

// Get all monitored processes with suspicious activity
int detection_get_suspicious_processes(DetectionContext **contexts, size_t max_count) {
    if (!contexts || max_count == 0) {
        return 0;
    }
    
    int count = 0;
    for (size_t i = 0; i < process_count && (size_t)count < max_count; i++) {
        if (monitored_processes[i].context.severity >= SEVERITY_LOW) {
            contexts[count++] = &monitored_processes[i].context;
        }
    }
    
    return count;
}

// Implement these functions:

void detection_poll(void) {
    // Poll each monitor
    process_monitor_poll();
    memory_monitor_poll();
    
    // Update detection status
    update_detection_status();
}

void detection_handle_event(const Event* event) {
    if (!event) {
        return;
    }
    
    // Process event based on type
    detection_process_event(event);
    
    // Update threat score
    update_threat_score(event);
}

int detection_add_process(pid_t pid) {
    // Add process to monitoring
    int result = process_monitor_add_process(pid);
    if (result == 0) {
        result = memory_monitor_add_process(pid);
    }
    return result;
}

void detection_remove_process(pid_t pid) {
    // Remove process from monitoring
    process_monitor_remove_process(pid);
    memory_monitor_remove_process(pid);
}
