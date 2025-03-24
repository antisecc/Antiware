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

// Forward declarations for monitor interfaces
extern void process_monitor_poll(void);
extern void memory_monitor_remove_process(pid_t pid);
extern int process_monitor_add_process(pid_t pid);
extern void process_monitor_remove_process(pid_t pid);

extern int memory_monitor_poll(void);
extern int memory_monitor_add_process(pid_t pid);
extern Configuration* config_get_current(void);
// Forward declarations for user filter functions
extern float user_filter_adjust_score(pid_t pid, float original_score, const BehaviorFlags* behavior);
extern int user_filter_is_whitelisted(pid_t pid, const char* process_name, const char* path);

// Forward declarations for context management
static void update_detection_status(void);
static void check_threat_thresholds(pid_t pid);
static DetectionContext* get_detection_context(pid_t pid);
static void add_detection_context(pid_t pid, DetectionContext* context);
static void remove_detection_context(pid_t pid);

// Process helpers
void get_process_name_from_pid(pid_t pid, char* buffer, size_t buffer_size);
void get_process_path_from_pid(pid_t pid, char* buffer, size_t buffer_size);

// Hash table for detection contexts (simple implementation)
#define MAX_DETECTION_CONTEXTS 1024
static struct {
    pid_t pid;
    DetectionContext* context;
    int used;
} detection_contexts[MAX_DETECTION_CONTEXTS];

static void init_detection_contexts(void) {
    static int initialized = 0;
    if (!initialized) {
        memset(detection_contexts, 0, sizeof(detection_contexts));
        initialized = 1;
    }
}

static DetectionContext* get_detection_context(pid_t pid) {
    init_detection_contexts();
    
    // Simple linear search (could be improved with hash table)
    for (int i = 0; i < MAX_DETECTION_CONTEXTS; i++) {
        if (detection_contexts[i].used && detection_contexts[i].pid == pid) {
            return detection_contexts[i].context;
        }
    }
    
    return NULL;
}

static void add_detection_context(pid_t pid, DetectionContext* context) {
    init_detection_contexts();
    
    // Find an empty slot
    for (int i = 0; i < MAX_DETECTION_CONTEXTS; i++) {
        if (!detection_contexts[i].used) {
            detection_contexts[i].pid = pid;
            detection_contexts[i].context = context;
            detection_contexts[i].used = 1;
            return;
        }
    }
    
    // If no empty slot, overwrite the first entry (not ideal but prevents leaks)
    LOG_WARNING("Detection context table full, overwriting first entry%s", "");
    detection_contexts[0].pid = pid;
    detection_contexts[0].context = context;
    detection_contexts[0].used = 1;
}

static void remove_detection_context(pid_t pid) {
    init_detection_contexts();
    
    for (int i = 0; i < MAX_DETECTION_CONTEXTS; i++) {
        if (detection_contexts[i].used && detection_contexts[i].pid == pid) {
            detection_contexts[i].used = 0;
            detection_contexts[i].pid = 0;
            detection_contexts[i].context = NULL;
            return;
        }
    }
}

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


/**
 * Polls all monitoring components for suspicious activity
 * Called periodically by the main polling thread
 */
void detection_poll(void) {
    // Poll individual monitoring components
    process_monitor_poll();
    memory_monitor_poll();
    
    // Process any pending events from the monitoring components
    // This is a coordinating function that ensures all monitors are checked
    
    // Check for process relationship changes (parent-child)
    // These might indicate process injection or malicious spawning
    
    // Update global threat scores based on recent activity
    update_detection_status();
    
    LOG_DEBUG("Detection poll completed%s", "");
}

/**
 * Handles security events from monitoring components
 * Primary entry point for event-driven detection
 */
void detection_handle_event(const Event* event) {
    if (!event) {
        LOG_ERROR("Null event passed to detection handler%s", "");
        return;
    }
    
    // Get configuration
    Configuration* config = config_get_current();
    if (!config) {
        LOG_ERROR("Failed to get configuration for event handling%s", "");
        return;
    }
    
    // First, check if the process is whitelisted
    BehaviorFlags behavior = {0}; // Initialize empty behavior flags
    
    // Extract behavior from event if possible
    if (event->type == EVENT_FILE_ACCESS || 
        event->type == EVENT_FILE_MODIFY) {
        behavior.rapid_file_access = 1;
    } else if (event->type == EVENT_PROCESS_CREATE) {
        behavior.high_process_activity = 1;  // Use existing field instead of rapid_process_spawning
    }
    
    float score_adjustment = user_filter_adjust_score(
        event->process_id, 
        event->score_impact,
        &behavior);
    
    // If significantly reduced by user filter, may skip processing
    if (score_adjustment < 0.1f * event->score_impact) {
        LOG_DEBUG("Event filtered due to whitelist/trust: PID %d", event->process_id);
        return;
    }
    
    // Process the event through the main detection logic
    detection_process_event(event, config);
    
    // Check if we need to take immediate action based on updated scores
    check_threat_thresholds(event->process_id);
}

/**
 * Adds a process to the monitoring and detection system
 * Called when a new process is discovered or started
 */
int detection_add_process(pid_t pid) {
    // Check if the process should be monitored (not system critical)
    char process_name[256] = {0};
    char process_path[1024] = {0};
    
    // Get basic process info
    get_process_name_from_pid(pid, process_name, sizeof(process_name));
    get_process_path_from_pid(pid, process_path, sizeof(process_path));
    
    LOG_DEBUG("Adding process to monitoring: %s (PID: %d)", process_name, pid);
    
    // Check if this process should be whitelisted
    if (user_filter_is_whitelisted(pid, process_name, process_path)) {
        LOG_DEBUG("Process whitelisted, minimal monitoring: %s (PID: %d)", 
                 process_name, pid);
        // Add with whitelist flag for minimal monitoring
        return process_monitor_add_process(pid);
    }
    
    // Add to process monitoring
    int result = process_monitor_add_process(pid);
    if (result != 0) {
        LOG_ERROR("Failed to add process to monitor: %s (PID: %d)", 
                 process_name, pid);
        return result;
    }
    
    // Add to memory monitoring
    result = memory_monitor_add_process(pid);
    if (result != 0) {
        LOG_ERROR("Failed to add process to memory monitor: %s (PID: %d)", 
                 process_name, pid);
        // Continue anyway, partial monitoring is better than none
    }
    
    // Initialize detection context for this process
    DetectionContext* context = malloc(sizeof(DetectionContext));
    if (context) {
        scoring_init_context(context, pid, process_name);
        // Store context in a global map or linked list
        add_detection_context(pid, context);
    }
    
    return 0;
}

/**
 * Removes a process from the monitoring and detection system
 * Called when a process terminates
 */
void detection_remove_process(pid_t pid) {
    // Get process info before removing
    char process_name[256] = {0};
    get_process_name_from_pid(pid, process_name, sizeof(process_name));
    
    LOG_DEBUG("Removing process from monitoring: %s (PID: %d)", 
             process_name, pid);
    
    // Remove from all monitoring components
    process_monitor_remove_process(pid);
    memory_monitor_remove_process(pid);
    
    // Free detection context if it exists
    DetectionContext* context = get_detection_context(pid);
    if (context) {
        // Log final status before removing
        if (context->total_score > 30.0f) {
            // Create message string for detection logger
            char message[512];
            snprintf(message, sizeof(message), 
                    "Process terminated with suspicion score %.1f: %s (PID: %d)",
                    context->total_score, process_name, pid);
            
            // Call logger with proper parameters
            logger_detection(context, message);
        }
        
        free(context);
        remove_detection_context(pid);
    }
}

// Helper functions that may need implementation:

void get_process_name_from_pid(pid_t pid, char* buffer, size_t buffer_size) {
    // Implementation depends on what's available in your codebase
    // This might call process_monitor_get_process_name or similar
    snprintf(buffer, buffer_size, "unknown"); // Default
    
    // Try to get from /proc/[pid]/comm
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);
    
    FILE* f = fopen(proc_path, "r");
    if (f) {
        if (fgets(buffer, buffer_size, f)) {
            // Remove trailing newline
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len-1] == '\n') {
                buffer[len-1] = '\0';
            }
        }
        fclose(f);
    }
}

void get_process_path_from_pid(pid_t pid, char* buffer, size_t buffer_size) {
    // Implementation depends on what's available in your codebase
    snprintf(buffer, buffer_size, "unknown"); // Default
    
    // Try to get from /proc/%d/exe
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    
    ssize_t len = readlink(proc_path, buffer, buffer_size - 1);
    if (len > 0) {
        buffer[len] = '\0';
    }
}

// Updates the overall detection status based on all monitor data
static void update_detection_status(void) {
    // Check all monitored processes for changes in threat level
    // This would aggregate data across all monitoring components
    
    // For now, this is a placeholder that just logs the call
    LOG_DEBUG("Updating detection status%s", "");
    
    // In a complete implementation, this would:
    // 1. Check all process monitors for high scores
    // 2. Update global threat assessment
    // 3. Trigger appropriate responses based on threat level
}

// Check if a process has crossed a threat threshold requiring action
static void check_threat_thresholds(pid_t pid) {
    DetectionContext* context = get_detection_context(pid);
    if (!context) {
        return;
    }
    
    // Get the current config for thresholds
    Configuration* config = config_get_current();
    if (!config) {
        LOG_ERROR("Failed to get configuration for threshold check%s", "");
        return;
    }
    
    // Check if severity requires action
    if (context->severity >= SEVERITY_MEDIUM) {
        char process_name[256] = {0};
        get_process_name_from_pid(pid, process_name, sizeof(process_name));
        
        LOG_WARNING("Process %s (PID %d) has crossed threat threshold: %.2f", 
                   process_name, pid, context->total_score);
        
        // Create message for detection log
        char message[512];
        snprintf(message, sizeof(message), 
                "Process has suspicious behavior score %.1f", 
                context->total_score);
        
        // Log detection with proper arguments
        logger_detection(context, message);
        
        // Determine and take action
        ResponseAction action = scoring_determine_action(context->severity, config);
        context->action = action;
        
        // Log the action
        logger_action(action, pid, process_name);
    }
}