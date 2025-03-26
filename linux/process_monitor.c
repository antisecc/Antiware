#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <strings.h>

#include "../include/antiransom.h"
#include "../include/events.h"
#include "../common/logger.h"
#include "../common/scoring.h"

// Maximum number of processes to monitor
#define MAX_MONITORED_PROCESSES 128

// Maximum length for path and command line
#define MAX_PATH_LENGTH 1024
#define MAX_CMDLINE_LENGTH 4096

// Polling interval in milliseconds
#define PROCESS_POLL_INTERVAL 1000

// Suspicious rapid file access threshold (files per second)
#define RAPID_FILE_ACCESS_THRESHOLD 10

// Suspicious process spawn threshold (number per minute)
#define RAPID_SPAWN_THRESHOLD 5

// Time window for child process tracking (seconds)
#define CHILD_TRACK_WINDOW 60

// Maximum number of children to track per process
#define MAX_CHILDREN_PER_PROCESS 32

// Number of history entries to maintain per process
#define BEHAVIOR_HISTORY_SIZE 10  

// Time window for behavioral analysis (seconds)
#define SHORT_TERM_WINDOW 60
#define MEDIUM_TERM_WINDOW 300
#define LONG_TERM_WINDOW 1800

// Monitoring levels for adaptive monitoring
#define MONITORING_LEVEL_LOW     1   // Minimal monitoring
#define MONITORING_LEVEL_MEDIUM  2   // Standard monitoring
#define MONITORING_LEVEL_HIGH    3   // Detailed monitoring
#define MONITORING_LEVEL_INTENSE 4   // Every possible check

// Structure to track a child process
typedef struct {
    pid_t pid;
    time_t spawn_time;
    char comm[256];
} ChildProcess;

// Structure to track a process behavior event
typedef struct {
    time_t timestamp;
    EventType type;
    float severity;
    char details[128];
} BehaviorEvent;

// Structure to track process information
typedef struct {
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    uid_t euid;
    char comm[256];
    char cmdline[MAX_CMDLINE_LENGTH];
    char exe_path[MAX_PATH_LENGTH];
    char cwd[MAX_PATH_LENGTH];
    
    // Process status
    int status;
    
    // Time tracking
    time_t first_seen;
    time_t last_updated;
    
    // File access tracking
    int file_access_count;
    time_t last_file_access_time;
    float file_access_rate;
    
    // Child process tracking
    ChildProcess children[MAX_CHILDREN_PER_PROCESS];
    int child_count;
    int spawn_rate; // processes per minute
    
    // Suspicious flags
    int is_from_suspicious_location;
    int has_suspicious_name;
    int has_suspicious_cmdline;
    int has_elevated_privileges;
    int has_rapid_file_access;
    int has_rapid_process_spawning;
    
    // Overall suspicion score (0-100)
    float suspicion_score;

    // Behavioral analysis
    BehaviorEvent behavior_history[BEHAVIOR_HISTORY_SIZE];
    int behavior_history_idx;
    time_t last_behavior_analysis;
    
    // Short and long term behavior statistics
    float short_term_risk;   // Last minute
    float medium_term_risk;  // Last 5 minutes
    float long_term_risk;    // Last 30 minutes
    
    // Correlated detection flags
    int memory_suspicious;   // Set if memory monitor flags this process
    int syscall_suspicious;  // Set if syscall monitor flags this process
    int file_types_accessed[5]; // Count of different file types accessed: docs, media, archives, etc.
    int consecutive_file_ops; // Track sequential operations
    time_t last_file_op_time;
    
    // Process lineage
    int is_system_launched;  // Process started by system
    int is_user_launched;    // Process started by user
    int ancestry_suspicious; // Launched by a suspicious process

    // Historical profiling data
    int execution_count;               // How many times we've seen this process
    time_t first_execution_time;       // When we first saw this process
    float historical_max_score;        // Historical maximum suspicion score
    float score_deviation;             // How much score typically fluctuates
    int false_positive_count;          // Times flagged but later deemed legitimate
    uint32_t process_hash;             // Hash of process path for consistent identification
    float contextual_trust_multiplier;  // Multiplier for trust level based on context

    // Memory statistics
    unsigned long memory_usage_kb;     // Current memory usage
    unsigned long prev_memory_usage_kb; // Previous memory usage
    float memory_growth_rate;          // Rate of memory increase
    time_t last_memory_check;          // When we last checked memory
    int high_entropy_buffers;          // Count of high-entropy memory regions
    int has_suspicious_memory;         // Memory monitoring flag

    // Adaptive monitoring
    int monitoring_level;                // Level of monitoring detail
    time_t last_level_adjustment;        // When we last adjusted monitoring level
    int monitoring_events_processed;     // Events processed since last adjustment
    time_t elevated_monitoring_until;    // Time until which heightened monitoring is active
    time_t elevated_monitoring_until;   // Timestamp until which monitoring is elevated
    struct file_attr* file_attributes;  // Optional file attributes (download time, etc.)

    ProcessOrigin origin;         // Classification of where process originated
} ProcessInfo;

// Process monitoring level
typedef enum {
    MONITORING_LEVEL_NONE = 0,
    MONITORING_LEVEL_LOW,
    MONITORING_LEVEL_NORMAL,
    MONITORING_LEVEL_HIGH
} MonitoringLevel;

// Process context for advanced monitoring
typedef struct ProcessContext {
    pid_t pid;
    char command[256];
    char path[MAX_PATH_LENGTH];
    MonitoringLevel monitoring_level;
    time_t creation_time;
    time_t last_update_time;
    int suspicious_score;
    unsigned int flags;
} ProcessContext;

// Maximum number of process contexts to maintain
#define MAX_PROCESS_CONTEXTS 256

// Global process context storage
static ProcessContext* process_contexts[MAX_PROCESS_CONTEXTS];
static int process_context_count = 0;

// Global state
static ProcessInfo monitored_processes[MAX_MONITORED_PROCESSES];
static int process_count = 0;
static time_t last_poll_time = 0;
static EventHandler event_callback = NULL;
static void* event_callback_data = NULL;

// Current user info for detecting privilege escalation
static uid_t current_user_uid = 0;
static char current_user_home[MAX_PATH_LENGTH] = {0};

// Forward declarations
static ProcessInfo* find_process_info(pid_t pid);
static ProcessInfo* add_process_info(pid_t pid);
static void remove_process_info(pid_t pid);
static void update_process_info(ProcessInfo* proc);
static void scan_processes(void);
static void analyze_process(ProcessInfo* proc);
static void check_suspicious_location(ProcessInfo* proc);
static void check_suspicious_name(ProcessInfo* proc);
static void check_suspicious_cmdline(ProcessInfo* proc);
static void check_privilege_escalation(ProcessInfo* proc);
static void update_process_suspicious_score(ProcessInfo* proc);
static int read_proc_file(pid_t pid, const char* file, char* buffer, size_t buffer_size);
static void generate_process_event(pid_t pid, EventType type, const char* details, float score_impact);
static void add_child_process(ProcessInfo* parent, pid_t child_pid, const char* child_comm);
static int is_process_alive(pid_t pid);
static void remove_old_children(ProcessInfo* proc);

// Forward declarations for process context management
static ProcessContext* create_process_context(pid_t pid);
static void free_process_context(ProcessContext* context);
static void add_process_context(ProcessContext* context);
static ProcessContext* get_process_context(pid_t pid);
static int is_system_utility(const char* process_name, const char* path);
static int is_numeric(const char* str);
static int get_process_info(pid_t pid, char* exe_path, size_t exe_path_size,
                          char* cmdline, size_t cmdline_size,
                          char* process_name, size_t process_name_size);

// Process origin classification
typedef enum {
    ORIGIN_UNKNOWN = 0,
    ORIGIN_SYSTEM,            // System directory
    ORIGIN_USER_INSTALLED,    // User-installed application
    ORIGIN_HOME_DIRECTORY,    // User's home directory
    ORIGIN_PACKAGE_MANAGER,   // Package manager
    ORIGIN_HIGH_RISK,         // Temp or other high-risk directory
    ORIGIN_RECENT_DOWNLOAD    // Recently downloaded file
} ProcessOrigin;

// Initialize the process monitor
int process_monitor_init(EventHandler handler, void* user_data) {
    memset(monitored_processes, 0, sizeof(monitored_processes));
    process_count = 0;
    last_poll_time = time(NULL);
    event_callback = handler;
    event_callback_data = user_data;
    
    // Initialize process context array
    memset(process_contexts, 0, sizeof(process_contexts));
    process_context_count = 0;
    
    // Get the current user info
    current_user_uid = getuid();
    struct passwd* pw = getpwuid(current_user_uid);
    if (pw != NULL) {
        strncpy(current_user_home, pw->pw_dir, sizeof(current_user_home) - 1);
    }
    
    LOG_INFO("Process monitor initialized (uid: %d)", current_user_uid);
    return 0;
}

// Clean up resources
void process_monitor_cleanup(void) {
    // Free all process contexts
    for (int i = 0; i < process_context_count; i++) {
        if (process_contexts[i]) {
            free_process_context(process_contexts[i]);
            process_contexts[i] = NULL;
        }
    }
    process_context_count = 0;
    
    // Reset process info array
    process_count = 0;
    
    LOG_INFO("Process monitor cleaned up%s", "");
}

// Poll processes for changes with batched processing
void process_monitor_poll(void) {
    time_t now = time(NULL);
    static int scan_counter = 0;
    
    // Only poll at the configured interval
    if (now - last_poll_time < PROCESS_POLL_INTERVAL / 1000) {
        return;
    }
    
    // Update last poll time
    last_poll_time = now;
    
    // Only do full scan every 5th poll to reduce overhead
    scan_counter++;
    if (scan_counter >= 5) {
        scan_processes();
        scan_counter = 0;
    }
    
    // Check each monitored process - use batching to limit overhead
    // Process only a subset of processes each time to distribute load
    int max_processes_per_poll = process_count > 20 ? process_count / 4 : process_count;
    static int last_process_idx = 0;
    
    int processes_checked = 0;
    for (int i = 0; i < process_count && processes_checked < max_processes_per_poll; i++) {
        // Calculate index with rotation to ensure all processes get checked
        int idx = (last_process_idx + i) % process_count;
        ProcessInfo* proc = &monitored_processes[idx];
        
        // Skip recently updated processes
        if (now - proc->last_updated < PROCESS_POLL_INTERVAL / 1000) {
            continue;
        }
        
        processes_checked++;
        
        // Check if process still exists
        if (!is_process_alive(proc->pid)) {
            LOG_INFO("Process %d (%s) terminated, removing from monitor", 
                     proc->pid, proc->comm);
            remove_process_info(proc->pid);
            i--; // Adjust index because we removed an element
            continue;
        }
        
        // Update process information
        update_process_info(proc);
        
        // Update memory statistics
        update_process_memory_stats(proc);
        
        // Update historical profile
        update_process_profile(proc);
        
        // Adjust monitoring level 
        adjust_monitoring_level(proc);
        
        // Analyze for suspicious behavior
        analyze_process(proc);
        
        // Remove old child entries
        remove_old_children(proc);
        
        // Update timestamp
        proc->last_updated = now;
    }
    
    // Update the last process index for the next poll
    last_process_idx = (last_process_idx + processes_checked) % process_count;
    
    // Every minute, perform additional analysis
    static time_t last_deep_analysis = 0;
    if (now - last_deep_analysis > 60) {
        // Deep analyze the most suspicious processes
        for (int i = 0; i < process_count; i++) {
            if (monitored_processes[i].suspicion_score > 40.0f) {
                analyze_behavior_patterns(&monitored_processes[i]);
                correlate_monitoring_data(&monitored_processes[i]);
            }
        }
        
        // Analyze process relationships
        propagate_process_suspicion();
        
        // Apply risk decay to all processes
        apply_risk_decay();
        
        last_deep_analysis = now;
    }
}

// Register a file access event for a process
                strcasecmp(ext, ".ppt") == 0 || strcasecmp(ext, ".pptx") == 0 ||
                strcasecmp(ext, ".pdf") == 0 || strcasecmp(ext, ".txt") == 0) {
                proc->file_types_accessed[0]++;
            }
            // Media
            else if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0 ||
                     strcasecmp(ext, ".png") == 0 || strcasecmp(ext, ".gif") == 0 ||
                     strcasecmp(ext, ".mp3") == 0 || strcasecmp(ext, ".mp4") == 0 ||
                     strcasecmp(ext, ".avi") == 0 || strcasecmp(ext, ".mov") == 0) {
                proc->file_types_accessed[1]++;
            }
            // Archives
            else if (strcasecmp(ext, ".zip") == 0 || strcasecmp(ext, ".rar") == 0 ||
                     strcasecmp(ext, ".7z") == 0 || strcasecmp(ext, ".tar") == 0 ||
                     strcasecmp(ext, ".gz") == 0 || strcasecmp(ext, ".bz2") == 0) {
                proc->file_types_accessed[2]++;
            }
            // Code/Config
            else if (strcasecmp(ext, ".c") == 0 || strcasecmp(ext, ".cpp") == 0 ||
                     strcasecmp(ext, ".h") == 0 || strcasecmp(ext, ".py") == 0 ||
                     strcasecmp(ext, ".js") == 0 || strcasecmp(ext, ".html") == 0 ||
                     strcasecmp(ext, ".css") == 0 || strcasecmp(ext, ".xml") == 0 ||
                     strcasecmp(ext, ".json") == 0 || strcasecmp(ext, ".yml") == 0 ||
                     strcasecmp(ext, ".ini") == 0 || strcasecmp(ext, ".conf") == 0) {
                proc->file_types_accessed[3]++;
            }
            // Others
            else {
                proc->file_types_accessed[4]++;
            }
        }
        
        // Track sequential operations
        if (time_diff < 2) { // Within 2 seconds
            proc->consecutive_file_ops++;
            
            // Detect sequential operations on different file types (ransomware pattern)
            if (proc->consecutive_file_ops > 20 && 
                proc->file_types_accessed[0] > 5 && 
                proc->file_types_accessed[1] > 5) {
                
                // This is highly suspicious - rapid sequential operations on multiple file types
                char details[256];
                snprintf(details, sizeof(details), 
                        "Suspicious sequential operations on multiple file types: %d consecutive operations",
                        proc->consecutive_file_ops);
                
                LOG_WARNING("Process %d (%s) performing sequential file operations on multiple file types",
                           proc->pid, proc->comm);
                
                generate_process_event(proc->pid, EVENT_PROCESS_BEHAVIOR, details, 35.0f);
                
                // Record this highly suspicious behavior
                record_behavior_event(proc, EVENT_PROCESS_BEHAVIOR, 35.0f, details);
            }
        } else {
            // Reset consecutive counter if operations are not rapid
            proc->consecutive_file_ops = 1;
        }
    }
    
    // Check for rapid file access
    if (proc->file_access_rate > RAPID_FILE_ACCESS_THRESHOLD) {
        if (!proc->has_rapid_file_access) {
            proc->has_rapid_file_access = 1;
            
            LOG_WARNING("Process %d (%s) shows rapid file access rate: %.2f files/sec",
                       proc->pid, proc->comm, proc->file_access_rate);
            
            char details[256];
            snprintf(details, sizeof(details), 
                    "Rapid file access rate: %.2f files/sec (threshold: %d)",
                    proc->file_access_rate, RAPID_FILE_ACCESS_THRESHOLD);
            
            // Generate event for rapid file access
            generate_process_event(proc->pid, EVENT_PROCESS_BEHAVIOR, details, 15.0f);
            
            // Record this behavior
            record_behavior_event(proc, EVENT_PROCESS_BEHAVIOR, 15.0f, details);
        }
    }
    
    // Detect read-then-write pattern (common in ransomware)
    if (write_access && proc->last_file_op_time > 0 && (now - proc->last_file_op_time < 1)) {
        // The sequential read-write pattern on many files is suspicious
        if (proc->consecutive_file_ops > 10) {
            char details[256];
            snprintf(details, sizeof(details), 
                    "Sequential read-write pattern detected on multiple files (%d operations)",
                    proc->consecutive_file_ops);
            
            LOG_WARNING("Process %d (%s) showing read-write pattern on multiple files",
                      proc->pid, proc->comm);
            
            // Generate event only every 20 operations to avoid spamming
            if (proc->consecutive_file_ops % 20 == 0) {
                generate_process_event(proc->pid, EVENT_PROCESS_BEHAVIOR, details, 20.0f);
                
                // Record this behavior
                record_behavior_event(proc, EVENT_PROCESS_BEHAVIOR, 20.0f, details);
            }
        }
    }
    
    // Update last access time and op type
    proc->last_file_access_time = now;
    proc->last_file_op_time = now;
    
    // Update suspicion score based on new information
    update_process_suspicious_score(proc);
    
    // Analyze behavior patterns on a schedule
    analyze_behavior_patterns(proc);
    
    // Correlate with other monitoring systems
    correlate_monitoring_data(proc);
}

// Register a new process (parent-child relationship)
// Update process_monitor_new_process with improved lineage tracking
void process_monitor_new_process(pid_t parent_pid, pid_t child_pid) {
    // Find or create parent process info
    ProcessInfo* parent = find_process_info(parent_pid);
    if (!parent) {
        parent = add_process_info(parent_pid);
        if (!parent) {
            return;
        }
        update_process_info(parent);
    }
    
    // Get child process info
    char comm[256] = {"<unknown>"};
    char exe_path[MAX_PATH_LENGTH] = {0};
    char cmdline[MAX_CMDLINE_LENGTH] = {0};
    
    // Get more complete child process information
    get_process_info(child_pid, exe_path, sizeof(exe_path), 
                    cmdline, sizeof(cmdline), 
                    comm, sizeof(comm));
    
    // Add child to parent's children list
    add_child_process(parent, child_pid, comm);
    
    // Calculate spawn rate (processes per minute)
    time_t now = time(NULL);
    time_t minute_ago = now - 60;
    int spawns_in_last_minute = 0;
    
    for (int i = 0; i < parent->child_count; i++) {
        if (parent->children[i].spawn_time > minute_ago) { 
            spawns_in_last_minute++;
        }
    }
    
    parent->spawn_rate = spawns_in_last_minute;
    
    // Check for rapid process spawning
    if (parent->spawn_rate > RAPID_SPAWN_THRESHOLD && !parent->has_rapid_process_spawning) {
        parent->has_rapid_process_spawning = 1;
        
        LOG_WARNING("Process %d (%s) shows rapid process creation: %d processes/min",
                   parent->pid, parent->comm, parent->spawn_rate);
        
        char details[256];
        snprintf(details, sizeof(details), 
                "Rapid process creation: %d processes/min (threshold: %d)",
                parent->spawn_rate, RAPID_SPAWN_THRESHOLD);
        
        // Generate event for rapid process spawning
        generate_process_event(parent->pid, EVENT_PROCESS_BEHAVIOR, details, 10.0f);
        
        // Record this behavior
        record_behavior_event(parent, EVENT_PROCESS_BEHAVIOR, 10.0f, details);
    }
    
    // Also add the child to our monitoring list
    ProcessInfo* child = find_process_info(child_pid);
    if (!child) {
        child = add_process_info(child_pid);
        if (child) {
            update_process_info(child);
            
            // Set process lineage information
            child->is_system_launched = is_system_utility(parent->comm, parent->exe_path);
            child->is_user_launched = (parent->uid == current_user_uid);
            
            // If parent is suspicious, child is also suspicious by lineage
            child->ancestry_suspicious = (parent->suspicion_score > 30.0f);
            
            if (child->ancestry_suspicious) {
                LOG_WARNING("Process %d (%s) has suspicious parent %d (%s) with score %.2f",
                           child->pid, child->comm, parent->pid, parent->comm, parent->suspicion_score);
                
                char details[256];
                snprintf(details, sizeof(details), 
                        "Process created by suspicious parent (PID %d, %s) with score %.2f",
                        parent->pid, parent->comm, parent->suspicion_score);
                
                generate_process_event(child->pid, EVENT_PROCESS_LINEAGE, details, 15.0f);
                
                // Record this behavior
                record_behavior_event(child, EVENT_PROCESS_LINEAGE, 15.0f, details);
            }
            
            analyze_process(child);
        }
    }
    
    // Update suspicion score based on new information
    update_process_suspicious_score(parent);
}

// Get process monitoring statistics
int process_monitor_get_stats(pid_t pid, ProcessStats* stats) {
    if (!stats) {
        return -1;
    }
    
    ProcessInfo* proc = find_process_info(pid);
    if (!proc) {
        return -1;
    }
    
    stats->file_access_rate = proc->file_access_rate;
    stats->spawn_rate = proc->spawn_rate;
    stats->is_from_suspicious_location = proc->is_from_suspicious_location;
    stats->has_suspicious_name = proc->has_suspicious_name;
    stats->has_suspicious_cmdline = proc->has_suspicious_cmdline;
    stats->has_elevated_privileges = proc->has_elevated_privileges;
    stats->has_rapid_file_access = proc->has_rapid_file_access;
    stats->has_rapid_process_spawning = proc->has_rapid_process_spawning;
    stats->suspicion_score = proc->suspicion_score;
    
    return 0;
}

// Scan all processes on the system
static void scan_processes(void) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        LOG_ERROR("Failed to open /proc directory: %s", strerror(errno));
        return;
    }
    
    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        // Only process numeric directories (PIDs)
        if (entry->d_type != DT_DIR) {
            continue;
        }
        
        // Check if the directory name is a number
        char* endptr;
        pid_t pid = (pid_t)strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0') {
            continue;  // Not a PID directory
        }
        
        // Skip processes we're already monitoring
        if (find_process_info(pid) != NULL) {
            continue;
        }
        
        // Check if we can access this process (it belongs to us)
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/status", pid);
        if (access(proc_path, R_OK) != 0) {
            continue;  // Can't access, skip
        }
        
        // Add process to monitoring
        ProcessInfo* proc = add_process_info(pid);
        if (proc) {
            update_process_info(proc);
            analyze_process(proc);
        }
    }
    
    closedir(proc_dir);
}

// Find a process in the monitoring list
static ProcessInfo* find_process_info(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (monitored_processes[i].pid == pid) {
            return &monitored_processes[i];
        }
    }
    return NULL;
}

// Add a process to the monitoring list
static ProcessInfo* add_process_info(pid_t pid) {
    if (process_count >= MAX_MONITORED_PROCESSES) {
        // Find the least suspicious process to replace
        int least_suspicious_idx = 0;
        float min_score = monitored_processes[0].suspicion_score;
        
        for (int i = 1; i < process_count; i++) {
            if (monitored_processes[i].suspicion_score < min_score) {
                min_score = monitored_processes[i].suspicion_score;
                least_suspicious_idx = i;
            }
        }
        
        // Only replace if the current process has a very low score
        if (min_score < 5.0f) {
            LOG_INFO("Replacing least suspicious process %d (%s, score: %.2f) in monitor",
                     monitored_processes[least_suspicious_idx].pid,
                     monitored_processes[least_suspicious_idx].comm,
                     min_score);
            
            // Clear the slot
            memset(&monitored_processes[least_suspicious_idx], 0, sizeof(ProcessInfo));
            monitored_processes[least_suspicious_idx].pid = pid;
            monitored_processes[least_suspicious_idx].first_seen = time(NULL);
            monitored_processes[least_suspicious_idx].last_updated = time(NULL);
            monitored_processes[least_suspicious_idx].behavior_history_idx = 0;
            monitored_processes[least_suspicious_idx].last_behavior_analysis = 0;
            monitored_processes[least_suspicious_idx].short_term_risk = 0.0f;
            monitored_processes[least_suspicious_idx].medium_term_risk = 0.0f;
            monitored_processes[least_suspicious_idx].long_term_risk = 0.0f;
            monitored_processes[least_suspicious_idx].last_file_op_time = 0;
            monitored_processes[least_suspicious_idx].consecutive_file_ops = 0;
            
            return &monitored_processes[least_suspicious_idx];
        }
        
        LOG_WARNING("Maximum number of monitored processes reached, cannot add %d", pid);
        return NULL;
    }
    
    // Add to the end of the array
    ProcessInfo* proc = &monitored_processes[process_count++];
    memset(proc, 0, sizeof(ProcessInfo));
    proc->pid = pid;
    proc->first_seen = time(NULL);
    proc->last_updated = time(NULL);
    proc->behavior_history_idx = 0;
    proc->last_behavior_analysis = 0;
    proc->short_term_risk = 0.0f;
    proc->medium_term_risk = 0.0f;
    proc->long_term_risk = 0.0f;
    proc->last_file_op_time = 0;
    proc->consecutive_file_ops = 0;
    
    return proc;
}

// Remove a process from the monitoring list
static void remove_process_info(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (monitored_processes[i].pid == pid) {
            // Move the last process to this slot
            if (i < process_count - 1) {
                monitored_processes[i] = monitored_processes[process_count - 1];
            }
            process_count--;
            return;
        }
    }
}

// Update information about a process
static void update_process_info(ProcessInfo* proc) {
    char buffer[4096];
    
    // Read process status
    if (read_proc_file(proc->pid, "status", buffer, sizeof(buffer)) > 0) {
        // Parse status file to extract information
        char* line = strtok(buffer, "\n");
        while (line != NULL) {
            if (strncmp(line, "Name:", 5) == 0) {
                sscanf(line, "Name: %255s", proc->comm);
            } else if (strncmp(line, "PPid:", 5) == 0) {
                sscanf(line, "PPid: %d", &proc->ppid);
            } else if (strncmp(line, "Uid:", 4) == 0) {
                sscanf(line, "Uid: %u %u", &proc->uid, &proc->euid);
            }
            line = strtok(NULL, "\n");
        }
    }
    
    // Read command line
    if (read_proc_file(proc->pid, "cmdline", buffer, sizeof(buffer)) > 0) {
        // Replace null bytes with spaces for display
        for (size_t i = 0; i < sizeof(buffer) && buffer[i]; i++) {
            if (buffer[i] == '\0' && i < sizeof(buffer) - 1 && buffer[i+1] != '\0') {
                buffer[i] = ' ';
            }
        }
        strncpy(proc->cmdline, buffer, sizeof(proc->cmdline) - 1);
    }
    
    // Read executable path
    char exe_path[64];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", proc->pid);
    ssize_t len = readlink(exe_path, proc->exe_path, sizeof(proc->exe_path) - 1);
    if (len != -1) {
        proc->exe_path[len] = '\0';
    } else {
        proc->exe_path[0] = '\0';
    }
    
    // Read current working directory
    char cwd_path[64];
    snprintf(cwd_path, sizeof(cwd_path), "/proc/%d/cwd", proc->pid);
    len = readlink(cwd_path, proc->cwd, sizeof(proc->cwd) - 1);
    if (len != -1) {
        proc->cwd[len] = '\0';
    } else {
        proc->cwd[0] = '\0';
    }
}

// Record a behavior event for a process
static void record_behavior_event(ProcessInfo* proc, EventType type, float severity, const char* details) {
    if (!proc) return;
    
    // Add to circular buffer
    int idx = proc->behavior_history_idx;
    proc->behavior_history[idx].timestamp = time(NULL);
    proc->behavior_history[idx].type = type;
    proc->behavior_history[idx].severity = severity;
    strncpy(proc->behavior_history[idx].details, details, sizeof(proc->behavior_history[idx].details) - 1);
    
    // Update index for next event
    proc->behavior_history_idx = (proc->behavior_history_idx + 1) % BEHAVIOR_HISTORY_SIZE;
}

// Analyze behavior patterns over time
static void analyze_behavior_patterns(ProcessInfo* proc) {
    if (!proc) return;
    
    time_t now = time(NULL);
    
    // Only analyze behavior every 10 seconds to avoid overhead
    if (now - proc->last_behavior_analysis < 10) {
        return;
    }
    
    proc->last_behavior_analysis = now;
    
    // Calculate time windows
    time_t short_cutoff = now - SHORT_TERM_WINDOW;
    time_t medium_cutoff = now - MEDIUM_TERM_WINDOW;
    time_t long_cutoff = now - LONG_TERM_WINDOW;
    
    float short_term_sum = 0.0f;
    float medium_term_sum = 0.0f;
    float long_term_sum = 0.0f;
    int short_count = 0;
    int medium_count = 0;
    int long_count = 0;
    
    // Process behavior history to calculate risk levels at different time scales
    for (int i = 0; i < BEHAVIOR_HISTORY_SIZE; i++) {
        BehaviorEvent* event = &proc->behavior_history[i];
        if (event->timestamp == 0) continue; // Empty slot
        
        // Apply time decay factor - events become less significant over time
        float time_factor = 1.0f - ((float)(now - event->timestamp) / (float)LONG_TERM_WINDOW);
        if (time_factor < 0.1f) time_factor = 0.1f; // Minimum weight
        
        float weighted_severity = event->severity * time_factor;
        
        // Count events in different time windows
        if (event->timestamp >= short_cutoff) {
            short_term_sum += weighted_severity;
            short_count++;
        }
        
        if (event->timestamp >= medium_cutoff) {
            medium_term_sum += weighted_severity * 0.8f; // Medium term events weighted less
            medium_count++;
        }
        
        if (event->timestamp >= long_cutoff) {
            long_term_sum += weighted_severity * 0.6f; // Long term events weighted even less
            long_count++;
        }
    }
    
    // Calculate average risk scores with normalization to avoid spikes with low counts
    proc->short_term_risk = short_count > 0 ? short_term_sum / short_count : 0.0f;
    proc->medium_term_risk = medium_count > 0 ? medium_term_sum / medium_count : 0.0f;
    proc->long_term_risk = long_count > 0 ? long_term_sum / long_count : 0.0f;
    
    // Check for accelerating risk pattern (short term risk significantly higher than long term)
    if (proc->short_term_risk > 0 && 
        proc->short_term_risk > proc->medium_term_risk * 1.5f && 
        proc->medium_term_risk > proc->long_term_risk * 1.2f) {
        
        LOG_WARNING("Process %d (%s) shows accelerating risk pattern: %.2f → %.2f → %.2f", 
                  proc->pid, proc->comm, proc->long_term_risk, proc->medium_term_risk, proc->short_term_risk);
        
        char details[256];
        snprintf(details, sizeof(details), 
                "Accelerating risk pattern detected: %.2f → %.2f → %.2f (long→medium→short)", 
                proc->long_term_risk, proc->medium_term_risk, proc->short_term_risk);
        
        generate_process_event(proc->pid, EVENT_PROCESS_BEHAVIOR, details, 15.0f);
    }
    
    // Detect behavioral changes
    // First access to interesting file types
    if (proc->file_types_accessed[0] > 10 && proc->file_types_accessed[1] > 10 && 
        proc->file_types_accessed[2] > 10 && proc->short_term_risk > 20.0f) {
        
        char details[256];
        snprintf(details, sizeof(details), 
                "Accessing multiple file types: docs:%d media:%d archive:%d other:%d", 
                proc->file_types_accessed[0], proc->file_types_accessed[1], 
                proc->file_types_accessed[2], proc->file_types_accessed[3]);
        
        generate_process_event(proc->pid, EVENT_PROCESS_BEHAVIOR, details, 20.0f);
    }
}

// Correlate process behavior with memory and syscall monitoring
static void correlate_monitoring_data(ProcessInfo* proc) {
    if (!proc) return;
    
    // If this process has raised flags in other monitoring systems
    if (proc->memory_suspicious && proc->has_rapid_file_access) {
        char details[256];
        snprintf(details, sizeof(details), 
                "Correlated detection: Suspicious memory activity with rapid file access (%.2f files/sec)", 
                proc->file_access_rate);
        
        LOG_WARNING("Correlated detection for process %d (%s): memory + file access",
                   proc->pid, proc->comm);
        
        generate_process_event(proc->pid, EVENT_PROCESS_CORRELATION, details, 25.0f);
        
        // Record this high-severity behavior
        record_behavior_event(proc, EVENT_PROCESS_CORRELATION, 25.0f, details);
    }
    
    if (proc->syscall_suspicious && proc->has_suspicious_cmdline) {
        char details[256];
        snprintf(details, sizeof(details), 
                "Correlated detection: Suspicious syscalls with suspicious command line");
        
        LOG_WARNING("Correlated detection for process %d (%s): syscalls + command line",
                  proc->pid, proc->comm);
        
        generate_process_event(proc->pid, EVENT_PROCESS_CORRELATION, details, 20.0f);
        
        // Record this behavior
        record_behavior_event(proc, EVENT_PROCESS_CORRELATION, 20.0f, details);
    }
    
    // Escalate risk if multiple indicators are present
    if (proc->has_rapid_file_access && proc->has_rapid_process_spawning && 
        (proc->is_from_suspicious_location || proc->has_suspicious_name)) {
        
        char details[256];
        snprintf(details, sizeof(details), 
                "Multiple indicators: file access (%.2f/s) + process spawning (%d/min) + %s",
                proc->file_access_rate, proc->spawn_rate,
                proc->is_from_suspicious_location ? "suspicious location" : "suspicious name");
        
        LOG_WARNING("Multiple risk indicators for process %d (%s)", proc->pid, proc->comm);
        
        generate_process_event(proc->pid, EVENT_PROCESS_CORRELATION, details, 30.0f);
        
        // Record this high-severity behavior
        record_behavior_event(proc, EVENT_PROCESS_CORRELATION, 30.0f, details);
    }

    // Check for memory-related suspicious patterns
    if (proc->memory_growth_rate > 5000.0f && proc->has_rapid_file_access) {
        char details[256];
        snprintf(details, sizeof(details),
                "Memory growth with file access: %.2f KB/sec memory growth with %.2f files/sec access",
                proc->memory_growth_rate, proc->file_access_rate);
        
        LOG_WARNING("Memory-correlated detection for process %d (%s)",
                   proc->pid, proc->comm);
        
        generate_process_event(proc->pid, EVENT_PROCESS_CORRELATION, details, 30.0f);
        record_behavior_event(proc, EVENT_PROCESS_CORRELATION, 30.0f, details);
    }
}

// Propagate suspicion scores across process tree
static void propagate_process_suspicion(void) {
    // Build a quick lookup map of parent-child relationships
    for (int i = 0; i < process_count; i++) {
        ProcessInfo* child = &monitored_processes[i];
        if (child->ppid <= 0) continue;
        
        // Look for parent in our monitored processes
        ProcessInfo* parent = find_process_info(child->ppid);
        if (!parent) continue;
        
        // If parent is highly suspicious, child inherits some suspicion
        if (parent->suspicion_score > 60.0f) {
            // Calculate inheritance factor - consider process origin and context
            float inheritance_factor = 0.3f;
            
            // Adjust inheritance based on parent-child relationship context
            if (child->origin == ORIGIN_SYSTEM && parent->origin != ORIGIN_SYSTEM) {
                // System processes are less likely to inherit suspicion from non-system parents
                inheritance_factor *= 0.5f;
            } 
            else if (parent->origin == ORIGIN_HIGH_RISK) {
                // High-risk parents pass more suspicion to children
                inheritance_factor *= 1.5f;
            }
            else if (parent->execution_count > 20 && parent->historical_max_score < 30.0f) {
                // Long-running stable parents pass less suspicion
                inheritance_factor *= 0.7f;
            }
            
            // Scale with parent's suspicion score
            inheritance_factor += ((parent->suspicion_score - 60.0f) / 100.0f);
            if (inheritance_factor > 0.6f) inheritance_factor = 0.6f;
            if (inheritance_factor < 0.1f) inheritance_factor = 0.1f;
            
            // Inherit suspicion if it would increase the child's score
            float inherited_score = parent->suspicion_score * inheritance_factor;
            if (inherited_score > child->suspicion_score) {
                float old_score = child->suspicion_score;
                child->suspicion_score = (child->suspicion_score + inherited_score) / 2.0f;
                
                // Add ancestry flag if not already set
                if (!child->ancestry_suspicious) {
                    child->ancestry_suspicious = 1;
                    
                    LOG_WARNING("Process %d (%s) inherits suspicion from parent %d (%s): %.2f -> %.2f",
                              child->pid, child->comm, parent->pid, parent->comm,
                              old_score, child->suspicion_score);
                    
                    char details[256];
                    snprintf(details, sizeof(details),
                            "Inherited suspicion from parent process %d (%s) with score %.2f",
                            parent->pid, parent->comm, parent->suspicion_score);
                    
                    // Generate event and record behavior
                    if (child->suspicion_score > 40.0f) {
                        generate_process_event(child->pid, EVENT_PROCESS_LINEAGE, details, 10.0f);
                        record_behavior_event(child, EVENT_PROCESS_LINEAGE, 10.0f, details);
                    }
                }
            }
        }
        
        // Check for sibling correlation - if this child and its siblings all exhibit
        // similar suspicious patterns, this strengthens the case for malware
        if (parent->child_count >= 3) {
            int suspicious_siblings = 0;
            for (int j = 0; j < parent->child_count; j++) {
                // Find this sibling in our process list
                ProcessInfo* sibling = find_process_info(parent->children[j].pid);
                if (sibling && sibling->suspicion_score > 30.0f) {
                    suspicious_siblings++;
                }
            }
            
            // If multiple siblings are suspicious, increase everyone's score
            if (suspicious_siblings >= 2 && 
                suspicious_siblings >= parent->child_count / 2) {
                
                LOG_WARNING("Detected suspicious sibling group under parent %d (%s): %d suspicious of %d total",
                          parent->pid, parent->comm, suspicious_siblings, parent->child_count);
                
                char details[256];
                snprintf(details, sizeof(details),
                        "Part of suspicious process group: %d of %d sibling processes are suspicious",
                        suspicious_siblings, parent->child_count);
                
                // Apply group suspicion bonus to all siblings
                for (int j = 0; j < parent->child_count; j++) {
                    ProcessInfo* sibling = find_process_info(parent->children[j].pid);
                    if (sibling) {
                        // Add group suspicion bonus
                        float old_score = sibling->suspicion_score;
                        sibling->suspicion_score += 15.0f;
                        if (sibling->suspicion_score > 100.0f) sibling->suspicion_score = 100.0f;
                        
                        if (old_score < 50.0f && sibling->suspicion_score >= 50.0f) {
                            generate_process_event(sibling->pid, EVENT_PROCESS_CORRELATION, details, 15.0f);
                            record_behavior_event(sibling, EVENT_PROCESS_CORRELATION, 15.0f, details);
                        }
                    }
                }
                
                // Also increase parent's suspicion - coordinating suspicious children
                // is a strong indicator of malware command-and-control
                float old_parent_score = parent->suspicion_score;
                parent->suspicion_score += 20.0f;
                if (parent->suspicion_score > 100.0f) parent->suspicion_score = 100.0f;
                
                if (old_parent_score < 70.0f && parent->suspicion_score >= 70.0f) {
                    char parent_details[256];
                    snprintf(parent_details, sizeof(parent_details),
                            "Coordinating multiple suspicious child processes (%d of %d children)",
                            suspicious_siblings, parent->child_count);
                    
                    generate_process_event(parent->pid, EVENT_PROCESS_CORRELATION, parent_details, 20.0f);
                    record_behavior_event(parent, EVENT_PROCESS_CORRELATION, 20.0f, parent_details);
                }
            }
        }
    }
}

// Update analyze_process to incorporate more behavioral analysis
static void analyze_process(ProcessInfo* proc) {
    // Skip some checks based on monitoring level
    if (proc->monitoring_level == MONITORING_LEVEL_LOW) {
        // For low-monitoring processes, only check for privilege escalation
        // and extremely suspicious behavior
        proc->is_from_suspicious_location = 0;
        proc->has_suspicious_name = 0;
        proc->has_suspicious_cmdline = 0;
        proc->has_elevated_privileges = 0;
        
        // Only run basic checks
        check_privilege_escalation(proc);
        
        // Skip other analysis unless suspicion score is rising
        if (proc->suspicion_score < 15.0f) {
            update_process_suspicious_score(proc);
            return;
        }
    }
    else if (proc->monitoring_level == MONITORING_LEVEL_MEDIUM) {
        // For medium monitoring, skip some intensive checks
        proc->is_from_suspicious_location = 0;
        proc->has_suspicious_name = 0;
        proc->has_suspicious_cmdline = 0;
        proc->has_elevated_privileges = 0;
        
        // Run most checks
        check_suspicious_location(proc);
        check_suspicious_cmdline(proc);
        check_privilege_escalation(proc);
        
        // Skip some analysis
        if (proc->suspicion_score < 30.0f) {
            update_process_suspicious_score(proc);
            adjust_monitoring_level(proc);
            return;
        }
    }
    
    // Full checks for high and intense monitoring

    // Reset suspicious flags
    proc->is_from_suspicious_location = 0;
    proc->has_suspicious_name = 0;
    proc->has_suspicious_cmdline = 0;
    proc->has_elevated_privileges = 0;
    
    // Run checks
    check_suspicious_location(proc);
    check_suspicious_name(proc);
    check_suspicious_cmdline(proc);
    check_privilege_escalation(proc);
    
    // Analyze behavioral patterns
    analyze_behavior_patterns(proc);
    
    // Correlate with other monitoring systems
    correlate_monitoring_data(proc);
    
    // Update overall suspicion score
    update_process_suspicious_score(proc);
    
    // Apply unified risk assessment for better accuracy
    float unified_score = calculate_unified_risk_score(proc);
    if (unified_score > proc->suspicion_score) {
        float old_score = proc->suspicion_score;
        proc->suspicion_score = unified_score;
        
        if (unified_score - old_score > 10.0f) {
            LOG_DEBUG("Unified risk assessment increased score for %s (PID %d): %.2f -> %.2f",
                     proc->comm, proc->pid, old_score, unified_score);
        }
    }
    
    // Generate events for highly suspicious processes
    if (proc->suspicion_score > 50.0f) {
        // Use existing event generation code
        char details[512];
        char cmdline_truncated[128] = {0};
        char path_truncated[128] = {0};

        // Safely truncate the command line and path
        strncpy(cmdline_truncated, proc->cmdline, sizeof(cmdline_truncated)-1);
        cmdline_truncated[sizeof(cmdline_truncated)-1] = '\0';

        strncpy(path_truncated, proc->exe_path, sizeof(path_truncated)-1);
        path_truncated[sizeof(path_truncated)-1] = '\0';

        // Build suspicion flags string separately
        char flags[128] = {0};
        if (proc->is_from_suspicious_location) strcat(flags, "Location ");
        if (proc->has_suspicious_name) strcat(flags, "Name ");
        if (proc->has_suspicious_cmdline) strcat(flags, "Cmdline ");
        if (proc->has_elevated_privileges) strcat(flags, "Privesc ");
        if (proc->has_rapid_file_access) strcat(flags, "FileAccess ");
        if (proc->has_rapid_process_spawning) strcat(flags, "Spawning ");
        if (proc->ancestry_suspicious) strcat(flags, "Lineage ");
        if (proc->memory_suspicious) strcat(flags, "Memory ");
        if (proc->syscall_suspicious) strcat(flags, "Syscall ");

        // First create a basic process identification string
        char *p = details;
        int remaining = sizeof(details);
        int n;

        // Format the first line with basic process info - this has predictable length
        n = snprintf(p, remaining, 
                     "Suspicious: %.32s (PID: %d) UID: %d→%d\n", 
                     proc->comm, proc->pid, proc->uid, proc->euid);
        if (n > 0 && n < remaining) {
            p += n;
            remaining -= n;
        }

        // Add command line if there's room
        if (remaining > 20) {  // Ensure enough space for reasonable output
            n = snprintf(p, remaining, "CMD: %.100s\n", cmdline_truncated);
            if (n > 0 && n < remaining) {
                p += n;
                remaining -= n;
            }
        }

        // Add path if there's room
        if (remaining > 20) {
            n = snprintf(p, remaining, "Path: %.100s\n", path_truncated);
            if (n > 0 && n < remaining) {
                p += n;
                remaining -= n;
            }
        }

        // Add flags if there's room
        if (remaining > 20) {
            snprintf(p, remaining, "Flags: %.100s", flags);
        }
        
        // Only generate events if score is significantly high or it's increasing
        static time_t last_event_time = 0;
        time_t now = time(NULL);
        
        if (proc->suspicion_score > 70.0f || 
            (proc->suspicion_score > 50.0f && now - last_event_time > 120)) {
            
            // Calculate impact based on score
            float impact = 10.0f + (proc->suspicion_score / 10.0f);
            
            generate_process_event(proc->pid, EVENT_PROCESS_SUSPICIOUS, details, impact);
            last_event_time = now;
        }
    }
}

// Check if process is running from a suspicious location
static void check_suspicious_location(ProcessInfo* proc) {
    const char* suspicious_paths[] = {
        "/tmp/", "/dev/shm/", "/run/", "/var/tmp/",
        NULL
    };
    
    // Check executable path
    if (proc->exe_path[0] != '\0') {
        for (int i = 0; suspicious_paths[i] != NULL; i++) {
            if (strncmp(proc->exe_path, suspicious_paths[i], strlen(suspicious_paths[i])) == 0) {
                proc->is_from_suspicious_location = 1;
                
                LOG_WARNING("Process %d (%s) is running from suspicious location: %s", 
                           proc->pid, proc->comm, proc->exe_path);
                return;
            }
        }
        
        // Check if running from home directory but not in standard directories
        if (current_user_home[0] != '\0' && 
            strncmp(proc->exe_path, current_user_home, strlen(current_user_home)) == 0) {
            
            // Skip standard home subdirectories
            const char* safe_home_dirs[] = {
                "/bin/", "/sbin/", "/.local/bin/", "/.config/",
                NULL
            };
            
            int is_safe = 0;
            for (int i = 0; safe_home_dirs[i] != NULL; i++) {
                char safe_path[MAX_PATH_LENGTH];
                snprintf(safe_path, sizeof(safe_path), "%s%s", current_user_home, safe_home_dirs[i]);
                
                if (strncmp(proc->exe_path, safe_path, strlen(safe_path)) == 0) {
                    is_safe = 1;
                    break;
                }
            }
            
            if (!is_safe) {
                proc->is_from_suspicious_location = 1;
                
                LOG_WARNING("Process %d (%s) is running from home directory: %s", 
                           proc->pid, proc->comm, proc->exe_path);
                return;
            }
        }
    }
}

// Check for suspicious process names
static void check_suspicious_name(ProcessInfo* proc) {
    const char* suspicious_names[] = {
        "crypto", "ransom", "crypt", "locker", "lock", "hidden", 
        "encrypt", "decrypt", "anonymous", "stealth", "silent",
        NULL
    };
    
    for (int i = 0; suspicious_names[i] != NULL; i++) {
        if (strcasestr(proc->comm, suspicious_names[i]) != NULL) {
            proc->has_suspicious_name = 1;
            
            LOG_WARNING("Process %d has suspicious name: %s (matched: %s)", 
                       proc->pid, proc->comm, suspicious_names[i]);
            return;
        }
    }
    
    // Check for randomized/obfuscated names
    int digit_count = 0;
    int hex_count = 0;
    int len = strlen(proc->comm);
    
    for (int i = 0; i < len; i++) {
        if (isdigit((unsigned char)proc->comm[i])) {
            digit_count++;
        }
        if (isxdigit((unsigned char)proc->comm[i])) {
            hex_count++;
        }
    }
    
    // If name is mostly digits or hexadecimal and not a common pattern
    if ((digit_count > len / 2 || hex_count > len * 0.7) && len > 5) {
        // Exclude common numeric process names
        const char* common_numeric[] = {"123", "chrome", "firefox", "ssh2", "x11", NULL};
        int is_common = 0;
        
        for (int i = 0; common_numeric[i] != NULL; i++) {
            if (strcasestr(proc->comm, common_numeric[i]) != NULL) {
                is_common = 1;
                break;
            }
        }
        
        if (!is_common) {
            proc->has_suspicious_name = 1;
            
            LOG_WARNING("Process %d has potentially obfuscated name: %s", 
                       proc->pid, proc->comm);
        }
    }
}

// Calculate entropy of a string (measure of randomness)
static float calculate_entropy(const char* str, size_t len) {
    if (!str || len == 0) return 0.0f;
    
    // Count occurrences of each byte
    unsigned int counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[(unsigned char)str[i]]++;
    }
    
    // Calculate entropy
    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            float p = (float)counts[i] / len;
            entropy -= p * log2f(p);
        }
    }
    
    return entropy;
}

// Check if a string looks like base64 encoded data
static int is_likely_base64(const char* str, size_t len) {
    if (!str || len < 16) return 0; // Too short to be meaningful base64
    
    // Count base64 characters (A-Z, a-z, 0-9, +, /, =)
    int base64_chars = 0;
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        if ((c >= 'A' && c <= 'Z') || 
            (c >= 'a' && c <= 'z') || 
            (c >= '0' && c <= '9') || 
            c == '+' || c == '/' || c == '=') {
            base64_chars++;
        }
    }
    
    // If over 90% of characters are valid base64 chars
    float base64_ratio = (float)base64_chars / len;
    if (base64_ratio > 0.9f && len >= 40) {
        // Additional check: base64 encoded strings often end with '='
        if (str[len-1] == '=' || str[len-2] == '=') {
            return 2; // Very likely base64
        }
        return 1; // Likely base64
    }
    
    return 0;
}

// Enhanced check_suspicious_cmdline function
static void check_suspicious_cmdline(ProcessInfo* proc) {
    if (!proc || !proc->cmdline[0]) return;
    
    // Original checks for known suspicious arguments
    const char* suspicious_args[] = {
        "-stealth", "--hidden", "-silent", "--quiet", "-encrypt", 
        "--decrypt", "shadow", "backup", "ransom", "bitcoin", "wallet",
        NULL
    };
    
    for (int i = 0; suspicious_args[i] != NULL; i++) {
        if (strcasestr(proc->cmdline, suspicious_args[i]) != NULL) {
            proc->has_suspicious_cmdline = 1;
            
            LOG_WARNING("Process %d (%s) has suspicious command line: %s (matched: %s)", 
                       proc->pid, proc->comm, proc->cmdline, suspicious_args[i]);
            return;
        }
    }
    
    // Enhanced detection for obfuscated commands
    
    // Split command line into arguments
    char cmdline_copy[MAX_CMDLINE_LENGTH];
    strncpy(cmdline_copy, proc->cmdline, sizeof(cmdline_copy)-1);
    cmdline_copy[sizeof(cmdline_copy)-1] = '\0';
    
    char* token = strtok(cmdline_copy, " \t");
    while (token != NULL) {
        size_t token_len = strlen(token);
        
        // Skip very short arguments
        if (token_len < 8) {
            token = strtok(NULL, " \t");
            continue;
        }
        
        // Check for hex-encoded arguments
        int consecutive_hex = 0;
        int max_consecutive_hex = 0;
        
        for (size_t i = 0; i < token_len; i++) {
            if (isxdigit((unsigned char)token[i])) {
                consecutive_hex++;
                if (consecutive_hex > max_consecutive_hex) {
                    max_consecutive_hex = consecutive_hex;
                }
            } else {
                consecutive_hex = 0;
            }
        }
        
        // Check for base64-encoded arguments
        int base64_likelihood = is_likely_base64(token, token_len);
        
        // Calculate entropy to detect randomized data
        float entropy = calculate_entropy(token, token_len);
        
        // Decision logic for suspicious arguments
        if ((max_consecutive_hex >= 32 && entropy > 3.8) || 
            (base64_likelihood == 2 && token_len > 40) ||
            (entropy > 4.5 && token_len > 30)) {
            
            proc->has_suspicious_cmdline = 1;
            
            char detection_type[32] = {0};
            if (max_consecutive_hex >= 32) {
                strcpy(detection_type, "hex-encoded");
            } else if (base64_likelihood > 0) {
                strcpy(detection_type, "base64-encoded");
            } else {
                strcpy(detection_type, "high-entropy");
            }
            
            LOG_WARNING("Process %d (%s) has obfuscated command argument: %s (type: %s, entropy: %.2f)", 
                       proc->pid, proc->comm, 
                       token_len > 20 ? "..." : token,  // Don't log the whole obfuscated string
                       detection_type, entropy);
            
            char details[256];
            snprintf(details, sizeof(details), 
                    "Detected obfuscated command line argument (%s, entropy: %.2f)", 
                    detection_type, entropy);
            
            // Generate event and record behavior
            generate_process_event(proc->pid, EVENT_PROCESS_OBFUSCATION, details, 20.0f);
            record_behavior_event(proc, EVENT_PROCESS_OBFUSCATION, 20.0f, details);
            
            return;
        }
        
        token = strtok(NULL, " \t");
    }
    
    // Check for unusually long single arguments (possible obfuscation)
    token = strtok(proc->cmdline, " \t");
    while (token != NULL) {
        if (strlen(token) > 100) {
            float entropy = calculate_entropy(token, strlen(token));
            if (entropy > 3.5) {
                proc->has_suspicious_cmdline = 1;
                
                LOG_WARNING("Process %d (%s) has unusually long command argument: %d chars (entropy: %.2f)", 
                           proc->pid, proc->comm, (int)strlen(token), entropy);
                
                char details[256];
                snprintf(details, sizeof(details), 
                        "Unusually long command argument: %d chars (entropy: %.2f)", 
                        (int)strlen(token), entropy);
                
                // Generate event and record behavior
                generate_process_event(proc->pid, EVENT_PROCESS_OBFUSCATION, details, 15.0f);
                record_behavior_event(proc, EVENT_PROCESS_OBFUSCATION, 15.0f, details);
                
                return;
            }
        }
        token = strtok(NULL, " \t");
    }
}

// Check for privilege escalation
static void check_privilege_escalation(ProcessInfo* proc) {
    // Check for effective user ID different from real user ID
    if (proc->uid != proc->euid && proc->euid == 0 && proc->uid != 0) {
        proc->has_elevated_privileges = 1;
        
        LOG_WARNING("Process %d (%s) has elevated privileges: UID %d -> EUID %d", 
                   proc->pid, proc->comm, proc->uid, proc->euid);
        
        char details[256];
        snprintf(details, sizeof(details), 
                "Privilege escalation detected: UID %d -> EUID %d",
                proc->uid, proc->euid);
        
        generate_process_event(proc->pid, EVENT_PROCESS_PRIVESC, details, 25.0f);
    }
    
    // TODO: Check for process with different UID than parent process
    // This requires tracking parent-child relationships more thoroughly
}

// Update the suspicion score calculation with more behavioral factors
static void update_process_suspicious_score(ProcessInfo* proc) {
    // Start with a base score
    float score = 0.0f;
    
    // Add points for static suspicious indicators
    if (proc->is_from_suspicious_location) score += 15.0f;
    if (proc->has_suspicious_name) score += 10.0f;
    if (proc->has_suspicious_cmdline) score += 12.0f;
    if (proc->has_elevated_privileges) score += 20.0f;
    
    // Add points for behavioral indicators
    if (proc->has_rapid_file_access) {
        score += 15.0f;
        
        // Scale with rate of access
        float rate_factor = proc->file_access_rate / RAPID_FILE_ACCESS_THRESHOLD;
        if (rate_factor > 1.0f) {
            score += 10.0f * (rate_factor > 5.0f ? 5.0f : rate_factor);
        }
    }
    
    if (proc->has_rapid_process_spawning) {
        score += 10.0f;
        
        // Scale with spawn rate
        float spawn_factor = (float)proc->spawn_rate / RAPID_SPAWN_THRESHOLD;
        if (spawn_factor > 1.0f) {
            score += 8.0f * (spawn_factor > 5.0f ? 5.0f : spawn_factor);
        }
    }
    
    // Add points for lineage
    if (proc->ancestry_suspicious) score += 15.0f;
    
    // Add points for multi-file-type operations
    int file_type_count = 0;
    for (int i = 0; i < 5; i++) {
        if (proc->file_types_accessed[i] > 5) file_type_count++;
    }
    
    if (file_type_count >= 3) {
        // Accessing 3+ file types is suspicious
        score += 10.0f + (file_type_count * 2.0f);
    }
    
    // Add points for consecutive operations
    if (proc->consecutive_file_ops > 20) {
        score += 5.0f + (proc->consecutive_file_ops / 10.0f);
    }
    
    // Add points for correlated detections
    if (proc->memory_suspicious) score += 20.0f;
    if (proc->syscall_suspicious) score += 15.0f;
    
    // Add points for behavioral pattern analysis
    score += proc->short_term_risk * 2.0f;
    score += proc->medium_term_risk * 1.0f;
    score += proc->long_term_risk * 0.5f;
    
    // Risk decay - reduce score slightly if the process has been running 
    // for a long time without triggering additional suspicious events
    time_t now = time(NULL);
    // Check when the last suspicious activity occurred
    time_t last_activity = 0;
    for (int j = 0; j < BEHAVIOR_HISTORY_SIZE; j++) {
        if (proc->behavior_history[j].timestamp > last_activity) {
            last_activity = proc->behavior_history[j].timestamp;
        }
    }
    time_t time_since_activity = now - last_activity;
    if (now - proc->first_seen > 3600 && proc->behavior_history[proc->behavior_history_idx].timestamp < now - 600) {
        // Last suspicious event was more than 10 minutes ago and process running > 1 hour
        score *= 0.9f;
    }

    // Adjust score based on historical profile
    if (proc->execution_count > 5) {
        // If we've seen this process many times and it's never been highly suspicious
        if (proc->historical_max_score < 40.0f && 
            proc->execution_count > 10) {
            
            // Gradually reduce the score for historically benign processes
            float reduction_factor = 0.9f - (min(proc->execution_count, 50) * 0.01f);
            if (reduction_factor < 0.6f) reduction_factor = 0.6f;
            
            float old_score = score;
            score *= reduction_factor;
            
            if (old_score > 30.0f && (old_score - score) > 5.0f) {
                LOG_DEBUG("Historical profile reduced score for %s (PID %d): %.2f -> %.2f (exec count: %d)",
                         proc->comm, proc->pid, old_score, score, proc->execution_count);
            }
        }
    }
    
    // Apply contextual trust multiplier to adjust score
    if (proc->contextual_trust_multiplier > 0.0f) {
        float original_score = score;
        
        // For trusted processes, reduce the score
        if (proc->contextual_trust_multiplier > 1.0f) {
            score /= proc->contextual_trust_multiplier;
        }
        // For untrusted processes, increase the score
        else {
            score *= (2.0f - proc->contextual_trust_multiplier);
        }
        
        // Log significant adjustments
        if (fabsf(original_score - score) > 10.0f && original_score > 20.0f) {
            LOG_DEBUG("Adjusted score for %s (PID %d) based on context: %.2f -> %.2f (multiplier: %.2f)",
                     proc->comm, proc->pid, original_score, score, proc->contextual_trust_multiplier);
        }
    }
    
    // Cap the score at 100
    if (score > 100.0f) {
        score = 100.0f;
    }
    
    // Update the score
    proc->suspicion_score = score;
    
    // Log significant score changes
    static time_t last_score_log = 0;
    if ((score > 50.0f && score > proc->suspicion_score + 10.0f) || 
        (score > 70.0f && now - last_score_log > 60)) {
        
        LOG_WARNING("Process %d (%s) suspicion score increased to %.2f", 
                   proc->pid, proc->comm, score);
        last_score_log = now;
    }
}

// Apply time-based decay to process suspicion scores
static void apply_risk_decay(void) {
    time_t now = time(NULL);
    static time_t last_decay_time = 0;
    
    // Only decay scores every 30 seconds to reduce overhead
    if (now - last_decay_time < 30) {
        return;
    }
    
    last_decay_time = now;
    
    // Calculate decay factor based on time elapsed
    for (int i = 0; i < process_count; i++) {
        ProcessInfo* proc = &monitored_processes[i];
        
        // Skip processes with no score
        if (proc->suspicion_score <= 0.0f) continue;
        
        // Check when the last suspicious activity occurred
        time_t last_activity = 0;
        for (int j = 0; j < BEHAVIOR_HISTORY_SIZE; j++) {
            if (proc->behavior_history[j].timestamp > last_activity) {
                last_activity = proc->behavior_history[j].timestamp;
            }
        }
        time_t time_since_activity = now - last_activity;
        
        // Apply different decay rates based on current score and activity time
        if (time_since_activity > 300) { // 5+ minutes of good behavior
            // Faster decay for higher scores, slower for lower scores
            float decay_rate;
            
            if (proc->suspicion_score > 70.0f) {
                decay_rate = 0.15f; // Aggressive decay for very suspicious processes
            } else if (proc->suspicion_score > 40.0f) {
                decay_rate = 0.08f; // Moderate decay for somewhat suspicious
            } else {
                decay_rate = 0.05f; // Slow decay for low suspicion
            }
            
            // Apply exponential decay: S(t) = S₀ × e^(-λt)
            // Using simplified version with discrete steps
    }
    
    buffer[bytes_read] = '\0';
    return bytes_read;
}

// Generate a process-related event
static void generate_process_event(pid_t pid, EventType type, const char* details, float score_impact) {
    if (!event_callback) {
        return;
    }
    
    Event event;
    memset(&event, 0, sizeof(event));
    
    event.type = type;
    event.process_id = pid;
    event.timestamp = time(NULL);
    event.score_impact = score_impact;
    
    // Fill process event data
    ProcessInfo* proc = find_process_info(pid);
    if (proc) {
        strncpy(event.data.process_event.comm, proc->comm, sizeof(event.data.process_event.comm) - 1);
        strncpy(event.data.process_event.image_path, proc->exe_path, sizeof(event.data.process_event.image_path) - 1);
        event.data.process_event.parent_pid = proc->ppid;
    }
    
    // Copy details
    strncpy(event.data.process_event.details, details, sizeof(event.data.process_event.details) - 1);
    
    // Call the event handler
    event_callback(&event, event_callback_data);
}

// Add a child process to a parent's list
static void add_child_process(ProcessInfo* parent, pid_t child_pid, const char* child_comm) {
    // Remove oldest child if the array is full
    if (parent->child_count >= MAX_CHILDREN_PER_PROCESS) {
        // Find the oldest child
        time_t oldest_time = parent->children[0].spawn_time;
        int oldest_idx = 0;
        
        for (int i = 1; i < parent->child_count; i++) {
            if (parent->children[i].spawn_time < oldest_time) {
                oldest_time = parent->children[i].spawn_time;
                oldest_idx = i;
            }
        }
        
        // Shift the array to remove the oldest child
        for (int i = oldest_idx; i < parent->child_count - 1; i++) {
            parent->children[i] = parent->children[i + 1];
        }
        
        parent->child_count--;
    }
    
    // Add the new child
    parent->children[parent->child_count].pid = child_pid;
    parent->children[parent->child_count].spawn_time = time(NULL);
    strncpy(parent->children[parent->child_count].comm, child_comm, sizeof(parent->children[parent->child_count].comm) - 1);
    
    parent->child_count++;
}

// Remove children that are no longer active or are too old
static void remove_old_children(ProcessInfo* proc) {
    time_t now = time(NULL);
    time_t cutoff = now - CHILD_TRACK_WINDOW;
    
    for (int i = 0; i < proc->child_count; i++) {
        // Remove if child is too old or no longer exists
        if (proc->children[i].spawn_time < cutoff || !is_process_alive(proc->children[i].pid)) {
            // Shift the array to remove this child
            for (int j = i; j < proc->child_count - 1; j++) {
                proc->children[j] = proc->children[j + 1];
            }
            
            proc->child_count--;
            i--; // Adjust index
        }
    }
}

// Check if a process is still alive
static int is_process_alive(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    return access(path, F_OK) == 0;
}

/**
 * Adds a process to the monitoring system
 * 
 * @param pid Process ID to monitor
 * @return 0 on success, non-zero on failure
 */
int process_monitor_add_process(pid_t pid) {
    if (pid <= 0) {
        LOG_ERROR("Invalid process ID: %d", pid);
        return -1;
    }
    
    // Check if process exists
    if (!is_process_alive(pid)) {
        LOG_ERROR("Process does not exist: %d", pid);
        return -1;
    }
    
    LOG_DEBUG("Adding process to monitor: PID %d", pid);
    
    // Find or create process info
    ProcessInfo* proc = find_process_info(pid);
    if (proc) {
        // Process already being monitored, just update it
        LOG_DEBUG("Process already being monitored: PID %d", pid);
        update_process_info(proc);
        return 0;
    }
    
    // Create new process info
    proc = add_process_info(pid);
    if (!proc) {
        LOG_ERROR("Failed to create process info: PID %d", pid);
        return -1;
    }
    
    // Update process info
    update_process_info(proc);
    
    // Analyze for suspicious behavior
    analyze_process(proc);
    
    LOG_INFO("Started monitoring process: %s (PID: %d)", proc->comm, pid);
    return 0;
}

/**
 * Removes a process from monitoring
 * 
 * @param pid Process ID to stop monitoring
 */
void process_monitor_remove_process(pid_t pid) {
    ProcessInfo* proc = find_process_info(pid);
    if (!proc) {
        LOG_DEBUG("Process not found in monitoring system: PID %d", pid);
        return;
    }
    
    LOG_INFO("Removing process from monitoring: %s (PID: %d)", 
             proc->comm, proc->pid);
    
    // Remove from monitored processes list
    remove_process_info(pid);
}

// Create a new process context
static ProcessContext* create_process_context(pid_t pid) {
    ProcessContext* context = (ProcessContext*)malloc(sizeof(ProcessContext));
    if (!context) {
        LOG_ERROR("Failed to allocate memory for process context%s", "");
        return NULL;
    }
    
    // Initialize with default values
    memset(context, 0, sizeof(ProcessContext));
    context->pid = pid;
    context->creation_time = time(NULL);
    context->last_update_time = time(NULL);
    context->monitoring_level = MONITORING_LEVEL_NORMAL;
    
    return context;
}

// Free a process context
static void free_process_context(ProcessContext* context) {
    if (context) {
        free(context);
    }
}

// Add a process context to the global list
static void add_process_context(ProcessContext* context) {
    if (!context) {
        return;
    }
    
    // Check if we already have this process
    for (int i = 0; i < process_context_count; i++) {
        if (process_contexts[i] && process_contexts[i]->pid == context->pid) {
            // Replace the existing context
            free_process_context(process_contexts[i]);
            process_contexts[i] = context;
            return;
        }
    }
    
    // Add new context if we have space
    if (process_context_count < MAX_PROCESS_CONTEXTS) {
        process_contexts[process_context_count++] = context;
    } else {
        // Find the oldest context to replace
        int oldest_idx = 0;
        time_t oldest_time = time(NULL);
        
        for (int i = 0; i < MAX_PROCESS_CONTEXTS; i++) {
            if (process_contexts[i] && process_contexts[i]->last_update_time < oldest_time) {
                oldest_time = process_contexts[i]->last_update_time;
                oldest_idx = i;
            }
        }
        
        // Replace the oldest context
        free_process_context(process_contexts[oldest_idx]);
        process_contexts[oldest_idx] = context;
    }
}

// Get a process context from the global list
static ProcessContext* get_process_context(pid_t pid) {
    for (int i = 0; i < process_context_count; i++) {
        if (process_contexts[i] && process_contexts[i]->pid == pid) {
            return process_contexts[i];
        }
    }
    return NULL;
}

// Check if a string is numeric (contains only digits)
static int is_numeric(const char* str) {
    if (!str || !*str) {
        return 0;
    }
    
    while (*str) {
        if (!isdigit((unsigned char)*str)) {
            return 0;
        }
        str++;
    }
    
    return 1;
}

// Check if a process is a common system utility
static int is_system_utility(const char* process_name, const char* path) {
    if (!process_name || !path) {
        return 0;
    }
    
    // Common system utilities that shouldn't need detailed monitoring
    const char* system_names[] = {
        "bash", "sh", "dash", "zsh", "systemd", "init", "kthreadd",
        "kworker", "ksoftirqd", "migration", "sshd", "rcu_", "cron",
        "rsyslogd", "dbus", "avahi", "cups", "NetworkManager", "polkit",
        "apache", "nginx", "mysqld", "dhclient", "ntpd", "snapd", "upstart",
        "udev", "login", "gnome", "pulseaudio", "X", "xorg", "Xorg", 
        "apt", "dpkg", "rpm", "yum", "dnf", "pacman", NULL
    };
    
    // Common system directories
    const char* system_paths[] = {
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
        "/usr/local/sbin/", "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
        "/opt/", "/snap/", NULL
    };
    
    // Check process name against common system utilities
    for (int i = 0; system_names[i] != NULL; i++) {
        if (strncmp(process_name, system_names[i], strlen(system_names[i])) == 0) {
            return 1;
        }
    }
    
    // Check if the executable is in a system directory
    for (int i = 0; system_paths[i] != NULL; i++) {
        if (strncmp(path, system_paths[i], strlen(system_paths[i])) == 0) {
            return 1;
        }
    }
    
    return 0;
}

// Get process information from the /proc filesystem
static int get_process_info(pid_t pid, char* exe_path, size_t exe_path_size,
                          char* cmdline, size_t cmdline_size,
                          char* process_name, size_t process_name_size) {
    if (pid <= 0 || !exe_path || !cmdline || !process_name) {
        return -1;
    }
    
    // Get executable path
    char proc_exe[64];
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", pid);
    ssize_t len = readlink(proc_exe, exe_path, exe_path_size - 1);
    if (len > 0) {
        exe_path[len] = '\0';
    } else {
        exe_path[0] = '\0';
    }
    
    // Get command line
    char proc_cmdline[64];
    snprintf(proc_cmdline, sizeof(proc_cmdline), "/proc/%d/cmdline", pid);
    FILE* f_cmdline = fopen(proc_cmdline, "r");
    if (f_cmdline) {
        size_t read = fread(cmdline, 1, cmdline_size - 1, f_cmdline);
        if (read > 0) {
            cmdline[read] = '\0';
            
            // Replace null bytes with spaces for display
            for (size_t i = 0; i < read; i++) {
                if (cmdline[i] == '\0' && i < read - 1) {
                    cmdline[i] = ' ';
                }
            }
        } else {
            cmdline[0] = '\0';
        }
        fclose(f_cmdline);
    } else {
        cmdline[0] = '\0';
    }
    
    // Get process name
    char proc_comm[64];
    snprintf(proc_comm, sizeof(proc_comm), "/proc/%d/comm", pid);
    FILE* f_comm = fopen(proc_comm, "r");
    if (f_comm) {
        if (fgets(process_name, process_name_size, f_comm)) {
            // Remove trailing newline
            size_t name_len = strlen(process_name);
            if (name_len > 0 && process_name[name_len - 1] == '\n') {
                process_name[name_len - 1] = '\0';
            }
        } else {
            process_name[0] = '\0';
        }
        fclose(f_comm);
    } else {
        process_name[0] = '\0';
    }
    
    // If we couldn't get the name from comm, extract it from the path
    if (process_name[0] == '\0' && exe_path[0] != '\0') {
        const char* last_slash = strrchr(exe_path, '/');
        if (last_slash) {
            strncpy(process_name, last_slash + 1, process_name_size - 1);
            process_name[process_name_size - 1] = '\0';
        }
    }
    
    return 0;
}

// Modify add_process_to_monitoring to reduce verbosity
static int add_process_to_monitoring(pid_t pid, EventHandler handler, void* user_data) {
    // Mark unused parameters
    (void)handler;     // Explicitly mark parameter as unused
    (void)user_data;   // Explicitly mark parameter as unused

    // Static counter to limit startup log spam
    static int process_count = 0;
    static time_t last_process_log = 0;
    static int skipped_process_logs = 0;
    
    ProcessContext* context = create_process_context(pid);
    if (!context) {
        return -1;
    }
    
    // Get process information
    char exe_path[512] = {0};
    char cmdline[1024] = {0};
    char process_name[256] = {0};
    
    if (get_process_info(pid, exe_path, sizeof(exe_path), cmdline, sizeof(cmdline), process_name, sizeof(process_name)) != 0) {
        free_process_context(context);
        return -1;
    }
    
    // Store process details
    context->pid = pid;
    strncpy(context->command, process_name, sizeof(context->command) - 1);
    strncpy(context->path, exe_path, sizeof(context->path) - 1);
    
    // Check if this is a system utility that should be less closely monitored
    int is_system = is_system_utility(process_name, exe_path);
    if (is_system) {
        context->monitoring_level = MONITORING_LEVEL_LOW;
        
        // Log at most once per minute, and only every 20th process to reduce spam
        time_t now = time(NULL);
        if (last_process_log < now - 60 || process_count % 20 == 0) {
            if (skipped_process_logs > 0) {
                LOG_DEBUG("Skipped logging %d system processes", skipped_process_logs);
                skipped_process_logs = 0;
            }
            LOG_DEBUG("Process whitelisted as system utility: %s (PID %d)", process_name, pid);
            last_process_log = now;
        } else {
            skipped_process_logs++;
        }
    } else {
        context->monitoring_level = MONITORING_LEVEL_NORMAL;
        
        // Only log non-system processes
        LOG_INFO("Added process to monitoring: %s (PID %d)", process_name, pid);
    }
    
    // Add to global list
    add_process_context(context);
    process_count++;
    
    return 0;
}

// Update scan_existing_processes to report summary instead of each process
static int __attribute__((unused)) scan_existing_processes(EventHandler handler, void* user_data) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        LOG_ERROR("Failed to open /proc directory: %s", strerror(errno));
        return -1;
    }
    
    int process_count = 0;
    int system_count = 0;
    int user_count = 0;
    struct dirent* entry;
    
    LOG_INFO("Scanning existing processes...%s", "");
    
    while ((entry = readdir(proc_dir)) != NULL) {
        // Check if the entry is a process directory (numeric name)
        if (entry->d_type == DT_DIR && is_numeric(entry->d_name)) {
            pid_t pid = atoi(entry->d_name);
            
            // Skip the process if it's already being monitored
            if (get_process_context(pid) != NULL) {
                continue;
            }
            
            // Check if this is a system process
            char exe_path[512] = {0};
            char process_name[256] = {0};
            
            // Try to get basic info to determine if it's a system process
            char proc_exe[64];
            snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", pid);
            ssize_t len = readlink(proc_exe, exe_path, sizeof(exe_path) - 1);
            if (len > 0) {
                exe_path[len] = '\0';
                
                // Extract process name from exe_path
                char* last_slash = strrchr(exe_path, '/');
                if (last_slash) {
                    strncpy(process_name, last_slash + 1, sizeof(process_name) - 1);
                }
                
                // Check if this is a system utility
                if (is_system_utility(process_name, exe_path)) {
                    system_count++;
                } else {
                    user_count++;
                }
                
                // Add the process to monitoring
                if (add_process_to_monitoring(pid, handler, user_data) == 0) {
                    process_count++;
                }
            }
        }
    }
    
    closedir(proc_dir);
    
    LOG_INFO("Completed process scan: found %d processes (%d system, %d user)",
             process_count, system_count, user_count);
    
    return process_count;
}

/**
 * Marks a process as suspicious from memory monitoring
 * 
 * @param pid Process ID
 * @param details Optional description of suspicious activity
 */
void process_monitor_memory_suspicious(pid_t pid, const char* details) {
    ProcessInfo* proc = find_process_info(pid);
    if (!proc) {
        return;
    }
    
    proc->memory_suspicious = 1;
    
    // Record a behavior event
    record_behavior_event(proc, EVENT_MEMORY_SUSPICIOUS, 20.0f, 
                          details ? details : "Suspicious memory activity");
    
    // Update scoring
    update_process_suspicious_score(proc);
}

/**
 * Marks a process as suspicious from syscall monitoring
 * 
 * @param pid Process ID
 * @param details Optional description of suspicious activity
 */
void process_monitor_syscall_suspicious(pid_t pid, const char* details) {
    ProcessInfo* proc = find_process_info(pid);
    if (!proc) {
        return;
    }
    
    proc->syscall_suspicious = 1;
    
    // Record a behavior event
    record_behavior_event(proc, EVENT_SYSCALL_SUSPICIOUS, 15.0f, 
                          details ? details : "Suspicious syscall activity");
    
    // Update scoring
    update_process_suspicious_score(proc);
}

// Calculate a hash for process identification
static uint32_t calculate_process_hash(const char* exe_path, const char* comm) {
    // Simple hash function for process identification
    uint32_t hash = 5381;
    
    // Hash executable path
    if (exe_path && exe_path[0]) {
        const char* ptr = exe_path;
        while (*ptr) {
            hash = ((hash << 5) + hash) + *ptr++;
        }
    }
    
    // Hash command name
    if (comm && comm[0]) {
        const char* ptr = comm;
        while (*ptr) {
            hash = ((hash << 5) + hash) + *ptr++;
        }
    }
    
    return hash;
}

// Update process historical profile
static void update_process_profile(ProcessInfo* proc) {
    if (!proc) return;
    
    // Calculate process hash if not already done
    if (proc->process_hash == 0) {
        proc->process_hash = calculate_process_hash(proc->exe_path, proc->comm);
    }
    
    // For newly tracked processes, just initialize profile data
    if (proc->execution_count == 0) {
        proc->execution_count = 1;
        proc->first_execution_time = proc->first_seen;
        proc->historical_max_score = proc->suspicion_score;
        proc->score_deviation = 0.0f;
        return;
    }
    
    // Update execution count
    proc->execution_count++;
    
    // Update max historical score
    if (proc->suspicion_score > proc->historical_max_score) {
        proc->historical_max_score = proc->suspicion_score;
    }
    
    // Update score deviation (simple moving average of deviation)
    float current_deviation = fabsf(proc->suspicion_score - proc->historical_max_score);
    proc->score_deviation = (proc->score_deviation * 0.7f) + (current_deviation * 0.3f);
    
    // If process has a high execution count but low historical max score,
    // it might be a legitimate process that occasionally does suspicious things
    if (proc->execution_count > 10 && 
        proc->historical_max_score < 50.0f &&
        (time(NULL) - proc->first_execution_time) > 86400) { // Seen for over a day
        
        // This process has been around a while and never been very suspicious
        // We'll mark it as having a lower base risk
        LOG_DEBUG("Process %d (%s) has established a benign historical profile (%d executions, max score: %.2f)",
                 proc->pid, proc->comm, proc->execution_count, proc->historical_max_score);
    }

    // Enhancement to update_process_profile()
    // Around line 1196, add after the existing profile logging:

    // Adjust decay rate based on process origin and history
    if (proc->execution_count > 15 && proc->historical_max_score < 40.0f) {
        // Trusted process based on multiple executions and low historical suspicion
        const char* system_dirs[] = {"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", NULL};
        int from_system_dir = 0;
        
        // Check if process is from a system directory
        for (int i = 0; system_dirs[i] != NULL; i++) {
            if (strncmp(proc->exe_path, system_dirs[i], strlen(system_dirs[i])) == 0) {
                from_system_dir = 1;
                break;
            }
        }
        
        // Apply contextual trust multiplier
        // System processes from trusted directories get higher trust
        if (from_system_dir) {
            proc->contextual_trust_multiplier = 2.0f;
            
            // Only log significant changes to avoid spam
            if (proc->contextual_trust_multiplier > 1.5f && 
                (proc->historical_max_score > 20.0f || proc->execution_count % 10 == 0)) {
                LOG_DEBUG("Increased contextual trust for system process %s (PID %d): multiplier %.1f",
                         proc->comm, proc->pid, proc->contextual_trust_multiplier);
            }
        }
        // Other stable processes get moderate trust
        else if (proc->execution_count > 30) {
            proc->contextual_trust_multiplier = 1.5f;
        }
    }
    // Reset trust for suspicious processes
    else if (proc->suspicion_score > 50.0f) {
        proc->contextual_trust_multiplier = 0.8f;
    }
}

// Update process memory statistics
static void update_process_memory_stats(ProcessInfo* proc) {
    if (!proc) return;
    
    time_t now = time(NULL);
    
    // Only update every 5 seconds to avoid overhead
    if (now - proc->last_memory_check < 5) {
        return;
    }
    
    // Store previous memory usage
    proc->prev_memory_usage_kb = proc->memory_usage_kb;
    
    // Get current memory usage from /proc/{pid}/statm
    char statm_path[64];
    snprintf(statm_path, sizeof(statm_path), "/proc/%d/statm", proc->pid);
    
    FILE* f = fopen(statm_path, "r");
    if (f) {
        // First value is total program size in pages
        unsigned long size = 0;
        if (fscanf(f, "%lu", &size) == 1) {
            // Convert pages to KB (assuming 4KB pages)
            proc->memory_usage_kb = size * 4;
            
            // Calculate memory growth rate if we have previous data
            if (proc->prev_memory_usage_kb > 0) {
                // Calculate time difference
                float time_diff = (float)(now - proc->last_memory_check);
                if (time_diff > 0) {
                    // Calculate absolute growth in KB
                    long memory_diff = (long)proc->memory_usage_kb - (long)proc->prev_memory_usage_kb;
                    
                    // Calculate growth rate in KB/sec
                    proc->memory_growth_rate = (float)memory_diff / time_diff;
                    
                    // Check for suspicious rapid memory growth
                    if (memory_diff > 50000 && proc->memory_growth_rate > 10000.0f) {
                        // 10MB/sec is very rapid growth
                        LOG_WARNING("Process %d (%s) shows rapid memory growth: %ld KB in %.1f sec (%.2f KB/sec)",
                                   proc->pid, proc->comm, memory_diff, time_diff, proc->memory_growth_rate);
                        
                        char details[256];
                        snprintf(details, sizeof(details),
                                "Rapid memory allocation: %ld KB in %.1f sec (%.2f KB/sec)",
                                memory_diff, time_diff, proc->memory_growth_rate);
                        
                        // Flag for suspicious memory activity
                        proc->has_suspicious_memory = 1;
                        
                        // Record this behavior
                        record_behavior_event(proc, EVENT_MEMORY_SUSPICIOUS, 15.0f, details);
                        
                        // If also has rapid file access, this is highly suspicious
                        if (proc->has_rapid_file_access) {
                            LOG_WARNING("Process %d (%s) has both rapid memory growth and file access!",
                                       proc->pid, proc->comm);
                            
                            snprintf(details, sizeof(details),
                                    "Correlated detection: Rapid memory growth (%.2f KB/sec) and file access (%.2f files/sec)",
                                    proc->memory_growth_rate, proc->file_access_rate);
                            
                            generate_process_event(proc->pid, EVENT_PROCESS_CORRELATION, details, 35.0f);
                            record_behavior_event(proc, EVENT_PROCESS_CORRELATION, 35.0f, details);
                        }
                    }
                }
            }
        }
        fclose(f);
    }
    
    proc->last_memory_check = now;
}

// Adjust monitoring level based on risk and activity
static void adjust_monitoring_level(ProcessInfo* proc) {
    if (!proc) return;
    
    time_t now = time(NULL);
    
    // Only adjust every 60 seconds
    if (now - proc->last_level_adjustment < 60) {
        return;
    }
    
    int new_level = MONITORING_LEVEL_MEDIUM; // Default level
    
    // Determine appropriate monitoring level
    if (proc->suspicion_score > 60.0f || 
        proc->has_rapid_file_access || 
        proc->has_suspicious_memory ||
        proc->has_suspicious_cmdline ||
        proc->ancestry_suspicious) {
        
        // High-risk processes get intense monitoring
        new_level = MONITORING_LEVEL_INTENSE;
    }
    else if (proc->suspicion_score > 30.0f) {
        // Medium-risk processes get high monitoring
        new_level = MONITORING_LEVEL_HIGH;
    }
    else if (proc->suspicion_score < 10.0f && 
             proc->execution_count > 5 &&
             !proc->is_from_suspicious_location) {
        
        // Low-risk processes with history get minimal monitoring
        new_level = MONITORING_LEVEL_LOW;
    }
    
    // Check for recent suspicious events to prioritize monitoring
    time_t recent_event_time = 0;
    
    for (int i = 0; i < BEHAVIOR_HISTORY_SIZE; i++) {
        if (proc->behavior_history[i].timestamp > recent_event_time) {
            recent_event_time = proc->behavior_history[i].timestamp;
        }
    }
    
    // If there was a recent suspicious event, increase monitoring temporarily
    if (recent_event_time > 0 && now - recent_event_time < 300) { // Within last 5 minutes
        // Find the most severe recent event
        float max_severity = 0.0f;
        for (int i = 0; i < BEHAVIOR_HISTORY_SIZE; i++) {
            if (proc->behavior_history[i].timestamp > now - 300 && 
                proc->behavior_history[i].severity > max_severity) {
                max_severity = proc->behavior_history[i].severity;
            }
        }
        
        // Temporarily increase monitoring level based on severity
        if (max_severity > 25.0f && new_level < MONITORING_LEVEL_INTENSE) {
            int old_level = new_level;
            new_level = MONITORING_LEVEL_INTENSE;
            
            LOG_DEBUG("Temporarily increasing monitoring level for process %d (%s) due to recent high-severity event (%.1f)",
                     proc->pid, proc->comm, max_severity);
            
            // Set a timer to return to normal monitoring
            proc->elevated_monitoring_until = now + 600; // 10 minutes of heightened monitoring
        }
        else if (max_severity > 15.0f && new_level < MONITORING_LEVEL_HIGH) {
            int old_level = new_level;
            new_level = MONITORING_LEVEL_HIGH;
            
            LOG_DEBUG("Temporarily increasing monitoring level for process %d (%s) due to recent suspicious event (%.1f)",
                     proc->pid, proc->comm, max_severity);
            
            // Set a timer to return to normal monitoring
            proc->elevated_monitoring_until = now + 300; // 5 minutes of heightened monitoring
        }
    }
    // Check if temporary heightened monitoring should be expired
    else if (proc->elevated_monitoring_until > 0 && now > proc->elevated_monitoring_until) {
        proc->elevated_monitoring_until = 0;
        // Let the normal monitoring level logic take over
    }
    else if (proc->elevated_monitoring_until > 0) {
        // Still in heightened monitoring period, maintain at least HIGH level
        if (new_level < MONITORING_LEVEL_HIGH) {
            new_level = MONITORING_LEVEL_HIGH;
        }
    }
    
    // If level is changing, log it
    if (new_level != proc->monitoring_level) {
        const char* level_str[] = {"Unknown", "Low", "Medium", "High", "Intense"};
        
        LOG_DEBUG("Adjusting monitoring level for process %d (%s): %s -> %s",
                 proc->pid, proc->comm, 
                 level_str[proc->monitoring_level], level_str[new_level]);
        
        proc->monitoring_level = new_level;
    }
    
    proc->last_level_adjustment = now;
    proc->monitoring_events_processed = 0;
}

// Add this function around line 765, after correlate_monitoring_data()

// Perform unified risk assessment across multiple monitoring dimensions
static float calculate_unified_risk_score(ProcessInfo* proc) {
    if (!proc) return 0.0f;
    
    // Base score from suspicion calculation
    float base_score = proc->suspicion_score;
    
    // Weight different types of evidence
    const float WEIGHTS[] = {
        0.8f,   // Memory evidence weight
        0.7f,   // Syscall evidence weight
        1.0f,   // File access evidence weight
        0.6f,   // Process behavior evidence weight
        0.5f,   // Lineage evidence weight
        0.9f    // Command line evidence weight
    };
    
    // Evidence counters
    int evidence_counts[6] = {0}; 
    float evidence_strengths[6] = {0.0f};
    
    // Analyze behavior history for different types of evidence
    for (int i = 0; i < BEHAVIOR_HISTORY_SIZE; i++) {
        BehaviorEvent* event = &proc->behavior_history[i];
        if (event->timestamp == 0) continue;
        
        // Categorize and count evidence by type
        switch (event->type) {
            case EVENT_MEMORY_SUSPICIOUS:
            case EVENT_MEMORY_RWX:
            case EVENT_MEMORY_PATTERN:
                evidence_counts[0]++;
                evidence_strengths[0] += event->severity;
                break;
                
            case EVENT_SYSCALL_SUSPICIOUS:
                evidence_counts[1]++;
                evidence_strengths[1] += event->severity;
                break;
                
            case EVENT_FILE_ACCESS:
            case EVENT_FILE_MODIFY:
            case EVENT_FILE_DELETE:
                evidence_counts[2]++;
                evidence_strengths[2] += event->severity;
                break;
                
            case EVENT_PROCESS_BEHAVIOR:
                evidence_counts[3]++;
                evidence_strengths[3] += event->severity;
                break;
                
            case EVENT_PROCESS_LINEAGE:
                evidence_counts[4]++;
                evidence_strengths[4] += event->severity;
                break;
                
            case EVENT_PROCESS_OBFUSCATION:
                evidence_counts[5]++;
                evidence_strengths[5] += event->severity;
                break;
        }
    }
    
    // Calculate evidence scores with diminishing returns
    float evidence_scores[6] = {0.0f};
    for (int i = 0; i < 6; i++) {
        if (evidence_counts[i] > 0) {
            // Average strength with diminishing returns for large numbers of events
            float avg_strength = evidence_strengths[i] / evidence_counts[i];
            float count_factor = 1.0f - (1.0f / (1.0f + (float)evidence_counts[i] * 0.5f));
            evidence_scores[i] = avg_strength * count_factor * WEIGHTS[i];
        }
    }
    
    // Calculate correlation bonus for multiple types of evidence
    int evidence_types = 0;
    for (int i = 0; i < 6; i++) {
        if (evidence_scores[i] > 0.0f) evidence_types++;
    }
    
    float correlation_bonus = 0.0f;
    if (evidence_types >= 2) {
        // Bonus increases with number of evidence types
        correlation_bonus = 5.0f * (evidence_types - 1);
        
        // Extra bonus for specific combinations (memory+file or syscall+file)
        if ((evidence_scores[0] > 0.0f && evidence_scores[2] > 0.0f) ||
            (evidence_scores[1] > 0.0f && evidence_scores[2] > 0.0f)) {
            correlation_bonus += 10.0f;
        }
    }
    
    // Combine base score with weighted evidence and correlation bonus
    float unified_score = base_score;
    for (int i = 0; i < 6; i++) {
        unified_score += evidence_scores[i];
    }
    unified_score += correlation_bonus;
    
    // Cap at 100
    if (unified_score > 100.0f) unified_score = 100.0f;
    
    // For significant adjustments, log details
    if (fabsf(unified_score - base_score) > 15.0f && base_score > 30.0f) {
        LOG_DEBUG("Unified risk assessment for %s (PID %d): %.2f -> %.2f (evidence types: %d, correlation bonus: %.2f)",
                 proc->comm, proc->pid, base_score, unified_score, 
                 evidence_types, correlation_bonus);
    }
    
    return unified_score;
}

// Add this function around line 1550, after is_system_utility()

// Classify process origin for more nuanced risk assessment
static int classify_process_origin(ProcessInfo* proc) {
    if (!proc || !proc->exe_path[0]) return ORIGIN_UNKNOWN;
    
    // Check for system directories
    const char* system_dirs[] = {
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/usr/lib/",
        NULL
    };
    
    // Check for package management directories
    const char* package_dirs[] = {
        "/var/lib/dpkg/", "/var/lib/apt/", "/var/cache/apt/", 
        "/var/lib/yum/", "/var/lib/rpm/",
        NULL
    };
    
    // Check for high-risk directories
    const char* high_risk_dirs[] = {
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/var/run/user/",
        NULL
    };
    
    // Check for user application directories
    const char* user_app_dirs[] = {
        "/.local/bin/", "/.local/share/", "/.config/", "/opt/", "/usr/local/",
        NULL
    };
    
    // Directory matching
    for (int i = 0; system_dirs[i] != NULL; i++) {
        if (strncmp(proc->exe_path, system_dirs[i], strlen(system_dirs[i])) == 0) {
            return ORIGIN_SYSTEM;
        }
    }
    
    for (int i = 0; package_dirs[i] != NULL; i++) {
        if (strncmp(proc->exe_path, package_dirs[i], strlen(package_dirs[i])) == 0) {
            return ORIGIN_PACKAGE_MANAGER;
        }
    }
    
    for (int i = 0; high_risk_dirs[i] != NULL; i++) {
        if (strncmp(proc->exe_path, high_risk_dirs[i], strlen(high_risk_dirs[i])) == 0) {
            return ORIGIN_HIGH_RISK;
        }
    }
    
    // Check for home directory
    if (current_user_home[0] && strncmp(proc->exe_path, current_user_home, strlen(current_user_home)) == 0) {
        // Check for specific user app directories
        for (int i = 0; user_app_dirs[i] != NULL; i++) {
            char full_path[MAX_PATH_LENGTH];
            snprintf(full_path, sizeof(full_path), "%s%s", current_user_home, user_app_dirs[i]);
            if (strncmp(proc->exe_path, full_path, strlen(full_path)) == 0) {
                return ORIGIN_USER_INSTALLED;
            }
        }
        return ORIGIN_HOME_DIRECTORY;
    }
    
    // Recently downloaded executables (if we can access this information)
    if (proc->file_attributes && proc->file_attributes->download_time > 0) {
        time_t now = time(NULL);
        if (now - proc->file_attributes->download_time < 3600) { // Downloaded in last hour
            return ORIGIN_RECENT_DOWNLOAD;
        }
    }
    
    return ORIGIN_UNKNOWN;
}

// Add these public function definitions to process_monitor.c

// Get process info by PID
ProcessInfo* process_monitor_get_process_info(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (monitored_processes[i].pid == pid) {
            return &monitored_processes[i];
        }
    }
    return NULL;
}

// Report process as suspicious
void process_monitor_process_suspicious(pid_t pid, const char* details) {
    ProcessInfo* proc = process_monitor_get_process_info(pid);
    if (proc) {
        // Record suspicious behavior
        record_behavior_event(proc, EVENT_PROCESS_SUSPICIOUS, 20.0f, details);
        
        // Generate an event
        generate_process_event(pid, EVENT_PROCESS_SUSPICIOUS, details, 20.0f);
        
        // Mark the process as suspicious
        proc->has_suspicious_behavior = 1;
    }
}

// Public function to trigger relationship analysis
void process_monitor_analyze_relationships(void) {
    // Call the internal function
    propagate_process_suspicion();
}

// Public function to apply risk decay
void process_monitor_apply_risk_decay(void) {
    // Call the internal function
    apply_risk_decay();
}