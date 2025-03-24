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

// Structure to track a child process
typedef struct {
    pid_t pid;
    time_t spawn_time;
    char comm[256];
} ChildProcess;

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
} ProcessInfo;

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

// Initialize the process monitor
int process_monitor_init(EventHandler handler, void* user_data) {
    memset(monitored_processes, 0, sizeof(monitored_processes));
    process_count = 0;
    last_poll_time = time(NULL);
    event_callback = handler;
    event_callback_data = user_data;
    
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
    process_count = 0;
    LOG_INFO("Process monitor cleaned up%s", "");
}

// Poll processes for changes
void process_monitor_poll(void) {
    time_t now = time(NULL);
    
    // Only poll at the configured interval
    if (now - last_poll_time < PROCESS_POLL_INTERVAL / 1000) {
        return;
    }
    
    // Update last poll time
    last_poll_time = now;
    
    // Scan for processes
    scan_processes();
    
    // Check each monitored process
    for (int i = 0; i < process_count; i++) {
        ProcessInfo* proc = &monitored_processes[i];
        
        // Skip recently updated processes
        if (now - proc->last_updated < PROCESS_POLL_INTERVAL / 1000) {
            continue;
        }
        
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
        
        // Analyze for suspicious behavior
        analyze_process(proc);
        
        // Remove old child entries
        remove_old_children(proc);
        
        // Update timestamp
        proc->last_updated = now;
    }
}

// Register a file access event for a process
void process_monitor_file_access(pid_t pid, const char* path, int write_access) {
    // Mark unused parameters
    (void)path;          // Explicitly mark parameter as unused
    (void)write_access;  // Explicitly mark parameter as unused
    
    ProcessInfo* proc = find_process_info(pid);
    if (!proc) {
        // Process not monitored yet, add it
        proc = add_process_info(pid);
        if (!proc) {
            return;
        }
        update_process_info(proc);
    }
    
    // Increment file access counter
    proc->file_access_count++;
    
    // Calculate file access rate (files per second)
    time_t now = time(NULL);
    time_t time_diff = now - proc->last_file_access_time;
    
    if (time_diff > 0 && proc->file_access_count > 1) {
        // Smooth the rate calculation with a weighted average
        float current_rate = 1.0f / (float)time_diff;
        proc->file_access_rate = (proc->file_access_rate * 0.7f) + (current_rate * 0.3f);
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
        }
    }
    
    // Update last access time
    proc->last_file_access_time = now;
    
    // Update suspicion score based on new information
    update_process_suspicious_score(proc);
}

// Register a new process (parent-child relationship)
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
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", child_pid);
    FILE* f = fopen(comm_path, "r");
    if (f) {
        if (fgets(comm, sizeof(comm), f)) {
            // Remove trailing newline
            size_t len = strlen(comm);
            if (len > 0 && comm[len - 1] == '\n') {
                comm[len - 1] = '\0';
            }
        }
        fclose(f);
    }
    
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
    }
    
    // Update suspicion score based on new information
    update_process_suspicious_score(parent);
    
    // Also add the child to our monitoring list
    ProcessInfo* child = find_process_info(child_pid);
    if (!child) {
        child = add_process_info(child_pid);
        if (child) {
            update_process_info(child);
            analyze_process(child);
        }
    }
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

// Analyze process for suspicious behavior
static void analyze_process(ProcessInfo* proc) {
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
    
    // Update overall suspicion score
    update_process_suspicious_score(proc);
    
    // Generate events for highly suspicious processes
    if (proc->suspicion_score > 50.0f) {
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
        if (proc->has_rapid_process_spawning) strcat(flags, "Spawning");

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
        
        generate_process_event(proc->pid, EVENT_PROCESS_SUSPICIOUS, details, 20.0f);
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

// Check for suspicious command line arguments
static void check_suspicious_cmdline(ProcessInfo* proc) {
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
    
    // Check for base64-encoded or hex-encoded arguments (potential obfuscation)
    int consecutive_hex = 0;
    int consecutive_base64 = 0;
    int max_consecutive_hex = 0;
    int max_consecutive_base64 = 0;
    
    for (size_t i = 0; i < strlen(proc->cmdline); i++) {
        char c = proc->cmdline[i];
        
        // Check for hex characters
        if (isxdigit((unsigned char)c)) {
            consecutive_hex++;
            if (consecutive_hex > max_consecutive_hex) {
                max_consecutive_hex = consecutive_hex;
            }
        } else {
            consecutive_hex = 0;
        }
        
        // Check for base64 characters
        if (isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=') {
            consecutive_base64++;
            if (consecutive_base64 > max_consecutive_base64) {
                max_consecutive_base64 = consecutive_base64;
            }
        } else {
            consecutive_base64 = 0;
        }
    }
    
    // Long hex or base64 strings are suspicious
    if (max_consecutive_hex > 32 || max_consecutive_base64 > 40) {
        proc->has_suspicious_cmdline = 1;
        
        LOG_WARNING("Process %d (%s) has potentially encoded command line: %s", 
                   proc->pid, proc->comm, proc->cmdline);
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

// Update the suspicion score for a process
static void update_process_suspicious_score(ProcessInfo* proc) {
    // Start with a base score
    float score = 0.0f;
    
    // Add points for suspicious indicators
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
    
    // Cap the score at 100
    if (score > 100.0f) {
        score = 100.0f;
    }
    
    // Update the score
    proc->suspicion_score = score;
    
    // Log high suspicion scores
    if (score > 50.0f && score > proc->suspicion_score + 10.0f) {
        LOG_WARNING("Process %d (%s) suspicion score increased to %.2f", 
                   proc->pid, proc->comm, score);
    }
}

// Read a file from the /proc filesystem
static int read_proc_file(pid_t pid, const char* file, char* buffer, size_t buffer_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, file);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    ssize_t bytes_read = read(fd, buffer, buffer_size - 1);
    close(fd);
    
    if (bytes_read <= 0) {
        return -1;
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
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    
    if (access(proc_path, F_OK) != 0) {
        LOG_ERROR("Process does not exist: %d", pid);
        return -1;
    }
    
    LOG_DEBUG("Adding process to monitor: PID %d", pid);
    
    // Find or create a monitor for this process
    char process_name[256] = {0};
    get_process_name(pid, process_name, sizeof(process_name));
    
    ProcessMonitor* monitor = find_or_create_process_monitor(pid, process_name);
    if (!monitor) {
        LOG_ERROR("Failed to create process monitor: %d", pid);
        return -1;
    }
    
    // Start monitoring
    monitor->is_monitored = 1;
    
    LOG_INFO("Started monitoring process: %s (PID: %d)", process_name, pid);
    return 0;
}

/**
 * Removes a process from monitoring
 * 
 * @param pid Process ID to stop monitoring
 */
void process_monitor_remove_process(pid_t pid) {
    ProcessMonitor* monitor = find_process_monitor(pid);
    if (!monitor) {
        LOG_DEBUG("Process not found in monitoring system: PID %d", pid);
        return;
    }
    
    LOG_INFO("Removing process from monitoring: %s (PID: %d)", 
             monitor->process_name, monitor->pid);
    
    // Stop monitoring but keep the monitor for history
    monitor->is_monitored = 0;
    
    // In a real implementation with resource constraints, you might 
    // want to free the monitor struct here
}