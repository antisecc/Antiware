#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fnmatch.h>
#include <regex.h>
#include <limits.h>

#include "../include/antiransom.h"
#include "../include/events.h"
#include "../common/logger.h"
#include "../common/config.h"
#include "../common/scoring.h"

// Maximum number of whitelist entries
#define MAX_WHITELIST_ENTRIES 256

// Maximum number of process signatures
#define MAX_PROCESS_SIGNATURES 128

// Maximum number of behavior patterns
#define MAX_BEHAVIOR_PATTERNS 64

// Maximum path length
#define MAX_PATH_LENGTH 1024

// Process whitelist entry
typedef struct {
    char process_name[256];
    char path_pattern[MAX_PATH_LENGTH];
    int exclude_children;     // Whether to exclude child processes too
    int trusted_level;        // 0-100, higher = more trusted
} WhitelistEntry;

// Process signature for known good behavior
typedef struct {
    char process_name[256];
    char path_pattern[MAX_PATH_LENGTH];
    regex_t cmdline_regex;
    int has_valid_regex;
    char description[512];
    BehaviorFlags allowed_behaviors;
} ProcessSignature;

// Common behavior pattern that might trigger false positives
typedef struct {
    char description[256];
    BehaviorFlags behavior_flags;
    time_t first_seen;
    int frequency;
    int is_whitelisted;
} BehaviorPattern;

// Globals
static WhitelistEntry process_whitelist[MAX_WHITELIST_ENTRIES];
static int whitelist_count = 0;

static ProcessSignature process_signatures[MAX_PROCESS_SIGNATURES];
static int signature_count = 0;

static BehaviorPattern behavior_patterns[MAX_BEHAVIOR_PATTERNS];
static int pattern_count = 0;

static char current_user_name[256] = {0};
static char current_user_home[MAX_PATH_LENGTH] = {0};
static uid_t current_user_uid = 0;

// Forward declarations
static int is_process_whitelisted(pid_t pid, const char *process_name, const char *exe_path);
static int is_system_utility(const char *process_name, const char *exe_path);
static int does_signature_match(pid_t pid, const char *process_name, const char *exe_path, const char *cmdline);
static BehaviorPattern* find_behavior_pattern(BehaviorFlags flags);
static void add_behavior_pattern(BehaviorFlags flags, const char *description);
static int is_path_in_user_directories(const char *path);
static int get_process_cmdline(pid_t pid, char *buffer, size_t buffer_size);
static int get_process_exe_path(pid_t pid, char *buffer, size_t buffer_size);
static int get_process_name(pid_t pid, char *buffer, size_t buffer_size);
static float calculate_trust_adjustment(pid_t pid, const char *process_name);

// Function declarations
int user_filter_add_whitelist(const char *process_name, const char *path_pattern, 
                            int exclude_children, int trusted_level);
int user_filter_add_signature(const char *process_name, const char *path_pattern, 
                            const char *cmdline_regex, const char *description, 
                            BehaviorFlags allowed_behaviors);

// Initialize the user filter
int user_filter_init(void) {
    // Get current user info
    current_user_uid = getuid();
    struct passwd *pw = getpwuid(current_user_uid);
    if (pw != NULL) {
        strncpy(current_user_name, pw->pw_name, sizeof(current_user_name) - 1);
        strncpy(current_user_home, pw->pw_dir, sizeof(current_user_home) - 1);
    }
    
    // Initialize with empty whitelist
    whitelist_count = 0;
    signature_count = 0;
    pattern_count = 0;
    
    // Add common system utilities to whitelist
    // Package managers
    user_filter_add_whitelist("apt", "/usr/bin/apt*", 1, 90);
    user_filter_add_whitelist("apt-get", "/usr/bin/apt-get", 1, 90);
    user_filter_add_whitelist("dpkg", "/usr/bin/dpkg", 1, 90);
    user_filter_add_whitelist("yum", "/usr/bin/yum", 1, 90);
    user_filter_add_whitelist("dnf", "/usr/bin/dnf", 1, 90);
    user_filter_add_whitelist("rpm", "/usr/bin/rpm", 1, 90);
    user_filter_add_whitelist("pacman", "/usr/bin/pacman", 1, 90);
    
    // Archive utilities
    user_filter_add_whitelist("tar", "/usr/bin/tar", 0, 70);
    user_filter_add_whitelist("gzip", "/usr/bin/gzip", 0, 70);
    user_filter_add_whitelist("bzip2", "/usr/bin/bzip2", 0, 70);
    user_filter_add_whitelist("xz", "/usr/bin/xz", 0, 70);
    user_filter_add_whitelist("zip", "/usr/bin/zip", 0, 70);
    user_filter_add_whitelist("unzip", "/usr/bin/unzip", 0, 70);
    
    // System utilities
    user_filter_add_whitelist("bash", "/usr/bin/bash", 0, 60);
    user_filter_add_whitelist("sh", "/usr/bin/sh", 0, 60);
    user_filter_add_whitelist("cp", "/usr/bin/cp", 0, 60);
    user_filter_add_whitelist("mv", "/usr/bin/mv", 0, 60);
    user_filter_add_whitelist("rm", "/usr/bin/rm", 0, 60);
    user_filter_add_whitelist("find", "/usr/bin/find", 0, 70);
    user_filter_add_whitelist("grep", "/usr/bin/grep", 0, 80);
    user_filter_add_whitelist("rsync", "/usr/bin/rsync", 0, 70);
    
    // Add common behavior patterns
    BehaviorFlags backup_behavior = {
        .rapid_file_access = 1,
        .high_file_io = 1,
        .multiple_file_extension_changes = 0,
        .multiple_file_renames = 1,
        .memory_pattern = 0,
        .system_changes = 0
    };
    add_behavior_pattern(backup_behavior, "Backup software behavior");
    
    BehaviorFlags update_behavior = {
        .rapid_file_access = 1,
        .high_file_io = 1,
        .multiple_file_extension_changes = 0,
        .multiple_file_renames = 0,
        .memory_pattern = 0,
        .system_changes = 1
    };
    add_behavior_pattern(update_behavior, "System update behavior");
    
    BehaviorFlags compile_behavior = {
        .rapid_file_access = 1,
        .high_file_io = 1,
        .multiple_file_extension_changes = 1,
        .multiple_file_renames = 0,
        .memory_pattern = 1,
        .system_changes = 0
    };
    add_behavior_pattern(compile_behavior, "Software compilation behavior");
    
    // Add process signatures for known legitimate software
    
    // Firefox browser
    const char *firefox_regex = "^/usr/lib/firefox(-esr)?/firefox(-esr)? (-.*)?$";
    user_filter_add_signature("firefox", "/usr/lib/firefox*", firefox_regex, 
                             "Mozilla Firefox Web Browser", 
                             (BehaviorFlags){.rapid_file_access = 1, .high_file_io = 1});
    
    // Chrome/Chromium browser
    const char *chrome_regex = "^/usr/bin/chrom(e|ium)(-browser)? (--.*)?$";
    user_filter_add_signature("chrome", "/usr/bin/chrome*", chrome_regex, 
                             "Google Chrome Web Browser", 
                             (BehaviorFlags){.rapid_file_access = 1, .high_file_io = 1});
    
    // LibreOffice suite
    const char *office_regex = "^/usr/lib/libreoffice/program/.*$";
    user_filter_add_signature("soffice", "/usr/lib/libreoffice/program/*", office_regex, 
                             "LibreOffice Suite", 
                             (BehaviorFlags){.rapid_file_access = 1, .high_file_io = 1, 
                                           .multiple_file_extension_changes = 1});
    
    // Git version control
    user_filter_add_signature("git", "/usr/bin/git", NULL, 
                             "Git Version Control", 
                             (BehaviorFlags){.rapid_file_access = 1, .high_file_io = 1, 
                                           .multiple_file_renames = 1});
    
    LOG_INFO("User filter initialized (user: %s, uid: %d)", current_user_name, current_user_uid);
    return 0;
}

// Clean up resources
void user_filter_cleanup(void) {
    // Free any compiled regex patterns
    for (int i = 0; i < signature_count; i++) {
        if (process_signatures[i].has_valid_regex) {
            regfree(&process_signatures[i].cmdline_regex);
        }
    }
    
    LOG_INFO("User filter cleaned up%s", "");
}

// Add a process to the whitelist
int user_filter_add_whitelist(const char *process_name, const char *path_pattern, 
                             int exclude_children, int trusted_level) {
    if (whitelist_count >= MAX_WHITELIST_ENTRIES) {
        LOG_ERROR("Failed to add process to whitelist: maximum entries reached%s", "");
        return -1;
    }
    
    if (!process_name || !path_pattern) {
        LOG_ERROR("Failed to add process to whitelist: invalid parameters%s", "");
        return -1;
    }
    
    // Add to whitelist
    WhitelistEntry *entry = &process_whitelist[whitelist_count++];
    strncpy(entry->process_name, process_name, sizeof(entry->process_name) - 1);
    strncpy(entry->path_pattern, path_pattern, sizeof(entry->path_pattern) - 1);
    entry->exclude_children = exclude_children;
    entry->trusted_level = trusted_level;
    
    LOG_INFO("Added process to whitelist: %s (path: %s, trust: %d)", 
             process_name, path_pattern, trusted_level);
    return 0;
}

// Remove a process from the whitelist
int user_filter_remove_whitelist(const char *process_name, const char *path_pattern) {
    for (int i = 0; i < whitelist_count; i++) {
        if (strcmp(process_whitelist[i].process_name, process_name) == 0 &&
            strcmp(process_whitelist[i].path_pattern, path_pattern) == 0) {
            
            // Remove by copying the last entry to this position
            if (i < whitelist_count - 1) {
                process_whitelist[i] = process_whitelist[whitelist_count - 1];
            }
            whitelist_count--;
            
            LOG_INFO("Removed process from whitelist: %s (path: %s)", 
                     process_name, path_pattern);
            return 0;
        }
    }
    
    LOG_WARNING("Process not found in whitelist: %s (path: %s)", 
               process_name, path_pattern);
    return -1;
}

// Add a process signature for known good behavior
int user_filter_add_signature(const char *process_name, const char *path_pattern, 
                             const char *cmdline_regex, const char *description, 
                             BehaviorFlags allowed_behaviors) {
    if (signature_count >= MAX_PROCESS_SIGNATURES) {
        LOG_ERROR("Failed to add process signature: maximum entries reached%s", "");
        return -1;
    }
    
    if (!process_name || !path_pattern) {
        LOG_ERROR("Failed to add process signature: invalid parameters%s", "");
        return -1;
    }
    
    // Add to signatures
    ProcessSignature *sig = &process_signatures[signature_count++];
    strncpy(sig->process_name, process_name, sizeof(sig->process_name) - 1);
    strncpy(sig->path_pattern, path_pattern, sizeof(sig->path_pattern) - 1);
    
    if (description) {
        strncpy(sig->description, description, sizeof(sig->description) - 1);
    } else {
        snprintf(sig->description, sizeof(sig->description), "Signature for %s", process_name);
    }
    
    sig->allowed_behaviors = allowed_behaviors;
    sig->has_valid_regex = 0;
    
    // Compile regex if provided
    if (cmdline_regex) {
        int regex_result = regcomp(&sig->cmdline_regex, cmdline_regex, REG_EXTENDED | REG_NOSUB);
        if (regex_result == 0) {
            sig->has_valid_regex = 1;
        } else {
            char error_buffer[256];
            regerror(regex_result, &sig->cmdline_regex, error_buffer, sizeof(error_buffer));
            LOG_ERROR("Failed to compile regex for process signature %s: %s", 
                     process_name, error_buffer);
        }
    }
    
    LOG_INFO("Added process signature: %s (path: %s)", process_name, path_pattern);
    return 0;
}

// Check if a process should be excluded from detection
int user_filter_should_exclude(pid_t pid, const char *process_name, const char *exe_path) {
    // Check whitelist first
    if (is_process_whitelisted(pid, process_name, exe_path)) {
        return 1;
    }
    
    // Check if it's a common system utility
    if (is_system_utility(process_name, exe_path)) {
        return 1;
    }
    
    return 0;
}

// Adjust the suspicion score based on user filtering
float user_filter_adjust_score(pid_t pid, float original_score, BehaviorFlags behavior) {
    char process_name[256] = {0};
    char exe_path[MAX_PATH_LENGTH] = {0};
    
    // Get process info
    if (get_process_name(pid, process_name, sizeof(process_name)) <= 0 ||
        get_process_exe_path(pid, exe_path, sizeof(exe_path)) <= 0) {
        // If we can't get information, don't adjust the score
        return original_score;
    }
    
    // Check whitelist for full exclusion
    if (is_process_whitelisted(pid, process_name, exe_path)) {
        return 0.0f;  // Fully exclude whitelisted processes
    }
    
    // Calculate trust adjustment
    float trust_adjustment = calculate_trust_adjustment(pid, process_name);
    
    // Check behavior patterns
    BehaviorPattern *pattern = find_behavior_pattern(behavior);
    if (pattern) {
        // Update pattern frequency
        pattern->frequency++;
        
        // If this is a known good behavior pattern, reduce the score
        if (pattern->is_whitelisted) {
            float pattern_adjustment = 0.5f;  // Reduce by 50%
            
            // Further reduce if the pattern is frequently seen (legitimate user behavior)
            if (pattern->frequency > 10) {
                pattern_adjustment = 0.25f;  // Reduce by 75%
            }
            
            return original_score * pattern_adjustment;
        }
    }
    
    // Get command line to check against signatures
    char cmdline[MAX_CMDLINE_LENGTH] = {0};
    get_process_cmdline(pid, cmdline, sizeof(cmdline));
    
    // Check against process signatures
    if (does_signature_match(pid, process_name, exe_path, cmdline)) {
        // If behavior is allowed for this signature, significantly reduce score
        return original_score * 0.2f;  // Reduce by 80%
    }
    
    // Apply general trust adjustment
    float adjusted_score = original_score * (1.0f - trust_adjustment);
    
    // Always maintain a minimum possible score for non-excluded processes
    if (adjusted_score < 1.0f && original_score > 5.0f) {
        adjusted_score = 1.0f;
    }
    
    return adjusted_score;
}

// Check if an event should be filtered based on context
int user_filter_check_event(const Event *event) {
    if (!event) {
        return 0;
    }
    
    // If process is whitelisted, filter all events
    char process_name[256] = {0};
    char exe_path[MAX_PATH_LENGTH] = {0};
    
    if (get_process_name(event->process_id, process_name, sizeof(process_name)) > 0 &&
        get_process_exe_path(event->process_id, exe_path, sizeof(exe_path)) > 0 &&
        is_process_whitelisted(event->process_id, process_name, exe_path)) {
        return 1;  // Filter this event
    }
    
    // For file events, check if it's in a user directory
    if (event->type == EVENT_FILE_ACCESS || 
        event->type == EVENT_FILE_WRITE || 
        event->type == EVENT_FILE_RENAME) {
        
        const char *path = event->data.file_event.path;
        
        // If it's a standard user directory, lower priority but don't filter completely
        if (is_path_in_user_directories(path)) {
            // Just return a "maybe" - the score adjuster can handle this
            return 0;
        }
    }
    
    // For process events, check for common patterns
    if (event->type == EVENT_PROCESS_BEHAVIOR) {
        // Examples of normal process behavior events that can be filtered
        if (strstr(event->data.process_event.details, "compiler") ||
            strstr(event->data.process_event.details, "linker") ||
            strstr(event->data.process_event.details, "make")) {
            
            // Check if this is in a development environment
            char cwd[MAX_PATH_LENGTH] = {0};
            char proc_cwd[64];
            snprintf(proc_cwd, sizeof(proc_cwd), "/proc/%d/cwd", event->process_id);
            ssize_t len = readlink(proc_cwd, cwd, sizeof(cwd) - 1);
            if (len != -1) {
                cwd[len] = '\0';
                
                // If it's in a typical dev directory, probably legitimate
                if (strstr(cwd, "/src") || 
                    strstr(cwd, "/build") || 
                    strstr(cwd, "/dev") ||
                    strstr(cwd, "git")) {
                    return 1;  // Filter this event
                }
            }
        }
    }
    
    // Don't filter by default
    return 0;
}

// Whitelist a behavior pattern
int user_filter_whitelist_behavior(BehaviorFlags behavior, int is_whitelisted) {
    BehaviorPattern *pattern = find_behavior_pattern(behavior);
    if (!pattern) {
        LOG_ERROR("Behavior pattern not found for whitelisting%s", "");
        return -1;
    }
    
    pattern->is_whitelisted = is_whitelisted;
    LOG_INFO("Updated behavior pattern whitelist status: %s, whitelist=%d", 
             pattern->description, is_whitelisted);
    return 0;
}

// Check if a process is whitelisted
static int is_process_whitelisted(pid_t pid, const char *process_name, const char *exe_path) {
    if (!process_name || !exe_path) {
        return 0;
    }
    
    for (int i = 0; i < whitelist_count; i++) {
        WhitelistEntry *entry = &process_whitelist[i];
        
        // Check if process name matches
        if (strcmp(entry->process_name, process_name) != 0 && 
            strcmp(entry->process_name, "*") != 0) {
            continue;
        }
        
        // Check if path matches the pattern
        if (fnmatch(entry->path_pattern, exe_path, 0) != 0) {
            continue;
        }
        
        // Check parent process if excluding children
        if (entry->exclude_children) {
            // Get parent PID
            pid_t ppid = 0;
            
            // Read status file to get PPID
            char status_path[64];
            snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
            
            FILE *status_file = fopen(status_path, "r");
            if (status_file) {
                char line[256];
                while (fgets(line, sizeof(line), status_file)) {
                    if (strncmp(line, "PPid:", 5) == 0) {
                        sscanf(line + 5, "%d", &ppid);
                        break;
                    }
                }
                fclose(status_file);
            }
            
            // Check if parent is also whitelisted
            if (ppid > 0) {
                char parent_name[256] = {0};
                char parent_exe[MAX_PATH_LENGTH] = {0};
                
                if (get_process_name(ppid, parent_name, sizeof(parent_name)) > 0 &&
                    get_process_exe_path(ppid, parent_exe, sizeof(parent_exe)) > 0) {
                    
                    if (is_process_whitelisted(ppid, parent_name, parent_exe)) {
                        LOG_DEBUG("Process %d (%s) whitelisted as child of %d (%s)", 
                                 pid, process_name, ppid, parent_name);
                        return 1;
                    }
                }
            }
        }
        
        LOG_DEBUG("Process %d (%s) matched whitelist entry: %s, %s", 
                 pid, process_name, entry->process_name, entry->path_pattern);
        return 1;
    }
    
    return 0;
}

// Check if a process is a common system utility
static int is_system_utility(const char *process_name, const char *exe_path) {
    if (!process_name || !exe_path) {
        return 0;
    }
    
    // Common system paths
    const char *system_paths[] = {
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
        "/usr/local/bin/", "/usr/local/sbin/",
        NULL
    };
    
    // Check if binary is in a system path
    for (int i = 0; system_paths[i] != NULL; i++) {
        if (strncmp(exe_path, system_paths[i], strlen(system_paths[i])) == 0) {
            // Common utilities to always whitelist
            const char *common_utils[] = {
                "ls", "cat", "grep", "sed", "awk", "sort", "uniq", "wc",
                "id", "whoami", "who", "w", "ps", "top", "htop", "free",
                "df", "du", "date", "uname", "hostname", "uptime", "ifconfig",
                "ip", "netstat", "ping", "ssh", "scp", "sftp", "rsync",
                NULL
            };
            
            for (int j = 0; common_utils[j] != NULL; j++) {
                if (strcmp(process_name, common_utils[j]) == 0) {
                    LOG_DEBUG("Process %s is a common system utility", process_name);
                    return 1;
                }
            }
            
            // For other system utilities, be more selective
            return 0;
        }
    }
    
    return 0;
}

// Check if a process matches a known signature
static int does_signature_match(pid_t pid, const char *process_name, const char *exe_path, const char *cmdline) {
    if (!process_name || !exe_path) {
        return 0;
    }
    
    for (int i = 0; i < signature_count; i++) {
        ProcessSignature *sig = &process_signatures[i];
        
        // Check if process name matches
        if (strcmp(sig->process_name, process_name) != 0 && 
            strcmp(sig->process_name, "*") != 0) {
            continue;
        }
        
        // Check if path matches the pattern
        if (fnmatch(sig->path_pattern, exe_path, 0) != 0) {
            continue;
        }
        
        // Check command line if regex is available
        if (sig->has_valid_regex && cmdline) {
            if (regexec(&sig->cmdline_regex, cmdline, 0, NULL, 0) != 0) {
                continue;
            }
        }
        
        LOG_DEBUG("Process %d (%s) matched signature: %s", 
                 pid, process_name, sig->description);
        return 1;
    }
    
    return 0;
}

// Find a behavior pattern that matches the given flags
static BehaviorPattern* find_behavior_pattern(BehaviorFlags flags) {
    for (int i = 0; i < pattern_count; i++) {
        // Check if all flags in the pattern match the input flags
        if (flags.rapid_file_access == behavior_patterns[i].behavior_flags.rapid_file_access &&
            flags.high_file_io == behavior_patterns[i].behavior_flags.high_file_io &&
            flags.multiple_file_extension_changes == behavior_patterns[i].behavior_flags.multiple_file_extension_changes &&
            flags.multiple_file_renames == behavior_patterns[i].behavior_flags.multiple_file_renames &&
            flags.memory_pattern == behavior_patterns[i].behavior_flags.memory_pattern &&
            flags.system_changes == behavior_patterns[i].behavior_flags.system_changes) {
            
            return &behavior_patterns[i];
        }
    }
    
    return NULL;
}

// Add a new behavior pattern
static void add_behavior_pattern(BehaviorFlags flags, const char *description) {
    if (pattern_count >= MAX_BEHAVIOR_PATTERNS) {
        LOG_ERROR("Failed to add behavior pattern: maximum entries reached%s", "");
        return;
    }
    
    BehaviorPattern *pattern = &behavior_patterns[pattern_count++];
    pattern->behavior_flags = flags;
    pattern->first_seen = time(NULL);
    pattern->frequency = 0;
    pattern->is_whitelisted = 0;  // Not whitelisted by default
    
    if (description) {
        strncpy(pattern->description, description, sizeof(pattern->description) - 1);
    } else {
        snprintf(pattern->description, sizeof(pattern->description), 
                "Behavior Pattern #%d", pattern_count);
    }
    
    LOG_INFO("Added behavior pattern: %s", pattern->description);
}

// Check if a path is in standard user directories
static int is_path_in_user_directories(const char *path) {
    if (!path || !current_user_home[0]) {
        return 0;
    }
    
    // Check if path is in user home directory
    if (strncmp(path, current_user_home, strlen(current_user_home)) == 0) {
        // Exclude certain sensitive directories
        const char *sensitive_dirs[] = {
            "/.ssh/", "/.gnupg/", "/.config/", "/.local/share/",
            "/Documents/", "/Pictures/", "/Videos/", "/Music/",
            NULL
        };
        
        for (int i = 0; sensitive_dirs[i] != NULL; i++) {
            char full_path[MAX_PATH_LENGTH];
            snprintf(full_path, sizeof(full_path), "%s%s", current_user_home, sensitive_dirs[i]);
            
            if (strncmp(path, full_path, strlen(full_path)) == 0) {
                return 0;  // This is a sensitive directory, don't filter
            }
        }
        
        return 1;  // It's in the user's home directory
    }
    
    // Check other common user directories
    const char *common_dirs[] = {
        "/tmp/", "/var/tmp/", "/run/user/",
        NULL
    };
    
    for (int i = 0; common_dirs[i] != NULL; i++) {
        if (strncmp(path, common_dirs[i], strlen(common_dirs[i])) == 0) {
            return 1;
        }
    }
    
    return 0;
}

// Get process command line
static int get_process_cmdline(pid_t pid, char *buffer, size_t buffer_size) {
    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
    
    int fd = open(cmdline_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    ssize_t bytes_read = read(fd, buffer, buffer_size - 1);
    close(fd);
    
    if (bytes_read <= 0) {
        return -1;
    }
    
    // Replace null bytes with spaces for easier handling
    for (ssize_t i = 0; i < bytes_read - 1; i++) {
        if (buffer[i] == '\0') {
            buffer[i] = ' ';
        }
    }
    
    buffer[bytes_read] = '\0';
    return bytes_read;
}

// Get process executable path
static int get_process_exe_path(pid_t pid, char *buffer, size_t buffer_size) {
    char exe_path[64];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    
    ssize_t len = readlink(exe_path, buffer, buffer_size - 1);
    if (len == -1) {
        return -1;
    }
    
    buffer[len] = '\0';
    return len;
}

// Get process name
static int get_process_name(pid_t pid, char *buffer, size_t buffer_size) {
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    
    FILE *f = fopen(comm_path, "r");
    if (!f) {
        return -1;
    }
    
    char *result = fgets(buffer, buffer_size, f);
    fclose(f);
    
    if (!result) {
        return -1;
    }
    
    // Remove trailing newline
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
        len--;
    }
    
    return len;
}

// In calculate_trust_adjustment function (line 739):
static float calculate_trust_adjustment(pid_t pid, const char *process_name) {
    // Mark unused parameter
    (void)process_name;  // Explicitly mark parameter as unused
    
    float trust_adjustment = 0.0f;
    
    // Check process origin
    char exe_path[MAX_PATH_LENGTH] = {0};
    if (get_process_exe_path(pid, exe_path, sizeof(exe_path)) > 0) {
        // System binaries get higher trust
        if (strncmp(exe_path, "/usr/bin/", 9) == 0 || 
            strncmp(exe_path, "/bin/", 5) == 0 ||
            strncmp(exe_path, "/usr/sbin/", 10) == 0 ||
            strncmp(exe_path, "/sbin/", 6) == 0) {
            trust_adjustment += 0.3f;
        }
        
        // Packages from package manager get medium trust
        if (strncmp(exe_path, "/usr/lib/", 9) == 0 ||
            strncmp(exe_path, "/usr/share/", 11) == 0 ||
            strncmp(exe_path, "/opt/", 5) == 0) {
            trust_adjustment += 0.2f;
        }
    }
    
    // Check process lifetime
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    
    FILE *stat_file = fopen(stat_path, "r");
    if (stat_file) {
        // Format is complex, see "man proc" for details
        // We're looking for process start time (field 22)
        unsigned long long starttime = 0;
        long uptime = 0;
        
        // Read uptime
        FILE *uptime_file = fopen("/proc/uptime", "r");
        if (uptime_file) {
            float up;
            if (fscanf(uptime_file, "%f", &up) == 1) {
                uptime = (long)up;
            }
            fclose(uptime_file);
        }
        
        // Skip to field 22 in stat file
        char buffer[1024];
        if (fgets(buffer, sizeof(buffer), stat_file)) {
            char *token = strtok(buffer, " ");
            for (int i = 1; token && i < 22; i++) {
                token = strtok(NULL, " ");
            }
            
            if (token) {
                starttime = strtoull(token, NULL, 10);
                
                // Calculate process runtime in seconds
                long ticks_per_sec = sysconf(_SC_CLK_TCK);
                long runtime = uptime - (starttime / ticks_per_sec);
                
                // Long-running processes are more trustworthy
                if (runtime > 3600) {  // > 1 hour
                    trust_adjustment += 0.2f;
                } else if (runtime > 600) {  // > 10 minutes
                    trust_adjustment += 0.1f;
                }
            }
        }
        
        fclose(stat_file);
    }
    
    // Check process user
    uid_t process_uid = -1;
    char status_path[64];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    
    FILE *status_file = fopen(status_path, "r");
    if (status_file) {
        char line[256];
        while (fgets(line, sizeof(line), status_file)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                sscanf(line + 4, "%u", &process_uid);
                break;
            }
        }
        fclose(status_file);
        
        // System processes (root or system users) get some trust
        if (process_uid == 0) {
            trust_adjustment += 0.2f;
        } else if (process_uid < 1000) {
            trust_adjustment += 0.1f;
        }
        
        // If process is running as same user, slightly increase trust
        if (process_uid == current_user_uid) {
            trust_adjustment += 0.1f;
        }
    }
    
    // Cap trust adjustment at 0.8 (never completely trust)
    if (trust_adjustment > 0.8f) {
        trust_adjustment = 0.8f;
    }
    
    return trust_adjustment;
}