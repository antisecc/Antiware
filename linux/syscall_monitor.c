#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <sys/inotify.h>
#include <limits.h>
#include "../include/antiransom.h"
#include "../include/events.h"
#include "../common/logger.h"

// Structure to maintain syscall context information
typedef struct {
    pid_t pid;
    int in_syscall;
    long syscall_number;
    unsigned long args[6];
    char path_buffer[1024];
    uint32_t access_flags;
    uint8_t entropy_before;
} SyscallContext;

// Process monitoring level
typedef enum {
    MONITORING_LEVEL_NONE = 0,
    MONITORING_LEVEL_LOW,
    MONITORING_LEVEL_MEDIUM,
    MONITORING_LEVEL_HIGH
} MonitoringLevel;

// Process context structure
typedef struct ProcessContext {
    pid_t pid;
    char process_name[256];
    MonitoringLevel monitoring_level;
    unsigned int flags;
    time_t last_activity;
    // Add other fields as needed
} ProcessContext;

// Add missing process context table
static ProcessContext* process_contexts_table = NULL;
static size_t process_context_count = 0;
static size_t process_context_capacity = 0;

// Add stub for calculate_string_hash
static uint32_t calculate_string_hash(const char* str) {
    uint32_t hash = 5381;
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    
    return hash;
}

// Add stub for is_interesting_extension
static int is_interesting_extension(const char* path) {
    if (!path) return 0;
    
    const char* ext = strrchr(path, '.');
    if (!ext) return 0;
    
    // Common interesting file types
    const char* interesting_extensions[] = {
        ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".jpeg", ".png",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".txt", ".db", NULL
    };
    
    for (int i = 0; interesting_extensions[i] != NULL; i++) {
        if (strcasecmp(ext, interesting_extensions[i]) == 0) {
            return 1;
        }
    }
    
    return 0;
}

// Logger state structure (define missing logger_state)
typedef struct {
    int current_level;
    FILE* log_file;
    int initialized;
} LoggerState;

static LoggerState logger_state = {
    .current_level = LOG_LEVEL_INFO,  // Default level
    .log_file = NULL,
    .initialized = 0
};

// Replace the stub get_process_context with a proper implementation

static ProcessContext* get_process_context(pid_t pid) {
    // Mark parameter as used to avoid warning
    (void)pid;
    
    // If we have a process_contexts_table, search for the process
    if (process_contexts_table && process_context_count > 0) {
        for (size_t i = 0; i < process_context_count; i++) {
            if (process_contexts_table[i].pid == pid) {
                return &process_contexts_table[i];
            }
        }
    }
    
    // Not found - in a real implementation, we might create one
    // For now, return NULL to indicate the process is not being monitored
    return NULL;
}

// Map of monitored processes
static SyscallContext *process_contexts = NULL;
static size_t context_count = 0;
static size_t context_capacity = 0;

// Directory monitoring structure
typedef struct {
    int inotify_fd;
    int watch_descriptor;
    char path[512];
    int initialized;
} DirectoryMonitor;

static DirectoryMonitor dir_monitor = {
    .inotify_fd = -1,
    .watch_descriptor = -1,
    .path = {0},
    .initialized = 0
};

// Forward declarations
static void handle_syscall_entry(SyscallContext *ctx, struct user_regs_struct *regs);
static void handle_syscall_exit(SyscallContext *ctx, struct user_regs_struct *regs, EventHandler event_handler, void *user_data);
static void handle_execve(SyscallContext *ctx, struct user_regs_struct *regs, int entry, EventHandler handler, void *user_data);
static void handle_open(SyscallContext *ctx, struct user_regs_struct *regs, int entry, EventHandler handler, void *user_data);
static void handle_read(SyscallContext *ctx, struct user_regs_struct *regs, int entry, EventHandler handler, void *user_data);
static void handle_write(SyscallContext *ctx, struct user_regs_struct *regs, int entry, EventHandler handler, void *user_data);
static void handle_rename(SyscallContext *ctx, struct user_regs_struct *regs, int entry, EventHandler handler, void *user_data);
static void handle_chmod(SyscallContext *ctx, struct user_regs_struct *regs, int entry, EventHandler handler, void *user_data);
static void handle_unlink(SyscallContext *ctx, struct user_regs_struct *regs, int entry, EventHandler handler, void *user_data);
static uint8_t calculate_file_entropy(const char *path);
static char *read_string_from_process(pid_t pid, unsigned long addr);
// Helper functions for syscall monitoring
static void init_monitored_processes(void);
static void setup_signal_handlers(void);
static void init_filesystem_monitoring(void);
static void detach_from_all_processes(void);
static void cleanup_filesystem_monitoring(void);
static void cleanup_monitored_processes(void);
static int init_directory_monitoring(const char* directory);
static void process_directory_events(EventHandler handler, void* user_data);
static void cleanup_directory_monitoring(void);

// Add these process management forward declarations
int syscall_monitor_add_process(pid_t pid);
void syscall_monitor_remove_process(pid_t pid);

// Initialize the syscall monitor
int syscall_monitor_init(const Configuration* config, EventHandler handler, void* user_data) {
    // Mark unused parameters
    (void)handler;    // Unused parameter 
    (void)user_data;  // Unused parameter
    
    // Allocate syscall context array
    process_contexts = malloc(10 * sizeof(SyscallContext));
    if (!process_contexts) {
        LOG_ERROR("Failed to allocate memory for syscall contexts%s", "");
        return -1;
    }
    
    // Also initialize process context table
    process_contexts_table = malloc(10 * sizeof(ProcessContext));
    if (!process_contexts_table) {
        LOG_ERROR("Failed to allocate memory for process contexts%s", "");
        free(process_contexts);
        process_contexts = NULL;
        return -1;
    }
    
    context_capacity = 10;
    context_count = 0;
    process_context_capacity = 10;
    process_context_count = 0;
    
    LOG_INFO("Syscall monitor initialized%s", "");

    // Initialize directory monitoring if configured
    if (config && config->watch_directory[0] != '\0') {
        if (init_directory_monitoring(config->watch_directory) != 0) {
            LOG_WARNING("Failed to initialize directory monitoring, continuing without it%s", "");
            // Non-fatal error, continue with other monitoring
        }
    }

    return 0;
}

// Clean up resources used by the syscall monitor
void syscall_monitor_cleanup(void) {
    if (process_contexts) {
        free(process_contexts);
        process_contexts = NULL;
    }
    
    if (process_contexts_table) {
        free(process_contexts_table);
        process_contexts_table = NULL;
    }
    
    context_capacity = 0;
    context_count = 0;
    process_context_capacity = 0;
    process_context_count = 0;
    
    LOG_INFO("Syscall monitor cleaned up%s", "");
    
    // Clean up directory monitoring
    cleanup_directory_monitoring();
}

// Start monitoring a specific process
int syscall_monitor_attach(pid_t pid, EventHandler event_handler, void *user_data) {
    // Mark unused parameters
    (void)event_handler;
    (void)user_data;
    
    // Check if we need to grow the contexts array
    if (context_count >= context_capacity) {
        size_t new_capacity = context_capacity * 2;
        SyscallContext *new_contexts = realloc(process_contexts, new_capacity * sizeof(SyscallContext));
        if (!new_contexts) {
            LOG_ERROR("Failed to resize process contexts array%s", "");
            return -1;
        }
        process_contexts = new_contexts;
        context_capacity = new_capacity;
    }
    
    // Attach to the target process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        LOG_ERROR("Failed to attach to process %d: %s", pid, strerror(errno));
        return -1;
    }
    
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        LOG_ERROR("waitpid failed for %d: %s", pid, strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    // Initialize context for this process
    SyscallContext *ctx = &process_contexts[context_count++];
    memset(ctx, 0, sizeof(SyscallContext));
    ctx->pid = pid;
    ctx->in_syscall = 0;
    
    // Configure ptrace to stop at each syscall
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1) {
        LOG_ERROR("Failed to set ptrace options for %d: %s", pid, strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        context_count--;
        return -1;
    }
    
    // Start tracing syscalls
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
        LOG_ERROR("Failed to start syscall tracing for %d: %s", pid, strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        context_count--;
        return -1;
    }
    
    LOG_INFO("Started monitoring process %d", pid);
    return 0;
}

// Stop monitoring a specific process
int syscall_monitor_detach(pid_t pid) {
    // Find the process context
    size_t idx;
    for (idx = 0; idx < context_count; idx++) {
        if (process_contexts[idx].pid == pid) {
            break;
        }
    }
    
    if (idx >= context_count) {
        LOG_WARNING("Process %d is not being monitored", pid);
        return -1;
    }
    
    // Detach from the process
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        LOG_ERROR("Failed to detach from process %d: %s", pid, strerror(errno));
        return -1;
    }
    
    // Remove the context by shifting the array
    if (idx < context_count - 1) {
        memmove(&process_contexts[idx], &process_contexts[idx + 1], 
                (context_count - idx - 1) * sizeof(SyscallContext));
    }
    context_count--;
    
    LOG_INFO("Stopped monitoring process %d", pid);
    return 0;
}

// Process one syscall event from a monitored process
int syscall_monitor_process_event(EventHandler event_handler, void *user_data) {
    int status;
    pid_t pid;
    
    // Wait for any child process to report an event
    pid = waitpid(-1, &status, WNOHANG);
    if (pid == -1) {
        if (errno == ECHILD) {
            // No children to wait for
            return 0;
        }
        LOG_ERROR("waitpid failed: %s", strerror(errno));
        return -1;
    } else if (pid == 0) {
        // No events available
        return 0;
    }
    
    // Find the context for this process
    SyscallContext *ctx = NULL;
    for (size_t i = 0; i < context_count; i++) {
        if (process_contexts[i].pid == pid) {
            ctx = &process_contexts[i];
            break;
        }
    }
    
    if (!ctx) {
        LOG_WARNING("Received event for unknown process %d", pid);
        return -1;
    }
    
    // Check if the process exited
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        LOG_INFO("Process %d has terminated", pid);
        syscall_monitor_detach(pid);
        return 0;
    }
    
    // Check if this is a syscall-related stop
    if (!WIFSTOPPED(status) || (WSTOPSIG(status) & 0x80) == 0) {
        // Not a syscall stop, continue the process
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        return 0;
    }
    
    // Get the registers to determine syscall number and arguments
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        LOG_ERROR("Failed to get registers for process %d: %s", pid, strerror(errno));
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        return -1;
    }
    
    // Handle the syscall entry or exit
    if (!ctx->in_syscall) {
        // Syscall entry
        handle_syscall_entry(ctx, &regs);
        ctx->in_syscall = 1;
    } else {
        // Syscall exit
        handle_syscall_exit(ctx, &regs, event_handler, user_data);
        ctx->in_syscall = 0;
    }
    
    // Continue the process until the next syscall
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
        LOG_ERROR("Failed to continue process %d: %s", pid, strerror(errno));
        return -1;
    }
    
    return 1;  // Successfully processed an event
}

// Process syscall entry - capture syscall number and arguments
static void handle_syscall_entry(SyscallContext *ctx, struct user_regs_struct *regs) {
#ifdef __x86_64__
    ctx->syscall_number = regs->orig_rax;
    ctx->args[0] = regs->rdi;
    ctx->args[1] = regs->rsi;
    ctx->args[2] = regs->rdx;
    ctx->args[3] = regs->r10;
    ctx->args[4] = regs->r8;
    ctx->args[5] = regs->r9;
#else
    ctx->syscall_number = regs->orig_eax;
    ctx->args[0] = regs->ebx;
    ctx->args[1] = regs->ecx;
    ctx->args[2] = regs->edx;
    ctx->args[3] = regs->esi;
    ctx->args[4] = regs->edi;
    ctx->args[5] = regs->ebp;
#endif

    // For specific syscalls, perform additional processing
    switch (ctx->syscall_number) {
        case SYS_execve:
        case SYS_open:
        case SYS_openat:
        case SYS_read:
        case SYS_write:
        case SYS_rename:
        case SYS_renameat:
        case SYS_chmod:
        case SYS_fchmod:
        case SYS_unlink:
        case SYS_unlinkat:
            // Read the path from process memory for syscalls that use paths
            if (ctx->syscall_number == SYS_open || 
                ctx->syscall_number == SYS_execve || 
                ctx->syscall_number == SYS_rename || 
                ctx->syscall_number == SYS_chmod || 
                ctx->syscall_number == SYS_unlink) {
                
                char *path = read_string_from_process(ctx->pid, ctx->args[0]);
                if (path) {
                    strncpy(ctx->path_buffer, path, sizeof(ctx->path_buffer) - 1);
                    ctx->path_buffer[sizeof(ctx->path_buffer) - 1] = '\0';
                    free(path);
                    
                    // For open, store access flags
                    if (ctx->syscall_number == SYS_open) {
                        ctx->access_flags = ctx->args[1];
                        
                        // If opening for writing, calculate entropy before modification
                        if (ctx->access_flags & O_WRONLY || ctx->access_flags & O_RDWR) {
                            ctx->entropy_before = calculate_file_entropy(ctx->path_buffer);
                        }
                    }
                }
            }
            break;
    }
}

// Process syscall exit - generate events based on syscall results
static void handle_syscall_exit(SyscallContext *ctx, struct user_regs_struct *regs, 
                               EventHandler event_handler, void *user_data) {
    // Get the syscall return value
#ifdef __x86_64__
    long result = regs->rax;
#else
    long result = regs->eax;
#endif

    // Only process successful syscalls
    if (result >= 0) {
        switch (ctx->syscall_number) {
            case SYS_execve:
                handle_execve(ctx, regs, 0, event_handler, user_data);
                break;
            case SYS_open:
            case SYS_openat:
                handle_open(ctx, regs, 0, event_handler, user_data);
                break;
            case SYS_read:
                handle_read(ctx, regs, 0, event_handler, user_data);
                break;
            case SYS_write:
                handle_write(ctx, regs, 0, event_handler, user_data);
                break;
            case SYS_rename:
            case SYS_renameat:
                handle_rename(ctx, regs, 0, event_handler, user_data);
                break;
            case SYS_chmod:
            case SYS_fchmod:
                handle_chmod(ctx, regs, 0, event_handler, user_data);
                break;
            case SYS_unlink:
            case SYS_unlinkat:
                handle_unlink(ctx, regs, 0, event_handler, user_data);
                break;
        }
    }
}

// Handle execve syscall - process creation
static void handle_execve(SyscallContext *ctx, struct user_regs_struct *regs, int entry, 
                         EventHandler handler, void *user_data) {
    // Mark unused parameters
    (void)regs;
    (void)entry;
    
    if (!handler) return;
    
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.type = EVENT_PROCESS_CREATE;
    event.process_id = ctx->pid;
    event.timestamp = time(NULL);
    event.score_impact = 2.0f;  // Base score for process creation
    
    // Fill process event data
    strncpy(event.data.process_event.image_path, ctx->path_buffer, sizeof(event.data.process_event.image_path) - 1);
    event.data.process_event.image_path[sizeof(event.data.process_event.image_path) - 1] = '\0';
    
    // Try to get the parent process ID
    char proc_stat_path[64];
    snprintf(proc_stat_path, sizeof(proc_stat_path), "/proc/%d/stat", ctx->pid);
    FILE *f = fopen(proc_stat_path, "r");
    if (f) {
        // Format of /proc/pid/stat: pid (comm) state ppid ...
        char comm[256];
        int pid, ppid;
        char state;
        if (fscanf(f, "%d %s %c %d", &pid, comm, &state, &ppid) == 4) {
            event.data.process_event.parent_pid = ppid;
        }
        fclose(f);
    }
    
    // Call the event handler
    handler(&event, user_data);
    
    LOG_INFO("Process %d executed: %s", ctx->pid, ctx->path_buffer);
}

// Handle open/openat syscall - file access
static void handle_open(SyscallContext *ctx, struct user_regs_struct *regs, int entry, 
                       EventHandler handler, void *user_data) {
    // Mark unused parameters
    (void)regs;
    (void)entry;
    
    if (!handler) return;
    
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.type = EVENT_FILE_ACCESS;
    event.process_id = ctx->pid;
    event.timestamp = time(NULL);
    
    // Score based on access type
    if (ctx->access_flags & O_WRONLY || ctx->access_flags & O_RDWR) {
        event.score_impact = 3.0f;  // Higher score for write access
    } else {
        event.score_impact = 1.0f;  // Lower score for read-only access
    }
    
    // Check if creating a new file
    if (ctx->access_flags & O_CREAT) {
        event.type = EVENT_FILE_CREATE;
        event.score_impact += 1.0f;  // Additional score for file creation
    }
    
    // Fill file event data
    strncpy(event.data.file_event.path, ctx->path_buffer, sizeof(event.data.file_event.path) - 1);
    event.data.file_event.path[sizeof(event.data.file_event.path) - 1] = '\0';
    event.data.file_event.access_flags = ctx->access_flags;
    event.data.file_event.entropy_before = ctx->entropy_before;
    
    // Call the event handler
    handler(&event, user_data);
    
    LOG_DEBUG("Process %d opened file: %s (flags: 0x%x)", ctx->pid, ctx->path_buffer, ctx->access_flags);
}

// Handle read syscall - reading file content
static void handle_read(SyscallContext *ctx, struct user_regs_struct *regs, int entry, 
                       EventHandler handler, void *user_data) {
    // Mark unused parameters
    (void)regs;
    (void)entry;
    (void)handler;
    (void)user_data;
    
    // For read, we just log the activity without generating events
    // because it's very common and would generate too much noise
    // We'll track specific read-write patterns in the detection logic
    
    LOG_DEBUG("Process %d read from fd: %lu, size: %lu", ctx->pid, ctx->args[0], ctx->args[2]);
}

// Handle write syscall - writing file content
static void handle_write(SyscallContext *ctx, struct user_regs_struct *regs, int entry, 
                        EventHandler handler, void *user_data) {
    // Mark unused parameters
    (void)regs;
    (void)entry;
    
    if (!handler) return;
    
    // Only generate events for significant writes to avoid noise
    if (ctx->args[2] < 1024) {  // Less than 1KB
        return;
    }
    
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.type = EVENT_FILE_MODIFY;
    event.process_id = ctx->pid;
    event.timestamp = time(NULL);
    event.score_impact = 2.5f;  // Base score for file modification
    
    // We don't have the filename here because write uses file descriptors
    // Real implementation would maintain a map of fds to filenames
    
    // Call the event handler
    handler(&event, user_data);
    
    LOG_DEBUG("Process %d wrote to fd: %lu, size: %lu", ctx->pid, ctx->args[0], ctx->args[2]);
}

// Handle rename syscall - renaming files (often used by ransomware)
static void handle_rename(SyscallContext *ctx, struct user_regs_struct *regs, int entry, 
                         EventHandler handler, void *user_data) {
    // Mark unused parameters
    (void)regs;
    (void)entry;
    
    if (!handler) return;
    
    char *oldpath = ctx->path_buffer;
    char *newpath = read_string_from_process(ctx->pid, ctx->args[1]);
    
    if (!newpath) {
        return;
    }
    
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.type = EVENT_FILE_RENAME;
    event.process_id = ctx->pid;
    event.timestamp = time(NULL);
    event.score_impact = 4.0f;  // Higher score for rename (common in ransomware)
    
    // Fill file event data
    strncpy(event.data.file_event.path, oldpath, sizeof(event.data.file_event.path) - 1);
    event.data.file_event.path[sizeof(event.data.file_event.path) - 1] = '\0';
    
    // Check for extension change (potential ransomware indicator)
    const char *old_ext = strrchr(oldpath, '.');
    const char *new_ext = strrchr(newpath, '.');
    
    if (old_ext && new_ext && strcmp(old_ext, new_ext) != 0) {
        // Extension changed - higher risk
        event.score_impact = 10.0f;
        
        // Check for known ransomware extensions
        const char *ransomware_exts[] = {
            ".encrypted", ".locked", ".crypted", ".crypt", ".crypto", 
            ".enc", ".ransomware", ".paying", ".ransom", ".cry"
        };
        
        for (size_t i = 0; i < sizeof(ransomware_exts) / sizeof(ransomware_exts[0]); i++) {
            if (strcmp(new_ext, ransomware_exts[i]) == 0) {
                event.score_impact = 50.0f;  // Very high score for known ransomware extension
                break;
            }
        }
    }
    
    // Call the event handler
    handler(&event, user_data);
    
    LOG_INFO("Process %d renamed: %s to %s", ctx->pid, oldpath, newpath);
    free(newpath);
}

// Handle chmod syscall - changing file permissions
static void handle_chmod(SyscallContext *ctx, struct user_regs_struct *regs, int entry, 
                        EventHandler handler, void *user_data) {
    // Mark unused parameters
    (void)regs;
    (void)entry;
    
    if (!handler) return;
    
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.type = EVENT_FILE_PERMISSION;
    event.process_id = ctx->pid;
    event.timestamp = time(NULL);
    event.score_impact = 2.0f;  // Base score for permission change
    
    // Fill file event data
    strncpy(event.data.file_event.path, ctx->path_buffer, sizeof(event.data.file_event.path) - 1);
    event.data.file_event.path[sizeof(event.data.file_event.path) - 1] = '\0';
    
    // Check for suspicious permission changes (e.g., removing read permissions)
    mode_t mode = (mode_t)ctx->args[1];
    if ((mode & S_IRUSR) == 0 || (mode & S_IRGRP) == 0 || (mode & S_IROTH) == 0) {
        // Removing read permissions - potential ransomware behavior
        event.score_impact = 8.0f;
    }
    
    // Call the event handler
    handler(&event, user_data);
    
    LOG_DEBUG("Process %d changed permissions of %s to %o", ctx->pid, ctx->path_buffer, (unsigned int)mode);
}

// Handle unlink syscall - file deletion
static void handle_unlink(SyscallContext *ctx, struct user_regs_struct *regs, int entry, 
                         EventHandler handler, void *user_data) {
    // Mark unused parameters
    (void)regs;
    (void)entry;
    
    if (!handler) return;
    
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.type = EVENT_FILE_DELETE;
    event.process_id = ctx->pid;
    event.timestamp = time(NULL);
    event.score_impact = 3.0f;  // Base score for file deletion
    
    // Fill file event data
    strncpy(event.data.file_event.path, ctx->path_buffer, sizeof(event.data.file_event.path) - 1);
    event.data.file_event.path[sizeof(event.data.file_event.path) - 1] = '\0';
    
    // Check if deleting backup files or shadow copies
    if (strstr(ctx->path_buffer, ".bak") || 
        strstr(ctx->path_buffer, "backup") || 
        strstr(ctx->path_buffer, "shadow")) {
        event.score_impact = 15.0f;  // Much higher score for backup deletion
    }
    
    // Call the event handler
    handler(&event, user_data);
    
    LOG_INFO("Process %d deleted file: %s", ctx->pid, ctx->path_buffer);
}

// Utility function to read a string from the process memory
static char *read_string_from_process(pid_t pid, unsigned long addr) {
    char *str = NULL;
    size_t allocated = 0;
    size_t len = 0;
    
    do {
        if (len >= allocated) {
            allocated += 128;
            str = realloc(str, allocated);
            if (!str) {
                LOG_ERROR("Failed to allocate memory for string%s", "");
                return NULL;
            }
        }
        
        long val = ptrace(PTRACE_PEEKDATA, pid, addr + len, NULL);
        if (val == -1 && errno) {
            LOG_ERROR("Failed to read string data: %s", strerror(errno));
            free(str);
            return NULL;
        }
        
        memcpy(str + len, &val, sizeof(long));
        
        // Find null terminator in the read data
        size_t i;
        for (i = 0; i < sizeof(long); i++) {
            if (str[len + i] == '\0') {
                len += i;
                return str;  // Found the end of the string
            }
        }
        
        len += sizeof(long);
    } while (len < 4096);  // Limit to 4KB to prevent infinite loops
    
    // If we get here, no null terminator was found within 4KB
    if (allocated > 0) {
        str[allocated - 1] = '\0';
    }
    
    return str;
}

// Simple entropy calculation for file content (Shannon entropy)
static uint8_t calculate_file_entropy(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return 0;
    }
    
    unsigned char buffer[4096];
    size_t bytes_read;
    unsigned long byte_counts[256] = {0};
    unsigned long total_bytes = 0;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            byte_counts[buffer[i]]++;
        }
        total_bytes += bytes_read;
    }
    
    fclose(f);
    
    if (total_bytes == 0) {
        return 0;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] > 0) {
            double prob = (double)byte_counts[i] / total_bytes;
            entropy -= prob * log2(prob);
        }
    }
    
    // Normalize to 0-100 scale
    uint8_t scaled_entropy = (uint8_t)(entropy * 100.0 / 8.0);
    return scaled_entropy;
}

/**
 * Starts the syscall monitoring system
 * Initializes ptrace-based syscall interception
 */
int syscall_monitor_start(void) {
    LOG_INFO("Starting syscall monitoring system%s", "");
    
    // Initialize syscall monitoring data structures
    init_monitored_processes();
    
    // Set up signal handlers for clean termination
    setup_signal_handlers();
    
    // Initialize any fd-based monitoring (inotify, etc.)
    init_filesystem_monitoring();
    
    // This is where ptrace setup would occur for a full implementation
    // For beta/placeholder, we'll just log that it's ready
    LOG_INFO("Syscall monitoring initialized and ready%s", "");
    return 0;
}

/**
 * Stops the syscall monitoring system
 * Cleans up resources and detaches from monitored processes
 */
void syscall_monitor_stop(void) {
    LOG_INFO("Stopping syscall monitoring system%s", "");
    
    // Release all ptrace attachments
    detach_from_all_processes();
    
    // Clean up filesystem monitoring
    cleanup_filesystem_monitoring();
    
    // Free any allocated resources
    cleanup_monitored_processes();
    
    LOG_INFO("Syscall monitoring stopped%s", "");
}

// Add this before the helper function implementations (around line 719)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

// Helper functions for syscall monitoring
static void init_monitored_processes(void) {
    // Initialize the data structure for tracking monitored processes
    // This might be a hash table, linked list, etc.
    
    // For beta/placeholder, this might be a no-op or minimal initialization
}

static void setup_signal_handlers(void) {
    // Set up handlers for SIGTERM, SIGINT, etc.
    // This ensures clean detachment from traced processes
    
    // For beta/placeholder, this might be minimal or empty
}

static void init_filesystem_monitoring(void) {
    // Set up inotify or other filesystem monitoring
    // This complements ptrace for more efficient file operation tracking
    
    // For beta/placeholder, this might be minimal or empty
}

static void detach_from_all_processes(void) {
    // Iterate through all monitored processes and detach ptrace
    // This prevents leaving processes in a traced state
    
    // For beta/placeholder, this might be minimal or empty
}

static void cleanup_filesystem_monitoring(void) {
    // Clean up inotify watches and related resources
    
    // For beta/placeholder, this might be minimal or empty
}

static void cleanup_monitored_processes(void) {
    // Free memory used for tracking monitored processes
    
    // For beta/placeholder, this might be minimal or empty
}

// Add this after the last helper function (around line 760)
#pragma GCC diagnostic pop

// Replace the entire handle_syscall function (around line 806)
static void __attribute__((unused)) handle_syscall(int syscall_num, pid_t pid, const char* path, EventHandler handler, void* user_data) {
    // Get process context
    ProcessContext* context = get_process_context(pid);
    if (!context) {
        // Process not being monitored, skip
        return;
    }
    
    // If this is a low-monitored process, only log suspicious syscalls
    if (context->monitoring_level == MONITORING_LEVEL_LOW) {
        // Check if this is a potentially suspicious syscall
        int is_suspicious = 0;
        
        // Suspicious syscalls: unlink, rename, chmod, etc.
        int suspicious_syscalls[] = {
            SYS_unlink, SYS_rename, SYS_renameat, 
            SYS_chmod, SYS_fchmod, SYS_fchmodat, -1
        };
        
        for (int i = 0; suspicious_syscalls[i] != -1; i++) {
            if (syscall_num == suspicious_syscalls[i]) {
                is_suspicious = 1;
                break;
            }
        }
        
        // Skip logging for non-suspicious syscalls by low-monitored processes
        if (!is_suspicious) {
            return;
        }
    }
    
    // Create event for the syscall
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.process_id = pid;
    event.timestamp = time(NULL);
    event.source = EVENT_SOURCE_SYSCALL;
    
    // Set default score impact (will be adjusted below)
    event.score_impact = 0.1f;
    
    // Process based on syscall type
    switch (syscall_num) {
        case SYS_open:
        case SYS_openat:
            event.type = EVENT_FILE_ACCESS; // Use EVENT_FILE_ACCESS instead of EVENT_SYSCALL_OPEN
            
            // Only log file open for interesting files or if high verbosity
            if (is_interesting_extension(path) || logger_state.current_level <= LOG_LEVEL_DEBUG) {
                LOG_DEBUG("Process %d opened file: %s", pid, path);
            }
            break;
        case SYS_unlink:
        case SYS_unlinkat:
            event.type = EVENT_FILE_DELETE; // Use EVENT_FILE_DELETE instead
            event.score_impact = 1.0f;
            LOG_INFO("Process %d deleted file: %s", pid, path);
            break;
        case SYS_rename:
        case SYS_renameat:
            event.type = EVENT_FILE_RENAME; // Use EVENT_FILE_RENAME instead
            event.score_impact = 0.5f;
            LOG_INFO("Process %d renamed file: %s", pid, path);
            break;
        case SYS_chmod:
        case SYS_fchmod:
        case SYS_fchmodat:
            event.type = EVENT_FILE_PERMISSION; // Use appropriate event type
            event.score_impact = 0.3f;
            LOG_DEBUG("Process %d changed file permissions: %s", pid, path);
            break;
        default:
            // For other syscalls, only log at debug level
            if (logger_state.current_level <= LOG_LEVEL_DEBUG) {
                LOG_DEBUG("Process %d syscall %d on: %s", pid, syscall_num, path);
            }
            return;  // Don't create an event for untracked syscalls
    }
    
    // Fill in the file event data (using file_event instead of syscall_event)
    strncpy(event.data.file_event.path, path, sizeof(event.data.file_event.path) - 1);
    event.data.file_event.path[sizeof(event.data.file_event.path) - 1] = '\0';
    
    // Use calculate_string_hash in handle_syscall where appropriate
    uint32_t path_hash = calculate_string_hash(path);
    LOG_DEBUG("Handling syscall %d for process %d, path: %s (hash: %u)", 
              syscall_num, pid, path, path_hash);
    
    // Send the event to the handler
    if (handler) {
        handler(&event, user_data);
    }
}

// Initialize directory monitoring
static int init_directory_monitoring(const char* directory) {
    if (!directory || directory[0] == '\0') {
        LOG_DEBUG("No directory specified for monitoring%s", "");
        return 0;  // Not an error, just nothing to monitor
    }
    
    // Check if already initialized, clean up if needed
    if (dir_monitor.initialized) {
        LOG_DEBUG("Directory monitoring already initialized, cleaning up first%s", "");
        if (dir_monitor.watch_descriptor >= 0) {
            inotify_rm_watch(dir_monitor.inotify_fd, dir_monitor.watch_descriptor);
        }
        if (dir_monitor.inotify_fd >= 0) {
            close(dir_monitor.inotify_fd);
        }
        dir_monitor.inotify_fd = -1;
        dir_monitor.watch_descriptor = -1;
        dir_monitor.initialized = 0;
    }
    
    // Initialize inotify
    dir_monitor.inotify_fd = inotify_init();
    if (dir_monitor.inotify_fd < 0) {
        LOG_ERROR("Failed to initialize inotify: %s", strerror(errno));
        return -1;
    }
    
    // Add watch for the specified directory
    dir_monitor.watch_descriptor = inotify_add_watch(dir_monitor.inotify_fd, directory, 
                                                  IN_CREATE | IN_MODIFY | IN_DELETE | 
                                                  IN_MOVED_FROM | IN_MOVED_TO);
    
    if (dir_monitor.watch_descriptor < 0) {
        LOG_ERROR("Failed to add watch for directory %s: %s", directory, strerror(errno));
        close(dir_monitor.inotify_fd);
        dir_monitor.inotify_fd = -1;
        return -1;
    }
    
    // Store path and set initialized flag
    strncpy(dir_monitor.path, directory, sizeof(dir_monitor.path) - 1);
    dir_monitor.path[sizeof(dir_monitor.path) - 1] = '\0';
    dir_monitor.initialized = 1;
    
    LOG_INFO("Directory monitoring initialized for: %s", directory);
    return 0;
}

// Process directory events
static void process_directory_events(EventHandler handler, void* user_data) {
    if (!dir_monitor.initialized || dir_monitor.inotify_fd < 0) {
        return;
    }
    
    // Check if events are available without blocking
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(dir_monitor.inotify_fd, &read_fds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    
    if (select(dir_monitor.inotify_fd + 1, &read_fds, NULL, NULL, &timeout) <= 0) {
        return;  // No events or error
    }
    
    // Buffer for inotify events
    char buffer[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    
    // Read events
    ssize_t len = read(dir_monitor.inotify_fd, buffer, sizeof(buffer));
    if (len <= 0) {
        return;
    }
    
    // Process all events in the buffer
    char *ptr = buffer;
    while (ptr < buffer + len) {
        struct inotify_event *event = (struct inotify_event *)ptr;
        
        // Skip events without names
        if (event->len > 0) {
            // Get the full path of the file
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", dir_monitor.path, event->name);
            
            // Create an event based on the file operation
            Event sec_event;
            memset(&sec_event, 0, sizeof(Event));
            
            sec_event.process_id = getpid();  // Use our PID as placeholder
            sec_event.timestamp = time(NULL);
            sec_event.source = EVENT_SOURCE_SYSCALL;  // Reuse existing source
            
            // Determine event type and score impact
            if (event->mask & IN_CREATE) {
                sec_event.type = EVENT_FILE_CREATE;
                sec_event.score_impact = 1.0f;
                LOG_INFO("File created in watched directory: %s", path);
            }
            else if (event->mask & IN_MODIFY) {
                sec_event.type = EVENT_FILE_MODIFY;
                sec_event.score_impact = 2.0f;
                LOG_INFO("File modified in watched directory: %s", path);
            }
            else if (event->mask & IN_DELETE) {
                sec_event.type = EVENT_FILE_DELETE;
                sec_event.score_impact = 4.0f;
                LOG_INFO("File deleted in watched directory: %s", path);
            }
            else if (event->mask & (IN_MOVED_FROM | IN_MOVED_TO)) {
                sec_event.type = EVENT_FILE_RENAME;
                sec_event.score_impact = 2.5f;
                LOG_INFO("File moved in watched directory: %s", path);
            }
            
            // Fill in file event data
            strncpy(sec_event.data.file_event.path, path, 
                   sizeof(sec_event.data.file_event.path) - 1);
            sec_event.data.file_event.path[sizeof(sec_event.data.file_event.path) - 1] = '\0';
            
            // Handle the event through the regular event system
            if (handler) {
                handler(&sec_event, user_data);
            }
        }
        
        // Move to next event
        ptr += sizeof(struct inotify_event) + event->len;
    }
}

// Update syscall_monitor_poll to process directory events
void syscall_monitor_poll(EventHandler handler, void* user_data) {
    // Process directory events
    process_directory_events(handler, user_data);
    
    // Then process any pending syscall events
    for (int i = 0; i < 10; i++) {  // Process up to 10 events per poll
        int result = syscall_monitor_process_event(handler, user_data);
        if (result <= 0) {
            break;  // No more events or error
        }
    }
    
    // Update process contexts
    time_t now = time(NULL);
    for (size_t i = 0; i < process_context_count; i++) {
        ProcessContext* ctx = &process_contexts_table[i];
        
        // Check if process is still alive
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/stat", ctx->pid);
        if (access(proc_path, F_OK) != 0) {
            // Process no longer exists, remove it
            LOG_INFO("Process %d (%s) has terminated, removing from monitoring", 
                    ctx->pid, ctx->process_name);
            syscall_monitor_remove_process(ctx->pid);
            i--;  // Adjust index since we removed an element
            continue;
        }
        
        // Update last activity timestamp for processes with recent activity
        if (now - ctx->last_activity > 300) {  // 5 minutes of inactivity
            LOG_DEBUG("Process %d (%s) has been inactive for %ld seconds", 
                     ctx->pid, ctx->process_name, now - ctx->last_activity);
        }
    }
}

// Cleanup directory monitoring
static void cleanup_directory_monitoring(void) {
    if (dir_monitor.initialized) {
        if (dir_monitor.watch_descriptor >= 0) {
            inotify_rm_watch(dir_monitor.inotify_fd, dir_monitor.watch_descriptor);
            dir_monitor.watch_descriptor = -1;
        }
        if (dir_monitor.inotify_fd >= 0) {
            close(dir_monitor.inotify_fd);
            dir_monitor.inotify_fd = -1;
        }
        
        LOG_INFO("Directory monitoring cleaned up for: %s", dir_monitor.path);
        dir_monitor.initialized = 0;
    }
}

// Add implementation for adding and removing processes from monitoring

// Add a process to the monitoring system
int syscall_monitor_add_process(pid_t pid) {
    // Check if we need to grow the process contexts table
    if (process_context_count >= process_context_capacity) {
        size_t new_capacity = process_context_capacity * 2;
        ProcessContext *new_table = realloc(process_contexts_table, 
                                           new_capacity * sizeof(ProcessContext));
        if (!new_table) {
            LOG_ERROR("Failed to resize process context table%s", "");
            return -1;
        }
        
        process_contexts_table = new_table;
        process_context_capacity = new_capacity;
    }
    
    // Check if process is already monitored
    for (size_t i = 0; i < process_context_count; i++) {
        if (process_contexts_table[i].pid == pid) {
            LOG_DEBUG("Process %d already being monitored", pid);
            return 0;
        }
    }
    
    // Get process name
    char process_name[256] = {0};
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);
    
    FILE* f = fopen(proc_path, "r");
    if (f) {
        if (fgets(process_name, sizeof(process_name), f)) {
            // Remove trailing newline
            size_t len = strlen(process_name);
            if (len > 0 && process_name[len-1] == '\n') {
                process_name[len-1] = '\0';
            }
        }
        fclose(f);
    }
    
    // Initialize the new process context
    ProcessContext* ctx = &process_contexts_table[process_context_count++];
    memset(ctx, 0, sizeof(ProcessContext));
    ctx->pid = pid;
    strncpy(ctx->process_name, process_name, sizeof(ctx->process_name) - 1);
    ctx->monitoring_level = MONITORING_LEVEL_MEDIUM; // Default level
    ctx->last_activity = time(NULL);
    
    LOG_INFO("Added process %d (%s) to monitoring", pid, process_name);
    
    // Attach to process for syscall monitoring if needed
    return syscall_monitor_attach(pid, NULL, NULL);
}

// Remove a process from the monitoring system
void syscall_monitor_remove_process(pid_t pid) {
    // Find the process in the context table
    for (size_t i = 0; i < process_context_count; i++) {
        if (process_contexts_table[i].pid == pid) {
            // Remove by shifting remaining elements
            if (i < process_context_count - 1) {
                memmove(&process_contexts_table[i], 
                       &process_contexts_table[i + 1],
                       (process_context_count - i - 1) * sizeof(ProcessContext));
            }
            process_context_count--;
            
            LOG_INFO("Removed process %d from monitoring", pid);
            
            // Detach from syscall monitoring
            syscall_monitor_detach(pid);
            return;
        }
    }
    
    LOG_DEBUG("Process %d not found in monitoring table", pid);
}