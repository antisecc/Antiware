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

// Map of monitored processes
static SyscallContext *process_contexts = NULL;
static size_t context_count = 0;
static size_t context_capacity = 0;

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

// Initialize the syscall monitor
int syscall_monitor_init(void) {
    process_contexts = malloc(10 * sizeof(SyscallContext));
    if (!process_contexts) {
        LOG_ERROR("Failed to allocate memory for process contexts");
        return -1;
    }
    
    context_capacity = 10;
    context_count = 0;
    
    LOG_INFO("Syscall monitor initialized");
    return 0;
}

// Clean up resources used by the syscall monitor
void syscall_monitor_cleanup(void) {
    if (process_contexts) {
        free(process_contexts);
        process_contexts = NULL;
    }
    context_capacity = 0;
    context_count = 0;
    
    LOG_INFO("Syscall monitor cleaned up");
}

// Start monitoring a specific process
int syscall_monitor_attach(pid_t pid, EventHandler event_handler, void *user_data) {
    // Check if we need to grow the contexts array
    if (context_count >= context_capacity) {
        size_t new_capacity = context_capacity * 2;
        SyscallContext *new_contexts = realloc(process_contexts, new_capacity * sizeof(SyscallContext));
        if (!new_contexts) {
            LOG_ERROR("Failed to resize process contexts array");
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
    if (!handler) return;
    
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.type = EVENT_PROCESS_CREATE;
    event.process_id = ctx->pid;
    event.timestamp = time(NULL);
    event.score_impact = 2.0f;  // Base score for process creation
    
    // Fill process event data
    strncpy(event.data.process_event.image_path, ctx->path_buffer, sizeof(event.data.process_event.image_path) - 1);
    
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
    event.data.file_event.access_flags = ctx->access_flags;
    event.data.file_event.entropy_before = ctx->entropy_before;
    
    // Call the event handler
    handler(&event, user_data);
    
    LOG_DEBUG("Process %d opened file: %s (flags: 0x%x)", ctx->pid, ctx->path_buffer, ctx->access_flags);
}

// Handle read syscall - reading file content
static void handle_read(SyscallContext *ctx, struct user_regs_struct *regs, int entry, 
                       EventHandler handler, void *user_data) {
    // For read, we just log the activity without generating events
    // because it's very common and would generate too much noise
    // We'll track specific read-write patterns in the detection logic
    
    LOG_TRACE("Process %d read from fd: %lu, size: %lu", ctx->pid, ctx->args[0], ctx->args[2]);
}

// Handle write syscall - writing file content
static void handle_write(SyscallContext *ctx, struct user_regs_struct *regs, int entry, 
                        EventHandler handler, void *user_data) {
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
    if (!handler) return;
    
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.type = EVENT_FILE_PERMISSION;
    event.process_id = ctx->pid;
    event.timestamp = time(NULL);
    event.score_impact = 2.0f;  // Base score for permission change
    
    // Fill file event data
    strncpy(event.data.file_event.path, ctx->path_buffer, sizeof(event.data.file_event.path) - 1);
    
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
    if (!handler) return;
    
    Event event;
    memset(&event, 0, sizeof(Event));
    
    event.type = EVENT_FILE_DELETE;
    event.process_id = ctx->pid;
    event.timestamp = time(NULL);
    event.score_impact = 3.0f;  // Base score for file deletion
    
    // Fill file event data
    strncpy(event.data.file_event.path, ctx->path_buffer, sizeof(event.data.file_event.path) - 1);
    
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
                LOG_ERROR("Failed to allocate memory for string");
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