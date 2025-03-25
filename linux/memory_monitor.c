#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>

#include "../include/antiransom.h"
#include "../include/events.h"
#include "../common/logger.h"
#include "../common/scoring.h"

// Maximum number of processes to monitor
#define MAX_MONITORED_PROCESSES 128

// Maximum number of memory regions to track per process
#define MAX_MEMORY_REGIONS 256

// Polling interval in milliseconds
#define MEMORY_POLL_INTERVAL 1000

// Threshold for significant memory change (in KB)
#define MEMORY_CHANGE_THRESHOLD 5120  // 5MB

// Structure to represent a memory region
typedef struct {
    unsigned long start;
    unsigned long end;
    unsigned long size;
    char perms[8];
    unsigned long offset;
    char device[16];
    unsigned long inode;
    char pathname[512];
    int is_rwx;
    int is_new;
    unsigned char checksum[16];  // Simple checksum for detecting changes
} MemoryRegion;

// Structure to track memory information for a process
typedef struct {
    pid_t pid;
    char comm[256];
    time_t last_updated;
    
    // Memory statistics
    unsigned long total_memory_kb;
    unsigned long last_total_memory_kb;
    time_t last_memory_check;
    
    // Memory regions
    MemoryRegion regions[MAX_MEMORY_REGIONS];
    int region_count;
    
    // RWX regions count
    int rwx_region_count;
    int last_rwx_region_count;
    
    // Suspicious memory activity flags
    int has_new_rwx_region;
    int has_modified_executable_region;
    int has_large_memory_increase;
    int has_suspicious_allocation_pattern;
    
    // Memory checksum validation
    unsigned char last_code_checksums[MAX_MEMORY_REGIONS][16];
} ProcessMemory;

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
    char command[256];
    MonitoringLevel monitoring_level;
    unsigned int flags;
    time_t last_activity;
    // Add other fields as needed
} ProcessContext;

// Global state
static ProcessMemory monitored_processes[MAX_MONITORED_PROCESSES];
static int process_count = 0;
static EventHandler event_callback = NULL;
static void* event_callback_data = NULL;

// Forward declarations
static ProcessMemory* find_process_memory(pid_t pid);
static ProcessMemory* add_process_memory(pid_t pid);
static void update_process_memory(ProcessMemory* process);
static void parse_memory_maps(ProcessMemory* process);
static void detect_rwx_regions(ProcessMemory* process);
static void detect_memory_changes(ProcessMemory* process);
static void detect_code_modifications(ProcessMemory* process);
static void calculate_region_checksum(ProcessMemory* process, MemoryRegion* region);
static int is_rwx_permission(const char* perms);
static int is_executable(const char* perms);
static int is_writeable(const char* perms);
static void generate_memory_event(pid_t pid, EventType type, const char* details, float score_impact);
static unsigned long get_process_memory_usage(pid_t pid);
static ProcessContext* get_process_context(pid_t pid);
static int is_interesting_file(const char* pathname);
static void analyze_memory_region(pid_t pid, unsigned long start, unsigned long end, 
                               const char* perms, const char* pathname, 
                               EventHandler handler, void* user_data);

// Initialize the memory monitor
int memory_monitor_init(EventHandler handler, void* user_data) {
    memset(monitored_processes, 0, sizeof(monitored_processes));
    process_count = 0;
    event_callback = handler;
    event_callback_data = user_data;
    
    LOG_INFO("Memory monitor initialized%s", "");
    return 0;
}

// Clean up resources
void memory_monitor_cleanup(void) {
    process_count = 0;
    LOG_INFO("Memory monitor cleaned up%s", "");
}

// Start monitoring a process
int memory_monitor_add_process(pid_t pid) {
    if (find_process_memory(pid) != NULL) {
        // Already monitoring this process
        return 0;
    }
    
    ProcessMemory* process = add_process_memory(pid);
    if (process == NULL) {
        LOG_ERROR("Failed to add process %d to memory monitor", pid);
        return -1;
    }
    
    // Get process name
    char proc_comm_path[64];
    snprintf(proc_comm_path, sizeof(proc_comm_path), "/proc/%d/comm", pid);
    FILE* f = fopen(proc_comm_path, "r");
    if (f) {
        if (fgets(process->comm, sizeof(process->comm), f)) {
            // Remove trailing newline
            size_t len = strlen(process->comm);
            if (len > 0 && process->comm[len - 1] == '\n') {
                process->comm[len - 1] = '\0';
            }
        }
        fclose(f);
    }
    
    // Initialize memory statistics
    process->total_memory_kb = get_process_memory_usage(pid);
    process->last_total_memory_kb = process->total_memory_kb;
    process->last_memory_check = time(NULL);
    
    // Initialize memory regions
    process->region_count = 0;
    process->rwx_region_count = 0;
    process->last_rwx_region_count = 0;
    
    // Initialize flags
    process->has_new_rwx_region = 0;
    process->has_modified_executable_region = 0;
    process->has_large_memory_increase = 0;
    process->has_suspicious_allocation_pattern = 0;
    
    // Perform initial scan
    parse_memory_maps(process);
    detect_rwx_regions(process);
    
    LOG_INFO("Started memory monitoring for process %d (%s)", pid, process->comm);
    return 0;
}

// Stop monitoring a process
int memory_monitor_remove_process(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (monitored_processes[i].pid == pid) {
            // Remove by swapping with the last element and decreasing count
            if (i < process_count - 1) {
                monitored_processes[i] = monitored_processes[process_count - 1];
            }
            process_count--;
            LOG_INFO("Stopped memory monitoring for process %d", pid);
            return 0;
        }
    }
    
    LOG_WARNING("Process %d not found in memory monitor", pid);
    return -1;
}

// Poll all monitored processes for memory changes
int memory_monitor_poll(void) {
    time_t now = time(NULL);
    
    for (int i = 0; i < process_count; i++) {
        ProcessMemory* process = &monitored_processes[i];
        
        // Skip processes we've checked very recently
        if (now - process->last_updated < MEMORY_POLL_INTERVAL / 1000) {
            continue;
        }
        
        // Check if process still exists
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d", process->pid);
        if (access(proc_path, F_OK) == -1) {
            LOG_INFO("Process %d no longer exists, removing from memory monitor", process->pid);
            memory_monitor_remove_process(process->pid);
            i--; // Adjust index since we removed an element
            continue;
        }
        
        // Update memory information
        update_process_memory(process);
        
        // Perform detection
        detect_memory_changes(process);
        detect_code_modifications(process);
        
        // Update timestamp
        process->last_updated = now;
    }
    
    return 0;  // Return success
}

// Update memory information for a process
static void update_process_memory(ProcessMemory* process) {
    // Update total memory usage
    unsigned long current_memory = get_process_memory_usage(process->pid);
    process->last_total_memory_kb = process->total_memory_kb;
    process->total_memory_kb = current_memory;
    
    // Save previous RWX count
    process->last_rwx_region_count = process->rwx_region_count;
    
    // Reset flags for this update cycle
    process->has_new_rwx_region = 0;
    process->has_modified_executable_region = 0;
    process->has_large_memory_increase = 0;
    process->has_suspicious_allocation_pattern = 0;
    
    // Re-parse memory maps
    parse_memory_maps(process);
    
    // Detect RWX regions
    detect_rwx_regions(process);
}

// Parse the memory maps file for a process
static void parse_memory_maps(ProcessMemory* process) {
    char maps_path[64];
    char line[1024];
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", process->pid);
    
    FILE* maps = fopen(maps_path, "r");
    if (!maps) {
        LOG_ERROR("Failed to open %s: %s", maps_path, strerror(errno));
        return;
    }
    
    // Reset region count
    process->region_count = 0;
    
    // Parse each line of the maps file
    while (fgets(line, sizeof(line), maps) && process->region_count < MAX_MEMORY_REGIONS) {
        MemoryRegion* region = &process->regions[process->region_count];
        
        // Example line format:
        // address           perms offset  dev   inode   pathname
        // 00400000-00452000 r-xp 00000000 08:02 173521  /usr/bin/dbus-daemon
        
        // Parse memory addresses
        if (sscanf(line, "%lx-%lx %7s %lx %15s %lu %511s",
                 &region->start, &region->end, region->perms, 
                 &region->offset, region->device, &region->inode, 
                 region->pathname) < 6) {
            // Some lines don't have pathnames
            region->pathname[0] = '\0';
        }
        
        // Calculate region size
        region->size = region->end - region->start;
        
        // Mark if this is an RWX region
        region->is_rwx = is_rwx_permission(region->perms);
        
        // Mark region as new by default (will be updated later)
        region->is_new = 1;
        
        // Calculate checksum for executable regions
        if (is_executable(region->perms)) {
            calculate_region_checksum(process, region);
        }
        
        process->region_count++;
    }
    
    fclose(maps);
}

// Detect RWX regions and memory allocation patterns
static void detect_rwx_regions(ProcessMemory* process) {
    process->rwx_region_count = 0;
    
    for (int i = 0; i < process->region_count; i++) {
        if (process->regions[i].is_rwx) {
            process->rwx_region_count++;
            
            // Check if this is a new RWX region
            int found = 0;
            for (int j = 0; j < process->last_rwx_region_count; j++) {
                if (process->regions[i].start == process->regions[j].start &&
                    process->regions[i].end == process->regions[j].end) {
                    found = 1;
                    process->regions[i].is_new = 0;
                    break;
                }
            }
            
            if (!found || process->regions[i].is_new) {
                process->has_new_rwx_region = 1;
                
                LOG_WARNING("New RWX memory region detected in process %d (%s): %lx-%lx %s",
                         process->pid, process->comm,
                         process->regions[i].start, process->regions[i].end,
                         process->regions[i].pathname);
                
                // Generate event for new RWX region
                char details[256];
                char pathname_truncated[128];
                strncpy(pathname_truncated, process->regions[i].pathname, sizeof(pathname_truncated)-1);
                pathname_truncated[sizeof(pathname_truncated)-1] = '\0';  // Ensure null termination

                snprintf(details, sizeof(details), 
                       "New RWX memory region: %lx-%lx (%lu KB) %s",
                       process->regions[i].start, process->regions[i].end,
                       process->regions[i].size / 1024,
                       pathname_truncated);
                
                // Higher score impact for regions with no pathname (anonymous mappings)
                float score_impact = process->regions[i].pathname[0] ? 10.0f : 15.0f;
                generate_memory_event(process->pid, EVENT_MEMORY_RWX, details, score_impact);
            }
        }
    }
    
    // Detect suspicious allocation patterns (many small allocations or very large ones)
    int small_alloc_count = 0;
    int large_alloc_count = 0;
    
    for (int i = 0; i < process->region_count; i++) {
        if (process->regions[i].is_new) {
            if (process->regions[i].size < 4096 && is_writeable(process->regions[i].perms)) {
                small_alloc_count++;
            } else if (process->regions[i].size > 1024 * 1024 * 10) { // 10MB
                large_alloc_count++;
            }
        }
    }
    
    if (small_alloc_count > 10) {
        LOG_WARNING("Suspicious pattern: many small memory allocations (%d) in process %d (%s)",
                 small_alloc_count, process->pid, process->comm);
        process->has_suspicious_allocation_pattern = 1;
        
        char details[256];
        snprintf(details, sizeof(details), 
               "Suspicious memory pattern: %d small allocations",
               small_alloc_count);
        generate_memory_event(process->pid, EVENT_MEMORY_PATTERN, details, 5.0f);
    }
    
    if (large_alloc_count > 2) {
        LOG_WARNING("Suspicious pattern: multiple large memory allocations (%d) in process %d (%s)",
                 large_alloc_count, process->pid, process->comm);
        process->has_suspicious_allocation_pattern = 1;
        
        char details[256];
        snprintf(details, sizeof(details), 
               "Suspicious memory pattern: %d large allocations (>10MB each)",
               large_alloc_count);
        generate_memory_event(process->pid, EVENT_MEMORY_PATTERN, details, 8.0f);
    }
}

// Detect significant memory changes
static void detect_memory_changes(ProcessMemory* process) {
    // Check for large memory increases
    long memory_diff = process->total_memory_kb - process->last_total_memory_kb;
    
    if (memory_diff > MEMORY_CHANGE_THRESHOLD) {
        LOG_WARNING("Large memory increase detected in process %d (%s): %ld KB",
                 process->pid, process->comm, memory_diff);
        process->has_large_memory_increase = 1;
        
        char details[256];
        snprintf(details, sizeof(details), 
               "Large memory increase: %ld KB (total: %lu KB)",
               memory_diff, process->total_memory_kb);
        
        // Scale score impact based on size of increase
        float score_impact = 2.0f;
        if (memory_diff > MEMORY_CHANGE_THRESHOLD * 2) {
            score_impact = 5.0f;
        }
        if (memory_diff > MEMORY_CHANGE_THRESHOLD * 5) {
            score_impact = 10.0f;
        }
        
        generate_memory_event(process->pid, EVENT_MEMORY_USAGE, details, score_impact);
    }
}

// Detect modifications to executable code regions
static void detect_code_modifications(ProcessMemory* process) {
    for (int i = 0; i < process->region_count; i++) {
        if (is_executable(process->regions[i].perms)) {
            // Check if this region existed before
            for (int j = 0; j < process->region_count; j++) {
                if (process->regions[i].start == process->regions[j].start &&
                    process->regions[i].end == process->regions[j].end &&
                    is_executable(process->regions[j].perms)) {
                    
                    // Compare checksums to detect modifications
                    if (memcmp(process->regions[i].checksum, 
                             process->last_code_checksums[j], 
                             sizeof(process->regions[i].checksum)) != 0) {
                        
                        LOG_WARNING("Executable memory region modified in process %d (%s): %lx-%lx %s",
                                 process->pid, process->comm,
                                 process->regions[i].start, process->regions[i].end,
                                 process->regions[i].pathname);
                        
                        process->has_modified_executable_region = 1;
                        
                        char details[256];
                        char pathname_truncated[128];
                        strncpy(pathname_truncated, process->regions[i].pathname, sizeof(pathname_truncated)-1);
                        pathname_truncated[sizeof(pathname_truncated)-1] = '\0';  // Ensure null termination

                        snprintf(details, sizeof(details), 
                               "Modified executable memory: %lx-%lx (%lu KB) %s",
                               process->regions[i].start, process->regions[i].end,
                               process->regions[i].size / 1024,
                               pathname_truncated);
                        
                        // Higher score for anonymous mappings vs. named mappings
                        float score_impact = process->regions[i].pathname[0] ? 15.0f : 25.0f;
                        generate_memory_event(process->pid, EVENT_MEMORY_MODIFIED, details, score_impact);
                    }
                    
                    // Update the stored checksum
                    memcpy(process->last_code_checksums[j], 
                         process->regions[i].checksum, 
                         sizeof(process->regions[i].checksum));
                    
                    break;
                }
            }
        }
    }
}

// Calculate a simple checksum for a memory region
static void calculate_region_checksum(ProcessMemory* process, MemoryRegion* region) {
    // Initialize checksum
    memset(region->checksum, 0, sizeof(region->checksum));
    
    // For simplicity and performance, we'll calculate checksum on a sample of the region
    // rather than reading the entire thing
    
    // Open mem file
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", process->pid);
    
    int fd = open(mem_path, O_RDONLY);
    if (fd < 0) {
        LOG_ERROR("Failed to open %s: %s", mem_path, strerror(errno));
        return;
    }
    
    // Sampling parameters - for large regions, we sample at intervals
    unsigned long region_size = region->end - region->start;
    unsigned long sample_size = 4096; // 4K sample
    unsigned long max_samples = 16;
    unsigned long sample_interval = region_size / max_samples;
    
    if (sample_interval < sample_size) {
        sample_interval = sample_size;
    }
    
    // Buffer for reading memory
    unsigned char buffer[sample_size];
    
    // Attach to the process with ptrace to access its memory
    int attached = 0;
    if (ptrace(PTRACE_ATTACH, process->pid, NULL, NULL) == 0) {
        waitpid(process->pid, NULL, 0);
        attached = 1;
    } else {
        LOG_ERROR("Failed to attach to process %d for memory checksum: %s", 
                process->pid, strerror(errno));
    }
    
    // Sample the memory region at intervals
    for (unsigned long offset = 0; offset < region_size; offset += sample_interval) {
        // Try to read from the mem file
        if (lseek(fd, region->start + offset, SEEK_SET) == -1) {
            LOG_ERROR("Failed to seek to %lx in process %d: %s", 
                    region->start + offset, process->pid, strerror(errno));
            continue;
        }
        
        // Read a sample
        ssize_t bytes_read = read(fd, buffer, sample_size);
        if (bytes_read <= 0) {
            // Reading failed, try using ptrace instead for small chunks
            if (attached) {
                for (unsigned long i = 0; i < sample_size && i + offset < region_size; i += sizeof(long)) {
                    long word = ptrace(PTRACE_PEEKDATA, process->pid, region->start + offset + i, NULL);
                    if (errno == 0 && i + sizeof(long) <= sample_size) {
                        memcpy(buffer + i, &word, sizeof(long));
                        bytes_read = i + sizeof(long);
                    }
                }
            }
            
            if (bytes_read <= 0) {
                LOG_ERROR("Failed to read memory at %lx in process %d: %s", 
                        region->start + offset, process->pid, strerror(errno));
                continue;
            }
        }
        
        // Update checksum (simple XOR-based rolling checksum)
        for (ssize_t i = 0; i < bytes_read; i++) {
            region->checksum[i % sizeof(region->checksum)] ^= buffer[i];
        }
    }
    
    // Detach from the process
    if (attached) {
        ptrace(PTRACE_DETACH, process->pid, NULL, NULL);
    }
    
    close(fd);
}

// Check if memory has RWX permissions
static int is_rwx_permission(const char* perms) {
    return (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x');
}

// Check if memory is executable
static int is_executable(const char* perms) {
    return (perms[2] == 'x');
}

// Check if memory is writeable
static int is_writeable(const char* perms) {
    return (perms[1] == 'w');
}

// Generate a memory-related event
static void generate_memory_event(pid_t pid, EventType type, const char* details, float score_impact) {
    if (!event_callback) {
        return;
    }
    
    Event event;
    memset(&event, 0, sizeof(event));
    
    event.type = type;
    event.process_id = pid;
    event.timestamp = time(NULL);
    event.score_impact = score_impact;
    
    // Fill memory event data
    strncpy(event.data.memory_event.details, details, sizeof(event.data.memory_event.details) - 1);
    
    // Call the event handler
    event_callback(&event, event_callback_data);
}

// Find or create process memory tracking structure
static ProcessMemory* find_process_memory(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (monitored_processes[i].pid == pid) {
            return &monitored_processes[i];
        }
    }
    return NULL;
}

// Add a new process to monitor
static ProcessMemory* add_process_memory(pid_t pid) {
    if (process_count >= MAX_MONITORED_PROCESSES) {
        LOG_ERROR("Cannot monitor more processes, limit reached%s", "");
        return NULL;
    }
    
    ProcessMemory* process = &monitored_processes[process_count++];
    memset(process, 0, sizeof(ProcessMemory));
    process->pid = pid;
    process->last_updated = time(NULL);
    
    return process;
}

// Get total memory usage of a process in KB
static unsigned long get_process_memory_usage(pid_t pid) {
    char statm_path[64];
    unsigned long size = 0;
    
    snprintf(statm_path, sizeof(statm_path), "/proc/%d/statm", pid);
    
    FILE* f = fopen(statm_path, "r");
    if (f) {
        // First value is total program size in pages
        if (fscanf(f, "%lu", &size) != 1) {
            size = 0;
        }
        fclose(f);
    }
    
    // Convert pages to KB (assuming 4KB pages)
    return size * 4;
}

// Get memory monitoring statistics for a process
int memory_monitor_get_stats(pid_t pid, MemoryStats* stats) {
    if (!stats) {
        return -1;
    }
    
    ProcessMemory* process = find_process_memory(pid);
    if (!process) {
        return -1;
    }
    
    stats->total_memory_kb = process->total_memory_kb;
    stats->rwx_region_count = process->rwx_region_count;
    stats->memory_region_count = process->region_count;
    stats->has_new_rwx_region = process->has_new_rwx_region;
    stats->has_modified_executable_region = process->has_modified_executable_region;
    stats->has_large_memory_increase = process->has_large_memory_increase;
    stats->has_suspicious_allocation_pattern = process->has_suspicious_allocation_pattern;
    
    return 0;
}

// Get the process context from the monitoring system
static ProcessContext* get_process_context(pid_t pid) {
    // This is a simplistic implementation - in a real system, you'd have
    // a shared process context database across all monitoring components
    static ProcessContext dummy_context;
    
    // Initialize the dummy context with reasonable defaults
    dummy_context.pid = pid;
    snprintf(dummy_context.command, sizeof(dummy_context.command), "process-%d", pid);
    dummy_context.monitoring_level = MONITORING_LEVEL_MEDIUM;
    dummy_context.flags = 0;
    dummy_context.last_activity = time(NULL);
    
    return &dummy_context;
}

// Check if a file is interesting for memory monitoring
static int is_interesting_file(const char* pathname) {
    if (!pathname || pathname[0] == '\0') {
        return 0;  // Anonymous mapping, not interesting by default
    }
    
    // Look for common libraries that might be interesting
    const char* interesting_patterns[] = {
        "libc", "libcrypto", "libssl", "libsystem", "libz",
        "python", "java", "dotnet", ".so", ".dll", ".exe",
        NULL
    };
    
    for (int i = 0; interesting_patterns[i] != NULL; i++) {
        if (strstr(pathname, interesting_patterns[i])) {
            return 1;
        }
    }
    
    return 0;
}

// Analyze a specific memory region for suspicious content/behavior
static void analyze_memory_region(pid_t pid, unsigned long start, unsigned long end, 
                              const char* perms, const char* pathname, 
                              EventHandler handler, void* user_data) {
    // Calculate region size
    unsigned long size = end - start;
    
    // Check for suspicious RWX permissions
    if (strcmp(perms, "rwx") == 0) {
        LOG_DEBUG("RWX memory region found at %lx-%lx (%lu KB) in process %d: %s", 
                 start, end, size / 1024, pid, pathname);
        
        // Generate an event for RWX memory
        if (handler) {
            Event event;
            memset(&event, 0, sizeof(event));
            
            event.type = EVENT_MEMORY_RWX;
            event.process_id = pid;
            event.timestamp = time(NULL);
            event.score_impact = 8.0f;  // RWX memory is quite suspicious
            
            // Prepare details
            char details[256];
            snprintf(details, sizeof(details), 
                   "RWX memory region: %lx-%lx (%lu KB) %s", 
                   start, end, size / 1024, pathname[0] ? pathname : "anonymous mapping");
            
            strncpy(event.data.memory_event.details, details, 
                   sizeof(event.data.memory_event.details) - 1);
            
            // Call the event handler
            handler(&event, user_data);
        }
    }
    
    // Additional analysis would go here:
    // - Check for shellcode signatures
    // - Check for encrypted content
    // - Check for suspicious strings
    // - etc.
}

// Modify scan_memory_regions to reduce log verbosity
static void __attribute__((unused)) scan_memory_regions(pid_t pid, EventHandler handler, void* user_data) {
    // Get process context
    ProcessContext* context = get_process_context(pid);
    if (!context) {
        return;
    }
    
    // Skip memory scanning for low-monitoring processes
    if (context->monitoring_level == MONITORING_LEVEL_LOW) {
        return;
    }
    
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE* maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        // Don't log errors for processes that might have terminated
        return;
    }
    
    char line[512];
    unsigned long start, end;
    char perms[5];
    char pathname[256];
    int interesting_regions = 0;
    int total_regions = 0;
    
    LOG_DEBUG("Scanning memory regions for process %d (%s)", pid, context->command);
    
    while (fgets(line, sizeof(line), maps_file)) {
        // Parse the line
        memset(pathname, 0, sizeof(pathname));
        int result = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &start, &end, perms, pathname);
        
        if (result < 3) {
            continue;
        }
        
        total_regions++;
        
        // Skip non-rwx regions for efficiency, unless it's an interesting file
        if (strcmp(perms, "rwx") != 0 && !is_interesting_file(pathname)) {
            continue;
        }
        
        interesting_regions++;
        
        // Only log every 5th region to reduce spam
        if (interesting_regions % 5 == 0) {
            LOG_DEBUG("Analyzing memory region at %lx-%lx (%s) for process %d", 
                      start, end, perms, pid);
        }
        
        // Process the memory region
        analyze_memory_region(pid, start, end, perms, pathname, handler, user_data);
    }
    
    fclose(maps_file);
    
    // Only log a summary rather than details of each region
    if (interesting_regions > 0) {
        LOG_DEBUG("Scanned %d memory regions (%d interesting) for process %d", 
                 total_regions, interesting_regions, pid);
    }
}