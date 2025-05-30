#ifndef EVENTS_H
#define EVENTS_H

#include <stdint.h>
#include <time.h>

/* Event sources */
typedef enum {
    EVENT_SOURCE_SYSCALL = 0,
    EVENT_SOURCE_PROCESS = 1,
    EVENT_SOURCE_MEMORY = 2,
    EVENT_SOURCE_FILE_MONITOR = 3,  // Add file monitor source
    // Other sources...
} EventSource;

/* Event types for unified monitoring */
typedef enum {
    EVENT_FILE_ACCESS = 0,      // Any file access operation
    EVENT_FILE_CREATE = 50,     // File creation
    EVENT_FILE_MODIFY = 51,     // File modification
    EVENT_FILE_DELETE = 52,     // File deletion
    EVENT_FILE_WRITE = EVENT_FILE_MODIFY,  // Alias for file modification
    EVENT_FILE_RENAME = 53,     // File rename operation
    EVENT_FILE_PERMISSION = 5,  // Permission changes
    EVENT_PROCESS_CREATE,       // Process creation
    EVENT_PROCESS_TERMINATE,    // Process termination
    EVENT_MEMORY_ALLOC,         // Memory allocation
    EVENT_MEMORY_FREE,          // Memory deallocation
    EVENT_MEMORY_PROTECT,       // Memory protection change
    EVENT_NETWORK_CONNECT,      // Network connection
    EVENT_REGISTRY_ACCESS,      // Registry access (Windows)
    EVENT_REGISTRY_MODIFY,      // Registry modification (Windows)
    EVENT_CRYPTO_API,           // Cryptographic API usage
    EVENT_BACKUP_ACCESS,        // Backup/shadow copy access
    
    // Additional process-related events
    EVENT_PROCESS_SUSPICIOUS,   // Suspicious process behavior
    EVENT_PROCESS_BEHAVIOR,     // General process behavior
    EVENT_PROCESS_PRIVESC,      // Privilege escalation attempts
    EVENT_PROCESS_CORRELATION,  // Correlated suspicious process activity
    EVENT_PROCESS_LINEAGE,      // Process ancestry/lineage suspicious
    EVENT_PROCESS_OBFUSCATION,  // Command line obfuscation detected
    EVENT_PROCESS_MASQUERADE,   // Process disguising as system process
    
    // Additional memory-related events
    EVENT_MEMORY_RWX,           // Executable and writable memory detected
    EVENT_MEMORY_PATTERN,       // Suspicious memory allocation pattern
    EVENT_MEMORY_USAGE,         // Unusual memory usage
    EVENT_MEMORY_MODIFIED,      // Modification of executable memory
    EVENT_MEMORY_SUSPICIOUS,    // Suspicious memory activity detected
    
    // Syscall-related events
    EVENT_SYSCALL_SUSPICIOUS,   // Suspicious syscall patterns
    
    // Alert events
    EVENT_DETECTION_ALERT       // Security detection alerts
} EventType;

/* File event data structure */
typedef struct {
    char path[512];
    char extension[32];
} FileEvent;

/* Generic event structure */
typedef struct {
    EventType type;
    uint32_t process_id;
    time_t timestamp;
    float score_impact;       // How this event affects the score
    EventSource source;       // Add event source
    
    union {
        struct {
            char path[512];
            uint32_t access_flags;
            uint8_t entropy_before;  // 0-100 scale
            uint8_t entropy_after;   // 0-100 scale
        } file_event;
        
        struct {
            uint32_t parent_pid;
            char image_path[512];
            char command_line[1024];
            char details[256];       // Add details field for process events
            char comm[256];
        } process_event;
        
        struct {
            uintptr_t address;
            size_t size;
            uint32_t protection_flags;
            char details[256];       // For detailed memory event info
        } memory_event;
        
        struct {
            char remote_address[128];
            uint16_t remote_port;
            uint16_t local_port;
            uint8_t protocol;
            uint8_t encrypted;
        } network_event;
        
        struct {
            char key_path[512];
            char value_name[128];
            uint32_t value_type;
        } registry_event;
        
        struct {
            char api_name[64];
            uint32_t flags;
        } crypto_event;
        
        // Add detection_event structure
        struct {
            uint32_t severity;
            float score;
            char message[512];
        } detection_event;
    } data;
} Event;

// Define event handler function pointer type
typedef void (*EventHandler)(const Event* event, void* user_data);

#endif // EVENTS_H