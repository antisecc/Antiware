#ifndef EVENTS_H
#define EVENTS_H

#include <stdint.h>
#include <time.h>

/* Event types for unified monitoring */
typedef enum {
    EVENT_FILE_ACCESS,        // Any file access operation
    EVENT_FILE_CREATE,        // File creation
    EVENT_FILE_MODIFY,        // File modification
    EVENT_FILE_DELETE,        // File deletion
    EVENT_FILE_RENAME,        // File rename operation
    EVENT_FILE_PERMISSION,    // Permission changes
    EVENT_PROCESS_CREATE,     // Process creation
    EVENT_PROCESS_TERMINATE,  // Process termination
    EVENT_MEMORY_ALLOC,       // Memory allocation
    EVENT_MEMORY_FREE,        // Memory deallocation
    EVENT_MEMORY_PROTECT,     // Memory protection change
    EVENT_NETWORK_CONNECT,    // Network connection
    EVENT_REGISTRY_ACCESS,    // Registry access (Windows)
    EVENT_REGISTRY_MODIFY,    // Registry modification (Windows)
    EVENT_CRYPTO_API,         // Cryptographic API usage
    EVENT_BACKUP_ACCESS,      // Backup/shadow copy access
    
    // Add missing event types
    EVENT_PROCESS_SUSPICIOUS, // Suspicious process behavior
    EVENT_PROCESS_BEHAVIOR,   // General process behavior
    EVENT_PROCESS_PRIVESC,    // Privilege escalation attempts
    EVENT_DETECTION_ALERT     // Security detection alerts
} EventType;

/* Generic event structure */
typedef struct {
    EventType type;
    uint32_t process_id;
    time_t timestamp;
    float score_impact;       // How this event affects the score
    
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
            char details[256];       // Add details field for extended info
        } process_event;
        
        // Add missing structure for memory events
        struct {
            uintptr_t address;
            size_t size;
            uint32_t protection_flags;
            char details[256];       // For detailed memory event info
        } memory_event;
        
        // Add missing structure for network events
        struct {
            char remote_address[128];
            uint16_t remote_port;
            uint16_t local_port;
            uint8_t protocol;
            uint8_t encrypted;
        } network_event;
        
        // Add missing structure for registry events
        struct {
            char key_path[512];
            char value_name[128];
            uint32_t value_type;
        } registry_event;
        
        // Add missing structure for crypto events
        struct {
            char api_name[64];
            uint32_t flags;
        } crypto_event;
        
        // Add missing structure for detection events
        struct {
            uint32_t severity;
            float score;
            char message[512];
        } detection_event;
    } data;
} Event;

typedef void (*EventHandler)(const Event* event, void* user_data);

#endif