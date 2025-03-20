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
    EVENT_BACKUP_ACCESS       // Backup/shadow copy access
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
        } process_event;
        
        struct {
            void* address;
            size_t size;
            uint32_t protection_flags;
        } memory_event;
        
        struct {
            char remote_address[64];
            uint16_t remote_port;
            bool encrypted;
        } network_event;
        
        struct {
            char key_path[512];
            bool is_write;
        } registry_event;
        
        struct {
            char api_name[128];
            bool is_symmetric;
        } crypto_event;
    } data;
} Event;

/* Callback function definition for event handling */
typedef void (*EventHandler)(const Event* event, void* user_data);

#endif /* EVENTS_H */