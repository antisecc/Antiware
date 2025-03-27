#ifndef SCORING_H
#define SCORING_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "../include/antiransom.h"
#include "../include/events.h"

// Default threshold for alerts (can be configured at runtime)
#define DEFAULT_RISK_THRESHOLD 20

// Risk score increments for different suspicious activities
#define RISK_RAPID_FILE_MODIFICATIONS 5
#define RISK_SUSPICIOUS_LOCATION 7
#define RISK_NO_TERMINAL 3
#define RISK_HIGH_ENTROPY_WRITES 10
#define RISK_CHILD_PROCESS_SPAWNING 4
#define RISK_PRIVILEGE_ESCALATION 8
#define RISK_OBFUSCATED_COMMAND 6
#define RISK_RAPID_MEMORY_GROWTH 7

// Risk decay rate (points per minute of good behavior)
#define RISK_DECAY_RATE 1.0f

/* Score thresholds */
#define SCORE_THRESHOLD_LOW       30.0f
#define SCORE_THRESHOLD_MEDIUM    60.0f
#define SCORE_THRESHOLD_HIGH      80.0f
#define SCORE_THRESHOLD_CRITICAL  95.0f

/* Score weights for different categories */
#define WEIGHT_FILE_OPERATIONS    0.5f
#define WEIGHT_ENTROPY_CHANGES    0.7f
#define WEIGHT_CRYPTO_API         0.6f
#define WEIGHT_MEMORY_CHANGES     0.4f
#define WEIGHT_NETWORK_ACTIVITY   0.3f
#define WEIGHT_BACKUP_ACCESS      0.8f
#define WEIGHT_REGISTRY_CHANGES   0.4f

// Process score context for adaptive scoring
typedef struct {
    pid_t pid;                     // Process ID
    float current_risk_score;      // Current cumulative risk score
    time_t last_score_update;      // When score was last updated
    int num_suspicious_activities; // Count of suspicious activities
    int file_mod_count;            // Count of file modifications
    int process_spawn_count;       // Count of child processes spawned
    uint32_t process_hash;         // Hash of process path for identification
    time_t first_activity_time;    // When process first showed suspicious activity
} ProcessScoreContext;

/* Pattern detection structure */
typedef struct {
    uint32_t consecutive_file_ops;        // Count of sequential file operations
    uint32_t entropy_increases;           // Count of file entropy increases
    uint32_t sensitive_files_accessed;    // Count of document files accessed
    uint32_t file_extension_changes;      // Count of extension changes
    float avg_entropy_delta;              // Average entropy increase
    bool detected_encryption_pattern;     // File read-then-write with entropy increase
    bool detected_shadow_copy_deletion;   // Attempted shadow copy deletion
    bool detected_ransom_note_creation;   // Possible ransom note detected
} DetectionPatterns;

/* Initialize a new detection context */
void scoring_init_context(DetectionContext* context, uint32_t pid, const char* process_name);

/* Process a new event and update scores */
void scoring_process_event(DetectionContext* context, const Event* event, DetectionPatterns* patterns);

/* Update the total score based on component scores */
void scoring_update_total(DetectionContext* context);

/* Determine threat severity based on the current score */
ThreatSeverity scoring_assess_severity(float total_score, const Configuration* config);

/* Recommend an appropriate response action based on severity */
ResponseAction scoring_determine_action(ThreatSeverity severity, const Configuration* config);

/* Check for specific ransomware patterns in file operations */
float scoring_analyze_file_patterns(const DetectionPatterns* patterns);

/* Calculate entropy score based on before/after measurements */
float scoring_calculate_entropy_impact(uint8_t before, uint8_t after);

// Initialize scoring system
int scoring_init(void);

// Clean up scoring system
void scoring_cleanup(void);

// Update a process risk score
// Returns 1 if threshold exceeded, 0 otherwise
int update_process_score(pid_t pid, float score_increase, const char* reason);

// Get current process risk score
float get_process_risk_score(pid_t pid);

// Reset a process risk score
void reset_process_risk_score(pid_t pid);

// Apply time-based decay to process risk scores
void apply_risk_score_decay(void);

// Set global risk threshold
void set_risk_threshold(float threshold);

// Get global risk threshold
float get_risk_threshold(void);

// Adjust score based on source and context
float adjust_score_for_context(pid_t pid, float base_score, 
                              const char* process_path, 
                              const char* process_name);

// Calculate entropy impact for file operations
float scoring_calculate_entropy_impact(const void* data, size_t size, float* entropy);

// Check if path is in a suspicious location
int is_suspicious_location(const char* path);

// Get process score context
ProcessScoreContext* get_process_score_context(pid_t pid);

#endif /* SCORING_H */