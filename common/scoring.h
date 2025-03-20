#ifndef SCORING_H
#define SCORING_H

#include "../include/antiransom.h"
#include "../include/events.h"

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

#endif /* SCORING_H */