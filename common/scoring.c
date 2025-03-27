/**
 * AntiRansom - Scoring System Implementation
 * Implements the scoring interface defined in scoring.h
 */

#include "scoring.h"
#include "logger.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

// Maximum number of processes to track for scoring
#define MAX_SCORE_PROCESSES 256

// Global process score contexts
static ProcessScoreContext* process_scores[MAX_SCORE_PROCESSES];
static int process_score_count = 0;
static float risk_threshold = DEFAULT_RISK_THRESHOLD;
static pthread_mutex_t scoring_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialize scoring system
int scoring_init(void) {
    pthread_mutex_lock(&scoring_mutex);
    
    // Initialize process score array
    memset(process_scores, 0, sizeof(process_scores));
    process_score_count = 0;
    risk_threshold = DEFAULT_RISK_THRESHOLD;
    
    pthread_mutex_unlock(&scoring_mutex);
    LOG_INFO("Scoring system initialized with threshold %.1f", risk_threshold);
    return 0;
}

// Clean up scoring system
void scoring_cleanup(void) {
    pthread_mutex_lock(&scoring_mutex);
    
    // Free all allocated contexts
    for (int i = 0; i < process_score_count; i++) {
        if (process_scores[i]) {
            free(process_scores[i]);
            process_scores[i] = NULL;
        }
    }
    process_score_count = 0;
    
    pthread_mutex_unlock(&scoring_mutex);
    LOG_INFO("Scoring system cleaned up%s", "");
}

// Find or create a process score context
static ProcessScoreContext* find_or_create_score_context(pid_t pid) {
    // First try to find existing context
    for (int i = 0; i < process_score_count; i++) {
        if (process_scores[i] && process_scores[i]->pid == pid) {
            return process_scores[i];
        }
    }
    
    // Not found, create new context
    if (process_score_count >= MAX_SCORE_PROCESSES) {
        // Find least recently updated context to replace
        int oldest_idx = 0;
        time_t oldest_time = time(NULL);
        
        for (int i = 0; i < process_score_count; i++) {
            if (process_scores[i] && process_scores[i]->last_score_update < oldest_time) {
                oldest_time = process_scores[i]->last_score_update;
                oldest_idx = i;
            }
        }
        
        // Free the oldest context
        if (process_scores[oldest_idx]) {
            LOG_DEBUG("Replacing oldest score context for PID %d", process_scores[oldest_idx]->pid);
            free(process_scores[oldest_idx]);
        }
        
        // Create new context
        process_scores[oldest_idx] = (ProcessScoreContext*)malloc(sizeof(ProcessScoreContext));
        if (!process_scores[oldest_idx]) {
            LOG_ERROR("Failed to allocate memory for process score context%s", "");
            return NULL;
        }
        
        // Initialize context
        memset(process_scores[oldest_idx], 0, sizeof(ProcessScoreContext));
        process_scores[oldest_idx]->pid = pid;
        process_scores[oldest_idx]->last_score_update = time(NULL);
        process_scores[oldest_idx]->first_activity_time = time(NULL);
        
        return process_scores[oldest_idx];
    } else {
        // Still have space, add new context
        ProcessScoreContext* context = (ProcessScoreContext*)malloc(sizeof(ProcessScoreContext));
        if (!context) {
            LOG_ERROR("Failed to allocate memory for process score context%s", "");
            return NULL;
        }
        
        // Initialize context
        memset(context, 0, sizeof(ProcessScoreContext));
        context->pid = pid;
        context->last_score_update = time(NULL);
        context->first_activity_time = time(NULL);
        
        // Add to array
        process_scores[process_score_count++] = context;
        
        return context;
    }
}

// Update a process risk score
int update_process_score(pid_t pid, float score_increase, const char* reason) {
    if (pid <= 0 || score_increase <= 0) {
        return 0;
    }
    
    pthread_mutex_lock(&scoring_mutex);
    
    // Find or create context for this process
    ProcessScoreContext* context = find_or_create_score_context(pid);
    if (!context) {
        pthread_mutex_unlock(&scoring_mutex);
        return 0;
    }
    
    // Update score
    float old_score = context->current_risk_score;
    context->current_risk_score += score_increase;
    context->num_suspicious_activities++;
    context->last_score_update = time(NULL);
    
    // Log score update
    LOG_DEBUG("Process %d risk score updated: %.1f -> %.1f (+%.1f) [%s]", 
             pid, old_score, context->current_risk_score, score_increase, 
             reason ? reason : "unspecified");
    
    // Check if threshold exceeded
    int threshold_exceeded = (old_score < risk_threshold && 
                              context->current_risk_score >= risk_threshold);
    
    if (threshold_exceeded) {
        LOG_WARNING("Process %d exceeded risk threshold (%.1f >= %.1f) [%s]", 
                   pid, context->current_risk_score, risk_threshold, 
                   reason ? reason : "unspecified");
    }
    
    pthread_mutex_unlock(&scoring_mutex);
    return threshold_exceeded;
}

// Get current process risk score
float get_process_risk_score(pid_t pid) {
    float score = 0.0f;
    
    pthread_mutex_lock(&scoring_mutex);
    
    // Find context for this process
    for (int i = 0; i < process_score_count; i++) {
        if (process_scores[i] && process_scores[i]->pid == pid) {
            score = process_scores[i]->current_risk_score;
            break;
        }
    }
    
    pthread_mutex_unlock(&scoring_mutex);
    return score;
}

// Reset a process risk score
void reset_process_risk_score(pid_t pid) {
    pthread_mutex_lock(&scoring_mutex);
    
    // Find context for this process
    for (int i = 0; i < process_score_count; i++) {
        if (process_scores[i] && process_scores[i]->pid == pid) {
            LOG_DEBUG("Reset process %d risk score from %.1f to 0", 
                     pid, process_scores[i]->current_risk_score);
            
            process_scores[i]->current_risk_score = 0.0f;
            process_scores[i]->num_suspicious_activities = 0;
            process_scores[i]->file_mod_count = 0;
            process_scores[i]->process_spawn_count = 0;
            process_scores[i]->last_score_update = time(NULL);
            break;
        }
    }
    
    pthread_mutex_unlock(&scoring_mutex);
}

// Apply time-based decay to process risk scores
void apply_risk_score_decay(void) {
    time_t now = time(NULL);
    
    pthread_mutex_lock(&scoring_mutex);
    
    for (int i = 0; i < process_score_count; i++) {
        if (!process_scores[i] || process_scores[i]->current_risk_score <= 0.0f) {
            continue;
        }
        
        // Calculate time since last update in minutes
        float minutes_elapsed = (float)(now - process_scores[i]->last_score_update) / 60.0f;
        
        if (minutes_elapsed >= 1.0f) {
            // Apply decay based on elapsed time
            float decay_amount = RISK_DECAY_RATE * minutes_elapsed;
            
            // Don't decay below zero
            if (decay_amount > process_scores[i]->current_risk_score) {
                decay_amount = process_scores[i]->current_risk_score;
            }
            
            if (decay_amount > 0) {
                process_scores[i]->current_risk_score -= decay_amount;
                process_scores[i]->last_score_update = now;
                
                LOG_DEBUG("Applied decay to process %d: -%.1f points (now %.1f)", 
                         process_scores[i]->pid, decay_amount, 
                         process_scores[i]->current_risk_score);
            }
        }
    }
    
    pthread_mutex_unlock(&scoring_mutex);
}

// Set global risk threshold
void set_risk_threshold(float threshold) {
    if (threshold <= 0) {
        return;
    }
    
    pthread_mutex_lock(&scoring_mutex);
    risk_threshold = threshold;
    pthread_mutex_unlock(&scoring_mutex);
    
    LOG_INFO("Risk threshold set to %.1f", threshold);
}

// Get global risk threshold
float get_risk_threshold(void) {
    float threshold;
    
    pthread_mutex_lock(&scoring_mutex);
    threshold = risk_threshold;
    pthread_mutex_unlock(&scoring_mutex);
    
    return threshold;
}

// Adjust score based on source and context
float adjust_score_for_context(pid_t pid, float base_score, 
                              const char* process_path, 
                              const char* process_name) {
    if (!process_path || !process_name) {
        return base_score;
    }
    
    float adjusted_score = base_score;
    
    // Reduce score for system utilities
    const char* system_dirs[] = {
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/usr/lib/",
        NULL
    };
    
    for (int i = 0; system_dirs[i] != NULL; i++) {
        if (strncmp(process_path, system_dirs[i], strlen(system_dirs[i])) == 0) {
            adjusted_score *= 0.7f; // 30% reduction for system processes
            break;
        }
    }
    
    // Reduce score for common utilities known to be high file access
    const char* safe_processes[] = {
        "backup", "rsync", "cp", "tar", "gzip", "dpkg", "apt", "yum", "dnf",
        "find", "grep", "sed", "awk", "gcc", "make", "systemd", "journal",
        NULL
    };
    
    for (int i = 0; safe_processes[i] != NULL; i++) {
        if (strstr(process_name, safe_processes[i]) != NULL) {
            adjusted_score *= 0.5f; // 50% reduction for known safe processes
            break;
        }
    }
    
    // Increase score for suspicious processes
    const char* suspicious_names[] = {
        "encrypt", "ransom", "crypt", "bitcoin", "locker", "anonymous",
        NULL
    };
    
    for (int i = 0; suspicious_names[i] != NULL; i++) {
        if (strstr(process_name, suspicious_names[i]) != NULL) {
            adjusted_score *= 1.5f; // 50% increase for suspicious names
            break;
        }
    }
    
    pthread_mutex_lock(&scoring_mutex);
    
    // Consider history (if we have seen this process before)
    ProcessScoreContext* context = NULL;
    for (int i = 0; i < process_score_count; i++) {
        if (process_scores[i] && process_scores[i]->pid == pid) {
            context = process_scores[i];
            break;
        }
    }
    
    if (context) {
        // If process has accumulated many suspicious activities recently,
        // increase the score more dramatically
        if (context->num_suspicious_activities > 10 && 
            (now - context->first_activity_time) < 300) { // 5 minutes
            
            // Rapidly accumulating suspicious activity
            adjusted_score *= 1.5f;
        }
        
        // If process has been around for a while with low activity,
        // reduce the score
        if (context->num_suspicious_activities < 5 && 
            (now - context->first_activity_time) > 3600) { // 1 hour
            
            // Long-running process with few suspicious activities
            adjusted_score *= 0.7f;
        }
    }
    
    pthread_mutex_unlock(&scoring_mutex);
    
    // Ensure score doesn't drop below 10% of original
    if (adjusted_score < (base_score * 0.1f)) {
        adjusted_score = base_score * 0.1f;
    }
    
    // Log significant adjustments
    if (fabs(adjusted_score - base_score) > (base_score * 0.3f)) {
        LOG_DEBUG("Adjusted score for process %d (%s): %.1f -> %.1f", 
                 pid, process_name, base_score, adjusted_score);
    }
    
    return adjusted_score;
}

// Calculate entropy for data
float calculate_entropy(const void* data, size_t size) {
    if (!data || size == 0) {
        return 0.0f;
    }
    
    // Count occurrences of each byte
    unsigned int counts[256] = {0};
    const unsigned char* bytes = (const unsigned char*)data;
    
    for (size_t i = 0; i < size; i++) {
        counts[bytes[i]]++;
    }
    
    // Calculate entropy
    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            float p = (float)counts[i] / size;
            entropy -= p * log2f(p);
        }
    }
    
    return entropy;
}

// Calculate entropy impact for file operations
float scoring_calculate_entropy_impact(const void* data, size_t size, float* entropy) {
    if (!data || size < 64) {
        // Too small to calculate meaningful entropy
        if (entropy) *entropy = 0.0f;
        return 0.0f;
    }
    
    float calculated_entropy = calculate_entropy(data, size);
    if (entropy) *entropy = calculated_entropy;
    
    // Entropy near 8.0 (maximum for byte data) is suspicious
    // Low entropy (< 3.0) or medium entropy is less likely to be encrypted/compressed
    if (calculated_entropy > 7.5f) {
        return RISK_HIGH_ENTROPY_WRITES;
    } else if (calculated_entropy > 7.0f) {
        return RISK_HIGH_ENTROPY_WRITES * 0.7f;
    } else if (calculated_entropy > 6.5f) {
        return RISK_HIGH_ENTROPY_WRITES * 0.3f;
    }
    
    return 0.0f;
}

// Check if path is in a suspicious location
int is_suspicious_location(const char* path) {
    if (!path) {
        return 0;
    }
    
    const char* suspicious_paths[] = {
        "/tmp/", "/dev/shm/", "/var/tmp/", "/run/", "/mnt/",
        NULL
    };
    
    for (int i = 0; suspicious_paths[i] != NULL; i++) {
        if (strncmp(path, suspicious_paths[i], strlen(suspicious_paths[i])) == 0) {
            return 1;
        }
    }
    
    // Check for home Downloads directory
    char* home = getenv("HOME");
    if (home) {
        char downloads[256];
        snprintf(downloads, sizeof(downloads), "%s/Downloads/", home);
        
        if (strncmp(path, downloads, strlen(downloads)) == 0) {
            return 1;
        }
    }
    
    return 0;
}

// Get process score context
ProcessScoreContext* get_process_score_context(pid_t pid) {
    ProcessScoreContext* context = NULL;
    
    pthread_mutex_lock(&scoring_mutex);
    
    for (int i = 0; i < process_score_count; i++) {
        if (process_scores[i] && process_scores[i]->pid == pid) {
            context = process_scores[i];
            break;
        }
    }
    
    pthread_mutex_unlock(&scoring_mutex);
    return context;
}

/* Initialize a new detection context */
void scoring_init_context(DetectionContext* context, uint32_t pid, const char* process_name) {
    if (!context) {
        return;
    }
    
    // Zero out the context first
    memset(context, 0, sizeof(DetectionContext));
    
    // Set basic information
    context->process_id = pid;
    strncpy(context->process_name, process_name, sizeof(context->process_name) - 1);
    context->start_time = (uint64_t)time(NULL);
    
    // Initialize scores to zero
    context->total_score = 0.0f;
    context->syscall_score = 0.0f;
    context->memory_score = 0.0f;
    context->process_score = 0.0f;
    
    // Set initial severity and action
    context->severity = SEVERITY_NONE;
    context->action = ACTION_NONE;
    
    LOG_INFO("Initialized detection context for PID %u (%s)", pid, process_name);
}

/* Process a new event and update scores */
void scoring_process_event(DetectionContext* context, const Event* event, DetectionPatterns* patterns) {
    if (!context || !event || !patterns) {
        return;
    }
    
    float score_delta = event->score_impact; // Starting point - use the event's own impact score
    const char* reason = "Unknown event";
    
    // Handle different event types
    switch (event->type) {
        // File operation events
        case EVENT_FILE_CREATE:
            if (score_delta == 0.0f) score_delta = 2.0f * WEIGHT_FILE_OPERATIONS;
            reason = "File creation";
            patterns->consecutive_file_ops++;
            break;
            
        case EVENT_FILE_DELETE:
            if (score_delta == 0.0f) score_delta = 10.0f * WEIGHT_FILE_OPERATIONS;
            reason = "File deletion";
            patterns->consecutive_file_ops++;
            context->files_deleted++;
            break;
            
        case EVENT_FILE_RENAME:
            if (score_delta == 0.0f) score_delta = 5.0f * WEIGHT_FILE_OPERATIONS;
            reason = "File rename";
            patterns->consecutive_file_ops++;
            
            // Check for extension changes (possible encryption)
            if (event->data.file_event.path[0] != '\0') {
                const char* file_path = event->data.file_event.path;
                const char* ext = strrchr(file_path, '.');
                
                // Analyze the file extension if available
                if (ext && (strcasecmp(ext, ".crypt") == 0 ||
                           strcasecmp(ext, ".locked") == 0 ||
                           strcasecmp(ext, ".encrypted") == 0 ||
                           strcasecmp(ext, ".crypted") == 0 ||
                           strcasecmp(ext, ".cryp") == 0 ||
                           strcasecmp(ext, ".WNCRY") == 0 ||
                           strcasecmp(ext, ".wcry") == 0)) {
                    patterns->file_extension_changes++;
                    score_delta += 40.0f * WEIGHT_FILE_OPERATIONS;
                    reason = "Ransomware file extension detected";
                    context->encryption_detected = true;
                }
            }
            break;
            
        case EVENT_FILE_MODIFY:
            if (score_delta == 0.0f) score_delta = 3.0f * WEIGHT_FILE_OPERATIONS;
            reason = "File modification";
            patterns->consecutive_file_ops++;
            context->files_modified++;
            
            // Check for sensitive file types
            const char* ext = strrchr(event->data.file_event.path, '.');
            if (ext && (strcasecmp(ext, ".doc") == 0 ||
                       strcasecmp(ext, ".docx") == 0 ||
                       strcasecmp(ext, ".xls") == 0 ||
                       strcasecmp(ext, ".xlsx") == 0 ||
                       strcasecmp(ext, ".pdf") == 0 ||
                       strcasecmp(ext, ".jpg") == 0 ||
                       strcasecmp(ext, ".png") == 0 ||
                       strcasecmp(ext, ".txt") == 0)) {
                patterns->sensitive_files_accessed++;
                score_delta += 5.0f * WEIGHT_FILE_OPERATIONS;
                reason = "Sensitive file modification";
            }
            
            // Check entropy changes
            if (event->data.file_event.entropy_before < event->data.file_event.entropy_after) {
                float entropy_increase = event->data.file_event.entropy_after - event->data.file_event.entropy_before;
                
                // Normalize to 0.0-8.0 scale (standard entropy scale)
                float normalized_entropy = (float)event->data.file_event.entropy_after / 12.5f;
                
                if (normalized_entropy > 7.0f) {
                    patterns->entropy_increases++;
                    patterns->avg_entropy_delta += entropy_increase;
                    score_delta += 20.0f * WEIGHT_ENTROPY_CHANGES;
                    reason = "High file entropy detected";
                    
                    if (patterns->entropy_increases > 2) {
                        patterns->detected_encryption_pattern = true;
                        context->encryption_detected = true;
                    }
                }
            }
            break;
            
        case EVENT_FILE_ACCESS:
            if (score_delta == 0.0f) score_delta = 1.0f * WEIGHT_FILE_OPERATIONS;
            reason = "File access";
            
            // Check if accessing backup files or shadow copies
            if (strstr(event->data.file_event.path, "\\System Volume Information\\") ||
                strstr(event->data.file_event.path, "\\Shadow Copy Volume\\")) {
                score_delta += 30.0f * WEIGHT_BACKUP_ACCESS;
                reason = "Shadow copy access";
                patterns->detected_shadow_copy_deletion = true;
                context->shadow_copy_access = true;
            }
            
            // Check for ransom note creation
            if (strstr(event->data.file_event.path, "README") ||
                strstr(event->data.file_event.path, "HOW_TO_DECRYPT") ||
                strstr(event->data.file_event.path, "HELP_DECRYPT") ||
                strstr(event->data.file_event.path, "RANSOM") ||
                strstr(event->data.file_event.path, "RECOVERY")) {
                
                patterns->detected_ransom_note_creation = true;
                score_delta += 50.0f * WEIGHT_FILE_OPERATIONS;
                reason = "Possible ransom note creation";
            }
            break;
            
        // Process events
        case EVENT_PROCESS_CREATE:
            if (score_delta == 0.0f) score_delta = 5.0f * WEIGHT_MEMORY_CHANGES;
            reason = "Process creation";
            
            // Check for suspicious process launch
            if (event->data.process_event.image_path[0] != '\0') {
                // Check for known suspicious processes
                if (strstr(event->data.process_event.image_path, "vssadmin.exe") ||
                    strstr(event->data.process_event.image_path, "bcdedit.exe") ||
                    strstr(event->data.process_event.image_path, "wbadmin.exe") ||
                    strstr(event->data.process_event.image_path, "powershell.exe") ||
                    strstr(event->data.process_event.image_path, "cmd.exe")) {
                    
                    // Check command line for suspicious flags
                    if (event->data.process_event.command_line[0] != '\0') {
                        if (strstr(event->data.process_event.command_line, "delete") ||
                            strstr(event->data.process_event.command_line, "shadow") ||
                            strstr(event->data.process_event.command_line, "recoveryenabled") ||
                            strstr(event->data.process_event.command_line, "bootstatuspolicy ignoreallfailures")) {
                            
                            score_delta += 50.0f * WEIGHT_BACKUP_ACCESS;
                            reason = "Backup deletion attempt";
                            patterns->detected_shadow_copy_deletion = true;
                            context->shadow_copy_access = true;
                        }
                    }
                }
            }
            break;
            
        case EVENT_PROCESS_TERMINATE:
            if (score_delta == 0.0f) score_delta = 1.0f * WEIGHT_MEMORY_CHANGES;
            reason = "Process termination";
            break;
            
        // Memory events
        case EVENT_MEMORY_ALLOC:
            if (score_delta == 0.0f) score_delta = 1.0f * WEIGHT_MEMORY_CHANGES;
            reason = "Memory allocation";
            break;
            
        case EVENT_MEMORY_PROTECT:
            if (score_delta == 0.0f) score_delta = 5.0f * WEIGHT_MEMORY_CHANGES;
            reason = "Memory protection change";
            
            // Check for executable memory
            if (event->data.memory_event.protection_flags & 0x10) { // Assuming 0x10 is executable flag
                score_delta += 15.0f * WEIGHT_MEMORY_CHANGES;
                reason = "Executable memory created";
            }
            break;
            
        // Network events
        case EVENT_NETWORK_CONNECT:
            context->network_activity = true;
            if (score_delta == 0.0f) score_delta = 5.0f * WEIGHT_NETWORK_ACTIVITY;
            reason = "Network connection";
            
            // Check for suspicious destinations
            if (event->data.network_event.remote_address[0] != '\0') {
                if (strstr(event->data.network_event.remote_address, ".onion") || 
                    strstr(event->data.network_event.remote_address, "tor")) {
                    score_delta += 20.0f * WEIGHT_NETWORK_ACTIVITY;
                    reason = "TOR network communication";
                }
            }
            
            // Check for encrypted communication
            if (event->data.network_event.encrypted) {
                score_delta += 5.0f * WEIGHT_NETWORK_ACTIVITY;
                reason = "Encrypted network traffic";
            }
            break;
            
        // Registry events (Windows)
        case EVENT_REGISTRY_ACCESS:
            if (score_delta == 0.0f) score_delta = 1.0f * WEIGHT_REGISTRY_CHANGES;
            reason = "Registry access";
            break;
            
        case EVENT_REGISTRY_MODIFY:
            context->registry_modification = true;
            if (score_delta == 0.0f) score_delta = 5.0f * WEIGHT_REGISTRY_CHANGES;
            reason = "Registry modification";
            
            // Check for startup registry keys
            if (event->data.registry_event.key_path[0] != '\0' && 
                (strstr(event->data.registry_event.key_path, "\\Run") ||
                 strstr(event->data.registry_event.key_path, "\\Startup"))) {
                score_delta += 15.0f * WEIGHT_REGISTRY_CHANGES;
                reason = "Startup registry modification";
            }
            break;
            
        // Cryptographic API
        case EVENT_CRYPTO_API:
            if (score_delta == 0.0f) score_delta = 10.0f * WEIGHT_CRYPTO_API;
            reason = "Cryptographic API usage";
            
            // Check for known encryption APIs
            if (event->data.crypto_event.api_name[0] != '\0') {
                if (strstr(event->data.crypto_event.api_name, "Crypt") ||
                    strstr(event->data.crypto_event.api_name, "AES") ||
                    strstr(event->data.crypto_event.api_name, "RSA") ||
                    strstr(event->data.crypto_event.api_name, "Cipher")) {
                    
                    score_delta += 15.0f * WEIGHT_CRYPTO_API;
                    reason = "Encryption API usage";
                    
                    if (patterns->entropy_increases > 0) {
                        // Encryption API used and high entropy files detected - very suspicious
                        score_delta += 25.0f * WEIGHT_CRYPTO_API;
                        reason = "Encryption API with high entropy files";
                        patterns->detected_encryption_pattern = true;
                        context->encryption_detected = true;
                    }
                }
            }
            break;
            
        // Shadow copy/backup access
        case EVENT_BACKUP_ACCESS:
            context->shadow_copy_access = true;
            if (score_delta == 0.0f) score_delta = 30.0f * WEIGHT_BACKUP_ACCESS;
            reason = "Backup/shadow copy access";
            patterns->detected_shadow_copy_deletion = true;
            break;
            
        default:
            if (score_delta == 0.0f) score_delta = 1.0f;
            break;
    }
    
    // Update the appropriate score component based on event type
    if (event->type >= EVENT_FILE_ACCESS && event->type <= EVENT_FILE_PERMISSION) {
        context->syscall_score += score_delta;
        if (context->syscall_score > 100.0f) context->syscall_score = 100.0f;
    }
    else if (event->type >= EVENT_PROCESS_CREATE && event->type <= EVENT_PROCESS_TERMINATE) {
        context->process_score += score_delta;
        if (context->process_score > 100.0f) context->process_score = 100.0f;
    }
    else if (event->type >= EVENT_MEMORY_ALLOC && event->type <= EVENT_MEMORY_PROTECT) {
        context->memory_score += score_delta;
        if (context->memory_score > 100.0f) context->memory_score = 100.0f;
    }
    else {
        // For other events, add to process score
        context->process_score += score_delta;
        if (context->process_score > 100.0f) context->process_score = 100.0f;
    }
    
    // Update mass file operations flag
    if (patterns->consecutive_file_ops > 20 && !context->mass_file_operations) {
        context->mass_file_operations = true;
        LOG_WARNING("Mass file operations detected for PID %u (%s)",
                   context->process_id, context->process_name);
    }
    
    // Log significant score changes
    if (score_delta >= 10.0f) {
        LOG_DEBUG("Added %.1f to score for PID %u (%s): %s",
                 score_delta, context->process_id, context->process_name, reason);
    }
    
    // Update the total score
    scoring_update_total(context);
}

/* Update the total score based on component scores */
void scoring_update_total(DetectionContext* context) {
    if (!context) {
        return;
    }
    
    // Base formula - weighted average of component scores
    float total = (context->syscall_score * 0.4f) +
                  (context->memory_score * 0.3f) +
                  (context->process_score * 0.3f);
    
    // Apply multipliers for high-risk indicators
    if (context->mass_file_operations) {
        total *= 1.5f;  // 50% increase for mass file operations
    }
    
    if (context->encryption_detected) {
        total *= 2.0f;  // Double score if encryption detected
    }
    
    if (context->shadow_copy_access) {
        total *= 1.7f;  // 70% increase for shadow copy access
    }
    
    context->total_score = total;
    
    // Cap at 100
    if (context->total_score > 100.0f) {
        context->total_score = 100.0f;
    }
}

/* Determine threat severity based on the current score */
ThreatSeverity scoring_assess_severity(float total_score, const Configuration* config) {
    if (!config) {
        // Use default thresholds if config not provided
        if (total_score >= SCORE_THRESHOLD_CRITICAL) {
            return SEVERITY_CRITICAL;
        } else if (total_score >= SCORE_THRESHOLD_HIGH) {
            return SEVERITY_HIGH;
        } else if (total_score >= SCORE_THRESHOLD_MEDIUM) {
            return SEVERITY_MEDIUM;
        } else if (total_score >= SCORE_THRESHOLD_LOW) {
            return SEVERITY_LOW;
        } else {
            return SEVERITY_NONE;
        }
    }
    
    // Use thresholds from configuration
    if (total_score >= config->threshold_critical) {
        return SEVERITY_CRITICAL;
    } else if (total_score >= config->threshold_high) {
        return SEVERITY_HIGH;
    } else if (total_score >= config->threshold_medium) {
        return SEVERITY_MEDIUM;
    } else if (total_score >= config->threshold_low) {
        return SEVERITY_LOW;
    } else {
        return SEVERITY_NONE;
    }
}

/* Recommend an appropriate response action based on severity */
ResponseAction scoring_determine_action(ThreatSeverity severity, const Configuration* config) {
    // If auto-respond is disabled, we only monitor or alert
    if (config && !config->auto_respond) {
        switch (severity) {
            case SEVERITY_CRITICAL:
            case SEVERITY_HIGH:
                return ACTION_ALERT;
                
            case SEVERITY_MEDIUM:
                return ACTION_MONITOR;
                
            case SEVERITY_LOW:
            case SEVERITY_NONE:
            default:
                return ACTION_NONE;
        }
    }
    
    // Auto-respond is enabled, take more active measures
    switch (severity) {
        case SEVERITY_CRITICAL:
            return ACTION_TERMINATE;
            
        case SEVERITY_HIGH:
            return ACTION_SUSPEND;
            
        case SEVERITY_MEDIUM:
            return ACTION_ISOLATE;
            
        case SEVERITY_LOW:
            return ACTION_ALERT;
            
        case SEVERITY_NONE:
        default:
            return ACTION_NONE;
    }
}

/* Check for specific ransomware patterns in file operations */
float scoring_analyze_file_patterns(const DetectionPatterns* patterns) {
    if (!patterns) {
        return 0.0f;
    }
    
    float pattern_score = 0.0f;
    
    // Consecutive file operations (typical in ransomware)
    if (patterns->consecutive_file_ops > 50) {
        pattern_score += 50.0f;
    } else if (patterns->consecutive_file_ops > 20) {
        pattern_score += 25.0f;
    } else if (patterns->consecutive_file_ops > 10) {
        pattern_score += 10.0f;
    }
    
    // File extension changes
    if (patterns->file_extension_changes > 10) {
        pattern_score += 50.0f;
    } else if (patterns->file_extension_changes > 5) {
        pattern_score += 30.0f;
    } else if (patterns->file_extension_changes > 2) {
        pattern_score += 15.0f;
    }
    
    // Entropy increases (encryption)
    if (patterns->entropy_increases > 5) {
        pattern_score += 50.0f;
    } else if (patterns->entropy_increases > 2) {
        pattern_score += 30.0f;
    } else if (patterns->entropy_increases > 0) {
        pattern_score += 10.0f;
    }
    
    // Sensitive files accessed
    if (patterns->sensitive_files_accessed > 20) {
        pattern_score += 40.0f;
    } else if (patterns->sensitive_files_accessed > 10) {
        pattern_score += 25.0f;
    } else if (patterns->sensitive_files_accessed > 5) {
        pattern_score += 10.0f;
    }
    
    // Specific detection flags
    if (patterns->detected_encryption_pattern) {
        pattern_score += 60.0f;
    }
    
    if (patterns->detected_shadow_copy_deletion) {
        pattern_score += 80.0f;
    }
    
    if (patterns->detected_ransom_note_creation) {
        pattern_score += 70.0f;
    }
    
    // Normalize to 0-100 range
    if (pattern_score > 100.0f) {
        pattern_score = 100.0f;
    }
    
    return pattern_score;
}

/* Calculate entropy score based on before/after measurements */
float scoring_calculate_entropy_impact(uint8_t before, uint8_t after) {
    // Calculate the entropy difference (after - before)
    float diff = (float)after - (float)before;
    
    // No impact or decrease in entropy
    if (diff <= 0) {
        return 0.0f;
    }
    
    // Slight increase (not significant)
    if (diff < 1.0f) {
        return 5.0f;
    }
    
    // Moderate increase (somewhat suspicious)
    if (diff < 2.0f) {
        return 15.0f;
    }
    
    // Large increase (highly suspicious, likely encryption)
    if (diff < 3.0f) {
        return 30.0f;
    }
    
    // Very large increase (almost certainly encryption)
    return 50.0f;
}