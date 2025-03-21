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

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

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