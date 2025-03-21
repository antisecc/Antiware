# Anti-Ransomware Framework Design

## Core Architecture

The anti-ransomware tool is designed with a platform-independent core and platform-specific implementations. This design allows for:

1. Common detection logic and scoring across operating systems
2. Platform-specific monitoring mechanisms
3. Unified response capabilities

### Operational Modes

- **Standalone Mode**: Direct execution with real-time feedback and interactive controls
- **Daemon Mode**: Background monitoring service for continuous threat protection

## Detection Components

The detection system combines three major components:

1. **Syscall/API Monitoring**
   - File operation patterns (read-write-delete sequences)
   - Cryptographic API usage
   - Backup/shadow copy deletion attempts
   - Registry modifications (Windows)

2. **Memory Analysis**
   - Detection of encryption code patterns in memory
   - Monitoring of dynamic code injection
   - Memory protection changes
   - Detection of RWX memory regions
   - Memory checksum verification
   - Memory usage spike detection
   - Suspicious allocation pattern recognition

3. **Process Behavior**
   - Process creation and relationship monitoring
   - Command-line argument analysis
   - Network connection monitoring for C2 communication
   - Execution from suspicious locations
   - Suspicious process naming patterns
   - Privilege escalation detection
   - Rapid file access rate monitoring
   - Rapid process spawning detection
   - Obfuscated command line analysis

## Scoring System

The scoring system employs a weighted approach to evaluate potential threats:

- Base scores for individual suspicious events
- Pattern multipliers for sequences of related activities
- Time-based scoring factors (rapid operations = higher scores)
- Severity thresholds for different response levels

### Key Scoring Factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| File Operations | 0.5 | Mass file access, modification, renames |
| Entropy Changes | 0.7 | Increases in file entropy after writes |
| Crypto API Usage | 0.6 | Use of encryption/decryption functions |
| Memory Changes | 0.4 | Suspicious memory allocation, protection |
| Network Activity | 0.3 | Connections to suspicious destinations |
| Backup Access | 0.8 | Attempts to delete backups/shadow copies |
| Registry Changes | 0.4 | Windows registry modification patterns |
| Process Location | 0.5 | Execution from temporary or suspicious locations |
| Process Behavior | 0.6 | Rapid file access, spawning patterns |

### False Positive Reduction

The user_filter.c module implements several strategies for minimizing false positives:

1. **Process Whitelisting**
   - System utilities and known good applications are whitelisted
   - Whitelisted processes can be excluded from monitoring completely
   - Child processes of trusted applications can inherit whitelist status

2. **Behavior Pattern Recognition**
   - Common legitimate patterns such as backups, system updates, and software compilation are recognized
   - Similar patterns can be marked as whitelisted when confirmed as benign
   - Frequency tracking helps identify recurring legitimate user behaviors

3. **Process Trust Scoring**
   - Process origin (system paths vs user paths) affects trust level
   - Long-running processes gain additional trust over time
   - Process ownership (system vs user) is factored into trust calculations

4. **Contextual Analysis**
   - File operations in expected locations receive lower suspicion scores
   - Process signatures for common applications define expected behaviors
   - Command-line patterns help identify known legitimate software

### Response Thresholds:

- **Low (30+)**: Begin enhanced monitoring, log suspicious activity
- **Medium (60+)**: Alert user to suspicious behavior, prepare for intervention
- **High (80+)**: Isolate process network access, prompt for user action
- **Critical (95+)**: Automatically suspend or terminate process

## Platform-Specific Implementation Notes

### Linux Implementation

- Using ptrace for syscall interception
- Filesystem monitoring with inotify
- Process monitoring via /proc filesystem
- Memory monitoring via /proc/[pid]/maps
- User activity filtering via /proc analysis and behavior patterns

## Linux Monitoring Implementation

### User Filter

The Linux user filter system provides intelligent false positive reduction through:

1. **Process Whitelist Management**
   - Maintains a database of trusted processes by executable path and name
   - Assigns trust levels (0-100) to different applications
   - Supports pattern matching for executable paths
   - Controls whether child processes inherit whitelist status

2. **Process Signature Recognition**
   - Captures known-good behavior patterns for specific applications
   - Uses regex pattern matching for command-line verification
   - Associates allowed behavior flags with specific applications
   - Provides detailed descriptions for logging and reporting

3. **Behavior Pattern Classification**
   - Groups common system behaviors (backups, updates, compilation)
   - Tracks frequency of observed patterns to improve accuracy
   - Allows runtime whitelisting of recurring patterns
   - Maintains history to improve detection accuracy over time

4. **Score Adjustment Algorithm**
   - Applies contextual trust modifiers to suspicion scores
   - Factors in process origin, lifespan, and ownership
   - Adjusts based on pattern matching and behavior recognition
   - Preserves minimum score for non-excluded processes

### Syscall Monitoring

The Linux implementation uses `ptrace` to hook into critical system calls that might indicate ransomware activity:

| Syscall | Purpose | Monitoring Goal |
|---------|---------|----------------|
| execve | Process execution | Track new process creation, command parameters |
| open/openat | File access | Monitor files being accessed, particularly sensitive documents |
| read | File reading | Track which files are being read before modification |
| write/pwrite64 | File writing | Detect content changes and potential encryption |
| rename/renameat | File renaming | Detect extension changes (.doc → .encrypted) |
| chmod/fchmod | Permission changes | Detect attempts to lock files by changing permissions |
| unlink/unlinkat | File deletion | Identify deletion after encryption |
| mkdir/mkdirat | Directory creation | Monitor for ransom note creation directories |
| rmdir | Directory removal | Detect cleanup activities |

### Detection Patterns

The detection engine analyzes sequences of syscalls to identify ransomware behavior:

1. **Read-Encrypt-Write Pattern**: Process reads file, processes content, writes back encrypted data
2. **Mass Operation Pattern**: Rapid sequence of similar operations across many files
3. **Extension Modification Pattern**: Systematic changing of file extensions
4. **Entropy Increase Pattern**: File content becomes more random after write operations

### Memory Monitoring

Memory monitoring focuses on:

1. Tracking memory regions through `/proc/<pid>/maps`
2. Detecting new RWX (read-write-execute) memory regions
3. Identifying memory regions with encryption code patterns
4. Monitoring for code injection techniques
5. Memory Change Detection: Tracking modifications to executable regions that might indicate self-modifying code
6. Memory Checksum Verification: Sampling memory regions to detect unauthorized modifications
7. Memory Usage Spikes: Detecting sudden large increases in memory usage that might indicate buffer preparation for encryption
8. Suspicious Allocation Patterns: Identifying both numerous small allocations and large allocations that don't match normal application behavior

### Memory Monitoring Events

The memory monitor generates several types of events with varying impact scores:

| Event Type | Description | Base Score | Score Multipliers |
|------------|-------------|------------|-------------------|
| RWX Region | New memory region with read-write-execute permissions | 10.0 | ×1.5 for anonymous mappings |
| Modified Code | Changes to executable memory regions | 15.0 | ×1.7 for anonymous mappings |
| Memory Spike | Sudden increase in process memory usage | 2.0-10.0 | Based on size and speed of increase |
| Allocation Pattern | Suspicious memory allocation patterns | 5.0-8.0 | Based on pattern type and quantity |

### Process Monitoring

Process monitoring checks for suspicious patterns in:

1. **Process Location**: Detection of executables running from unusual locations such as /tmp, /dev/shm, or non-standard directories in user's home
2. **Process Names**: Identification of suspicious or obfuscated process names, including randomized names or those containing keywords related to ransomware
3. **Command Lines**: Analysis of command-line arguments for suspicious parameters, encoded content, or known malicious patterns
4. **Privilege Escalation**: Detection of processes that change their effective user ID or gain elevated privileges
5. **File Access Rates**: Monitoring the rate at which processes access files, flagging abnormally high rates that could indicate mass encryption
6. **Process Spawning**: Tracking parent-child relationships and identifying abnormal patterns of process creation

### Process Monitoring Events

The process monitor generates these event types:

| Event Type | Description | Base Score | Score Multipliers |
|------------|-------------|------------|-------------------|
| Process Suspicious | Process with multiple suspicious indicators | 20.0 | Based on number of suspicious factors |
| Process Behavior | Abnormal behavioral pattern detected | 10.0-15.0 | Based on severity of behavior |
| Process PrivEsc | Privilege escalation detected | 25.0 | Higher for critical system processes |

### Process Hierarchy Analysis

Process monitoring tracks:

1. Parent-child relationships between processes
2. Command-line arguments of suspicious processes
3. Short-lived processes performing file operations
4. Unexpected process creation chains

### Linux-Specific Scoring Adjustments

| Behavior | Base Score | Multiplier Conditions |
|----------|------------|----------------------|
| Sequential file operations | 5 | ×2 if >10 files/second, ×3 if >50 files/second |
| Extension changes | 15 | ×2 if known ransomware extensions (.locked, .encrypted) |
| RWX memory allocations | 10 | ×2 if in non-developer processes |
| Process spawning shell | 8 | ×2 if shell spawns further processes accessing files |
| High file entropy after write | 20 | ×1.5 if multiple files show entropy increases |
| Modified executable memory | 15 | ×2 if process is accessing sensitive files |
| Process from tmp directory | 15 | ×1.5 if also showing suspicious behavior |
| Process with suspicious name | 10 | ×2 if multiple suspicious indicators present |
| Rapid file access | 15 | Scaled with access rate (higher = more suspicious) |
| Rapid process spawning | 10 | Scaled with spawn rate |

## Component Dependencies

### User Filter Dependencies
- **Common Headers**: 
  - antiransom.h: Core definitions and structures
  - events.h: Event type definitions
  - logger.h: Logging functions
  - config.h: Configuration settings
  - scoring.h: Scoring system functions

- **Linux Components**:
  - detection.c: Uses user_filter to adjust suspicion scores
  - syscall_monitor.c: Passes events through user_filter before processing
  - memory_monitor.c: Coordinates with user_filter for behavior pattern validation
  - process_monitor.c: Consults user_filter for process legitimacy evaluation

## Future Optimizations

### User Filter Optimizations
- Implement caching of process verification results
- Add machine learning capabilities to improve pattern recognition
- Provide user feedback mechanism to report false positives
- Develop automatic signature generation for common applications
- Create centralized reputation database for processes and behaviors

### Build System Enhancements
- Support for CMake as an alternative build system
- Integration with package management tools (deb, rpm)
- Automated dependency resolution
- Cross-compilation support for different architectures
- Unit test integration and coverage reporting

### Main Program Enhancements
- GUI interface option for desktop environments
- Remote management API for enterprise deployments
- Plugin architecture for custom detection modules
- Integration with system notification mechanisms
- Automated update capabilities

## Future Scope

- Machine learning component for adaptive detection
- Cloud-based threat intelligence integration
- Ransomware recovery capabilities
- Remote management console for enterprise deployments
- Encryption behavior simulations for testing