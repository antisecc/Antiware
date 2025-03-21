# Anti-Ransomware Framework Design

## Core Architecture

The anti-ransomware tool is designed with a platform-independent core and platform-specific implementations. This design allows for:

1. Common detection logic and scoring across operating systems
2. Platform-specific monitoring mechanisms
3. Unified response capabilities

### Program Structure

The AntiRansom tool uses a layered architecture with a clear separation between platform-agnostic and platform-specific code:

1. **Platform-Agnostic Entry Point (main.c)**
   - Detects the host operating system at runtime
   - Provides common command-line argument handling (help, version)
   - Initializes shared components (basic logging, configuration)
   - Dispatches execution to the appropriate platform-specific implementation
   - Ensures graceful failure on unsupported platforms
   - Maintains a clean abstraction layer between platforms

2. **Platform-Specific Implementations**
   - **Linux Implementation (linux/main.c)**
     - Exports `linux_main()` function called by the global entry point
     - Handles Linux-specific initialization and monitoring
     - Uses ptrace for syscall monitoring and /proc for process inspection
     - Manages Linux-specific resources and signal handling
   
   - **Windows Implementation (windows/main.c - future)**
     - Will export `windows_main()` function called by the global entry point
     - Will handle Windows-specific API hooking and event monitoring
     - Will use Windows API for process and memory inspection
     - Will manage Windows-specific resources and event handling

3. **Common Components**
   - Shared scoring algorithms
   - Logging and configuration systems
   - Event handling infrastructure
   - Detection logic common to all platforms

### Build System

The Makefile implements a flexible build system that supports multi-platform development:

1. **Platform Detection and Selection**
   - Automatically detects the host platform using `uname`
   - Allows explicit platform selection via targets (`make linux` or `make windows`)
   - Sets appropriate compiler flags and libraries for each platform
   
2. **Source Organization**
   - Compiles the global entry point (main.c) for all platforms
   - Includes platform-specific source files based on target platform
   - Maintains separate object directories for clean builds
   
3. **Compilation Strategy**
   - Uses conditional compilation to handle platform-specific code
   - Separates platform-specific libraries and flags
   - Supports both debug and release build configurations

4. **Future Windows Integration**
   - Maintains placeholders for Windows-specific source files
   - Includes conditional compilation for Windows libraries
   - Defines appropriate output extensions (.exe for Windows)

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

### Future Windows Implementation

- API hooking for system call interception
- File system minifilter for real-time file monitoring
- Process monitoring via Windows Management Instrumentation (WMI)
- Memory monitoring through ReadProcessMemory and VirtualQueryEx
- ETW (Event Tracing for Windows) for additional event sources
- User activity filtering via Windows API pattern recognition

## Future Windows Integration Considerations

The Windows implementation will need to address several platform-specific challenges:

1. **API Hooking Strategy**
   - Choosing between user-mode hooks (IAT/EAT) vs. kernel-mode hooks
   - Managing hook persistence across process creation
   - Handling privilege escalation attempts via API monitoring

2. **File System Monitoring**
   - Implementing efficient file system change notifications
   - Detecting ransomware patterns in NTFS operations
   - Monitoring shadow copy deletion attempts

3. **Process Privileges**
   - Managing administrator vs. standard user execution contexts
   - Handling UAC elevation events
   - Monitoring for token manipulation and privilege escalation

4. **Windows-Specific Behavior Patterns**
   - Registry modification patterns
   - Windows service manipulation
   - Task scheduler abuse
   - Windows security feature bypasses

5. **Integration with Windows Security Features**
   - Controlled Folder Access coordination
   - Windows Defender integration
   - SmartScreen and other reputation systems

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

## Future Improvements

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