#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <time.h>

#include "../include/antiransom.h"  // This now contains GlobalArgs
#include "../include/events.h"
#include "../common/logger.h"
#include "../common/config.h"
#include "../common/scoring.h"

// Forward declarations for monitoring components
extern int syscall_monitor_init(EventHandler handler, void* user_data);
extern void syscall_monitor_cleanup(void);
extern int syscall_monitor_start(void);
extern void syscall_monitor_stop(void);

extern int process_monitor_init(EventHandler handler, void* user_data);
extern void process_monitor_cleanup(void);
extern void process_monitor_poll(void);
extern int process_monitor_add_process(pid_t pid);
extern ProcessInfo* process_monitor_get_process_info(pid_t pid);
extern void process_monitor_process_suspicious(pid_t pid, const char* details);
extern void process_monitor_memory_suspicious(pid_t pid, const char* details);
extern void process_monitor_syscall_suspicious(pid_t pid, const char* details);
extern void process_monitor_analyze_relationships(void);
extern void process_monitor_apply_risk_decay(void);

extern int memory_monitor_init(EventHandler handler, void* user_data);
extern void memory_monitor_cleanup(void);
extern void memory_monitor_poll(void);
extern int memory_monitor_add_process(pid_t pid);

extern int user_filter_init(void);
extern void user_filter_cleanup(void);

extern int detection_init(EventHandler handler, void* user_data, const char* config_path);
extern void detection_cleanup(void);
extern int detection_add_process(pid_t pid);
extern void detection_remove_process(pid_t pid);
extern int detection_handle_event(const Event* event);
extern void detection_poll(void);

// Default config file path
#define DEFAULT_CONFIG_PATH "/etc/antiransom.conf"

// Program version
#define VERSION "1.0.0"

// Global state
static int running = 0;
static int daemon_mode = 0;
static int verbose_mode = 0;
static Configuration config;
static pthread_mutex_t poll_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t poll_thread;

// Function prototypes
static void __attribute__((unused)) parse_arguments(int argc, char* argv[]);
static void print_usage(const char* program_name);
static void signal_handler(int signal);
static void __attribute__((unused)) setup_signal_handlers(void);
static void __attribute__((unused)) initialize_components(void);
static void __attribute__((unused)) cleanup_components(void);
static void* __attribute__((unused)) polling_thread_func(void* arg);
static void event_callback(const Event* event, void* user_data);
static int __attribute__((unused)) daemonize(void);
static void __attribute__((unused)) scan_running_processes(void);
static void __attribute__((unused)) initialize_logging(void);
void configure_risk_scoring(int threshold);

// Remove redundant argument parsing

int linux_main(int argc, char* argv[], const GlobalArgs* global_args) {
    // Suppress unused parameter and function warnings
    (void)argc;
    (void)argv;
    
    // Cast unused functions to void to suppress warnings
    (void)parse_arguments;
    (void)setup_signal_handlers;
    (void)initialize_components;
    (void)cleanup_components;
    (void)polling_thread_func;
    (void)daemonize;
    (void)scan_running_processes;
    (void)initialize_logging;
    (void)poll_thread;  // For the unused variable
    
    // Initialize configuration
    Configuration config;
    config_init(&config);
    
    // Apply global arguments instead of re-parsing command line
    if (global_args) {
        config.mode = global_args->daemon_mode ? MODE_DAEMON : MODE_STANDALONE;
        config.verbose_logging = global_args->verbose_mode;
        
        if (global_args->watch_directory[0] != '\0') {
            strncpy(config.watch_directory, global_args->watch_directory, 
                    sizeof(config.watch_directory) - 1);
            config.watch_directory[sizeof(config.watch_directory) - 1] = '\0';
        }
        
        if (global_args->config_path[0] != '\0') {
            // Load specified config file
            config_load(&config, global_args->config_path);
        } else {
            // Load default config
            config_load(&config, DEFAULT_CONFIG_PATH);
        }
    }
    
    // Continue with initialization
    LOG_INFO("Initializing Linux monitoring with %s mode", 
            config.mode == MODE_DAEMON ? "daemon" : "standalone");
    
    // Initialize logging based on configuration
    initialize_logging();
    
    // Set up signal handlers for clean shutdown
    setup_signal_handlers();
    
    // Initialize all monitoring components
    initialize_components();
    
    // If we're running in daemon mode
    if (config.mode == MODE_DAEMON) {
        if (daemonize() != 0) {
            LOG_ERROR("Failed to daemonize process: %s", strerror(errno));
            cleanup_components();
            return EXIT_FAILURE;
        }
    }
    
    // Scan for existing processes to monitor
    scan_running_processes();
    
    // Set running flag
    running = 1;
    
    // Create polling thread
    if (pthread_create(&poll_thread, NULL, polling_thread_func, NULL) != 0) {
        LOG_ERROR("Failed to create polling thread: %s", strerror(errno));
        cleanup_components();
        return EXIT_FAILURE;
    }
    
    // Main loop (simplified for this example)
    while (running) {
        sleep(1);
    }
    
    // Clean up when exiting
    pthread_join(poll_thread, NULL);
    cleanup_components();
    
    LOG_INFO("Linux monitoring terminated normally%s", "");
    return 0;
}

// Parse command line arguments
static void parse_arguments(int argc, char* argv[]) {
    int opt;
    int option_index = 0;
    const char* config_path = DEFAULT_CONFIG_PATH;
    
    static struct option long_options[] = {
        {"help",      no_argument,       0, 'h'},
        {"version",   no_argument,       0, 'v'},
        {"daemon",    no_argument,       0, 'd'},
        {"verbose",   no_argument,       0, 'V'},
        {"config",    required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "hvdVc:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
                
            case 'v':
                // Version is handled by the global main
                exit(EXIT_SUCCESS);
                break;
                
            case 'd':
                daemon_mode = 1;
                break;
                
            case 'V':
                verbose_mode = 1;
                break;
                
            case 'c':
                config_path = optarg;
                break;
                
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    // Load configuration
    memset(&config, 0, sizeof(config));
    
    // Set default config values
    config.threshold_low = 50;
    config.threshold_medium = 70;
    config.threshold_high = 90;
    
    // Override with values from config file if exists
    config_load(&config, config_path);
}

// Print Linux-specific usage information
static void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Linux-specific options:\n");
    printf("  -h, --help               Display this help message\n");
    printf("  -d, --daemon             Run as a daemon in the background\n");
    printf("  -V, --verbose            Enable verbose logging\n");
    printf("  -c, --config=FILE        Use specified config file (default: /etc/antiransom.conf)\n");
}

// Signal handler for clean shutdown
static void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        LOG_INFO("Received signal %d, shutting down", signal);
        running = 0;
    }
}

// Set up signal handlers
static void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    // Ignore SIGPIPE to avoid termination when writing to closed sockets/pipes
    signal(SIGPIPE, SIG_IGN);
}

// Initialize all components
static void initialize_components(void) {
    // Initialize detection system
    if (detection_init(event_callback, &config, NULL) != 0) {
        LOG_ERROR("Failed to initialize detection system%s", "");
        exit(EXIT_FAILURE);
    }
    
    // Initialize user filter
    if (user_filter_init() != 0) {
        LOG_ERROR("Failed to initialize user filter%s", "");
        detection_cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Initialize process monitor
    if (process_monitor_init(event_callback, &config) != 0) {
        LOG_ERROR("Failed to initialize process monitor%s", "");
        user_filter_cleanup();
        detection_cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Initialize memory monitor
    if (memory_monitor_init(event_callback, &config) != 0) {
        LOG_ERROR("Failed to initialize memory monitor%s", "");
        process_monitor_cleanup();
        user_filter_cleanup();
        detection_cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Initialize syscall monitor (must be last)
    if (syscall_monitor_init(event_callback, &config) != 0) {
        LOG_ERROR("Failed to initialize syscall monitor%s", "");
        memory_monitor_cleanup();
        process_monitor_cleanup();
        user_filter_cleanup();
        detection_cleanup();
        exit(EXIT_FAILURE);
    }
    
    LOG_INFO("All components initialized successfully%s", "");
}

// Clean up all components
static void cleanup_components(void) {
    // Clean up in reverse order of initialization
    syscall_monitor_stop();
    syscall_monitor_cleanup();
    memory_monitor_cleanup();
    process_monitor_cleanup();
    user_filter_cleanup();
    detection_cleanup();
    
    LOG_INFO("All components cleaned up%s", "");
}

// Polling thread function
static void* polling_thread_func(void* arg) {
    (void)arg; // Unused
    
    struct timespec sleep_time;
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = 100 * 1000 * 1000; // 100ms
    
    // Track when we last performed deep analysis
    time_t last_deep_analysis = 0;
    
    while (running) {
        pthread_mutex_lock(&poll_mutex);
        
        // Poll each monitoring component
        process_monitor_poll();
        memory_monitor_poll();
        detection_poll();
        
        // ENHANCEMENT: Periodically perform deep analysis and risk assessment
        time_t now = time(NULL);
        if (now - last_deep_analysis > 60) { // Every minute
            // Perform deep analysis functions in process_monitor.c
            process_monitor_analyze_relationships();
            process_monitor_apply_risk_decay();
            
            last_deep_analysis = now;
        }
        
        pthread_mutex_unlock(&poll_mutex);
        
        // Sleep to avoid consuming too much CPU
        nanosleep(&sleep_time, NULL);
    }
    
    return NULL;
}

// Event callback function
static void event_callback(const Event* event, void* user_data) {
    (void)user_data; // May use for extra configuration
    
    // Pass event to detection system
    detection_handle_event(event);
    
    // For process events that indicate a new process, add to monitoring
    if (event->type == EVENT_PROCESS_CREATE) {
        pid_t child_pid = event->data.process_event.child_pid;
        
        // Add to all monitoring components
        detection_add_process(child_pid);
        memory_monitor_add_process(child_pid);
        process_monitor_add_process(child_pid);
        
        // ENHANCEMENT: Setup cross-monitor communication
        // If parent is suspicious, notify process monitor about the child
        pid_t parent_pid = event->process_id;
        ProcessInfo* parent = process_monitor_get_process_info(parent_pid);
        if (parent && parent->suspicion_score > 40.0f) {
            char details[256];
            snprintf(details, sizeof(details), 
                     "Child of suspicious parent (score: %.1f)", 
                     parent->suspicion_score);
            process_monitor_process_suspicious(child_pid, details);
        }
    }
    
    // For process exit events, remove from monitoring
    if (event->type == EVENT_PROCESS_TERMINATE) {
        detection_remove_process(event->process_id);
        process_monitor_remove_process(event->process_id);
    }
    
    // In verbose mode, log all events
    if (verbose_mode) {
        char timestamp[32];
        time_t now = event->timestamp ? event->timestamp : time(NULL);
        struct tm* tm_info = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        
        switch (event->type) {
            case EVENT_FILE_ACCESS:
                LOG_DEBUG("[%s] Process %d accessed file: %s", 
                         timestamp, event->process_id, event->data.file_event.path);
                break;
                
            case EVENT_FILE_MODIFY:
                LOG_DEBUG("[%s] Process %d wrote to file: %s", 
                         timestamp, event->process_id, event->data.file_event.path);
                break;
                
            case EVENT_FILE_RENAME:
                LOG_DEBUG("[%s] Process %d renamed file: %s -> %s", 
                         timestamp, event->process_id, 
                         event->data.file_event.path, "N/A");
                break;
                
            case EVENT_PROCESS_CREATE:
                LOG_DEBUG("[%s] Process %d created child process: %d (%s)", 
                         timestamp, event->process_id, 
                         event->data.process_event.child_pid, 
                         event->data.process_event.image_path ? 
                         event->data.process_event.image_path : "unknown");
                break;
                
            case EVENT_PROCESS_TERMINATE:
                LOG_DEBUG("[%s] Process %d exited", timestamp, event->process_id);
                break;
                
            case EVENT_MEMORY_ALLOC:
            case EVENT_MEMORY_FREE:
            case EVENT_MEMORY_PROTECT:
                LOG_DEBUG("[%s] Memory event in process %d: %s", 
                         timestamp, event->process_id, "memory operation");
                break;
                
            case EVENT_PROCESS_SUSPICIOUS:
                LOG_WARNING("[%s] Process %d suspicious behavior: %s", 
                         timestamp, event->process_id, event->data.process_event.details);
                break;
                
            case EVENT_PROCESS_BEHAVIOR:
                LOG_DEBUG("[%s] Process %d behavior: %s", 
                         timestamp, event->process_id, event->data.process_event.details);
                break;
                
            case EVENT_PROCESS_PRIVESC:
                LOG_WARNING("[%s] Process %d privilege escalation: %s", 
                         timestamp, event->process_id, event->data.process_event.details);
                break;
                
            // ENHANCEMENT: Add handlers for new event types
            case EVENT_PROCESS_CORRELATION:
                LOG_WARNING("[%s] Process %d correlation detected: %s", 
                         timestamp, event->process_id, event->data.process_event.details);
                break;
                
            case EVENT_PROCESS_LINEAGE:
                LOG_INFO("[%s] Process %d lineage event: %s", 
                         timestamp, event->process_id, event->data.process_event.details);
                break;
                
            case EVENT_PROCESS_OBFUSCATION:
                LOG_WARNING("[%s] Process %d command obfuscation: %s", 
                         timestamp, event->process_id, event->data.process_event.details);
                break;
                
            case EVENT_MEMORY_SUSPICIOUS:
                LOG_WARNING("[%s] Process %d suspicious memory activity: %s", 
                         timestamp, event->process_id, event->data.process_event.details);
                break;
                
            case EVENT_SYSCALL_SUSPICIOUS:
                LOG_WARNING("[%s] Process %d suspicious syscall: %s", 
                         timestamp, event->process_id, event->data.process_event.details);
                break;
                
            case EVENT_DETECTION_ALERT:
                LOG_INFO("[%s] DETECTION ALERT: %s (score: %.1f)", 
                        timestamp, event->data.detection_event.message, 
                        event->data.detection_event.score);
                break;
                
            default:
                LOG_DEBUG("[%s] Unknown event type %d from process %d",
                         timestamp, event->type, event->process_id);
        }
    }
}

// Daemonize the process
static int daemonize(void) {
    pid_t pid, sid;
    
    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        return -1;
    }
    
    // If we got a good PID, then we can exit the parent process
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    // Change the file mode mask
    umask(0);
    
    // Create a new SID for the child process
    sid = setsid();
    if (sid < 0) {
        return -1;
    }
    
    // Change the current working directory
    if (chdir("/") < 0) {
        return -1;
    }
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Redirect standard file descriptors to /dev/null
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0) {
        return -1;
    }
    
    dup2(null_fd, STDIN_FILENO);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
    
    if (null_fd > STDERR_FILENO) {
        close(null_fd);
    }
    
    return 0;
}

// Scan for existing processes to monitor
static void scan_running_processes(void) {
    LOG_INFO("Scanning for existing processes to monitor%s", "");
    
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        LOG_ERROR("Failed to open /proc directory: %s", strerror(errno));
        return;
    }
    
    struct dirent* entry;
    int processes_added = 0;
    int system_processes = 0;
    int user_processes = 0;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        // Only look at directories with numeric names (PIDs)
        if (entry->d_type != DT_DIR) {
            continue;
        }
        
        char* endptr;
        pid_t pid = (pid_t)strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0') {
            continue;  // Not a PID directory
        }
        
        // Skip current process and kernel processes
        if (pid <= 1 || pid == getpid()) {
            continue;
        }
        
        // Attempt to read process information
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        
        // Skip if we can't access this process
        if (access(comm_path, R_OK) != 0) {
            continue;
        }
        
        // Read executable path to determine process type
        char exe_path[PATH_MAX];
        char proc_exe[64];
        snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", pid);
        ssize_t len = readlink(proc_exe, exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
            
            // Classify as system or user process
            if (strncmp(exe_path, "/usr/bin/", 9) == 0 || 
                strncmp(exe_path, "/bin/", 5) == 0 || 
                strncmp(exe_path, "/sbin/", 6) == 0 || 
                strncmp(exe_path, "/usr/sbin/", 10) == 0) {
                system_processes++;
            } else {
                user_processes++;
            }
        }
        
        // Add process to all monitoring components
        if (process_monitor_add_process(pid) == 0) {
            if (detection_add_process(pid) == 0) {
                if (memory_monitor_add_process(pid) == 0) {
                    processes_added++;
                    
                    if (verbose_mode && processes_added % 10 == 0) {
                        LOG_DEBUG("Added %d processes to monitoring...", processes_added);
                    }
                }
            }
        }
    }
    
    closedir(proc_dir);
    LOG_INFO("Added %d processes to monitoring (%d system, %d user)", 
             processes_added, system_processes, user_processes);
}

// Initialize logging based on configuration
static void initialize_logging(void) {
    LogLevel level = verbose_mode ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO;
    
    if (daemon_mode) {
        // In daemon mode, log to syslog
        logger_init(LOG_TO_SYSLOG, level);
    } else {
        // In console mode, log to stdout
        logger_init(LOG_TO_STDOUT, level);
    }
}

// Add to main.c or similar configuration handling code:

void configure_risk_scoring(int threshold) {
    // Set risk threshold if provided in config
    if (threshold > 0) {
        set_risk_threshold((float)threshold);
        LOG_INFO("Risk threshold configured to %d", threshold);
    }
}

// In main.c, initialize the logging system

int main(int argc, char* argv[]) {
    // Parse command line options
    int verbose = 0;
    int json_logs = 0;
    char json_file[256] = {0};
    
    // ... parse command line options ...
    
    // Initialize logging
    LogDestination log_dest = json_logs ? LOG_TO_JSON : LOG_TO_STDOUT;
    logger_init(log_dest, verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO);
    
    if (verbose) {
        logger_set_verbose(1);
    }
    
    if (json_logs && json_file[0] != '\0') {
        logger_set_json_file(json_file);
    }
    
    // Set minimum risk score (default is 10.0)
    logger_set_min_risk_score(10.0f);
    
    // ... initialize other components ...
    
    // Register cleanup
    atexit(logger_cleanup);
    
    // ... main program ...
    
    return 0;
}