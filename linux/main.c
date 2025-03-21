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

#include "../include/antiransom.h"
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
static void parse_arguments(int argc, char* argv[]);
static void print_usage(const char* program_name);
static void signal_handler(int signal);
static void setup_signal_handlers(void);
static void initialize_components(void);
static void cleanup_components(void);
static void* polling_thread_func(void* arg);
static void event_callback(const Event* event, void* user_data);
static int daemonize(void);
static void scan_running_processes(void);
static void initialize_logging(void);

// Linux-specific entry point (called from global main.c)
int linux_main(int argc, char* argv[]) {
    // Parse command line arguments
    parse_arguments(argc, argv);
    
    // Initialize logging
    initialize_logging();
    
    LOG_INFO("AntiRansom Linux implementation starting up");
    
    // Handle daemon mode if requested
    if (daemon_mode) {
        LOG_INFO("Starting in daemon mode");
        if (daemonize() != 0) {
            LOG_ERROR("Failed to start daemon mode");
            return EXIT_FAILURE;
        }
    }
    
    // Set up signal handlers for clean shutdown
    setup_signal_handlers();
    
    // Initialize all components
    initialize_components();
    
    // Scan for already running processes
    scan_running_processes();
    
    // Start syscall monitoring
    if (syscall_monitor_start() != 0) {
        LOG_ERROR("Failed to start syscall monitoring");
        cleanup_components();
        return EXIT_FAILURE;
    }
    
    LOG_INFO("AntiRansom is now monitoring the system");
    
    // Start polling thread
    running = 1;
    if (pthread_create(&poll_thread, NULL, polling_thread_func, NULL) != 0) {
        LOG_ERROR("Failed to create polling thread: %s", strerror(errno));
        running = 0;
        cleanup_components();
        return EXIT_FAILURE;
    }
    
    // Main thread now waits for signals
    if (!daemon_mode) {
        printf("AntiRansom is running. Press Ctrl+C to stop.\n");
    }
    
    // Wait for polling thread to complete (after receiving signal)
    pthread_join(poll_thread, NULL);
    
    // Clean up and exit
    LOG_INFO("AntiRansom shutting down");
    cleanup_components();
    return EXIT_SUCCESS;
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
        LOG_ERROR("Failed to initialize detection system");
        exit(EXIT_FAILURE);
    }
    
    // Initialize user filter
    if (user_filter_init() != 0) {
        LOG_ERROR("Failed to initialize user filter");
        detection_cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Initialize process monitor
    if (process_monitor_init(event_callback, &config) != 0) {
        LOG_ERROR("Failed to initialize process monitor");
        user_filter_cleanup();
        detection_cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Initialize memory monitor
    if (memory_monitor_init(event_callback, &config) != 0) {
        LOG_ERROR("Failed to initialize memory monitor");
        process_monitor_cleanup();
        user_filter_cleanup();
        detection_cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Initialize syscall monitor (must be last)
    if (syscall_monitor_init(event_callback, &config) != 0) {
        LOG_ERROR("Failed to initialize syscall monitor");
        memory_monitor_cleanup();
        process_monitor_cleanup();
        user_filter_cleanup();
        detection_cleanup();
        exit(EXIT_FAILURE);
    }
    
    LOG_INFO("All components initialized successfully");
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
    
    LOG_INFO("All components cleaned up");
}

// Polling thread function
static void* polling_thread_func(void* arg) {
    (void)arg; // Unused
    
    struct timespec sleep_time;
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = 100 * 1000 * 1000; // 100ms
    
    while (running) {
        pthread_mutex_lock(&poll_mutex);
        
        // Poll each monitoring component
        process_monitor_poll();
        memory_monitor_poll();
        detection_poll();
        
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
        pid_t child_pid = event->data.process_event.parent_pid;
        
        // Add to detection and memory monitoring
        detection_add_process(child_pid);
        memory_monitor_add_process(child_pid);
    }
    
    // For process exit events, remove from monitoring
    if (event->type == EVENT_PROCESS_TERMINATE) {
        detection_remove_process(event->process_id);
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
                         event->data.process_event.parent_pid, event->data.process_event.image_path);
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
            case EVENT_PROCESS_BEHAVIOR:
            case EVENT_PROCESS_PRIVESC:
                LOG_DEBUG("[%s] Process behavior event %d: %s", 
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
    LOG_INFO("Scanning for existing processes to monitor");
    
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        LOG_ERROR("Failed to open /proc directory: %s", strerror(errno));
        return;
    }
    
    struct dirent* entry;
    int processes_added = 0;
    
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
        
        // Add process to monitoring
        if (detection_add_process(pid) == 0) {
            if (memory_monitor_add_process(pid) == 0) {
                processes_added++;
                
                if (verbose_mode && processes_added % 10 == 0) {
                    LOG_DEBUG("Added %d processes to monitoring...", processes_added);
                }
            }
        }
    }
    
    closedir(proc_dir);
    LOG_INFO("Added %d processes to monitoring", processes_added);
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