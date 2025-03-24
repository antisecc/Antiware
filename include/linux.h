// Update forward declaration for linux_main

#ifndef ANTIRANSOM_LINUX_H
#define ANTIRANSOM_LINUX_H

// Forward declaration of GlobalArgs
typedef struct {
    int daemon_mode;
    int verbose_mode;
    char config_path[512];
    char watch_directory[512];
} GlobalArgs;

// Linux platform entry point
int linux_main(int argc, char* argv[], const GlobalArgs* global_args);

#endif // ANTIRANSOM_LINUX_H