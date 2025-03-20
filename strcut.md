AntiRansom/
├── common/                  # Purely shared structs + scoring logic, no syscalls
│   ├── scoring.h
│   ├── scoring.c
│   ├── config.h
│   ├── config.c
│   ├── logger.h
│   ├── logger.c
├── linux/                   # Linux-specific syscall, memory, and process handling
│   ├── main.c
│   ├── detection.c
│   ├── syscall_monitor.c
│   ├── memory_monitor.c
│   ├── process_monitor.c
│   ├── user_filter.c
├── windows/                 # Windows-specific syscall and memory handling
│   ├── main.c
│   ├── detection.c
│   ├── api_hook.c
│   ├── memory_monitor.c
│   ├── process_monitor.c
│   ├── user_filter.c
├── include/
│   ├── antiransom.h         # Common struct and scoring definitions
│   ├── events.h             # Event definitions (OS-agnostic)
├── utils/
├── context.md               # Co-Pilot's memory log
├── Makefile
├── README.md
