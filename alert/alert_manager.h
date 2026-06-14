#ifndef ALERT_MANAGER_H
#define ALERT_MANAGER_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

#define MAX_ALERTS 1000
#define MAX_VM_NAME 64

typedef enum {
    ALERT_INFO = 0,
    ALERT_WARNING = 1,
    ALERT_CRITICAL = 2
} alert_severity_t;

typedef enum {
    MODULE_HIDDEN_PROCESS = 0,
    MODULE_SYSCALL,
    MODULE_IDT,
    MODULE_FALLBACK, 
    MODULE_MAX
} module_type_t;

typedef struct {
    int alert_id;
    time_t timestamp;
    char vm_name[MAX_VM_NAME];
    module_type_t module;
    alert_severity_t severity;
    char description[256];
    uint64_t memory_addr;
    uint32_t pid;
    char process_name[32];
    bool is_resolved;
} alert_t;

void init_alert_manager(void);
int add_alert(alert_t *alert);
int get_alert_count(void);
char* generate_alerts_json(void);
void clear_all_alerts(void);

#endif
