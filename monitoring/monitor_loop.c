#include "monitor_loop.h"
#include "../modules/module_headers.h"
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

extern int detect_hidden_processes(vm_instance_t *vm);
extern int check_syscall_integrity(vm_instance_t *vm);
extern int check_idt_integrity(vm_instance_t *vm);
extern int check_fallback_detection(vm_instance_t *vm);
extern int check_syscall_via_guest(vm_instance_t *vm);

static int g_monitoring_active = 0;
static pthread_t g_monitor_thread;
static vmi_system_t *g_system_ptr = NULL;
static pthread_mutex_t g_monitor_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_scan_counter = 0;

void log_forensic_event(const char *vm_name, const char *event_type, const char *details) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    FILE *log = fopen("forensic_audit.log", "a");
    if (log) {
        fprintf(log, "[%s] VM: %s | Event: %s | Details: %s\n",
                timestamp, vm_name ? vm_name : "SYSTEM", event_type, details ? details : "");
        fclose(log);
    }
    printf("[FORENSIC] [%s] %s | %s | %s\n", timestamp,
           vm_name ? vm_name : "SYSTEM", event_type, details ? details : "");
}

int monitor_single_vm(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return -1;
    time_t scan_start = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime(&scan_start));
    printf("\n[MONITOR] === Starting Scan Cycle for %s at %s ===\n", vm->name, time_str);
    log_forensic_event(vm->name, "SCAN_START", "Starting scan cycle");
    int hidden = 0, syscall = 0, idt = 0, fallback = 0;
    printf("[MONITOR] Running Hidden Process Detection...\n");
    hidden = detect_hidden_processes(vm);
    printf("[MONITOR] Running Syscall Integrity Check...\n");
    syscall = check_syscall_integrity(vm);
    printf("[MONITOR] Running IDT Check...\n");
    idt = check_idt_integrity(vm);
    printf("[MONITOR] Running Fallback Detection...\n");
    fallback = check_fallback_detection(vm);
    vm->anomalies.hidden_processes = hidden;
    vm->anomalies.hooked_syscalls = syscall;
    vm->anomalies.hooked_idt = idt;
    vm->anomalies.fallback_detections = fallback;
    vm->last_scan = scan_start;
    char msg[256];
    snprintf(msg, sizeof(msg), "Hidden:%d Syscall:%d IDT:%d Fallback:%d", hidden, syscall, idt, fallback);
    log_forensic_event(vm->name, "SCAN_COMPLETE", msg);
    printf("[MONITOR] === Scan Cycle Complete. Results: %s ===\n", msg);
    return 0;
}

int monitor_all_vms(vmi_system_t *system) {
    if (!system) return -1;
    int scanned = 0;
    pthread_mutex_lock(&system->lock);
    for (int i = 0; i < system->vm_count; i++) {
        if (system->vms[i].is_monitored) {
            if (monitor_single_vm(&system->vms[i]) == 0) {
                scanned++;
            }
        }
    }
    pthread_mutex_unlock(&system->lock);
    return scanned;
}

static void* monitor_thread_func(void *arg) {
    vmi_system_t *system = (vmi_system_t*)arg;
    g_system_ptr = system;
    log_forensic_event(NULL, "THREAD", "Monitoring thread started");
    printf("[MONITOR] Thread started\n");
    int consecutive_failures = 0;
    while (1) {
        pthread_mutex_lock(&g_monitor_lock);
        int should_stop = !g_monitoring_active;
        pthread_mutex_unlock(&g_monitor_lock);
        if (should_stop) break;
        g_scan_counter++;
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
        printf("\n[MONITOR] === Scan cycle #%d at %s ===\n", g_scan_counter, time_str);
        int scanned = monitor_all_vms(system);
        if (scanned == 0) {
            consecutive_failures++;
            if (consecutive_failures > 5) {
                printf("[MONITOR] Too many failures, rediscovering VMs...\n");
                consecutive_failures = 0;
            }
        } else {
            consecutive_failures = 0;
        }
        printf("[MONITOR] Scanned %d VMs this cycle\n", scanned);
        for (int i = 0; i < 20; i++) {
            pthread_mutex_lock(&g_monitor_lock);
            int stop = !g_monitoring_active;
            pthread_mutex_unlock(&g_monitor_lock);
            if (stop) break;
            sleep(1);
        }
    }
    log_forensic_event(NULL, "THREAD", "Monitoring thread stopped");
    return NULL;
}

int start_monitoring(vmi_system_t *system) {
    if (!system) return -1;
    pthread_mutex_lock(&g_monitor_lock);
    if (g_monitoring_active) {
        pthread_mutex_unlock(&g_monitor_lock);
        printf("[MONITOR] Already monitoring\n");
        return 0;
    }
    g_monitoring_active = 1;
    system->monitoring_active = true;
    pthread_mutex_unlock(&g_monitor_lock);
    log_forensic_event(NULL, "MONITORING", "Starting monitoring service");
    if (pthread_create(&g_monitor_thread, NULL, monitor_thread_func, system) != 0) {
        log_forensic_event(NULL, "ERROR", "Failed to create monitoring thread");
        pthread_mutex_lock(&g_monitor_lock);
        g_monitoring_active = 0;
        system->monitoring_active = false;
        pthread_mutex_unlock(&g_monitor_lock);
        return -1;
    }
    printf("[MONITOR] Monitoring started successfully\n");
    return 0;
}

int stop_monitoring(vmi_system_t *system) {
    if (!system) return -1;
    pthread_mutex_lock(&g_monitor_lock);
    if (!g_monitoring_active) {
        pthread_mutex_unlock(&g_monitor_lock);
        return 0;
    }
    g_monitoring_active = 0;
    if (system) system->monitoring_active = false;
    pthread_mutex_unlock(&g_monitor_lock);
    log_forensic_event(NULL, "MONITORING", "Stopping monitoring service");
    pthread_join(g_monitor_thread, NULL);
    printf("[MONITOR] Monitoring stopped\n");
    return 0;
}

int get_scan_count(void) {
    return g_scan_counter;
}
