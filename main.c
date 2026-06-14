#include "core/vmi_core.h"
#include "monitoring/monitor_loop.h"
#include "alert/alert_manager.h"
#include "web/dashboard_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>

vmi_system_t g_system;
static int g_running = 1;
static int g_monitoring_started = 0;

void signal_handler(int sig) {
    printf("\n[SYSTEM] Shutting down...\n");
    g_running = 0;
    exit(0); // Force exit to kill all threads
   }

int load_configuration(const char *config_file) {
    printf("[SYSTEM] Loading configuration from %s\n", config_file);
    return 0;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("[SYSTEM] ================================================\n");
    printf("[SYSTEM] VMI Rootkit Detector Starting...\n");
    printf("[SYSTEM] Version: 1.1.0\n");
    printf("[SYSTEM] ================================================\n");

    load_configuration("config/fyp_config.json");

    if (initialize_vmi_system(&g_system) != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize VMI system\n");
        return 1;
    }

    init_alert_manager();
    printf("[SYSTEM] Alert manager initialized\n");
    
    alert_t test_alert = {0};
    strcpy(test_alert.vm_name, "SYSTEM");
    test_alert.module = MODULE_HIDDEN_PROCESS;
    test_alert.severity = ALERT_INFO;
    time_t now = time(NULL);
struct tm *tm_info = localtime(&now);
strftime(test_alert.description, sizeof(test_alert.description), 
         "System started at %Y-%m-%d %H:%M:%S", tm_info);
    int alert_id = add_alert(&test_alert);
    printf("[SYSTEM] Added test alert with ID: %d\n", alert_id);

    printf("[SYSTEM] Discovering virtual machines...\n");
    int vm_count = discover_vms(&g_system);

    if (vm_count == 0) {
    printf("[WARNING] No running VMs found.\n");
    printf("[INFO] Use 'virsh start <vmname>' to start a VM\n");
    printf("[INFO] Or wait for VMs to start automatically...\n");
} else {
    printf("[SYSTEM] Found %d VM(s)\n", vm_count);
    for (int i = 0; i < g_system.vm_count; i++) {
        printf("  - %s (UUID: %.8s...)\n",
               g_system.vms[i].name, g_system.vms[i].uuid);
    }
}
    
    printf("[SYSTEM] Attempting to connect to VMs (Max 3 attempts)...\n");
    for (int attempt = 1; attempt <= 3 && vm_count > 0; attempt++) {
        int connected_count = 0;
        for (int i = 0; i < g_system.vm_count && i < MAX_VMS; i++) {
            vm_instance_t *vm = &g_system.vms[i];
            if (vm->name[0] == '\0') continue;
            
            if (!vm->is_connected) {
                printf("[CORE] Connecting to %s (Attempt %d/3)...\n", vm->name, attempt);
                if (connect_to_vm(vm) == 0) {
                    connected_count++;
                } else {
                    printf("[CORE] Connection failed, retrying in 2 seconds...\n");
                    sleep(2);
                }
            } else {
                connected_count++;
            }
        }
        
        if (connected_count > 0) {
            printf("[SYSTEM] Successfully connected to %d VM(s)\n", connected_count);
            break;
        } else if (attempt < 3) {
            printf("[SYSTEM] Waiting 3 seconds before retry %d/3...\n", attempt + 1);
            sleep(3);
        }
    }

    // Only start monitoring automatically if there are connected VMs
    if (g_system.vm_count > 0) {
        int has_connected = 0;
        for (int i = 0; i < g_system.vm_count && i < MAX_VMS; i++) {
            if (g_system.vms[i].is_connected) {
                has_connected = 1;
                break;
            }
        }
        
        if (has_connected) {
            printf("[SYSTEM] Starting automatic monitoring for connected VMs...\n");
            for (int i = 0; i < g_system.vm_count && i < MAX_VMS; i++) {
                if (g_system.vms[i].is_connected) {
                    g_system.vms[i].is_monitored = 1;
                    printf("[SYSTEM] Monitoring started for %s\n", g_system.vms[i].name);
                }
            }
            
            if (start_monitoring(&g_system) == 0) {
                g_monitoring_started = 1;
                printf("[SYSTEM] Monitoring service active\n");
            }
        } else {
            printf("[SYSTEM] No VMs connected. Monitoring will start when you click START on dashboard.\n");
        }
    } else {
        printf("[SYSTEM] No VMs connected. Monitoring thread will start automatically when a VM connects.\n");
    }

    if (start_dashboard_server(5000) != 0) {
        fprintf(stderr, "[ERROR] Failed to start web server on port 5000\n");
        return 1;
    }

    printf("\n[SYSTEM] ================================================\n");
    printf("[SYSTEM] Dashboard URL: http://localhost:5000\n");
    printf("[SYSTEM] API Endpoint: http://localhost:5000/api\n");
    printf("[SYSTEM] Press Ctrl+C to shutdown\n");
    printf("[SYSTEM] ================================================\n");

    time_t last_discovery = time(NULL);
    time_t last_stats = time(NULL);

    while (g_running) {
        time_t now = time(NULL);

        // Rediscover VMs every 30 seconds
        if (now - last_discovery > 30) {
            int old_count = g_system.vm_count;
            discover_vms(&g_system);
            
            // Clean up any invalid VM entries
            for (int i = 0; i < g_system.vm_count && i < MAX_VMS; i++) {
                if (g_system.vms[i].name[0] == '\0') {
                    memset(&g_system.vms[i], 0, sizeof(vm_instance_t));
                }
            }
            
            if (g_system.vm_count > old_count) {
                printf("[SYSTEM] New VMs detected: %d total\n", g_system.vm_count);
            }
            last_discovery = now;
        }

        if (now - last_stats > 10) {
            int monitored = 0;
            int connected = 0;
            int total_alerts = get_alert_count();
            int scan_count = get_scan_count();
            
            for (int i = 0; i < g_system.vm_count && i < MAX_VMS; i++) {
                if (g_system.vms[i].name[0] == '\0') continue;
                if (g_system.vms[i].is_monitored) monitored++;
                if (g_system.vms[i].is_connected) connected++;
            }
            
            printf("[STATUS] VMs: %d | Connected: %d | Monitored: %d | Alerts: %d | Scans: %d\n",
                   g_system.vm_count, connected, monitored, total_alerts, scan_count);
            last_stats = now;
        }
        
        sleep(1);
    }

    printf("\n[SYSTEM] Shutting down...\n");
    
    if (g_monitoring_started) {
        stop_monitoring(&g_system);
    }
    
    stop_dashboard_server();
    
    for (int i = 0; i < g_system.vm_count && i < MAX_VMS; i++) {
        if (g_system.vms[i].name[0] == '\0') continue;
        if (g_system.vms[i].is_connected) {
            disconnect_from_vm(&g_system.vms[i]);
        }
    }
    
    printf("[SYSTEM] Shutdown complete\n");
    return 0;
}
