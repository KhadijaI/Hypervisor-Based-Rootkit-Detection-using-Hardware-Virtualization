#include "module_headers.h"
#include "../core/vmi_core.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

extern void store_scan_result(const char *vm_name, const char *module, const char *data);
extern int get_guest_process_list(const char *vm_name, uint64_t **pids, char ***names);

int scan_memory_for_processes(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return -1;
    
    printf("\n[PROCESS] Scanning physical memory of %s (Total: %lu MB)...\n", 
           vm->name, vm->mem_size / (1024 * 1024));
    
    unsigned char *buffer = malloc(1024 * 1024);
    if (!buffer) return -1;
    
    int process_count = 0;
    uint64_t mem_size = vm->mem_size;
    uint64_t total_scanned = 0;
    int last_percent = 0;
    
    // Buffer for progressive results
    char progressive_buffer[65536];
    int prog_pos = 0;
    
    // Initialize progressive result buffer
    prog_pos += snprintf(progressive_buffer + prog_pos, sizeof(progressive_buffer) - prog_pos,
            "\n=== HIDDEN PROCESS DETECTION RESULTS FOR %s ===\n", vm->name);
    prog_pos += snprintf(progressive_buffer + prog_pos, sizeof(progressive_buffer) - prog_pos,
            "Scan in progress...\n\n");
    
    for (uint64_t pa = 0; pa < mem_size && process_count < 500; pa += 1024 * 1024) {
        size_t bytes_read = 0;
        if (vmi_read_pa(vm->vmi, pa, 1024 * 1024, buffer, &bytes_read) != VMI_SUCCESS) {
            continue;
        }
        
        total_scanned += bytes_read;
        int percent = (int)((total_scanned * 100) / mem_size);
        
        if (percent >= last_percent + 5) {
            printf("[PROCESS] Scanning progress: %d%% (%lu MB / %lu MB)\n", 
                   percent, total_scanned / (1024*1024), mem_size / (1024*1024));
            last_percent = percent;
            
            // Send progress update to dashboard
            char progress_msg[256];
            snprintf(progress_msg, sizeof(progress_msg),
                    "\n[STATUS] Scanning %d%% complete (%lu MB / %lu MB) - Found %d process names so far\n",
                    percent, total_scanned / (1024*1024), mem_size / (1024*1024), process_count);
            
            // Store progressive update
            prog_pos += snprintf(progressive_buffer + prog_pos, sizeof(progressive_buffer) - prog_pos,
                    "%s", progress_msg);
            store_scan_result(vm->name, "hidden", progressive_buffer);
        }
        
        for (size_t i = 0; i < bytes_read - 16; i++) {
            if (isprint(buffer[i]) && buffer[i] > 32) {
                int len = 0;
                while (i + len < bytes_read && isprint(buffer[i+len]) && len < 15) {
                    len++;
                }
                
                if (len >= 3 && len <= 15) {
                    char name[16];
                    memcpy(name, &buffer[i], len);
                    name[len] = '\0';
                    
                    if (strcmp(name, "systemd") == 0 ||
                        strcmp(name, "init") == 0 ||
                        strcmp(name, "bash") == 0 ||
                        strcmp(name, "sshd") == 0 ||
                        strcmp(name, "kernel") == 0 ||
                        strcmp(name, "kthreadd") == 0 ||
                        strcmp(name, "python") == 0 ||
                        strcmp(name, "java") == 0 ||
                        strcmp(name, "systemd-journal") == 0) {
                        
                        printf("[PROCESS] Found process name '%s' at physical 0x%lx\n", 
                               name, (unsigned long)(pa + i));
                        process_count++;
                        
                        // Add to progressive buffer
                        prog_pos += snprintf(progressive_buffer + prog_pos, 
                                sizeof(progressive_buffer) - prog_pos,
                                "Found: %s at 0x%lx\n", name, (unsigned long)(pa + i));
                        
                        // Update dashboard every 10 findings
                        if (process_count % 10 == 0) {
                            store_scan_result(vm->name, "hidden", progressive_buffer);
                        }
                    }
                }
                i += len;
            }
        }
    }
    
    // Final update
    prog_pos += snprintf(progressive_buffer + prog_pos, sizeof(progressive_buffer) - prog_pos,
            "\n=== SCAN COMPLETE ===\n");
    prog_pos += snprintf(progressive_buffer + prog_pos, sizeof(progressive_buffer) - prog_pos,
            "Scanned %lu MB, found %d process names\n", 
            total_scanned / (1024*1024), process_count);
    
    printf("[PROCESS] Scan complete! Scanned %lu MB, found %d process names\n", 
           total_scanned / (1024*1024), process_count);
    
    store_scan_result(vm->name, "hidden", progressive_buffer);
    
    free(buffer);
    return process_count;
}

int detect_hidden_processes(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return -1;
    
    time_t scan_start = time(NULL);
    struct tm *tm_info = localtime(&scan_start);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    printf("\n[PROCESS] Starting Hidden Process Detection for %s at %s\n", vm->name, time_str);
    
    int vmi_count = scan_memory_for_processes(vm);
    
    return vmi_count;
}
