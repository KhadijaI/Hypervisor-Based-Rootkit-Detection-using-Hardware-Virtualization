#include "module_headers.h"
#include "../core/vmi_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void store_scan_result(const char *vm_name, const char *module, const char *data);

int check_syscall_via_guest(vm_instance_t *vm) {
    if (!vm || !vm->name) return -1;
    
    time_t scan_start = time(NULL);
    struct tm *tm_info = localtime(&scan_start);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    printf("\n[GUEST] Getting system info from %s via guest agent at %s\n", vm->name, time_str);
    
    char result_buffer[262144];
    int pos = 0;
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "\n=== GUEST AGENT SYSTEM INFORMATION ===\n");
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "VM: %s | Time: %s\n", vm->name, time_str);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "=======================================\n\n");
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
            "sudo virsh qemu-agent-command %s '{\"execute\":\"guest-ping\"}' 2>/dev/null",
            vm->name);
    
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                    "[OK] Guest agent is responding\n\n");
        } else {
            pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                    "[ERROR] Guest agent not responding\n\n");
        }
        pclose(fp);
    }
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "--- SYSTEM INFORMATION ---\n");
    
    snprintf(cmd, sizeof(cmd),
            "sudo virsh qemu-agent-command %s '{\"execute\":\"guest-exec\",\"arguments\":{\"path\":\"/bin/hostname\",\"capture-output\":true}}' 2>/dev/null | grep -o 'out-data.*' | cut -d'\"' -f3",
            vm->name);
    
    fp = popen(cmd, "r");
    if (fp) {
        char line[1024];
        if (fgets(line, sizeof(line), fp)) {
            pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                    "Hostname: %s", line);
        }
        pclose(fp);
    }
    
    snprintf(cmd, sizeof(cmd),
            "sudo virsh qemu-agent-command %s '{\"execute\":\"guest-exec\",\"arguments\":{\"path\":\"/bin/uname\",\"arg\":[\"-a\"],\"capture-output\":true}}' 2>/dev/null | grep -o 'out-data.*' | cut -d'\"' -f3",
            vm->name);
    
    fp = popen(cmd, "r");
    if (fp) {
        char line[1024];
        if (fgets(line, sizeof(line), fp)) {
            pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                    "Kernel: %s", line);
        }
        pclose(fp);
    }
    
    snprintf(cmd, sizeof(cmd),
            "sudo virsh qemu-agent-command %s '{\"execute\":\"guest-exec\",\"arguments\":{\"path\":\"/bin/cat\",\"arg\":[\"/proc/meminfo\"],\"capture-output\":true}}' 2>/dev/null | grep -E 'MemTotal|MemFree' | grep -o 'out-data.*' | cut -d'\"' -f3",
            vm->name);
    
    fp = popen(cmd, "r");
    if (fp) {
        char line[1024];
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "\n--- MEMORY INFORMATION ---\n");
        while (fgets(line, sizeof(line), fp)) {
            pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos, "%s", line);
        }
        pclose(fp);
    }
    
    snprintf(cmd, sizeof(cmd),
            "sudo virsh qemu-agent-command %s '{\"execute\":\"guest-exec\",\"arguments\":{\"path\":\"/bin/lsmod\",\"capture-output\":true}}' 2>/dev/null | grep -o 'out-data.*' | cut -d'\"' -f3 | grep -i -E 'diamorphine|adore|knark|rkit|override'",
            vm->name);
    
    fp = popen(cmd, "r");
    if (fp) {
        int found = 0;
        char line[1024];
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "\n--- ROOTKIT CHECKS ---\n");
        while (fgets(line, sizeof(line), fp)) {
            pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                    "WARNING: Suspicious module found: %s", line);
            found = 1;
        }
        if (!found) {
            pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                    "No suspicious kernel modules found\n");
        }
        pclose(fp);
    }
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "\n=======================================\n");
    
    printf("%s", result_buffer);
    store_scan_result(vm->name, "guest", result_buffer);
    
    return 0;
}
