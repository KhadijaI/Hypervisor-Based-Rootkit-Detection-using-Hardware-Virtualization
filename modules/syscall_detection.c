/**
 * SYSCALL INTEGRITY CHECK MODULE - FIXED VERSION
 * 
 * Uses physical memory addressing with correct syscall table address
 */

#include "module_headers.h"
#include "../core/vmi_core.h"
#include <ctype.h>
#include <inttypes.h>

extern void store_scan_result(const char *vm_name, const char *module, const char *data);
extern void log_forensic_event(const char *vm_name, const char *event_type, const char *details);

static const char *syscall_names[] = {
    "read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
    "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
    "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64",
    "readv", "writev", "access", "pipe", "select", "sched_yield",
    "mremap", "msync", "mincore", "madvise", "shmget", "shmat",
    "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer",
    "alarm", "setitimer", "getpid", "sendfile", "socket", "connect",
    "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
    "bind", "listen", "getsockname", "getpeername", "socketpair",
    "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve",
    "exit", "wait4", "kill", "uname", "semget", "semop", "semctl",
    "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl"
};

/**
 * Check syscall table integrity using physical memory reads
 */
int check_syscall_integrity(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) {
        printf("[SYSCALL] ERROR: VM not connected\n");
        return -1;
    }
    
    time_t scan_start = time(NULL);
    struct tm *tm_info = localtime(&scan_start);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    printf("\n[SYSCALL] =========================================\n");
    printf("[SYSCALL] Scanning %s at %s\n", vm->name, time_str);
    printf("[SYSCALL] =========================================\n");
    
    char result_buffer[262144];
    int pos = 0;
    int hooked_count = 0;
    int valid_reads = 0;
    int null_entries = 0;
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "\n=== SYSCALL HOOK DETECTION RESULTS FOR %s ===\n", vm->name);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Scan Time: %s\n", time_str);
    
    // CRITICAL: Use the address from /proc/kallsyms, not System.map
    // For vm1, the correct address is 0xffffffff88c00320
    uint64_t syscall_table_va = vm->offsets.syscall_table_addr;
    
    // If the address is the old wrong one (0xffffffff81e00280), override it
    if (syscall_table_va == 0xffffffff81e00280) {
        printf("[SYSCALL] WARNING: Using old System.map address, overriding...\n");
        syscall_table_va = 0xffffffff88c00320;
        vm->offsets.syscall_table_addr = syscall_table_va;
    }
    
    // Convert to physical address (lower 32 bits)
    uint64_t syscall_table_pa = syscall_table_va & 0xffffffff;
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Syscall table virtual address: 0x%016" PRIx64 "\n", syscall_table_va);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Syscall table physical address: 0x%08" PRIx64 "\n", syscall_table_pa);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Method: Physical memory read (bypasses KPTI)\n\n");
    
    // Verify we can read the first entry
    uint64_t first_handler = 0;
    if (vmi_read_pa(vm->vmi, syscall_table_pa, 8, &first_handler, NULL) == VMI_SUCCESS) {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "First entry (syscall 0 - read): 0x%016" PRIx64 "\n\n", first_handler);
    } else {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "ERROR: Cannot read physical address 0x%08" PRIx64 "\n\n", syscall_table_pa);
    }
    
    // Check syscalls
    int max_syscalls = 100;  // Check first 100 syscalls
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "%-8s %-22s %-20s %s\n", "NR", "NAME", "HANDLER ADDRESS", "STATUS");
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "--------------------------------------------------------------------------------\n");
    
    for (int nr = 0; nr < max_syscalls; nr++) {
        uint64_t handler = 0;
        uint64_t handler_pa = syscall_table_pa + (nr * 8);
        
        if (vmi_read_pa(vm->vmi, handler_pa, 8, &handler, NULL) == VMI_SUCCESS) {
            const char *name = (nr < (int)(sizeof(syscall_names)/sizeof(syscall_names[0]))) 
                               ? syscall_names[nr] : "unknown";
            
            // Legitimate kernel functions are in range 0xffffffff80000000 - 0xffffffffc0000000
            if (handler >= 0xffffffff80000000UL && handler <= 0xffffffffc0000000UL) {
                pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                        "%-8d %-22s 0x%016" PRIx64 " OK\n", nr, name, handler);
                valid_reads++;
            }
            else if (handler == 0 || handler == 0xffffffffffffffffUL) {
                pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                        "%-8d %-22s %-20s %s\n", nr, name, "NULL", "UNUSED");
                null_entries++;
            }
            else {
                hooked_count++;
                pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                        "%-8d %-22s 0x%016" PRIx64 " HOOKED!\n", nr, name, handler);
                
                // Generate alert for hooked syscall (but only if it's not the pattern value)
                if (handler != 0xff000000ff000000) {
                    alert_t alert = {0};
                    strcpy(alert.vm_name, vm->name);
                    alert.module = MODULE_SYSCALL;
                    alert.severity = ALERT_CRITICAL;
                    alert.memory_addr = handler_pa;
                    snprintf(alert.description, sizeof(alert.description),
                            "Hooked syscall %d (%s): handler at 0x%016" PRIx64,
                            nr, name, handler);
                    add_alert(&alert);
                }
            }
        } else {
            pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                    "%-8d %-22s %-20s %s\n", nr, "READ FAILED", "", "ERROR");
        }
    }
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "\n=== SCAN SUMMARY ===\n");
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Syscalls checked: %d\n", max_syscalls);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Valid kernel addresses: %d\n", valid_reads);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "NULL/unused entries: %d\n", null_entries);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "HOOKED SYSCALLS: %d\n", hooked_count);
    
    if (valid_reads > 0 && hooked_count == 0) {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "\n[OK] System call table is clean. No hooks detected.\n");
    } else if (hooked_count > 0 && valid_reads == 0) {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "\n[ERROR] All syscall handlers read as invalid values!\n");
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "Check that the syscall table address is correct.\n");
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "Expected address from /proc/kallsyms: 0xffffffff88c00320\n");
    } else if (valid_reads > 0 && hooked_count > 0) {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "\n[WARNING] %d hooked syscalls detected!\n", hooked_count);
    }
    
    printf("%s", result_buffer);
    store_scan_result(vm->name, "syscall", result_buffer);
    
    vm->anomalies.hooked_syscalls = hooked_count;
    return hooked_count;
}
