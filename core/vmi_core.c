#define _GNU_SOURCE
#include "vmi_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <inttypes.h>

//=============================================================================
// INITIALIZATION & CONNECTION
//=============================================================================

static int initialize_vmi_instance(vmi_instance_t *vmi, const char *domain) {
    if (!vmi || !domain) return -1;
    
    vmi_init_error_t error = VMI_INIT_ERROR_NONE;
    
    printf("[CORE] Initializing VMI for domain: %s\n", domain);
    
    if (vmi_init(vmi, VMI_KVM | VMI_INIT_DOMAINNAME, (void *)domain,
                VMI_INIT_DOMAINNAME, NULL, &error) != VMI_SUCCESS) {
        printf("[CORE] VMI init failed for %s (error: %d)\n", domain, error);
        return -1;
    }
    
    // Initialize paging
    vmi_init_paging(*vmi, 0);
    
    return 0;
}

int initialize_vmi_system(vmi_system_t *system) {
    if (!system) return -1;
    
    memset(system, 0, sizeof(vmi_system_t));
    pthread_mutex_init(&system->lock, NULL);
    system->monitoring_active = false;
    
    printf("[CORE] VMI system initialized\n");
    return 0;
}

int discover_vms(vmi_system_t *system) {
    if (!system) return -1;
    
    pthread_mutex_lock(&system->lock);
    
    int old_count = system->vm_count;
    system->vm_count = 0;
    
    FILE *fp = popen("virsh list --name --state-running 2>/dev/null", "r");
    if (!fp) {
        printf("[CORE] Failed to execute virsh\n");
        pthread_mutex_unlock(&system->lock);
        return -1;
    }
    
    char line[256];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp) && count < MAX_VMS) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) == 0) continue;
        
        // Check if VM already exists
        int existing_idx = -1;
        for (int i = 0; i < old_count; i++) {
            if (strcmp(system->vms[i].name, line) == 0) {
                existing_idx = i;
                break;
            }
        }
        
        vm_instance_t *vm;
        if (existing_idx >= 0) {
            vm = &system->vms[existing_idx];
        } else {
            vm = &system->vms[count];
            memset(vm, 0, sizeof(vm_instance_t));
            pthread_mutex_init(&vm->lock, NULL);
        }
        
        strncpy(vm->name, line, MAX_NAME_LEN - 1);
        vm->name[MAX_NAME_LEN - 1] = '\0';
        
        // Get UUID
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                "virsh dumpxml %s 2>/dev/null | grep -oP '(?<=<uuid>).*?(?=</uuid>)' | head -1",
                line);
        
        FILE *uuid_fp = popen(cmd, "r");
        if (uuid_fp) {
            if (fgets(vm->uuid, MAX_UUID_LEN, uuid_fp)) {
                vm->uuid[strcspn(vm->uuid, "\n")] = 0;
            }
            pclose(uuid_fp);
        }
        
        vm->is_monitored = false;
        vm->last_scan = 0;
        vm->alert_count = 0;
        vm->offsets_valid = false;
        memset(&vm->offsets, 0, sizeof(kernel_offsets_t));
        
        printf("[CORE] Discovered VM: %s (UUID: %.8s...)\n", vm->name, vm->uuid);
        count++;
    }
    
    pclose(fp);
    system->vm_count = count;
    
    if (count > old_count) {
        printf("[CORE] New VMs detected: %d running\n", count);
    }
    
    pthread_mutex_unlock(&system->lock);
    return count;
}

//=============================================================================
// SYSTEM.MAP PARSING
//=============================================================================

static uint64_t get_symbol_from_system_map(const char *symbol_name) {
    const char *map_paths[] = {
        "/boot/System.map-4.15.0-112-generic",
        "/boot/System.map",
        NULL
    };
    
    for (int p = 0; map_paths[p] != NULL; p++) {
        FILE *fp = fopen(map_paths[p], "r");
        if (!fp) continue;
        
        char line[512];
        uint64_t addr = 0;
        char type;
        char name[256];
        
        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "%" SCNx64 " %c %255s", &addr, &type, name) == 3) {
                if (strcmp(name, symbol_name) == 0) {
                    fclose(fp);
                    printf("[CORE] Found %s at 0x%lx (type: %c)\n", symbol_name, addr, type);
                    return addr;
                }
            }
        }
        fclose(fp);
    }
    
    printf("[CORE] Symbol %s not found in System.map\n", symbol_name);
    return 0;
}

//=============================================================================
// CONNECTION & OFFSET DETECTION
//=============================================================================

int connect_to_vm(vm_instance_t *vm) {
    if (!vm) return -1;
    if (vm->is_connected) {
        printf("[CORE] Already connected to %s\n", vm->name);
        return 0;
    }
    
    printf("[CORE] Connecting to VM: %s\n", vm->name);
    
    if (initialize_vmi_instance(&vm->vmi, vm->name) != 0) {
        printf("[CORE] Failed to initialize VMI for %s\n", vm->name);
        vm->is_connected = false;
        return -1;
    }
    
    vm->is_connected = true;
    vm->vm_id = vmi_get_vmid(vm->vmi);
    vm->mem_size = vmi_get_memsize(vm->vmi);
    
    // Get OS type
    os_t os = vmi_get_ostype(vm->vmi);
    if (os == VMI_OS_LINUX) {
        strcpy(vm->os_type, "Linux");
    } else if (os == VMI_OS_WINDOWS) {
        strcpy(vm->os_type, "Windows");
    } else {
        strcpy(vm->os_type, "Unknown");
    }
    
    printf("[CORE] Connected to %s. Memory: %lu MB\n", vm->name, vm->mem_size / (1024*1024));
    
    // Detect kernel offsets using System.map
    detect_kernel_offsets(vm);
    
    // Find syscall table
    if (vm->offsets.syscall_table_addr == 0) {
        vm->offsets.syscall_table_addr = find_syscall_table(vm);
    }
    
    if (vm->offsets.syscall_table_addr != 0) {
        printf("[CORE] Syscall table found at 0x%lx\n", vm->offsets.syscall_table_addr);
        vm->offsets_valid = true;
    } else {
        printf("[CORE] WARNING: Could not find syscall table\n");
    }
    
    return 0;
}

void disconnect_from_vm(vm_instance_t *vm) {
    if (!vm) return;
    
    if (vm->is_connected && vm->vmi) {
        vmi_destroy(vm->vmi);
        vm->vmi = NULL;
        vm->is_connected = false;
        printf("[CORE] Disconnected from %s\n", vm->name);
    }
}

vm_instance_t* find_vm_by_name(vmi_system_t *system, const char *name) {
    if (!system || !name) return NULL;
    
    for (int i = 0; i < system->vm_count; i++) {
        if (strcmp(system->vms[i].name, name) == 0) {
            return &system->vms[i];
        }
    }
    return NULL;
}

//=============================================================================
// MEMORY ACCESS
//=============================================================================

int read_physical_memory(vm_instance_t *vm, uint64_t paddr, void *buffer, size_t size) {
    if (!vm || !vm->is_connected || !buffer) return -1;
    
    size_t bytes_read = 0;
    if (vmi_read_pa(vm->vmi, paddr, size, buffer, &bytes_read) != VMI_SUCCESS) {
        return -1;
    }
    
    return (int)bytes_read;
}

int read_virtual_memory(vm_instance_t *vm, uint64_t vaddr, void *buffer, size_t size) {
    if (!vm || !vm->is_connected || !buffer) return -1;
    
    size_t bytes_read = 0;
    if (vmi_read_va(vm->vmi, vaddr, 0, size, buffer, &bytes_read) != VMI_SUCCESS) {
        if (vmi_read_pa(vm->vmi, vaddr, size, buffer, &bytes_read) != VMI_SUCCESS) {
            return -1;
        }
    }
    
    return (int)bytes_read;
}

//=============================================================================
// PHYSICAL MEMORY SCANNING
//=============================================================================

uint64_t find_syscall_table_physical(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return 0;
    
    printf("[CORE] >>> Starting Physical Memory Scan (Total: %lu MB)...\n", vm->mem_size / (1024*1024));
    
    unsigned char *buffer = malloc(1024 * 1024);
    if (!buffer) return 0;
    
    uint64_t found_addr = 0;
    uint64_t mem_size = vm->mem_size;
    uint64_t total_scanned = 0;
    int last_percent = 0;
    
    for (uint64_t pa = 0; pa < mem_size && !found_addr; pa += 1024 * 1024) {
        size_t bytes_read = 0;
        if (vmi_read_pa(vm->vmi, pa, 1024 * 1024, buffer, &bytes_read) != VMI_SUCCESS) {
            continue;
        }
        
        total_scanned += bytes_read;
        int percent = (int)((total_scanned * 100) / mem_size);
        if (percent >= last_percent + 5) {
            printf("[CORE] >>> Scanning: %d%% (%lu MB / %lu MB)\n", 
                   percent, total_scanned / (1024*1024), mem_size / (1024*1024));
            last_percent = percent;
        }
        
        for (size_t i = 0; i < bytes_read - 256; i += 8) {
            int valid_count = 0;
            for (int j = 0; j < 32; j++) {
                uint64_t *ptr = (uint64_t*)&buffer[i + j*8];
                if (*ptr >= 0xffffffff80000000UL && *ptr < 0xffffffffc0000000UL) {
                    valid_count++;
                } else {
                    break;
                }
            }
            if (valid_count >= 28) {
                found_addr = pa + i;
                printf("[CORE] >>> PATTERN FOUND at 0x%lx!\n", found_addr);
                break;
            }
        }
    }
    
    printf("[CORE] >>> Physical Scan Complete. Total Scanned: %lu MB\n", total_scanned / (1024*1024));
    
    if (found_addr) {
        printf("[CORE] >>> SUCCESS: Syscall table located at 0x%lx\n", found_addr);
    } else {
        printf("[CORE] >>> WARNING: Syscall table NOT found in physical memory.\n");
    }
    
    free(buffer);
    return found_addr;
}

//=============================================================================
// KERNEL INTROSPECTION
//=============================================================================

int detect_kernel_offsets(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return -1;
    
    printf("[CORE] Detecting kernel offsets for %s\n", vm->name);
    
    // Default offsets for Linux 4.x kernels
    vm->offsets.tasks_offset = 0x298;
    vm->offsets.pid_offset = 0x9c0;
    vm->offsets.comm_offset = 0x9e0;
    
    // Try to get symbol addresses from System.map
    uint64_t init_task_addr = get_symbol_from_system_map("init_task");
    if (init_task_addr != 0) {
        vm->offsets.init_task_addr = init_task_addr;
        vm->offsets_valid = true;
        printf("[CORE] init_task physical address: 0x%lx\n", init_task_addr);
    }
    
    uint64_t syscall_addr = get_symbol_from_system_map("sys_call_table");
    if (syscall_addr != 0) {
        vm->offsets.syscall_table_addr = syscall_addr;
        printf("[CORE] sys_call_table physical address: 0x%lx\n", syscall_addr);
    }
    
    uint64_t idt_addr = get_symbol_from_system_map("idt_table");
    if (idt_addr != 0) {
        vm->offsets.idt_base = idt_addr;
        vm->offsets.idt_limit = 4095;
        printf("[CORE] idt_table physical address: 0x%lx\n", idt_addr);
    }
    
    return vm->offsets_valid ? 0 : -1;
}

uint64_t find_syscall_table(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return 0;
    
    uint64_t syscall_table = 0;
    
    // Try symbol lookup from System.map first
    syscall_table = get_symbol_from_system_map("sys_call_table");
    if (syscall_table != 0) {
        printf("[CORE] Found syscall table at 0x%lx from System.map\n", syscall_table);
        return syscall_table;
    }
    
    // Try LibVMI symbol lookup
    if (vmi_translate_ksym2v(vm->vmi, "sys_call_table", &syscall_table) == VMI_SUCCESS) {
        printf("[CORE] Found syscall table at 0x%lx via LibVMI symbols\n", syscall_table);
        return syscall_table;
    }
    
    // Fall back to physical scan
    syscall_table = find_syscall_table_physical(vm);
    return syscall_table;
}

uint64_t find_idt_base(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return 0;
    
    uint64_t idt_base = 0;
    
    // Try symbol lookup from System.map
    idt_base = get_symbol_from_system_map("idt_table");
    if (idt_base != 0) {
        printf("[CORE] Found IDT at 0x%lx from System.map\n", idt_base);
        vm->offsets.idt_limit = 4095;
        return idt_base;
    }
    
    // Try LibVMI symbol lookup
    if (vmi_translate_ksym2v(vm->vmi, "idt_table", &idt_base) == VMI_SUCCESS) {
        printf("[CORE] Found IDT at 0x%lx via LibVMI symbols\n", idt_base);
        vm->offsets.idt_limit = 4095;
        return idt_base;
    }
    
    return 0;
}

uint64_t get_kernel_base(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return 0;
    
    uint64_t kernel_base = 0;
    
    // Try to get _stext from System.map
    kernel_base = get_symbol_from_system_map("_stext");
    if (kernel_base != 0) {
        return kernel_base;
    }
    
    kernel_base = get_symbol_from_system_map("_text");
    if (kernel_base != 0) {
        return kernel_base;
    }
    
    return 0;
}

//=============================================================================
// PROCESS LIST TRAVERSAL USING PHYSICAL MEMORY
//=============================================================================

int traverse_process_list(vm_instance_t *vm, uint64_t **pids, char ***names, int *count) {
    if (!vm || !vm->is_connected || !pids || !names || !count) return -1;
    if (!vm->offsets_valid || vm->offsets.init_task_addr == 0) {
        printf("[CORE] Offsets not valid for %s\n", vm->name);
        return -1;
    }
    
    // Use physical address (KPTI is off, so virtual = physical for kernel)
    uint64_t init_task_pa = vm->offsets.init_task_addr;
    
    printf("[CORE] Using physical address for init_task: 0x%lx\n", init_task_pa);
    printf("[CORE] tasks_offset: 0x%lx\n", vm->offsets.tasks_offset);
    
    // Read the tasks list head using physical address
    uint64_t tasks_list_pa = init_task_pa + vm->offsets.tasks_offset;
    uint64_t next = 0;
    
    if (vmi_read_pa(vm->vmi, tasks_list_pa, 8, &next, NULL) != VMI_SUCCESS) {
        printf("[CORE] Failed to read tasks list head at physical 0x%lx\n", tasks_list_pa);
        return -1;
    }
    
    printf("[CORE] First task pointer (physical): 0x%lx\n", next);
    
    // Temporary storage
    uint64_t pid_array[1024];
    char *name_array[1024];
    int proc_count = 0;
    int safety = 0;
    int max_iter = 2000;
    
    uint64_t current = next;
    
    while (current != tasks_list_pa && proc_count < 1024 && safety++ < max_iter) {
        // Current points to the list_head structure inside a task_struct
        // The task_struct physical address is at current - tasks_offset
        uint64_t current_task_pa = current - vm->offsets.tasks_offset;
        
        // Read PID using physical address
        uint64_t pid_addr = current_task_pa + vm->offsets.pid_offset;
        uint32_t pid = 0;
        
        if (vmi_read_pa(vm->vmi, pid_addr, 4, &pid, NULL) == VMI_SUCCESS) {
            if (pid > 0 && pid < 65535) {
                // Read process name using physical address
                uint64_t comm_addr = current_task_pa + vm->offsets.comm_offset;
                char comm[16] = {0};
                
                if (vmi_read_pa(vm->vmi, comm_addr, 15, comm, NULL) == VMI_SUCCESS) {
                    comm[15] = '\0';
                    // Clean the name (remove any non-printable chars)
                    for (int i = 0; i < 15 && comm[i]; i++) {
                        if (comm[i] < 32 || comm[i] > 126) comm[i] = '?';
                    }
                    
                    printf("[CORE] Found process: PID=%u, name=%s\n", pid, comm);
                    
                    pid_array[proc_count] = pid;
                    name_array[proc_count] = strdup(comm);
                    proc_count++;
                }
            }
        }
        
        // Move to next task - the next pointer is at current (list_head)
        if (vmi_read_pa(vm->vmi, current, 8, &current, NULL) != VMI_SUCCESS) {
            printf("[CORE] Failed to read next task pointer\n");
            break;
        }
    }
    
    printf("[CORE] Found %d processes via physical memory traversal\n", proc_count);
    
    if (proc_count == 0) return -1;
    
    // Allocate output
    *pids = malloc(proc_count * sizeof(uint64_t));
    *names = malloc(proc_count * sizeof(char*));
    *count = proc_count;
    
    if (!*pids || !*names) {
        for (int i = 0; i < proc_count; i++) free(name_array[i]);
        if (*pids) free(*pids);
        if (*names) free(*names);
        return -1;
    }
    
    memcpy(*pids, pid_array, proc_count * sizeof(uint64_t));
    for (int i = 0; i < proc_count; i++) {
        (*names)[i] = name_array[i];
    }
    
    return proc_count;
}
