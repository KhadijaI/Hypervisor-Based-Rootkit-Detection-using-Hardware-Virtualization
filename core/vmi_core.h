#ifndef VMI_CORE_H
#define VMI_CORE_H

#include <libvmi/libvmi.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#define MAX_VMS 32
#define MAX_NAME_LEN 64
#define MAX_UUID_LEN 37

typedef struct {
    uint64_t tasks_offset;
    uint64_t pid_offset;
    uint64_t tgid_offset;
    uint64_t comm_offset;
    uint64_t parent_offset;
    uint64_t syscall_table_addr;
    uint64_t kernel_base;
    uint64_t kernel_text_start;
    uint64_t kernel_text_end;
    uint64_t idt_base;
    uint16_t idt_limit;
    uint64_t init_task_addr;
} kernel_offsets_t;

typedef struct vm_instance {
    char name[64];
    char uuid[64];
    unsigned int vm_id;
    vmi_instance_t vmi;
    uint64_t mem_size;
    char os_type[64];
    int is_connected;
    int is_monitored;
    time_t last_scan;
    int alert_count;
    kernel_offsets_t offsets;
    bool offsets_valid;
    struct {
        int hidden_processes;
        int hooked_syscalls;
        int hooked_idt;
        int fallback_detections;
    } anomalies;
    pthread_mutex_t lock;
} vm_instance_t;

typedef struct {
    vm_instance_t vms[MAX_VMS];
    int vm_count;
    bool monitoring_active;
    pthread_mutex_t lock;
} vmi_system_t;

int initialize_vmi_system(vmi_system_t *system);
int discover_vms(vmi_system_t *system);
int connect_to_vm(vm_instance_t *vm);
void disconnect_from_vm(vm_instance_t *vm);
vm_instance_t* find_vm_by_name(vmi_system_t *system, const char *name);
vm_instance_t* find_vm_by_uuid(vmi_system_t *system, const char *uuid);
int refresh_vm_info(vm_instance_t *vm);

int read_physical_memory(vm_instance_t *vm, uint64_t paddr, void *buffer, size_t size);
int read_virtual_memory(vm_instance_t *vm, uint64_t vaddr, void *buffer, size_t size);
int read_physical_uint64(vm_instance_t *vm, uint64_t paddr, uint64_t *value);
int read_virtual_uint64(vm_instance_t *vm, uint64_t vaddr, uint64_t *value);

int detect_kernel_offsets(vm_instance_t *vm);
int traverse_process_list(vm_instance_t *vm, uint64_t **pids, char ***names, int *count);
uint64_t find_syscall_table(vm_instance_t *vm);
uint64_t find_idt_base(vm_instance_t *vm);
uint64_t get_kernel_base(vm_instance_t *vm);
uint64_t find_syscall_table_physical(vm_instance_t *vm);

#endif
