#ifndef MODULE_HEADERS_H
#define MODULE_HEADERS_H

#include "../core/vmi_core.h"
#include "../alert/alert_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>

// Detection function declarations
int scan_for_processes(vm_instance_t *vm);
int check_syscall_integrity(vm_instance_t *vm);
int check_idt_integrity(vm_instance_t *vm);

// Fallback detection functions
int scan_memory_for_strings(vm_instance_t *vm);
int check_syscall_fallback(vm_instance_t *vm);
int check_idt_fallback(vm_instance_t *vm);
int check_fallback_detection(vm_instance_t *vm);

// Guest agent functions
int get_guest_process_list(const char *vm_name, uint64_t **pids, char ***names);
int check_syscall_via_guest(vm_instance_t *vm);

// Alternative process detection
int detect_hidden_processes(vm_instance_t *vm);
int scan_memory_for_processes(vm_instance_t *vm);

#endif
