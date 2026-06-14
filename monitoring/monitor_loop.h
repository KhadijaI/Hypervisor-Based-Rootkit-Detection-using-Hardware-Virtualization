#ifndef MONITOR_LOOP_H
#define MONITOR_LOOP_H

#include "../core/vmi_core.h"

int start_monitoring(vmi_system_t *system);
int stop_monitoring(vmi_system_t *system);
int monitor_all_vms(vmi_system_t *system);
int monitor_single_vm(vm_instance_t *vm);
int get_scan_count(void);  

#endif
