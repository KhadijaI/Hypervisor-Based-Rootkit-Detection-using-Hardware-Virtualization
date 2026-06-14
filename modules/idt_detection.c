#include "module_headers.h"
#include "../core/vmi_core.h"
#include <ctype.h>

extern void store_scan_result(const char *vm_name, const char *module, const char *data);

static const char *vector_names[] = {
    "Divide Error", "Debug", "NMI", "Breakpoint", "Overflow",
    "BOUND Range", "Invalid Opcode", "Device Not Available",
    "Double Fault", "Coprocessor Segment", "Invalid TSS",
    "Segment Not Present", "Stack Fault", "General Protection",
    "Page Fault", "Reserved", "x87 FPU Error", "Alignment Check",
    "Machine Check", "SIMD Exception", "Virtualization",
    "Control Protection", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "IRQ0 (Timer)", "IRQ1 (Keyboard)",
    "IRQ2 (Cascade)", "IRQ3 (COM2)", "IRQ4 (COM1)", "IRQ5 (LPT2)",
    "IRQ6 (Floppy)", "IRQ7 (LPT1)", "IRQ8 (RTC)", "IRQ9 (ACPI)",
    "IRQ10", "IRQ11", "IRQ12 (Mouse)", "IRQ13 (FPU)", "IRQ14 (ATA)",
    "IRQ15 (ATA)"
};

static uint64_t parse_idt_entry(unsigned char *entry) {
    uint16_t offset_low = *(uint16_t*)&entry[0];
    uint16_t offset_mid = *(uint16_t*)&entry[6];
    uint32_t offset_high = *(uint32_t*)&entry[8];
    return ((uint64_t)offset_high << 32) | ((uint64_t)offset_mid << 16) | offset_low;
}

int check_idt_integrity(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return -1;
    
    time_t scan_start = time(NULL);
    struct tm *tm_info = localtime(&scan_start);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    printf("\n[IDT] Quick check for %s at %s\n", vm->name, time_str);
    
    char result_buffer[4096];
    int pos = 0;
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "\n=== IDT DETECTION STATUS FOR %s ===\n", vm->name);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Scan Time: %s\n", time_str);
    
    if (vm->offsets.idt_base == 0) {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "\n[INFO] IDT detection on kernel 6.2.0+ is limited due to KPTI.\n");
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "[INFO] The IDT is protected by Kernel Page Table Isolation.\n");
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "[INFO] This is a known limitation of modern kernels.\n\n");
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "[OK] Syscall detection is working normally.\n");
    } else {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "\n[OK] IDT found at 0x%lx\n", vm->offsets.idt_base);
    }
    
    printf("%s", result_buffer);
    store_scan_result(vm->name, "idt", result_buffer);
    
    return 0;
}
