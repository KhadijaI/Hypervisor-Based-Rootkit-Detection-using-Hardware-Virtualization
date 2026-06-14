#define _GNU_SOURCE
#include "module_headers.h"
#include "../core/vmi_core.h"
#include <ctype.h>

#define SCAN_CHUNK (1024 * 1024)  // 1MB chunks

extern void store_scan_result(const char *vm_name, const char *module, const char *data);

int check_fallback_detection(vm_instance_t *vm) {
    if (!vm || !vm->is_connected) return -1;
    
    time_t scan_start = time(NULL);
    struct tm *tm_info = localtime(&scan_start);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    printf("\n[FALLBACK] Scanning %s at %s\n", vm->name, time_str);
    printf("[FALLBACK] Total memory to scan: %lu MB\n", vm->mem_size / (1024 * 1024));
    
    unsigned char *buffer = malloc(SCAN_CHUNK);
    if (!buffer) {
        printf("[FALLBACK] ERROR: Failed to allocate buffer\n");
        return -1;
    }
    
    char result_buffer[262144];
    int pos = 0;
    int anomaly_count = 0;
    int suspicious_count = 0;
    int rootkit_count = 0;
    uint64_t total_scanned = 0;
    uint64_t mem_size = vm->mem_size;
    int last_percent = 0;
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "\n=== FALLBACK DETECTION RESULTS FOR %s ===\n", vm->name);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Scan Time: %s\n", time_str);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Total Memory Scanned: %lu MB\n", mem_size / (1024 * 1024));
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Method: Physical memory scanning (rootkit signatures + executable code detection)\n\n");
    
    // Rootkit signature patterns
    const struct {
        const char *name;
        const unsigned char *pattern;
        int len;
        int min_confidence;
        int severity;  // 2=critical(rootkit), 1=warning(suspicious)
    } signatures[] = {
        {"Diamorphine", (const unsigned char*)"diamorphine", 11, 85, 2},
        {"Adore-ng", (const unsigned char*)"adore-ng", 8, 85, 2},
        {"Kbeast", (const unsigned char*)"kbeast", 6, 85, 2},
        {"Rkit", (const unsigned char*)"rkit", 4, 75, 2},
        {"Override", (const unsigned char*)"override", 8, 90, 2},
        {"Suterusu", (const unsigned char*)"suterusu", 8, 85, 2},
        {"Enye LKM", (const unsigned char*)"enye", 4, 85, 2},
        {"Kbdv3", (const unsigned char*)"kbdv3", 5, 85, 2},
        {"Kdoor", (const unsigned char*)"kdoor", 5, 85, 2},
        {"Knark", (const unsigned char*)"knark", 5, 85, 2},
        {"Phalanx", (const unsigned char*)"phalanx", 7, 85, 2},
        {"Mood-nt", (const unsigned char*)"mood-nt", 7, 85, 2},
        {"Kjackal", (const unsigned char*)"kjackal", 7, 85, 2},
        {"Linux Rootkit 1", (const unsigned char*)"rootkit", 7, 70, 1},
        {"Linux Rootkit 2", (const unsigned char*)"rootkit found", 12, 80, 1},
    };
    
    int sig_index = 0;
    int exec_pages = 0;
    
    printf("[FALLBACK] Starting physical memory scan...\n\n");
    
    for (uint64_t pa = 0; pa < mem_size; pa += SCAN_CHUNK) {
        size_t bytes_read = 0;
        if (vmi_read_pa(vm->vmi, pa, SCAN_CHUNK, buffer, &bytes_read) != VMI_SUCCESS || bytes_read == 0) {
            continue;
        }
        
        total_scanned += bytes_read;
        int percent = (int)((total_scanned * 100) / mem_size);
        
        if (percent >= last_percent + 5) {
            printf("[FALLBACK] Progress: %d%% (%lu MB / %lu MB)\n", 
                   percent, total_scanned / (1024*1024), mem_size / (1024*1024));
            last_percent = percent;
        }
        
        // Check for rootkit signatures
        for (size_t i = 0; i < bytes_read - 32 && anomaly_count < 100; i++) {
            for (int s = 0; s < (int)(sizeof(signatures)/sizeof(signatures[0])); s++) {
                if (i + signatures[s].len < bytes_read &&
                    memcmp(buffer + i, signatures[s].pattern, signatures[s].len) == 0) {
                    
                    int confidence = 50;
                    
                    // Check nearby for executable code (CALL, JMP, RET instructions)
                    int has_code_nearby = 0;
                    for (int j = -16; j <= 16; j += 4) {
                        if ((int)(i + j) >= 0 && (int)(i + j + 4) < (int)bytes_read) {
                            unsigned char *p = buffer + i + j;
                            if (*p == 0xe8 || *p == 0xe9 || *p == 0xc3 || *p == 0xcc) {
                                has_code_nearby = 1;
                                break;
                            }
                        }
                    }
                    
                    if (has_code_nearby) confidence += 30;
                    
                    // Check if in kernel module space
                    if (pa >= 0xffffffffc0000000) {
                        confidence += 20;
                    }
                    
                    if (confidence >= signatures[s].min_confidence) {
                        anomaly_count++;
                        if (signatures[s].severity == 2) rootkit_count++;
                        else suspicious_count++;
                        sig_index++;
                        
                        const char *severity_str = (signatures[s].severity == 2) ? "ROOTKIT" : "SUSPICIOUS";
                        
                        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                                "%-8d 0x%016lx %s signature: %s (confidence: %d%%) [%s]\n",
                                sig_index, (unsigned long)(pa + i), severity_str, 
                                signatures[s].name, confidence, 
                                has_code_nearby ? "near executable code" : "in data section");
                        
                        // Generate alert
                        alert_t alert = {0};
                        strcpy(alert.vm_name, vm->name);
                        alert.module = MODULE_FALLBACK;
                        alert.severity = signatures[s].severity;
                        alert.memory_addr = pa + i;
                        snprintf(alert.description, sizeof(alert.description),
                                "%s %s signature at 0x%lx (confidence: %d%%)", 
                                severity_str, signatures[s].name, (unsigned long)(pa + i), confidence);
                        add_alert(&alert);
                        
                        i += signatures[s].len;
                    }
                }
            }
        }
        
        // Check for executable code in non-executable regions (suspicious)
        if (pa < 0x10000000) {  // Only scan lower memory for executable patterns
            for (size_t i = 0; i < bytes_read - 48; i++) {
                int exec_instructions = 0;
                for (int j = 0; j < 16; j++) {
                    unsigned char *p = buffer + i + j;
                    if (*p == 0xe8 || *p == 0xe9 || *p == 0xc3 || *p == 0xcc || 
                        *p == 0x55 || *p == 0x89 || *p == 0x48 || *p == 0x8b) {
                        exec_instructions++;
                    }
                }
                
                if (exec_instructions >= 8) {
                    // Check if this looks like a region with many code patterns
                    int nearby_code = 0;
                    for (int j = -64; j <= 64; j += 4) {
                        if ((int)(i + j) >= 0 && (int)(i + j + 4) < (int)bytes_read) {
                            unsigned char *p = buffer + i + j;
                            if (*p == 0xe8 || *p == 0xe9 || *p == 0xc3) {
                                nearby_code++;
                            }
                        }
                    }
                    
                    if (nearby_code >= 5 && exec_instructions >= 10) {
                        exec_pages++;
                        if (exec_pages <= 30) {
                            pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                                    "0x%016lx: Executable code detected in data region (%d instructions, %d nearby)\n",
                                    (unsigned long)(pa + i), exec_instructions, nearby_code);
                            
                            if (exec_pages <= 10) {
                                alert_t alert = {0};
                                strcpy(alert.vm_name, vm->name);
                                alert.module = MODULE_FALLBACK;
                                alert.severity = ALERT_WARNING;
                                alert.memory_addr = pa + i;
                                snprintf(alert.description, sizeof(alert.description),
                                        "Suspicious executable code at 0x%lx in data region", (unsigned long)(pa + i));
                                add_alert(&alert);
                                suspicious_count++;
                                anomaly_count++;
                            }
                        }
                        i += 32;
                    }
                }
            }
        }
    }
    
    free(buffer);
    
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "\n=== SCAN SUMMARY ===\n");
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Total memory scanned: %lu MB\n", total_scanned / (1024*1024));
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Rootkit signatures found: %d\n", rootkit_count);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Suspicious patterns found: %d\n", suspicious_count);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Executable code pages in data regions: %d\n", exec_pages);
    pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
            "Total anomalies: %d\n\n", anomaly_count);
    
    if (rootkit_count > 0) {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "!!! %d ROOTKIT SIGNATURES DETECTED !!!\n", rootkit_count);
    } else if (anomaly_count > 0) {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "!!! %d ANOMALIES DETECTED (Suspicious patterns) !!!\n", anomaly_count);
    } else {
        pos += snprintf(result_buffer + pos, sizeof(result_buffer) - pos,
                "[OK] No anomalies detected in memory scan\n");
    }
    
    printf("%s", result_buffer);
    store_scan_result(vm->name, "fallback", result_buffer);
    
    vm->anomalies.fallback_detections = anomaly_count;
    return anomaly_count;
}
