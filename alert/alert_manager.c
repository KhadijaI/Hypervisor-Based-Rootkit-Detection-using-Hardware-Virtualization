#include "alert_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

static alert_t g_alerts[MAX_ALERTS];
static int g_alert_count = 0;
static int g_next_id = 1;
static pthread_mutex_t g_alert_lock = PTHREAD_MUTEX_INITIALIZER;

void init_alert_manager(void) {
    pthread_mutex_lock(&g_alert_lock);
    memset(g_alerts, 0, sizeof(g_alerts));
    g_alert_count = 0;
    g_next_id = 1;
    pthread_mutex_unlock(&g_alert_lock);
    printf("[ALERT] Manager initialized (alerts cleared)\n");
}

int add_alert(alert_t *alert) {
    if (!alert) {
        printf("[ALERT DEBUG] add_alert called with NULL alert\n");
        return -1;
    }
    printf("[ALERT DEBUG] Attempting to add alert: %s\n", alert->description);
    pthread_mutex_lock(&g_alert_lock);
    printf("[ALERT DEBUG] Current alert count: %d, max: %d\n", g_alert_count, MAX_ALERTS);
    if (g_alert_count >= MAX_ALERTS) {
        printf("[ALERT DEBUG] Alert buffer full, removing oldest\n");
        for (int i = 1; i < g_alert_count; i++) {
            g_alerts[i-1] = g_alerts[i];
        }
        g_alert_count--;
    }
    alert->alert_id = g_next_id++;
    alert->timestamp = time(NULL);
    printf("[ALERT DEBUG] Assigned ID: %d, timestamp: %ld\n", alert->alert_id, alert->timestamp);
    g_alerts[g_alert_count++] = *alert;
    printf("[ALERT DEBUG] New alert count: %d, next_id: %d\n", g_alert_count, g_next_id);
    pthread_mutex_unlock(&g_alert_lock);
    printf("[ALERT] #%d: %s\n", alert->alert_id, alert->description);
    return alert->alert_id;
}

int get_alert_count(void) {
    pthread_mutex_lock(&g_alert_lock);
    int count = g_alert_count;
    pthread_mutex_unlock(&g_alert_lock);
    return count;
}

char* generate_alerts_json(void) {
    char *buffer = malloc(262144);
    if (!buffer) return strdup("[]");
    
    buffer[0] = '\0';
    char temp[8192];
    char escaped_desc[512];
    
    pthread_mutex_lock(&g_alert_lock);
    
    strcat(buffer, "[");
    
    for (int i = 0; i < g_alert_count && i < 200; i++) {
        alert_t *a = &g_alerts[i];
        
        char time_buf[64];
        strftime(time_buf, sizeof(time_buf), "%H:%M:%S", localtime(&a->timestamp));
        
        // Escape description for JSON (remove newlines and escape quotes)
        char *src = a->description;
        char *dst = escaped_desc;
        while (*src && dst - escaped_desc < 500) {
            if (*src == '"') {
                *dst++ = '\\';
                *dst++ = '"';
            } else if (*src == '\n') {
                *dst++ = ' ';
            } else if (*src == '\r') {
                *dst++ = ' ';
            } else if (*src == '\\') {
                *dst++ = '\\';
                *dst++ = '\\';
            } else {
                *dst++ = *src;
            }
            src++;
        }
        *dst = '\0';
        
        snprintf(temp, sizeof(temp),
            "%s{\"id\":%d,\"timestamp\":%ld,\"time\":\"%s\",\"vm\":\"%s\","
            "\"severity\":%d,\"description\":\"%s\"}",
            (i > 0 ? "," : ""),
            a->alert_id, a->timestamp, time_buf, a->vm_name,
            a->severity, escaped_desc);
        strcat(buffer, temp);
    }
    
    strcat(buffer, "]");
    
    pthread_mutex_unlock(&g_alert_lock);
    return buffer;
}

void clear_all_alerts(void) {
    pthread_mutex_lock(&g_alert_lock);
    memset(g_alerts, 0, sizeof(g_alerts));
    g_alert_count = 0;
    g_next_id = 1;
    pthread_mutex_unlock(&g_alert_lock);
    printf("[ALERT] All alerts cleared\n");
}

int get_alert_count_by_vm(const char *vm_name) {
    pthread_mutex_lock(&g_alert_lock);
    int count = 0;
    for (int i = 0; i < g_alert_count; i++) {
        if (strcmp(g_alerts[i].vm_name, vm_name) == 0) {
            count++;
        }
    }
    pthread_mutex_unlock(&g_alert_lock);
    return count;
}
