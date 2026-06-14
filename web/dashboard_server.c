#define _GNU_SOURCE
#include "dashboard_server.h"
#include "../core/vmi_core.h"
#include "../alert/alert_manager.h"
#include "../monitoring/monitor_loop.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

void store_scan_result(const char *vm_name, const char *module, const char *data);

extern void log_forensic_event(const char *vm_name, const char *event_type, const char *details);
extern vmi_system_t g_system;

static int server_running = 0;
static int server_fd = -1;
static pthread_t server_thread;

typedef struct {
    char vm_name[64];
    char module[32];
    time_t scan_time;
    char data[262144];
    int anomaly_count;
    int suspicious_count;
    int rootkit_count;
} scan_result_t;

static scan_result_t g_last_scan[20];
static int g_scan_count = 0;
static pthread_mutex_t g_scan_mutex = PTHREAD_MUTEX_INITIALIZER;

void store_scan_result(const char *vm_name, const char *module, const char *data) {
    if (!vm_name || !vm_name[0] || !module || !data) {
        printf("[DASHBOARD] WARNING: store_scan_result called with invalid params\n");
        return;
    }
    printf("[DASHBOARD] Storing scan result for VM: %s, Module: %s, length: %ld\n", 
           vm_name, module, strlen(data));
    pthread_mutex_lock(&g_scan_mutex);
    int idx = -1;
    for (int i = 0; i < g_scan_count; i++) {
        if (strcmp(g_last_scan[i].vm_name, vm_name) == 0 &&
            strcmp(g_last_scan[i].module, module) == 0) {
            idx = i;
            break;
        }
    }
    if (idx == -1 && g_scan_count < 20) {
        idx = g_scan_count++;
        strncpy(g_last_scan[idx].vm_name, vm_name, sizeof(g_last_scan[idx].vm_name) - 1);
        g_last_scan[idx].vm_name[sizeof(g_last_scan[idx].vm_name) - 1] = '\0';
        strncpy(g_last_scan[idx].module, module, sizeof(g_last_scan[idx].module) - 1);
        g_last_scan[idx].module[sizeof(g_last_scan[idx].module) - 1] = '\0';
        g_last_scan[idx].scan_time = time(NULL);
        printf("[DASHBOARD] Created NEW entry for %s/%s at index %d\n", vm_name, module, idx);
    }
    if (idx >= 0) {
        g_last_scan[idx].scan_time = time(NULL);
        strncpy(g_last_scan[idx].data, data, sizeof(g_last_scan[idx].data) - 1);
        g_last_scan[idx].data[sizeof(g_last_scan[idx].data) - 1] = '\0';
        printf("[DASHBOARD] UPDATED %s/%s, data length: %ld, total entries: %d\n", 
               vm_name, module, strlen(data), g_scan_count);
    } else {
        printf("[DASHBOARD] ERROR: Could not store result for %s/%s (buffer full?)\n", vm_name, module);
    }
    pthread_mutex_unlock(&g_scan_mutex);
}

static const char* get_mime_type(const char *path) {
    if (strstr(path, ".html") || strcmp(path, "/") == 0)
        return "text/html; charset=utf-8";
    if (strstr(path, ".css"))
        return "text/css; charset=utf-8";
    if (strstr(path, ".js"))
        return "application/javascript; charset=utf-8";
    if (strstr(path, ".json"))
        return "application/json";
    return "text/plain";
}

static char* generate_vms_json(void) {
    char *buffer = malloc(131072);
    if (!buffer) return NULL;
    
    buffer[0] = '\0';
    
    pthread_mutex_lock(&g_system.lock);
    
    char temp[8192];
    snprintf(temp, sizeof(temp),
            "{\n  \"total\": %d,\n  \"timestamp\": %ld,\n  \"vms\": [\n",
            g_system.vm_count, (long)time(NULL));
    strcat(buffer, temp);
    
    for (int i = 0; i < g_system.vm_count; i++) {
        vm_instance_t *vm = &g_system.vms[i];
        
        char last_scan_str[64] = "Never";
        if (vm->last_scan > 0) {
            strftime(last_scan_str, sizeof(last_scan_str), "%H:%M:%S", localtime(&vm->last_scan));
        }
        
        snprintf(temp, sizeof(temp),
                "    {\n"
                "      \"name\": \"%s\",\n"
                "      \"uuid\": \"%s\",\n"
                "      \"is_connected\": %s,\n"
                "      \"is_monitored\": %s,\n"
                "      \"memory_mb\": %lu,\n"
                "      \"os\": \"%s\",\n"
                "      \"last_scan\": \"%s\",\n"
                "      \"anomalies\": {\n"
                "        \"hidden_processes\": %d,\n"
                "        \"hooked_syscalls\": %d,\n"
                "        \"hooked_idt\": %d\n"
                "      }\n"
                "    }%s\n",
                vm->name, vm->uuid,
                vm->is_connected ? "true" : "false",
                vm->is_monitored ? "true" : "false",
                (unsigned long)(vm->mem_size / (1024 * 1024)),
                vm->os_type[0] ? vm->os_type : "Linux",
                last_scan_str,
                vm->anomalies.hidden_processes,
                vm->anomalies.hooked_syscalls,
                vm->anomalies.hooked_idt,
                (i < g_system.vm_count - 1) ? "," : "");
        strcat(buffer, temp);
        printf("[API] Added VM %s to JSON response\n", vm->name);
    }
    
    strcat(buffer, "  ]\n}\n");
    pthread_mutex_unlock(&g_system.lock);
    
    printf("[API] generate_vms_json: returning %d VMs\n", g_system.vm_count);
    return buffer;
}

static void handle_api_request(int client_fd, const char *path, const char *method, const char *body) {
    char response[1048576];
    char *json_response = NULL;
    const char *cors =
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n";
    if (strcmp(method, "OPTIONS") == 0) {
        snprintf(response, sizeof(response), "HTTP/1.1 204 No Content\r\n%s\r\n", cors);
        send(client_fd, response, strlen(response), 0);
        return;
    }
    if (strncmp(path, "/api/scan/", 10) == 0) {
        char vm_name[64] = {0}, module[64] = {0};
        int parsed = sscanf(path + 10, "%63[^/]/%63s", vm_name, module);
        if (parsed != 2 || !vm_name[0] || !module[0]) {
            snprintf(response, sizeof(response),
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid request");
            send(client_fd, response, strlen(response), 0);
            return;
        }
        printf("[API] REQUEST: %s/%s\n", vm_name, module);
        char *response_data = NULL;
        pthread_mutex_lock(&g_scan_mutex);
        printf("[API] Checking %d stored entries...\n", g_scan_count);
        for (int i = 0; i < g_scan_count; i++) {
            printf("[API] Entry %d: VM='%s', Module='%s'\n", i, g_last_scan[i].vm_name, g_last_scan[i].module);
            if (strcmp(g_last_scan[i].vm_name, vm_name) == 0 &&
                strcmp(g_last_scan[i].module, module) == 0) {
                response_data = strdup(g_last_scan[i].data);
                printf("[API] FOUND DATA for %s/%s, length: %ld\n", vm_name, module, strlen(response_data));
                break;
            }
        }
        pthread_mutex_unlock(&g_scan_mutex);
        if (!response_data) {
            response_data = strdup("No scan data available yet. Please wait for scan to complete.");
            printf("[API] NO DATA FOUND for %s/%s\n", vm_name, module);
        }
        snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n%sContent-Length: %ld\r\n\r\n%s",
                cors, (long)strlen(response_data), response_data);
        send(client_fd, response, strlen(response), 0);
        free(response_data);
        return;
    }
    if (strcmp(path, "/api/alerts") == 0 && strcmp(method, "GET") == 0) {
        extern char* generate_alerts_json(void);
        char *alerts_json = generate_alerts_json();
        if (!alerts_json) alerts_json = strdup("[]");
        snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n%sContent-Length: %ld\r\n\r\n%s",
                cors, (long)strlen(alerts_json), alerts_json);
        send(client_fd, response, strlen(response), 0);
        free(alerts_json);
        return;
    }
    if (strcmp(path, "/api/vms") == 0 && strcmp(method, "GET") == 0) {
        json_response = generate_vms_json();
        if (json_response) {
            snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n%sContent-Length: %ld\r\nConnection: close\r\n\r\n%s",
                    cors, (long)strlen(json_response), json_response);
            send(client_fd, response, strlen(response), 0);
            free(json_response);
        }
        return;
    }
    if (strcmp(path, "/api/discover") == 0 && strcmp(method, "POST") == 0) {
        discover_vms(&g_system);
        json_response = generate_vms_json();
        if (json_response) {
            snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n%sContent-Length: %ld\r\n\r\n%s",
                    cors, (long)strlen(json_response), json_response);
            send(client_fd, response, strlen(response), 0);
            free(json_response);
        }
        return;
    }
    if (strcmp(path, "/api/forensic-log") == 0 && strcmp(method, "GET") == 0) {
        FILE *fp = fopen("forensic_audit.log", "r");
        char log_content[65536] = "No forensic log available.";
        if (fp) {
            size_t bytes = fread(log_content, 1, sizeof(log_content) - 1, fp);
            log_content[bytes] = '\0';
            fclose(fp);
        }
        snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n%sContent-Length: %ld\r\n\r\n%s",
                cors, (long)strlen(log_content), log_content);
        send(client_fd, response, strlen(response), 0);
        return;
    }
    if (strncmp(path, "/api/monitor/", 13) == 0) {
        char vm_name[64] = {0};
        if (sscanf(path + 13, "%63s", vm_name) != 1 || !vm_name[0]) {
            snprintf(response, sizeof(response),
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid VM name");
            send(client_fd, response, strlen(response), 0);
            return;
        }
        int start = 1;
        if (body) {
            if (strstr(body, "stop") || strstr(body, "\"action\":\"stop\"")) {
                start = 0;
            }
        }
        printf("[DASHBOARD] %s monitoring for VM: %s\n", start ? "Starting" : "Stopping", vm_name);
        vm_instance_t *vm = find_vm_by_name(&g_system, vm_name);
        if (!vm) {
            snprintf(response, sizeof(response),
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nVM %s not found", vm_name);
            send(client_fd, response, strlen(response), 0);
            return;
        }
        if (start) {
            if (!vm->is_connected) {
                printf("[DASHBOARD] VM %s not connected, attempting to connect...\n", vm_name);
                if (connect_to_vm(vm) != 0) {
                    snprintf(response, sizeof(response),
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nFailed to connect to VM");
                    send(client_fd, response, strlen(response), 0);
                    return;
                }
                printf("[DASHBOARD] Successfully connected to %s\n", vm_name);
            }
            vm->is_monitored = 1;
            extern int start_monitoring(vmi_system_t *);
            start_monitoring(&g_system);
            printf("[DASHBOARD] Started monitoring %s\n", vm_name);
        } else {
            vm->is_monitored = 0;
            printf("[DASHBOARD] Stopped monitoring %s\n", vm_name);
        }
        json_response = generate_vms_json();
        if (json_response) {
            snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n%sContent-Length: %ld\r\n\r\n%s",
                    cors, (long)strlen(json_response), json_response);
            send(client_fd, response, strlen(response), 0);
            free(json_response);
        }
        return;
    }
    char file_path[512];
    if (strcmp(path, "/") == 0) {
        snprintf(file_path, sizeof(file_path), "web/static/index.html");
    } else if (strstr(path, ".css")) {
        snprintf(file_path, sizeof(file_path), "web/static/styles.css");
    } else if (strstr(path, ".js")) {
        snprintf(file_path, sizeof(file_path), "web/static/app.js");
    } else if (strstr(path, ".html")) {
        snprintf(file_path, sizeof(file_path), "web/static%s", path);
    } else {
        snprintf(file_path, sizeof(file_path), "web/static%s", path);
    }
    int fd = open(file_path, O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        fstat(fd, &st);
        char *file_content = malloc(st.st_size + 1);
        if (file_content) {
            ssize_t bytes_read = read(fd, file_content, st.st_size);
            if (bytes_read > 0) {
                file_content[bytes_read] = '\0';
                const char *content_type = get_mime_type(path);
                snprintf(response, sizeof(response),
                        "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n%sContent-Length: %ld\r\nCache-Control: no-cache\r\n\r\n%s",
                        content_type, cors, (long)st.st_size, file_content);
                send(client_fd, response, strlen(response), 0);
            }
            free(file_content);
        }
        close(fd);
    } else {
        snprintf(response, sizeof(response),
                "HTTP/1.1 404 Not Found\r\n%sContent-Type: text/html\r\n\r\n<html><body><h1>404 Not Found</h1></body></html>", cors);
        send(client_fd, response, strlen(response), 0);
    }
}

static void* client_handler(void *arg) {
    int client_fd = *(int*)arg;
    free(arg);
    char buffer[32768];
    char method[16], path[1024], version[16];
    char *body = NULL;
    int bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        sscanf(buffer, "%15s %1023s %15s", method, path, version);
        char *body_start = strstr(buffer, "\r\n\r\n");
        if (body_start) body = body_start + 4;
        handle_api_request(client_fd, path, method, body);
    }
    close(client_fd);
    return NULL;
}

static void* server_loop(void *arg) {
    int port = *(int*)arg;
    free(arg);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[WEB] Socket failed");
        return NULL;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[WEB] Bind failed");
        close(server_fd);
        return NULL;
    }
    if (listen(server_fd, 10) < 0) {
        perror("[WEB] Listen failed");
        close(server_fd);
        return NULL;
    }
    printf("[WEB] Dashboard running on http://localhost:%d\n", port);
    server_running = 1;
    while (server_running) {
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, NULL, NULL);
        if (*client_fd > 0) {
            pthread_t thread;
            pthread_create(&thread, NULL, client_handler, client_fd);
            pthread_detach(thread);
        } else {
            free(client_fd);
        }
    }
    close(server_fd);
    return NULL;
}

int start_dashboard_server(int port) {
    if (server_running) return 0;
    int *port_ptr = malloc(sizeof(int));
    *port_ptr = port;
    if (pthread_create(&server_thread, NULL, server_loop, port_ptr) != 0) {
        free(port_ptr);
        return -1;
    }
    return 0;
}

void stop_dashboard_server(void) {
    server_running = 0;
    if (server_fd > 0) close(server_fd);
    pthread_join(server_thread, NULL);
}
