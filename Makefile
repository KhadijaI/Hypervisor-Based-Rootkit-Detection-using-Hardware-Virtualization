CC = gcc
CFLAGS = -Wall -O2 -g -pthread -I. -Icore -Imodules -Ialert -Imonitoring -Iweb -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lvmi -ljson-c -lpthread

SOURCES = main.c \
          core/vmi_core.c \
          alert/alert_manager.c \
          modules/process_scanner.c \
          modules/syscall_detection.c \
          modules/idt_detection.c \
          modules/fallback_detection.c \
          modules/guest_syscall.c \
          modules/alternative_process_detection.c \
          monitoring/monitor_loop.c \
          web/dashboard_server.c

OBJECTS = $(SOURCES:.c=.o)
TARGET = vmi

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) *.log

.PHONY: all clean
