#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <string.h>
#include "xdp_stats_kern_user.h"

#define MAX_SVC_NAME 16

static volatile bool exiting = false;

struct {
    __u16 port;
    const char *name;
} services[] = {
    {53, "DNS"},
    {80, "HTTP"},
    {443, "HTTPS"},
    {22, "SSH"},
    {25, "SMTP"},
    {0, NULL}  // sentinel
};

void handle_signal(int sig)
{
    exiting = true;
}

int populate_service_map(int map_fd)
{
    for (int i = 0; services[i].name != NULL; i++) {
        __u32 key = services[i].port;
        struct svc_rec_t value = {};

        strncpy(value.svc_name, services[i].name, MAX_SVC_NAME - 1);
        value.count = 0;

        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {
            perror("bpf_map_update_elem");
            return -1;
        }

        printf("Initialized %u -> %s\n", key, value.svc_name);
    }
    return 0;
}

int poll_service_map(int map_fd)
{
    printf("\n=== Service Packet Counts ===\n");

    for (int i = 0; services[i].name != NULL; i++) {
        __u32 key = services[i].port;
        struct svc_rec_t value = {};

        if (bpf_map_lookup_elem(map_fd, &key, &value) < 0) {
            perror("bpf_map_lookup_elem");
            continue;
        }

        printf("Port %-5u  %-6s  Count: %lu\n",
               key, value.svc_name, value.count);
    }

    printf("==============================\n");
    return 0;
}


int main(int argc, char **argv)
{
    struct bpf_object *obj;
    int map_fd, err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open BPF object
    obj = bpf_object__open_file("xdp_prog.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // Load programs
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    // Get the map FD
    map_fd = bpf_object__find_map_fd_by_name(obj, "svc_port_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map fd\n");
        return 1;
    }

    // Populate the initial service entries
    populate_service_map(map_fd);

    printf("Polling array map every 1 second... (Ctrl+C to exit)\n");

    // Main polling loop
    while (!exiting) {
        poll_service_map(map_fd);
        sleep(1);
    }

    printf("Exiting...\n");

    bpf_object__close(obj);
    return 0;
}
