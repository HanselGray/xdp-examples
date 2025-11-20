#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
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

int populate_service_map(int map_fd)
{
    for (int i = 0; services[i].name != NULL; i++) {
        __u32 key = services[i].port;
        struct svc_rec_t value = {};
        strncpy(value.svc_name, services[i].name, MAX_SVC_NAME - 1);
        value.count = 0; // initialize count

        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {
            perror("bpf_map_update_elem");
            return -1;
        }

        printf("Populated port %u -> service %s\n", key, value.svc_name);
    }

    return 0;
}

void handle_signal(int sig)
{
    exiting = true;
}

// This callback is called for every ring buffer event
int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct datarec *evt = data;

    printf("Packet arrived on port %u, service %s, no: %u\n",
           evt->port, evt->svc_name, evt->count);

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int map_fd;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open BPF object file
    struct bpf_object *obj = bpf_object__open_file("xdp_prog.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    // Get and populate the service map by port:name/rx_count
    map_fd = bpf_object__find_map_fd_by_name(obj, "svc_port_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        return 1;
    }

    populate_service_map(map_fd);

    // Get the ring buffer map file descriptor
    map_fd = bpf_object__find_map_fd_by_name(obj, "rx_packet_msg");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get ring buffer map fd\n");
        return 1;
    }

    // Create the ring buffer and attach the callback
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for events... Press Ctrl+C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);

    printf("Exiting...\n");
    return 0;
}
