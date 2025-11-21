
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "packet_parser.h"

SEC("xdp_drop_UDP")                           /* section in ELF-binary and "program_by_title" in libbpf */
int xdp_prog_drop_all_UDP(struct xdp_md *ctx) /* "name" visible with bpftool */
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct hdr_cursor nh;
    u32 nh_type = 0;

    struct ethhdr *ethh;
    struct iphdr *iph;
    struct udphdr *udph;

    // Start pointer
    nh.pos = data;

    // Parsing eth header
    nh_type = parse_ethhdr(&nh, data_end, &ethh);

    // Parsing ip/ipv6 header
    if (nh_type == bpf_htons(ETH_P_IP))
        nh_type = parse_iphdr(&nh, data_end, &iph);
        
    if (nh_type == IPPROTO_UDP)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";