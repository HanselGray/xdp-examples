/* SPDX-License-Identifier: GPL-2.0 */
#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include<bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct svc_rec{
	char[16] svc_name;
	int count;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, short);
	__type(value, struct svc_rec);
	__uint(max_entries, 65536);
} svc_port_map SEC(".maps");

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

// Parsing helpers

static __always_inline int parse_ethhdr(void *data,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (data+ 1 > data_end)
		return -1;

	data += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **icmphdr)
{
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct iphdr **iphdr)
{
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
}

SEC("xdp")
int xdp_packet_inspect(struct xdp_md *ctx){
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	//parsing eth header
	struct ethhdr *eth;

	struct svc_map *rec;
	rec = bpf_map_lookup_elem(&svc_port_map,&key);
	if(!rec) return XDP_ABORTED;	
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL-2.0";

