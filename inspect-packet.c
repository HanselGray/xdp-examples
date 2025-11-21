/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/*
 *	Description: This simple program will every other icmp packets on ingress, 
 *	record the number of packet that arrived on each port, which is mapped to a service name.
*/
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_stats_kern_user.h"
#include "packet_parser.h"



/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif



/* Service map */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct svc_rec_t);
	__uint(max_entries, 65536);
} svc_port_map SEC(".maps");


/* Ringbuf output map */
// struct
// {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(key_size, 0);
// 	__uint(value_size, 0);
// 	__uint(max_entries, 4096);
// } rx_packet_msg SEC(".maps");


/* Packet Parsing */
SEC("xdp")
int xdp_packet_inspect(struct xdp_md *ctx){
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *ethh;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct icmphdr *icmph;
	struct icmp6hdr *icmp6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	

	// Tracking next header and next header type
	struct hdr_cursor nh;
	int nh_type;
	// Start pointer
	nh.pos = data;


	// Parsing eth header
	nh_type = parse_ethhdr(&nh, data_end, &ethh);


	// Parsing ip/ipv6 header
	if (nh_type == bpf_htons(ETH_P_IP))
	{
		nh_type = parse_iphdr(&nh, data_end, &iph);
	}
	else if (nh_type == bpf_htons(ETH_P_IPV6))
	{
		nh_type = parse_ipv6hdr(&nh, data_end, &ipv6h);
	}


	// Parsing ICMP/ICMP6
	if (nh_type == IPPROTO_ICMP)
	{
		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if(bpf_ntohs(icmph->un.echo.sequence)&1) return XDP_DROP;
	}
	else if (nh_type == IPPROTO_ICMPV6)
	{
		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if(bpf_ntohs(icmp6h->icmp6_dataun.u_echo.sequence)&1) return XDP_DROP;
	}


	// Parsing TCP/UDP header and record into map
	if (nh_type == IPPROTO_TCP)
	{
		nh_type = parse_tcphdr(&nh, data_end, &tcph);
		struct svc_rec_t *rec = bpf_map_lookup_elem(&svc_port_map, &nh_type);
		
		if(rec) {
			lock_xadd(&(rec->count), 1);
		}

		
	}
	else if (nh_type == IPPROTO_UDP)
	{
		nh_type = parse_udphdr(&nh, data_end, &udph);
		struct svc_rec_t *rec = bpf_map_lookup_elem(&svc_port_map, &nh_type);
		
		if(rec) {
			lock_xadd(&(rec->count), 1);
		}

	}


	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
