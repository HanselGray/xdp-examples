/* SPDX-License-Identifier: GPL-2.0 

	Description: This simple program will every other icmp packets on ingress, 
	and forwarded other packets up to the upper layer in the kernel. It will also
	record the number of packet that arrived on each port, which is mapped to a service name.
*/
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "xdp_stats_kern_user.h"

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif



/* Header cursor to keep track of current parsing position */
struct hdr_cursor
{
	void *pos;
};

/* Service map */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct svc_rec_t);
	__uint(max_entries, 65536);
} svc_port_map SEC(".maps");



/* Ringbuf output map */
struct
{
	__uint(type, BPF_MAP_TYPE_RIN);
	__uint(key_size, 0);
	__uint(value_size, 0)
	__uint(max_entries, 4096);
} rx_packet_msg SEC(".maps");



/* Ethernet header parser */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
										void *data_end,
										struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

/* IP and IP_6 header parser*/
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
									   void *data_end,
									   struct iphdr **iphdr)
{
	struct iphdr *ip = nh->pos;
	int hdrsize = sizeof(*ip);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = ip;

	return ip->protocol;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
										void *data_end,
										struct ipv6hdr **ipv6hdr)
{
	struct ipv6hdr *ipv6 = nh->pos;
	int hdrsize = sizeof(*ipv6);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ipv6hdr = ipv6;

	return ipv6->nexthdr;
}

/* ICMP and ICMP_6 parser */
static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
										 void *data_end,
										 struct icmphdr **icmphdr)
{
	struct icmphdr *icmp = nh->pos;
	int hdrsize = sizeof(*icmp);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmphdr = icmp;

	return icmp->type;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
										  void *data_end,
										  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;
	int hdrsize = sizeof(*icmp6);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp6hdr = icmp6;

	return icmp6->icmp6_type;
}

/* TCP and UDP parser */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
										void *data_end,
										struct tcphdr **tcphdr)
{
	struct tcphdr *tcp = nh->pos;
	int hdrsize = sizeof(*tcp);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;

	*tcphdr = tcp;

	return tcp->dest;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
										void *data_end,
										struct udphdr **udp)
{
	struct udphdr *udp = nh->pos;
	int hdrsize = sizeof(*udp);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;

	*udphdr = udp;

	return udp->dest;
}

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
	if (nh_type == IPRPOTO_ICMP)
	{
		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if(bpf_ntohs(icmp->un.echo.sequence)&1) return XDP_DROP;
	}
	else if (nh_type == IPPROTO_ICMP6)
	{
		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if(bpf_ntohs(icmp6->icmp6_dataun.u_echo.sequence)&1) return XDP_DROP;
	}


	// Parsing TCP/UDP header and record into map
	if (nh_type == IPPROTO_TCP)
	{
		nh_type = parse_tcphdr(&nh, data_end, &tcph);
		struct svc_rec_t *rec = bpf_map_lookup_elem(&svc_port_map, &nh_type);
		
		if(rec) {
			lock_xadd(&(rec->count), 1);

			struct datarec pkt_event;
			pkt_event.port = nh_type;
			pkt_event.count = rec->count;
			bpf_probe_read_str(pkt_event.svc_name, sizeof(pkt_event.svc_name), rec->svc_name);

			bpf_ringbuf_output(&rx_packet_msg, &pkt_event, sizeof(pkt_event), 0);
		}

		
	}
	else if (nh_type == IPPROTO_UDP)
	{
		nh_type = parse_udphdr(&nh, data_end, &udph);
		struct svc_rec_t *rec = bpf_map_lookup_elem(&svc_port_map, &nh_type);
		
		if(rec) {
			lock_xadd(&(rec->count), 1);

			struct datarec pkt_event;
			pkt_event.port = nh_type;
			pkt_event.count = rec->count;
			bpf_probe_read_str(pkt_event.svc_name, sizeof(pkt_event.svc_name), rec->svc_name);
		
			bpf_ringbuf_output(&rx_packet_msg, &pkt_event, sizeof(pkt_event), 0);
		}

	}


	return XDP_PASS;
}

char _license[] SEC("license") = "GPL-2.0";
