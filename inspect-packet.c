/* SPDX-License-Identifier: GPL-2.0 */
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

/* Header cursor to keep track of current parsing position */
struct hdr_cursor
{
	void *pos;
};

struct svc_rec
{
	char[16] svc_name;
	int count;
};

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, short);
	__type(value, struct svc_rec);
	__uint(max_entries, 65536);
} svc_port_map SEC(".maps");

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

// Parsing helpers 


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
int xdp_packet_inspect(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	bool is_icmp = false;

	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct icmphdr *icmphdr;
	struct icmp6hdr *icmp6hdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;

	// Tracking next header and next header type
	struct hdr_cursor nh;
	int nh_type;

	// Start pointer
	nh.pos = data;

	// Parsing eth header
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	// Parsing ip/ipv6 header
	if (nh_type == bpf_htons(ETH_P_IP))
	{
		nh_type = parse_iphdr(&nh, data_end, &iphdr);
	}
	else if (nh_type == bpf_htons(ETH_P_IPV6))
	{
		nh_type = parse_ipv6hdr(&nh, data_end, &ipv6hdr);
	}

	// Parsing ICMP/TCP/UDP header
	if (nh_type == IPRPOTO_ICMP)
	{
		nh_type = parse_icmphdr(&nh, data_end, &icmphdr);
		is_icmp = true;
	}
	else if (nh_type == IPPROTO_ICMP6)
	{
		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6hdr);
		is_icmp = true;
	}
	else if (nh_type == IPPROTO_TCP)
	{
		nh_type = parse_tcphdr(&nh, data_end, &tcphdr);
	}
	else if (nh_type == IPPROTO_UDP)
	{
		nh_type = parse_udphdr(&nh, data_end, &udphdr);
	}

	// Record information into a map
	if(!is_icmp) {
		struct svc_rec *rec;
	rec = bpf_map_lookup_elem(&svc_port_map, &key);
	}
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL-2.0";
