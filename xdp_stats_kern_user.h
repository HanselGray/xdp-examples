/* SPDX-License-Identifier: GPL-2.0 */

/* Used by BPF-prog kernel side BPF-progs and userspace programs,
 * for sharing xdp_stats common struct and DEFINEs.
 */
#ifndef __XDP_STATS_KERN_USER_H
#define __XDP_STATS_KERN_USER_H

/* This is the data record stored in the map */
struct datarec {
    __u16 port;
	char svc_name[16];
	__u32 count;
};

struct svc_rec_t
{
	char svc_name[16];
	__u32 count;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __XDP_STATS_KERN_USER_H */