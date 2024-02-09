/*
 * This file contains functions that are used in the TC and XDP programs to
 * manipulate on packets data. The functions are marked as __always_inline, and
 * fully defined in this header file to be included in the BPF program.
 */

#ifndef __REWRITE_HELPERS_H
#define __REWRITE_HELPERS_H

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline void ipv4_csum(struct iphdr *iph)
{
    __u32 csum;

    iph->check = 0;
    csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0);
    iph->check = csum_fold_helper(csum);
}


static __always_inline void mod_dscp_ipv4(struct iphdr *iph, __u8 dscp)
{
    iph->tos &= ~0xfc;
    iph->tos |= dscp << 2;
}

#endif
