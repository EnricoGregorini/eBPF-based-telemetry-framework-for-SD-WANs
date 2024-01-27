#include <stddef.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if.h>

#include "../include/int_headers.h"
#include "../include/rewrite_helpers.h"
#include "../include/parsing_helpers.h"

#define trace_printk(fmt, ...) do { \
    char _fmt[] = "[SOURCE] " fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)

#define DEBUG_MODE 0
#define SEC(NAME) __attribute__((section(NAME), used))
// INT DSCP constant
#define INT_DSCP 0x02

int observe_packets(struct __sk_buff *skb);

SEC("observe")
int observe_packets(struct __sk_buff *skb) {

    __u64 ingress_ts = bpf_ktime_get_ns();
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u16 int_len = sizeof(struct int_shim_hdr) + sizeof(struct int_metadata_hdr) + sizeof(struct int_metadata_entry);
	int action = TC_ACT_OK;
	int ret;
    __u16 off = 0;

    /* for easy access we re-use the Kernel's struct definitions */
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;  
    int seq_num = 0;


    int eth_type = parse_ethhdr(data, data_end, &off, &eth);
    
    if (data_end - data == 60 || data_end - data == 42){
        // STP or ARP packets, ignore those packets
		return TC_ACT_UNSPEC;  
    } 
    trace_printk("Packet received with %d bytes \n", data_end-data);
    if (bpf_ntohs(eth_type)==2048){
        trace_printk("Packet is IP (eth_type=%d)\n", bpf_ntohs(eth_type));
    } else {
		// Not IP packet, ignore it
		return TC_ACT_UNSPEC;
	}
    
    int ip_type = parse_iphdr(data, data_end, &off, &ip);
    if (ip_type < 0)  // check if the parsing of IP header was successfully
        return TC_ACT_SHOT;
    trace_printk("IP header fields. saddr:%d, daddr:%d, proto:%d \n", ip->saddr, ip->daddr, ip->protocol);
    if (ip->saddr != __constant_htonl(0x0A0A0915) || ip->daddr != __constant_htonl(0xC0A80815))
        // Continue only for the matching source-destination end-hosts (10.10.9.21->192.168.8.21)
		return TC_ACT_UNSPEC;
 
    if (ip_type == 17){  // UDP PACKET
        int len = parse_udphdr(data, data_end, &off, &udp);
        if (len < 0)
            return TC_ACT_SHOT;
        trace_printk("UDP len is %d", bpf_ntohs(udp->len));
    } else if (ip_type == 6) {   // TCP PACKET
		int len = parse_tcphdr(data, data_end, &off, &tcp);
		if (len < 0)
			return TC_ACT_SHOT;
		trace_printk("TCP len is %d", bpf_ntohs(tcp->len));
	} else {
		// Ignore not UDP or TCP packets at Level 4
		return TC_ACT_UNSPEC;
	}
    
    if ((data_end - data) + int_len > 1400){
		trace_printk("Not enough space to add INT section for the tunnel MTU, ignore the packet");
		return TC_ACT_UNSPEC;
	}

    // Modify DSCP field of IPv4 header to notify the presence of INT metadata inside the packet
	__u8 new_dscp = INT_DSCP;
	//mod_dscp_ipv4(ip, new_dscp);
	ip->tos &= ~0xfc;
    ip->tos |= new_dscp << 2;
	ipv4_csum(ip);
	
	 /*
     * Grow room for INT data in the packet associated to skb by length
     * BPF_ADJ_ROOM_NET: Adjust room at the network layer
     *  (new bytes are added just after the layer 3 header).
     */
    ret = bpf_skb_adjust_room(skb, int_len, BPF_ADJ_ROOM_NET, 0);
    if (ret < 0) {
        trace_printk("Failed (%d) to bpf_skb_adjust_room by %d - dropping packet\n",
                   			ret, int_len);
		return TC_ACT_SHOT;
	} else {
#if DEBUG_MODE
		trace_printk("bpf_skb_adjust_room (int_len=%d) success. Current length of packet is: %d\n", int_len, (void *)(long)skb->data_end - (void *)(long)skb->data);
#endif	
	}

	struct int_shim_hdr shim_hdr = {
		.type = 2,
		.G = 0,
		.rsvd = 0,
		.length = 3,  // metadata header is 12-bytes long (3 words)
		.next_protocol = bpf_htons(0x11),
	};  
	struct int_metadata_hdr md_hdr = {
		.ver = 2,
		.D = 0,
		.E = 0,
		.M = 0,
		.R = 0,
		.HopMLen = 4,
		.rem_hop_count = 0,
		.instruction_bitmap = bpf_htons(0x0000),
		.domain_ID = bpf_htons(0),
		.DS_instructions = bpf_htons(0),		
		.DS_flags = bpf_htons(0),
	};  
	__u32 egress_ts = (__u32)bpf_ktime_get_ns();
	// Create the metadata entry to insert
	struct int_metadata_entry mdentry = {
		.node_id = (1),
		.seq_num = (seq_num),
		//.ingress_port_id = skb->ifindex,   // No need to convert the ingress network interface since it is already in network byte order
		//.egress_port_id = skb->ifindex,    // same for egress network interface
		.ingress_ts = (ingress_ts),
		.egress_ts = (egress_ts),
	};

	__u16 store_bytes_offset = sizeof(struct ethhdr) + sizeof(struct iphdr); // + sizeof(struct iphdr);

	// insert the shim header in the packet
	ret = bpf_skb_store_bytes(skb, store_bytes_offset, &shim_hdr, sizeof(struct int_shim_hdr), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		trace_printk("Failed to insert int shim header\n");
		return TC_ACT_UNSPEC;
	}
	store_bytes_offset += sizeof(struct int_shim_hdr);  // update the offset

	// insert the metadata header
	ret = bpf_skb_store_bytes(skb, store_bytes_offset, &md_hdr, sizeof(struct int_metadata_hdr), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		trace_printk("Failed to insert int metadata header\n");
		return TC_ACT_UNSPEC;
	}
	store_bytes_offset += sizeof(struct int_metadata_hdr); //update the offset
	//mdentry.egress_ts = bpf_htonl(bpf_ktime_get_ns());
	// Insert the metadata entry struct in the packet in the room created by bpf_skb_adjust_room
	ret = bpf_skb_store_bytes(skb, store_bytes_offset, &mdentry, sizeof(struct int_metadata_entry), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		trace_printk("Failed to store bytes\n");
		return TC_ACT_UNSPEC;
	} else {
		trace_printk("Metadata entry of source node are: node_id = %d; seq_num = %d\n", mdentry.node_id, mdentry.seq_num);
    	trace_printk("ingress_ts = %llu; egress_ts = %llu\n", (mdentry.ingress_ts), (mdentry.egress_ts));
	}

	int gre_int_index = 10; 
	return bpf_redirect(gre_int_index, 0);   // redirect to gre1 interface
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";