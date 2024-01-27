
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if.h>

#include "../include/int_headers.h"
#include "../include/parsing_helpers.h"
#include "../include/rewrite_helpers.h"


// Define a BPF map with key and value types
BPF_HASH(conn_map, u32, u16);    // Hash Map to store the flag of the controller connection status
BPF_HASH(src_packet_counter, u32, u16);   // Hash map to store the packet counter to sample INT-packets sent
BPF_HASH(sync_time_map, u32, u64);   // Hash map to store the synchronization time between monotonic and realtime clock
BPF_HASH(rcv_packet_counter, u32, u16);   // Hash map to store the packet counter to sample INT-packets received

BPF_PERF_OUTPUT(packet_lost_event);   // Perf event to notify the packet lost
BPF_PERF_OUTPUT(update_time_map);

// Define BPF_PERF_EVENTS to pass INT metadat to user-space application
BPF_PERF_OUTPUT(local_int_source_events);
BPF_PERF_OUTPUT(remote_int_source_events);
BPF_PERF_OUTPUT(int_sink_events);
BPF_PERF_OUTPUT(owd_events);

//#define SEC(NAME) __attribute__((section(NAME), used))
#define DEBUG_MODE 0   // set to 1 to enable debug, otherwise 0
// INT DSCP constant
#define INT_DSCP 0x02  
#define N 1   // number of packets to sample for INT

int tc_source(struct __sk_buff *skb);
int tc_sink(struct __sk_buff *skb);

/******* SOURCE SECTION ****************/
int tc_source(struct __sk_buff *skb)
{
    u32 key = 0;   // key for both Hash Map (controller connection and packet counter)
    update_time_map.perf_submit(skb, &key, sizeof(u32)); // send the key to user-space application to update the sync_time_map

	__u64 monotonic_clk = bpf_ktime_get_ns();
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	const __u16 int_len = sizeof(struct int_shim_hdr) + sizeof(struct int_metadata_hdr) + sizeof(struct int_metadata_entry); 
	int ret;
    /*************** BPF MAPS ********************/
    u16 start_count = 0;
    u16 *src_counter;

    u64 *realtime_clk = sync_time_map.lookup(&key);  // find the synchronization time between monotonic and realtime clock
    if (realtime_clk){   
        #if DEBUG_MODE
        bpf_trace_printk("Ingress timestamp is %llu \n", *realtime_clk);
        #endif
    } else {
        return TC_ACT_SHOT;
    }

    // Load the value from the map into a register using bpf_map_lookup_elem()
    src_counter = src_packet_counter.lookup(&key);
    // Check if src_counter is null
    if (!src_counter) {
        src_packet_counter.update(&key, &start_count);   // Initialize the counter to 1
        src_counter = src_packet_counter.lookup(&key);
    } 
      
    u16 *contr_status;
    contr_status = conn_map.lookup(&key);  // find if the controller is correctly connected 
    if (contr_status){
        #if DEBUG_MODE
        bpf_trace_printk("The controller connection is %d \n", *contr_status);
        #endif 
    }

    /********************* END BPF MAPS ***********************/

	bpf_trace_printk("[SOURCE] Packet received with %d bytes\n", data_end-data);
	if (data + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
		bpf_trace_printk("Memory exceeded\n");
		return TC_ACT_UNSPEC;
	}

	/* for easy access we re-use the Kernel's struct definitions */
	struct iphdr *ip  = data;
	struct udphdr *udp; //  = (data + sizeof(struct iphdr));
	struct tcphdr *tcp; //  = (data + sizeof(struct iphdr));

    __u16 offset = 0;
    int ip_type = parse_iphdr(data, data_end, &offset, &ip);
    if (ip_type < 0)  return TC_ACT_SHOT;

    // for CPE A
    /*if ((ip->saddr == __constant_htonl(0x0a000001) && ip->daddr == __constant_htonl(0x0a000002)) || // gre1 address
        (ip->saddr == __constant_htonl(0x0a000101) && ip->daddr == __constant_htonl(0x0a000102)) || // gre2 addresses
		(ip->saddr == __constant_htonl(0x0a000201) && ip->daddr == __constant_htonl(0x0a000202))) {  // gre3 addresses
    */
    // for CPE B
    if ((ip->saddr == __constant_htonl(0x0a000002) && ip->daddr == __constant_htonl(0x0a000001)) || // gre1 address
        (ip->saddr == __constant_htonl(0x0a000102) && ip->daddr == __constant_htonl(0x0a000101)) || // gre2 addresses
		(ip->saddr == __constant_htonl(0x0a000202) && ip->daddr == __constant_htonl(0x0a000201))) {  // gre3 addresses
#if DEBUG_MODE
		// src_addr=10.10.9.21 and dst_addr=192.168.8.21 or src_addr=10.0.0.5 and dst_addr=10.0.0.8
        bpf_trace_printk("Packet destined to 192.168.8.21, let's insert INT metadata! saddr:%d; daddr:%d\n", __constant_ntohl(ip->saddr), __constant_ntohl(ip->daddr));
#endif
    } else {
#if DEBUG_MODE
		bpf_trace_printk("Not src-dst correct, pass! saddr:%d; daddr:%d\n", __constant_ntohl(ip->saddr), __constant_ntohl(ip->daddr));
#endif
		return TC_ACT_UNSPEC;
	}

	/* We check L4 protocol */
	if (ip_type == 17){
        int udp_len = parse_udphdr(data, data_end, &offset, &udp);
        if (udp_len < 0)   return TC_ACT_SHOT;
#if DEBUG_MODE
		bpf_trace_printk("Packet is UDP with src_port:%d and dst_port:%d\n", udp->source, udp->dest);
#endif	
		if(udp->source==62465 || udp->dest==62465){  // ISAKMP packets
#if DEBUG_MODE
			bpf_trace_printk("IPSec tunnel configuration packet (ISAKMP), ignore it! \n");
#endif
			return TC_ACT_UNSPEC;
		}	
	} else if (ip_type == 6) {
#if DEBUG_MODE
		bpf_trace_printk("Packet is TCP\n");
#endif
        int tcp_len = parse_tcphdr(data, data_end, &offset, &tcp);
		if (tcp_len < 0)   return TC_ACT_SHOT;
        //int seq_num = tcp->seq;  // save the sequence number of the packet for INT metadata
	} else if (ip_type == 50) {
#if DEBUG_MODE
		bpf_trace_printk("Packet is ESP\n");
#endif       
    } else {
#if DEBUG_MODE
		bpf_trace_printk("Packet is neither TCP nor UDP nor ESP, ignore it");
#endif
		return TC_ACT_UNSPEC;
	}

    // The packet is a valid INT packet, so we can update the packet counter
    if (src_counter) {    
        // Every N packets modify with INT section
        if (*src_counter % N != 0){
            // Skip the packet if it's not the Nth packet
            #if DEBUG_MODE
            bpf_trace_printk("This is the %d-th packet, skip it", *src_counter);
            #endif            
            (*src_counter)++;
            src_packet_counter.update(&key, src_counter);   // Update the counter
            return TC_ACT_UNSPEC;
        }  
        #if DEBUG_MODE
        bpf_trace_printk("This is the Nth packet (%d), ADD INT SECTION from source", *src_counter); 
        #endif
        (*src_counter)++;
        src_packet_counter.update(&key, src_counter);   // Update the counter
    }

	// Modify DSCP field of IPv4 header to notify the presence of INT metadata inside the packet
	__u8 new_dscp = INT_DSCP;
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
        bpf_trace_printk("Failed (%d) to bpf_skb_adjust_room by %d - dropping packet\n",
                   			ret, int_len);
		return TC_ACT_SHOT;
	} else {
		//bpf_trace_printk("bpf_skb_adjust_room success. Current length of packet is: %d\n", (void *)(long)skb->data_end - (void *)(long)skb->data);
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

    if (src_counter) {
        #if DEBUG_MODE
        bpf_trace_printk("Packet counter is %d\n", *src_counter);
        #endif
    } else {
        bpf_trace_printk("Packet counter is NULL\n");
        return TC_ACT_UNSPEC;
    }
    // Create the metadata entry to insert
	struct int_metadata_entry mdentry = {
		.node_id = *src_counter,
		.controller_status = (contr_status ? *contr_status : 0),
		.tunnel_id = skb->ifindex,   
		.realtime_ts = (*realtime_clk),
		.monotonic_ts = (monotonic_clk),
	};

	__u16 store_bytes_offset = sizeof(struct iphdr);

	// insert the shim header in the packet
	ret = bpf_skb_store_bytes(skb, store_bytes_offset, &shim_hdr, sizeof(struct int_shim_hdr), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		bpf_trace_printk("Failed to insert int shim header\n");
		return TC_ACT_UNSPEC;
	}
	store_bytes_offset += sizeof(struct int_shim_hdr);  // update the offset

	// insert the metadata header
	ret = bpf_skb_store_bytes(skb, store_bytes_offset, &md_hdr, sizeof(struct int_metadata_hdr), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		bpf_trace_printk("Failed to insert int metadata header\n");
		return TC_ACT_UNSPEC;
	}
	store_bytes_offset += sizeof(struct int_metadata_hdr); //update the offset
	// Insert the metadata entry struct in the packet in the room created by bpf_skb_adjust_room
	ret = bpf_skb_store_bytes(skb, store_bytes_offset, &mdentry, sizeof(struct int_metadata_entry), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		bpf_trace_printk("Failed to store bytes\n");
		return TC_ACT_UNSPEC;
	} else {
#if DEBUG_MODE
		/* bpf_trace_printk("Metadata entry of source node are: node_id = %d; controller_status = %d\n", mdentry.node_id, mdentry.controller_status);
    	bpf_trace_printk("realtime_clock = %llu; monotonic_clock = %llu\n", (mdentry.realtime_ts), (mdentry.monotonic_ts));*/
#endif
	}

int_out:
    local_int_source_events.perf_submit(skb, &mdentry, sizeof(struct int_metadata_entry));
    return TC_ACT_UNSPEC;
}

/************ SINK SECTION ********************/

int tc_sink(struct __sk_buff *skb) 
{
    u32 key = 0;   // key for both Hash Map (controller connection and packet counter)
    update_time_map.perf_submit(skb, &key, sizeof(u32)); // send the key to user-space application to update the sync_time_map

	__u64 monotonic_clk = bpf_ktime_get_ns();
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u16 int_len = sizeof(struct int_shim_hdr) + sizeof(struct int_metadata_hdr) + sizeof(struct int_metadata_entry);
	int action = TC_ACT_OK;
	int ret;
    __u16 off = 0;

    /*************** BPF MAPS ********************/
    u16 start_count = 1;

    u64 *realtime_clk = sync_time_map.lookup(&key);  // find the synchronization time between monotonic and realtime clock
    if (realtime_clk){   
        #if DEBUG_MODE
        bpf_trace_printk("Ingress timestamp is %llu \n", *realtime_clk);
        #endif
    } else {
        return TC_ACT_SHOT;
    }

    u16 *rec_counter = rcv_packet_counter.lookup(&key);   // find the packet counter to sample INT-packets received
    if (!rec_counter) {
        rcv_packet_counter.update(&key, &start_count);   // Initialize the counter to 1
    } 
    /**************** END BPF MAPS ****************/

    bpf_trace_printk("[SINK] Packet received with %d bytes \n", data_end-data);

    /* for easy access we re-use the Kernel's struct definitions */
    struct iphdr *ip = data;
    struct gre_base_hdr *gre;
    struct iphdr *inner_ip;
    struct int_metadata_entry *mdentry_source; 
    struct int_metadata_entry mdentry_source_cpy = {};
    struct int_metadata_entry mdentry_sink = {};
    struct udphdr *udp;  
    struct tcphdr *tcp;  

    int ip_type = parse_iphdr(data, data_end, &off, &ip);

    if (ip_type == 6) {
        #if DEBUG_MODE
        bpf_trace_printk("Packet is TCP (save the sequence number for RTT calculation) \n");
        #endif
        //int seq_num = tcp->seq;
    } 
    else if (ip_type == 17) {
        #if DEBUG_MODE
        bpf_trace_printk("Packet is UDP \n");
        #endif
    } else if(ip_type == 50) { 
        #if DEBUG_MODE
		bpf_trace_printk("Packet is ESP, encrypted packet of IPSec tunnel\n");
        #endif
	} else {
        bpf_trace_printk("Packet is neither UDP nor TCP, ignore it! (L3 protocol = %d)\n", ip_type);
        return TC_ACT_UNSPEC;
    }

    if (ip->tos != 0x08){
        //Packet does not contain INT metadata
        bpf_trace_printk("Packet does not contain INT metadata \n");
        action = TC_ACT_OK;
        return action;
    }
    /* Packet contains INT metadata
    *  First thing is modify ToS field to notify that INT part have been managed (set to 0 default value) and removed
    */
    #if DEBUG_MODE
    bpf_trace_printk("Packet contains INT metadata!");
	#endif 
    __u8 new_dscp = 0;
	ip->tos &= ~0xfc;
    ip->tos |= new_dscp << 2;
	ipv4_csum(ip);
    
    // Manage INT header and metadata
    struct int_shim_hdr *shimhdr_src;  // = (data + sizeof(struct iphdr));
    struct int_metadata_hdr *mdhdr_src; // = (data + sizeof(struct iphdr) + sizeof(struct int_shim_hdr));

    if (parse_int_hdr(data, data_end, &off, &shimhdr_src, &mdhdr_src) < 0){
        bpf_trace_printk("Failed to parse INT header\n");
        action = TC_ACT_OK;
        return action;
    }
    #if DEBUG_MODE
    else {
        bpf_trace_printk("INT header parsed successfully\n");
    }
    #endif
    if (parse_int_mdentry(data, data_end, &off, &mdentry_source) < 0){
        bpf_trace_printk("Failed to parse INT metadata entry\n");
        action = TC_ACT_OK;
        return action;
    } 
    #if DEBUG_MODE
    else {
        bpf_trace_printk("INT metadata entry parsed successfully\n");
    }
    #endif

    
    // Build the metadata entry 
    if(rec_counter)
        mdentry_sink.node_id = *rec_counter;
    else
        mdentry_sink.node_id = 0;   
    mdentry_sink.controller_status = mdentry_source->controller_status;
    mdentry_sink.tunnel_id = (skb->ifindex);
    mdentry_sink.realtime_ts = *realtime_clk;
    mdentry_sink.monotonic_ts = monotonic_clk;  

    // Convert the fields of the metadata entry to host byte order
    /* mdentry_source->node_id = (mdentry_source->node_id);
    mdentry_source->controller_status = (mdentry_source->controller_status);
    mdentry_source->tunnel_id = (mdentry_source->tunnel_id);
    mdentry_source->realtime_ts = (mdentry_source->realtime_ts);
    mdentry_source->monotonic_ts = (mdentry_source->monotonic_ts); */

    /* Make a copy of metadata source for passing it to user-space correctly */
    mdentry_source_cpy.node_id = mdentry_source->node_id;
    mdentry_source_cpy.controller_status = mdentry_source->controller_status;
    mdentry_source_cpy.tunnel_id = mdentry_source->tunnel_id;
    mdentry_source_cpy.realtime_ts = mdentry_source->realtime_ts;
    mdentry_source_cpy.monotonic_ts = mdentry_source->monotonic_ts;

#if DEBUG_MODE
    bpf_trace_printk("Metadata entry of source node are: node_id = %d; controller_status = %d\n", 
                    mdentry_source->node_id, mdentry_source->controller_status);
    bpf_trace_printk("realtime clock = %llu; monotonic clock = %llu\n", 
                    mdentry_source->realtime_ts, mdentry_source->monotonic_ts);

    bpf_trace_printk("Metadata entry of sink node are: node_id = %d; controller_status = %d\n", 
                    mdentry_sink.node_id, mdentry_sink.controller_status);
    bpf_trace_printk("realtime_ts = %llu; monotonic_ts = %llu\n", 
                    mdentry_sink.realtime_ts, mdentry_sink.monotonic_ts);
#endif

    if(!rec_counter)
        return TC_ACT_UNSPEC;
    else 
        bpf_trace_printk("Current packet id = %d; rec_counter = %d\n", mdentry_source->node_id, *rec_counter);
    // Check if there are no packet lost through the rec packet counter
    if (mdentry_source->node_id - *rec_counter > 1){
        bpf_trace_printk("Packet lost! Current packet id = %d; rec_counter = %d\n", mdentry_source->node_id, *rec_counter);
        u32 packet_lost = mdentry_source->node_id - *rec_counter - 1;
        packet_lost_event.perf_submit(skb, &packet_lost, sizeof(u32));
    }
    rcv_packet_counter.update(&key, &mdentry_source->node_id);   // Update the counter
    if(rcv_packet_counter.lookup(&key)){
        #if DEBUG_MODE
        bpf_trace_printk("Packet counter updated to %d\n", *rec_counter);
        #endif
    } else {
        bpf_trace_printk("Packet counter is NULL\n");
        return TC_ACT_UNSPEC;
    }
    
    u64 owd = 0;
    if (mdentry_sink.realtime_ts < mdentry_source->realtime_ts) {
        owd = mdentry_source->realtime_ts - mdentry_sink.realtime_ts;
    } else {
        owd = mdentry_sink.realtime_ts - mdentry_source->realtime_ts;
    }
    /*
    * Shrink (we pass 0-int_len that is negative) room to remove the INT metadata
    * BPF_ADJ_ROOM_NET: Adjust room at the network layer
    *  (new bytes are removed just between l3 and l4 layer).
    */
    ret = bpf_skb_adjust_room(skb, 0-int_len, BPF_ADJ_ROOM_NET, 0);
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;

    if (ret < 0) {
        bpf_trace_printk("INT headers extraction failed, drop the packet!");
		action = TC_ACT_SHOT;
		return action;
	} else {
        #if DEBUG_MODE
        bpf_trace_printk("INT headers (int_len=%d) removed from the packet successfully\n", int_len);
        #endif
        goto int_out;
    }

int_out:
    remote_int_source_events.perf_submit(skb, &mdentry_source_cpy, sizeof(struct int_metadata_entry));
    int_sink_events.perf_submit(skb, &mdentry_sink, sizeof(struct int_metadata_entry));
    owd_events.perf_submit(skb, &owd, sizeof(u64));
    //bpf_trace_printk("Packet has been modified!, size of packet = %d\n", data_end-data);
    return TC_ACT_OK;
}
