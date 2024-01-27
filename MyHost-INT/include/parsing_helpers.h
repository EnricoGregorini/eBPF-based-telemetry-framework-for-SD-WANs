
#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
   struct ethhdr *eth = (struct ethhdr *)data;
   int hdr_size = sizeof(*eth);

   /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
   if ((void *)eth + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

   return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
    struct iphdr *ip = (struct iphdr *)(data + *nh_off);
    int hdr_size;

    if ((void *)ip + sizeof(*ip) > data_end)
        return -1;
    
    hdr_size = ip->ihl * 4;

    // Sanity check packet field is valid 
    if(hdr_size < sizeof(*ip))
        return -1;

    // Variable-length IPv4 header, need to use byte-based arithmetic 
    if ((void *)ip + hdr_size > data_end)
        return -1;

    *nh_off += hdr_size;
    *iphdr = ip;
    //bpf_printk("DSCP field of Inner IP header: %d\n", ip->tos);

    return ip->protocol;
}

static __always_inline int parse_iphdr_and_tos(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr, __u16 *tos) {
    struct iphdr *ip = (struct iphdr *)(data + *nh_off);
    int hdr_size;

    if ((void *)ip + sizeof(*ip) > data_end)
        return -1;
    
    hdr_size = ip->ihl * 4;

    // Sanity check packet field is valid 
    if(hdr_size < sizeof(*ip))
        return -1;

    // Variable-length IPv4 header, need to use byte-based arithmetic 
    if ((void *)ip + hdr_size > data_end)
        return -1;

    *nh_off += hdr_size;
    *iphdr = ip;
    // save the current ToS field
    *tos = ip->tos;
    // if tos is 8 (INT-packet), we must restore the default value that is 0
    /*if (ip->tos == 0x08){
        __u8 new_dscp = 0;
        ip->tos &= ~0xfc;
        ip->tos |= new_dscp << 2;
        ipv4_csum(ip);
    }*/

    return ip->protocol;
}

static __always_inline int parse_grehdr(void *data, void *data_end, __u16 *nh_off, struct gre_base_hdr **grehdr) {
    struct gre_base_hdr *gre = (struct gre_base_hdr *)(data + *nh_off);
    int hdr_size = sizeof(*gre);

    if ((void *)gre + hdr_size > data_end)
        return -1;

    *nh_off += hdr_size;
    *grehdr = gre;

    return gre->protocol;
}


static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off, struct udphdr **udphdr) {
    struct udphdr *udp = data + *nh_off;
    __be16 hdr_size = sizeof(*udp);

    if ((void *)udp + hdr_size > data_end)
        return -1;

    *nh_off += hdr_size;
    *udphdr = udp;

    int len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
    if (len < 0)
        return -1;

    return len;
}


static __always_inline int parse_tcphdr(void *data, void *data_end, __u16 *nh_off, struct tcphdr **tcphdr) {
   struct tcphdr *tcp = (struct tcphdr *)(data + *nh_off);
   int hdr_size = sizeof(*tcp);
   int len;

   if ((void *)tcp + hdr_size > data_end)
      return -1;

   len = tcp->doff * 4;
   if (len < hdr_size)
      return -1;

   // Variable-length TCP header, need to use byte-based arithmetic
   if ((void *)tcp + len > data_end)
      return -1;
   
   *nh_off += len;
   *tcphdr = tcp;

   return len;
}


static __always_inline int parse_int_hdr(void *data, void *data_end, __u16 *nh_off, struct int_shim_hdr **shimhdr_src, struct int_metadata_hdr **mdhdr_src){
    struct int_shim_hdr *shim = (struct int_shim_hdr *)(data + *nh_off);
    struct int_metadata_hdr *mdhdr = (struct int_metadata_hdr *)(data + *nh_off + sizeof(struct int_shim_hdr));
    
    int shim_hdr_size = sizeof(shim);
    int md_hdr_size = sizeof(mdhdr);

    if((void *)shim + shim_hdr_size > data_end)
        return -1;
    *shimhdr_src = shim;

    
    if ((void *)mdhdr + md_hdr_size > data_end)
        return -1;
    *mdhdr_src = mdhdr;

    *nh_off += shim_hdr_size + md_hdr_size;

    return 0;
}

static __always_inline int parse_int_mdentry(void *data, void *data_end, __u16 *nh_off, struct int_metadata_entry **mdentry_src){
    struct int_metadata_entry *mdentry = (struct int_metadata_entry *)(data + *nh_off);   
    int mdentry_size = sizeof(*mdentry);

    if((void *)mdentry + mdentry_size > data_end)
        return -1;   

    *nh_off += mdentry_size;

    *mdentry_src = mdentry;

    return 0;
}


#endif  /*  __PARSING_HELPERS_H  */