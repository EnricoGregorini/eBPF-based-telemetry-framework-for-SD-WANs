/* Gre base header with fields: flags and upper layer protocol */
struct gre_base_hdr {
    __be16 flags;
    __be16 protocol;
} __packed;

#pragma pack(1)
struct int_shim_hdr{  // 4 Bytes
    /*
    * --> type will be 0010 0000 = 0x20
    */
    __u8 type : 4;   // 4 bit 
    __u8 G : 1;
    __u8 rsvd : 3;
    // length of the int metadata header in Bytes (10)
    __u8 length; 
    // next protocol -> UDP default (0x11 = 17) or TCP (0x06)
    __u16 next_protocol;  
};

#pragma pack(1)
struct int_metadata_hdr{  // 12 Bytes
    
    __u8 ver : 4; // (4b) set to 2
    __u8 D : 1;  // (1b)  set to 0
    __u8 E : 1;  // (1b)  set to 0
    __u8 M : 1;  // (1b)  set to 0
    __u16 R : 12;  // set to 0
    __u8 HopMLen : 5;  // length in 4-bytes word of the INT metadata entry (4 words since 16-bytes)
    __u8 rem_hop_count;  // remaining hop count (set to 0)
    
    // 2 bytes instruction bitmap
    __u16 instruction_bitmap; 
    // 2 bytes domain ID (0 is default domain ID)
    __u16 domain_ID; 
    // 2 bytes DS instructions (set to 0 by default)
    __u16 DS_instructions; 
    // 2 bytes DS flags (set to 0 by default)
    __u16 DS_flags;
};

//#pragma pack(1)
// length of the struct should be 24 bytes (6 words) 
struct int_metadata_entry{   
    __u16 node_id;
    __u16 controller_status;
    __u32 sequence_number;
    __u64 realtime_ts;
    __u64 monotonic_ts;
};


