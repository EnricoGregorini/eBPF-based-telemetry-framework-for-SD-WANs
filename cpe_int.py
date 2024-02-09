#!/usr/bin/python3
# 

########### CPE A ###################

from bcc import BPF 
import ctypes as ct
import pyroute2 
import subprocess
import numpy as np
import threading
import time
import sys

from int_event_helpers import * #sync_cpes, INTEvent, print_int_local_src_event, print_int_remote_src_event, print_int_sink_event

lost_packets = []

def get_packet_lost_event(cpu, data, size):
    global packet_lost_counter
    lost_packet_id = ct.cast(data, ct.POINTER(ct.c_uint16)).contents.value
    print("Packet lost notification received. Lost packet id:", lost_packet_id)
    lost_packets.append(lost_packet_id)

# Function to check connection from controller and update the BPF map
def check_controller_conn_periodic(bpf, key, controller_addr, interval):
    while True:
        check_controller_conn(bpf, key, controller_addr)
        time.sleep(interval)
            
# Function to check connection from controller and update the BPF map
def check_controller_conn(bpf, key, controller_addr):
    bpf_map = bpf["conn_map"]
    key = ct.c_uint32(key)
    try:
        # Ping the SD-WAN controller
        subprocess.run(["ping", "-c", "1", controller_addr], check=True, stdout=subprocess.DEVNULL)
        # If ping is successful, update the BPF map with value 1
        bpf_map[key] = ct.c_uint32(1)
    except subprocess.CalledProcessError:
        # If ping fails, update the BPF map with value 0
        bpf_map[key] = ct.c_uint32(0)  
    print("Controller connection status checked and result is", bpf_map[key])
      
def check_stats(interval=30):
    global packet_lost_counter
    while True:
        # Function to check statistics (and print them) of OWD and TWD
        check_statistics()
        if len(sink_events) > 0 and len(lost_packets) > 0:
            print("Packet lost counter:", len(lost_packets), " over a total of ", sink_events[-1]["Packet ID"])   
        save_to_file(lost_packets, "./results/PacketLoss/packet_lost_sin.json")     
        time.sleep(interval)

tunnel_int = sys.argv[1]  
ip = pyroute2.IPRoute()
src_fn, sink_fn = "tc_source", "tc_sink"

print("\nStart the eBPF kernel program\n")
start_time = time.time()
to_call = True
try:
    gre = ip.link_lookup(ifname=tunnel_int)[0]

    bpf = BPF(src_file=bpf_src_file, cflags=["-Wno-macro-redefined", "-Wno-pragma-pack"])
    fn_source = bpf.load_func(src_fn, BPF.SCHED_CLS)   
    fn_sink = bpf.load_func(sink_fn, BPF.SCHED_CLS) 
    ip = pyroute2.IPRoute()
    
    def update_time_map(cpu, data, size):
        time_adjust_map = bpf["sync_time_map"]
        key = ct.c_uint32(0)
        # update time instant on the sync map
        time_adjust_map[key] = ct.c_uint64(int(time.time()*1e9))
        
    # SINK ATTACHED TO gre1 at ingress
    ip.tc("add", "ingress", gre, "ffff:")
    ip.tc("add-filter", "bpf", gre, ":1", fd=fn_sink.fd, name=fn_sink.name, 
          parent="ffff:fff3", action="ok", classid=1 ) 
    # SOURCE ATTACHED TO gre2 at egress
    ip.tc("add", "sfq", gre, "1:")      
    ip.tc("add-filter", "bpf", gre, ":1", fd=fn_source.fd, name=fn_source.name,
           parent="1:", action="ok", classid=1)
    
    # Listening to BPF_PERF_RING_BUFFER event from kernel
    bpf["update_time_map"].open_perf_buffer(update_time_map)
    bpf["local_int_source_events"].open_perf_buffer(print_int_local_src_event)
    bpf["remote_int_source_events"].open_perf_buffer(print_int_remote_src_event)
    bpf["int_sink_events"].open_perf_buffer(print_int_sink_event) 
    bpf["owd_events"].open_perf_buffer(get_owd_event)  
    bpf["packet_lost_event"].open_perf_buffer(get_packet_lost_event)
    
    # Start a thread to run check_controller_conn every controller_interval seconds
    controller_interval = 300
    controller_thread = threading.Thread(
        target=check_controller_conn_periodic,
        args=(bpf, 0, sdwan_controller_ip, controller_interval)
    )
    controller_thread.daemon = True  # This will make the thread exit when the main program exits
    controller_thread.start()
    
    # Start a thread to calculate the statistics of last stats_interval seconds
    stats_thread = threading.Thread(
        target=check_stats,
        args=()
    )
    stats_thread.daemon = True  # This will make the thread exit when the main program exits
    stats_thread.start()
    
    try:
        while True:                     
            # Infinite loop to keep eBPF works
            bpf.perf_buffer_poll()
                   
    except KeyboardInterrupt:
        pass 

finally:
    # Detach the TC filters and sfq to the gre interface
    ip.tc("del", "ingress", gre)  # delete tc filter for sink at ingress 
    ip.tc("del", "sfq", gre)   # delete tc qdisc clsact for source at egress 
    print(f"TC filters from {gre} deleted")
