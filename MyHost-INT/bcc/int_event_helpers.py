import ctypes as ct
import subprocess
import numpy as np
import json
import time
#from include.shared_variables import * 

import numpy as np
import netifaces as ni
import pandas as pd

# Create Arrays for storing INT metadata from packets
remote_src_events = []  # Local source event (packet) for Two-Way calculation (source->sink->source)
local_src_events = []   # Remote source event (packet) sent by the source to the sink (source->sink)
sink_events = []  # Sink event (packet) received by the sink
owd_records = np.array([])  # One-Way Delay arrays (each entry is a packet received by sink)
twd_records = np.array([])  # Two-Way Delay arrays (each entry is a packet received by sink)
file_freq = 10**6  # Frequency of saving INT events to a file

local_addr = ni.ifaddresses('gre1')[ni.AF_INET][0]['addr']
bpf_src_file = "int_cpeA_kern.c" if local_addr == "10.0.0.1" else "int_cpeB_kern.c"
owd_filename = "results/PacketLoss/int_owd_sin.json"   #"results/PacketLoss/int_BtoA_owd_records.json" if local_addr == "10.0.0.1" else "results/PacketLoss/int_AtoB_owd_records.json"
twd_filename = "results/PacketLoss/int_twd_sin.json" 
sdwan_controller_ip = "10.10.5.253"    # IP of SD-WAN controller to check the connection status with current CPE

owd_statistics = pd.DataFrame(columns=['Min', 'Max', 'Average', 'Std Dev'])  # Dictionary to store statistics of OWD 
twd_statistics = pd.DataFrame(columns=['Min', 'Max', 'Average', 'Std Dev'])  # Dictionary to store statistics of TWD

test = "owd"  # Test to perform (owd or twd)

class INTEvent(ct.Structure):
    _fields_ =  [("node_id", ct.c_uint16),
                    ("controller_status", ct.c_uint16),
                    ("sequence_number", ct.c_uint32),
                    ("realtime_ts", ct.c_uint64),
                    ("monotonic_ts", ct.c_uint64)]
  
           
# Calculate minimum, maximum, average, and standard deviation of numpy array data
def calculate_owd_statistics(data, name):
    global owd_statistics
    # Filter unspurious values (delay higher than 2s are not considered as in Ping)
    data = data[(data >= 0) & (data <= 100)]
    min_value = np.min(data)
    max_value = np.max(data)
    avg_value = np.mean(data)
    std_dev = np.std(data)
    
    # Create a new DataFrame for the row
    new_row = pd.DataFrame({'Min': [min_value], 'Max': [max_value], 'Average': [avg_value], 'Std Dev': [std_dev]})
    # Concatenate the new row to the existing DataFrame
    owd_statistics = pd.concat([owd_statistics, new_row], ignore_index=True)    
    print(name)
    print(owd_statistics)

# Calculate minimum, maximum, average, and standard deviation of numpy array data
def calculate_twd_statistics(data, name):
    global twd_statistics
    # Filter unspurious values (delay higher than 2s are not considered as in Ping)
    data = data[(data >= 0) & (data <= 100)]
    min_value = np.min(data)
    max_value = np.max(data)
    avg_value = np.mean(data)
    std_dev = np.std(data)
    # Create a new DataFrame for the row
    new_row = pd.DataFrame({'Min': [min_value], 'Max': [max_value], 'Average': [avg_value], 'Std Dev': [std_dev]})
    # Concatenate the new row to the existing DataFrame
    twd_statistics = pd.concat([twd_statistics, new_row], ignore_index=True)    
    print(name)
    print(twd_statistics)  
 
# Function to save INT events to a JSON file
def save_to_file(data, filename):
    with open(filename, 'w') as file:
        for dictionary in data:
            json.dump(dictionary, file)
            file.write('\n')  # Add a newline to separate entries
            
def print_int_local_src_event(cpu, data, size):
    int_event = ct.cast(data, ct.POINTER(INTEvent)).contents
    event = {
        "Node ID": (int_event.node_id),
        "Controller Status": (int_event.controller_status),
        "Packet ID": (int_event.sequence_number),
        "Realtime TS": (float(int_event.realtime_ts)/10**6),
        "Monotonic TS": (float(int_event.monotonic_ts)/10**6)
    }
    local_src_events.append(event)
    # Serialize data to JSON file
    if len(local_src_events) % file_freq == 0:
        save_to_file(local_src_events, "results/local_src_metadata.json")

def print_int_remote_src_event(cpu, data, size):
    int_event = ct.cast(data, ct.POINTER(INTEvent)).contents
    event = {
        "Node ID": (int_event.node_id),
        "Controller Status": (int_event.controller_status),
        "Packet ID": (int_event.sequence_number),
        "Realtime TS": (float(int_event.realtime_ts)/10**6),
        "Monotonic TS": (float(int_event.monotonic_ts)/10**6)
    }
    remote_src_events.append(event)
    # Serialize data to JSON file
    if len(remote_src_events) % file_freq == 0:
        save_to_file(remote_src_events, "results/remote_src_metadata.json")

        
def print_int_sink_event(cpu, data, size):
    int_event = ct.cast(data, ct.POINTER(INTEvent)).contents
    event = {
        "Node ID": (int_event.node_id),
        "Controller Status": (int_event.controller_status),
        "Packet ID": (int_event.sequence_number),
        "Realtime TS": (float(int_event.realtime_ts)/10**6),
        "Monotonic TS": (float(int_event.monotonic_ts)/10**6)
    }
    sink_events.append(event)
    # Serialize data to JSON file
    if len(sink_events) % file_freq == 0:
        save_to_file(sink_events, "results/sink_metadata.json")
         
    if test == "twd":
        # get the Two-Way Delay measurement from the monotonic clock difference
        global twd_records  # Declare twd_records as a global variable
        if len(sink_events) > 0 and len(local_src_events) > 0:
            twd = sink_events[-1]["Monotonic TS"] - local_src_events[-1]["Monotonic TS"]
            twd_records = np.append(twd_records, twd)
            if test == "twd" and len(twd_records) % 1000 == 0:
                print(f"Two-Way Delay (TWD) for the last packet: {twd} [ms]")
            # Serialize data to JSON file
            if len(twd_records) % file_freq == 0 and test == "twd":
                save_to_file(twd_records, twd_filename)
   
    
def get_owd_event(cpu, data, size):
    global owd_records  # Declare owd_records as a global variable
    owd = ct.cast(data, ct.POINTER(ct.c_uint64)).contents.value / 10**6
    owd_records = np.append(owd_records, owd)
    if test == "owd" and len(owd_records) % 1000 == 0:
        print(f"One-Way Delay (OWD) for the last packet: {owd} [ms]")
    # Serialize data to JSON file
    if len(owd_records) % file_freq == 0 and test == "owd":
        save_to_file(owd_records, owd_filename)

    
# Function to periodically print statistics about the delay
def check_statistics():
    global owd_records, twd_records
    print()
    # Print the average of One-Way and Two-Way delay every n packets
    if test == "owd" and len(owd_records):
        calculate_owd_statistics(owd_records, "One-Way Delay")
    if test == "twd" and len(twd_records):    
        calculate_twd_statistics(twd_records, "Two-Way Delay")
