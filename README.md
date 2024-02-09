# Enrico Gregorini MS Thesis 

## SD-WAN INT 
SD-WAN INT (In-band Network Telemetry) is a telemetry framework designed to enhance the monitoring capabilities of SD-WANs (Software-Defined Wide Area Networks). This project focuses on manipulating packets at the Customer Premises Equipment (CPE) level within the SD-WAN infrastructure. The primary goal is to ensure secure transmission of business traffic by encrypting and encapsulating packets within tunnels, while concurrently embedding essential telemetry and monitoring metadata.

## Description
In the dynamic landscape of SD-WANs, understanding and troubleshooting network performance is paramount. SD-WAN INT addresses this need by introducing a comprehensive telemetry framework that seamlessly integrates with the existing SD-WAN architecture.

### Key Features
- **Packet Encryption and Encapsulation**: SD-WAN INT encrypts business traffic packets and encapsulates them within tunnels, ensuring the confidentiality and integrity of the transmitted data.

- **Telemetry Metadata Insertion**: The framework inserts telemetry and monitoring metadata into the packets, providing crucial insights into the network's behavior. This metadata serves as a valuable resource for troubleshooting and performance optimization.

- **In-band Network Telemetry with eBPF**: Leveraging eBPF (extended Berkeley Packet Filter) attached to Traffic Control (TC) hooks of the tunnel interface in CPEs, SD-WAN INT implements In-band Network Telemetry. This approach allows real-time monitoring and data collection without introducing additional network overhead.

### Background
To delve deeper into SD-WANs and In-band Network Telemetry, refer to the following resources:

- [SD-WAN Overview](https://www.example-sdwan-reference.com): Familiarize yourself with the fundamentals of SD-WAN technology and its significance in modern networking.

- [eBPF Documentation](https://www.example-ebpf-reference.com): Explore the capabilities of eBPF and how it can be utilized for efficient packet filtering and manipulation.

## Requirements
The eBPF code has been compiled and tested on this Linux distribution:
- Ubuntu 20.04 

The preferred Linux kernel version is 5.15 or higher.
We plan to test and add support for other Linux distributions in future releases.


# Installation

## Building the project from source code
To obtain a copy of this project:
```
git clone https://gitlab.com/master-thesis-bonsai-polimi/enrico-gregorini.git
```
For the installation section of the project, first of all we move in the scripts folder:
```
cd MyHost-INT/scripts
```

To install packages that are needed in order to compile the SD-WAN INT code, : 
```
# For Ubuntu 20.04
sudo ./build_setup_ubuntu.sh
```

The following command installs the version of the [libbpf
library](https://github.com/libbpf/libbpf) that this project has been
tested with:
```
sudo ./install_libbpf.sh
```

A very useful set of tools [bpftool](https://github.com/libbpf/bpftool/blob/main/README.md) has been used in order to work with eBPF, the following command download and install this library:
```
sudo ./install_bpftool.sh
```

# Configuration

## Establish IPSec over GRE tunnel between CPEs
In the scripts folder there is a bash script that has been developed to automate and scale the creation of tunnels between CPEs. These are basically L3 GRE tunnel where IPSec will be configured in order to exchange encrypted and secure information. 

The script file needs a file containing a set of ip addresses and IP subnet that will be part of the SD-WAN architecture. In the "/home/bonsai" folder you must write a tunnel configuration file named *addresses.txt* containing exactly 6 lines. An example of this file is:
```
10.10.9.11
192.168.8.11
10.0.0.1
10.0.0.2
10.10.9.0/24
192.168.8.0/24
```

where the 6 lines representes respectively:

- IP public address of the local CPE 
- IP public address of the remote CPE
- IP GRE tunnel address of the local CPE
- IP GRE tunnel address of the remote CPE
- Local subnet connected to the current CPE (source end-hosts)
- Remote subnet connected to the remote CPE (destination end-hosts)

After having created and tuned the tunnel configuration file, in the scripts folder it is possible to execute the tunnel script in the first CPE, passing as argument the Pre-Shared Key (PSK) for the IPSec tunnel:
```
./sudo sdwan_tunnel.sh "PSK"
```

The process has to be re-execute on the other endpoint of the tunnel (remote CPE) with every parameter in the opposite order. For example, the *addresses.txt* file in the second CPE will be:
```
192.168.8.11
10.10.9.11
10.0.0.2
10.0.0.1
192.168.8.0/24
10.10.9.0/24
```

**Note that the PSK key must be the same for both CPEs in order to correctly establish the IPSec tunnel.**

## Reduce MTU and MSS
SD-WAN INT adds at least 40 Bytes of headers (16 Bytes of INT headers + 24 Bytes of INT metadata) to selected IPv4+TCP or IPv4+UDP packets. The INT module cannot add these section if this would cause the modified packet to increase in size above the MTU configured for the outgoing interface (INT source).

Since the system uses tunnels to exchange information between the LANs of the network, it must also take into account the overhead and headers inserted by the tunnelling technology:
- **GRE** adds 24 Bytes of headers (20 Bytes of new IPv4 header and 4 Bytes of GRE header).
- **IPSec** adds 8 Bytes of ESP header to include the key and a sequence number for the packets exchanged and approximately additional 100 Bytes for encryption purposes. 

In the end, for now the optimal MTU for this system is set to 1300 Bytes so that no packets need to be fragmented or lost during the INT modification. To modify the MTU of the system it is sufficient to change it on the LAN interface of one of the end-hosts using the following command (supposing interface `eth0` is the one connecting to the CPE):
```
ip link set dev eth0 mtu 1300
```

## Enabling CPEs to send packets with INT section
Executing the user-space application int_cpeX_user.py should be done on all CPEs where you wish to be able to send and receive packets wth INT telemetry headers added to business traffic. This python script will load two eBPF programs, tc_source and tc_sink, that will add and extract respectively those INT metadata before the packets are processed by the Linux Kernel networking code. 

For example, suppose we have to start the python application on CPE A; first we need to move on the bcc folder and then start as usual a python3 script.

## Run the `cpe_int.py` application
```
cd MyHost-INT/bcc/
sudo python3 cpe_int.py gre1
```
The same command needs to be executed also on the other CPE (endpoint of the SD-WAN tunnel). Note that "gre1" is the network interface of the GRE tunnel where INT will be applied.

First of all, this python program will call another script to calculate the time difference in terms of Linux Kernel MONOTONIC_CLOCK between the two CPEs that will exchange traffic and use this time_delta to synchronize the devices to get quite precise results. 

Then it automatically checks the status of the connection to the SDWAN controller (ip address to configure in the file "bcc/include/shared_variables.py) and sends a flag to the kernel-space programs through an eBPF Hash Map.

Finally it manages every INT metadata collected and extracted from packets and calculate:
- One-Way Delay (OWD) in ms calculated as the difference between the ingress timestamp of the sink and the egress timestamp of the source.
- Two-Way Delay (TWD) in ms calculated as the difference between the ingress timestamp of the returned packet in the source and the ingress timestamp of the original packet. 


# Usage

# Support
Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

# Authors 
- Enrico Gregorini 

