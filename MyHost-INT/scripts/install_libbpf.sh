#! /bin/bash

# Clone and install libbpf 
git clone https://github.com/libbpf/libbpf
cd ./libbpf
# This is the version of libbpf that our project has been tested with
# so far.
git checkout v0.3
cd ./libbpf/src
make
sudo make install
echo "/usr/lib64" | sudo tee /etc/ld.so.conf.d/libbpf.conf > /dev/null
sudo ldconfig

